"""SOCKS5 UDP ASSOCIATE validator for the experimental RTC screen tunnel.

A TCP/TLS-capable public SOCKS5 server is not necessarily able to relay UDP.
This module independently validates RFC 1928 UDP ASSOCIATE by sending a tiny
DNS query through the relay and requiring a valid response.  It does not use
or alter application traffic during validation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Optional

from config import (
    UDP_PROXY_CONCURRENCY,
    UDP_PROXY_DNS_TARGET,
    UDP_PROXY_TIMEOUT,
    UDP_PROXY_MAX_TOTAL_MS,
    UDP_PROXY_MAX_RTT_MS,
)
from modules.socks_utils import encode_socks_address

logger = logging.getLogger("split_tunnel.udp_checker")


@dataclass
class UdpProxyResult:
    address: str
    latency_ms: float
    relay_host: str
    relay_port: int
    setup_ms: float = 0.0
    udp_rtt_ms: float = 0.0


def _parse_host_port(address: str) -> tuple[str, int]:
    host, port = address.rsplit(":", 1)
    return host.strip("[]"), int(port)


async def _read_reply_endpoint(reader: asyncio.StreamReader) -> tuple[str, int]:
    head = await reader.readexactly(4)
    if head[0] != 0x05:
        raise ConnectionError(f"SOCKS_VERSION_{head[0]}")
    if head[1] != 0x00:
        raise ConnectionError(f"UDP_ASSOC_REP=0x{head[1]:02x}")
    atyp = head[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 0x03:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode("ascii", "replace")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ConnectionError(f"UDP_ASSOC_ATYP=0x{atyp:02x}")
    port = int.from_bytes(await reader.readexactly(2), "big")
    return host, port


def _dns_query() -> tuple[int, bytes]:
    txid = random.SystemRandom().randrange(0, 65536)
    # A query for discord.com.  Small, deterministic and accepted by normal
    # recursive DNS servers.  We only inspect txid + QR on the response.
    qname = b"\x07discord\x03com\x00"
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    return txid, packet


def _udp_frame(host: str, port: int, payload: bytes) -> bytes:
    return b"\x00\x00\x00" + encode_socks_address(host) + int(port).to_bytes(2, "big") + payload


def _unwrap_udp_frame(data: bytes) -> bytes:
    if len(data) < 4 or data[0:2] != b"\x00\x00" or data[2] != 0:
        raise ConnectionError("UDP_FRAME_INVALID")
    atyp = data[3]
    pos = 4
    if atyp == 0x01:
        pos += 4
    elif atyp == 0x03:
        if len(data) <= pos:
            raise ConnectionError("UDP_FRAME_SHORT")
        pos += 1 + data[pos]
    elif atyp == 0x04:
        pos += 16
    else:
        raise ConnectionError(f"UDP_FRAME_ATYP=0x{atyp:02x}")
    pos += 2
    if pos > len(data):
        raise ConnectionError("UDP_FRAME_SHORT")
    return data[pos:]


class UdpProxyChecker:
    def __init__(
        self,
        timeout: float = UDP_PROXY_TIMEOUT,
        concurrency: int = UDP_PROXY_CONCURRENCY,
        max_total_ms: float = UDP_PROXY_MAX_TOTAL_MS,
        max_udp_rtt_ms: float = UDP_PROXY_MAX_RTT_MS,
    ):
        self.timeout = float(timeout)
        self.concurrency = max(1, int(concurrency))
        self.max_total_ms = float(max_total_ms)
        self.max_udp_rtt_ms = float(max_udp_rtt_ms)
        self._sem = asyncio.Semaphore(self.concurrency)
        self.stats: Counter[str] = Counter()

    def _fail(self, exc: BaseException) -> None:
        if isinstance(exc, asyncio.TimeoutError):
            self.stats["UDP_TIMEOUT"] += 1
        elif isinstance(exc, ConnectionError):
            self.stats[str(exc)] += 1
        else:
            self.stats[f"UDP_{type(exc).__name__.upper()}"] += 1

    async def check_one(self, address: str) -> Optional[UdpProxyResult]:
        async with self._sem:
            writer = None
            udp = None
            started = time.perf_counter()
            try:
                proxy_host, proxy_port = _parse_host_port(address)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy_host, proxy_port), timeout=self.timeout
                )
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                greeting = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
                if greeting != b"\x05\x00":
                    raise ConnectionError("UDP_NOAUTH_REJECTED")

                loop = asyncio.get_running_loop()
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind(("0.0.0.0", 0))
                udp.setblocking(False)
                local_port = udp.getsockname()[1]

                req = b"\x05\x03\x00\x01\x00\x00\x00\x00" + int(local_port).to_bytes(2, "big")
                writer.write(req)
                await writer.drain()
                relay_host, relay_port = await asyncio.wait_for(_read_reply_endpoint(reader), timeout=self.timeout)
                if relay_port <= 0:
                    raise ConnectionError("UDP_RELAY_PORT_ZERO")
                if relay_host in {"0.0.0.0", "::"}:
                    relay_host = proxy_host
                try:
                    relay_ip = str(ipaddress.ip_address(relay_host))
                except ValueError:
                    info = await asyncio.wait_for(
                        loop.getaddrinfo(relay_host, relay_port, family=socket.AF_INET, type=socket.SOCK_DGRAM),
                        timeout=self.timeout,
                    )
                    relay_ip = info[0][4][0]

                setup_done = time.perf_counter()
                txid, dns = _dns_query()
                target_host, target_port = UDP_PROXY_DNS_TARGET
                frame = _udp_frame(target_host, target_port, dns)
                udp_started = time.perf_counter()
                await asyncio.wait_for(loop.sock_sendto(udp, frame, (relay_ip, relay_port)), timeout=self.timeout)
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(udp, 4096), timeout=self.timeout)
                udp_done = time.perf_counter()
                payload = _unwrap_udp_frame(data)
                if len(payload) < 12:
                    raise ConnectionError("UDP_DNS_SHORT")
                rxid, flags = struct.unpack("!HH", payload[:4])
                if rxid != txid or not (flags & 0x8000):
                    raise ConnectionError("UDP_DNS_INVALID")

                total_ms = (udp_done - started) * 1000.0
                setup_ms = (setup_done - started) * 1000.0
                udp_rtt_ms = (udp_done - udp_started) * 1000.0
                if self.max_total_ms > 0 and total_ms > self.max_total_ms:
                    raise ConnectionError("UDP_TOO_SLOW_TOTAL")
                if self.max_udp_rtt_ms > 0 and udp_rtt_ms > self.max_udp_rtt_ms:
                    raise ConnectionError("UDP_TOO_SLOW_RTT")

                return UdpProxyResult(
                    address=address,
                    latency_ms=total_ms,
                    relay_host=relay_host,
                    relay_port=relay_port,
                    setup_ms=setup_ms,
                    udp_rtt_ms=udp_rtt_ms,
                )
            except Exception as exc:
                self._fail(exc)
                return None
            finally:
                if udp is not None:
                    udp.close()
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

    async def check_many_fast(self, proxies: Iterable[str], desired: int = 1) -> list[UdpProxyResult]:
        unique = list(dict.fromkeys(str(p).strip() for p in proxies if str(p).strip()))
        if not unique:
            return []
        tasks = [asyncio.create_task(self.check_one(proxy)) for proxy in unique]
        found: list[UdpProxyResult] = []
        try:
            for done in asyncio.as_completed(tasks):
                result = await done
                if result is not None:
                    found.append(result)
                    logger.info(
                        "UDP ASSOCIATE aprovado: %s (setup %.1f ms, UDP RTT %.1f ms, total %.1f ms)",
                        result.address,
                        result.setup_ms,
                        result.udp_rtt_ms,
                        result.latency_ms,
                    )
                    if len(found) >= max(1, desired):
                        break
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        found.sort(key=lambda r: r.latency_ms)
        return found
