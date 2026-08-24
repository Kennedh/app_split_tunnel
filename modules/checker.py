"""Concurrent SOCKS5 checker with end-to-end TLS verification.

Public SOCKS lists frequently contain relays that accept RFC 1928 CONNECT but
then redirect, intercept or truncate TLS.  A CONNECT-only checker therefore
produces false positives.  This module validates three independent layers:

1. SOCKS5 greeting/liveness.
2. SOCKS5 CONNECT to the configured application hosts.
3. Real TLS + hostname/certificate validation + an HTTPS response.

Only proxies that pass the required TLS targets are returned to the tunnel
engine.  This prevents a transparent split tunnel from selecting a relay that
breaks certificate validation in the target application.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .socks_utils import SOCKS_VERSION, consume_socks_reply_address, encode_socks_address

logger = logging.getLogger("split_tunnel.checker")

Target = Tuple[str, int]


async def _safe_close_writer(
    writer: asyncio.StreamWriter | None,
    timeout: float = 0.35,
) -> None:
    """Best-effort close with a hard deadline.

    Public relays can leave a TCP/TLS stream half-open forever.  Waiting for
    ``StreamWriter.wait_closed()`` without a timeout allows one bad relay to
    keep the whole phase alive even after every useful probe has finished.
    After the short grace period, abort the transport; checker sockets are
    disposable and must never block the batch shutdown.
    """
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        return

    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
        return
    except (
        asyncio.TimeoutError,
        ConnectionResetError,
        BrokenPipeError,
        OSError,
        ssl.SSLError,
    ):
        pass

    # ``transport`` is exposed by StreamWriter.  Abort is intentionally used
    # only after graceful close exceeded its deadline.
    try:
        writer.transport.abort()
    except Exception:
        pass


@dataclass
class ProxyResult:
    latency_ms: float
    address: str
    tcp_target: str = ""
    mode: str = "ipv4"
    error: str = ""
    success_targets: Tuple[str, ...] = field(default_factory=tuple)
    connect_targets: Tuple[str, ...] = field(default_factory=tuple)
    tls_latency_ms: float = 0.0

    @property
    def coverage(self) -> int:
        """Number of end-to-end TLS/HTTPS targets that passed."""
        return len(self.success_targets)

    @property
    def connect_coverage(self) -> int:
        return len(self.connect_targets)


class ProxyChecker:
    """Validate public SOCKS5 relays for application-level HTTPS proxying.

    CONNECT success alone is intentionally *not* enough.  A relay is usable
    only if all ``required_tls_targets`` complete a verified TLS handshake and
    return an HTTP response through the tunnel.
    """

    # Only destinations that will actually use the relay at runtime are
    # validated. Media/CDN/update traffic is deliberately direct in the TUN.
    DEFAULT_TARGETS: List[Target] = [
        ("gateway.discord.gg", 443),
        ("discord.com", 443),
    ]

    DEFAULT_REQUIRED_TLS_TARGETS: Tuple[Target, ...] = (
        ("gateway.discord.gg", 443),
        ("discord.com", 443),
    )

    def __init__(
        self,
        test_targets: Optional[List[Target]] = None,
        required_tls_targets: Optional[Sequence[Target]] = None,
        connect_timeout: float = 7.0,
        liveness_timeout: float = 3.0,
        tls_timeout: float = 9.0,
        per_proxy_tls_timeout: float = 16.0,
        concurrency: int = 100,
        latency_samples: int = 1,
        tls_batch_size: int = 12,
    ):
        self.test_targets = test_targets or list(self.DEFAULT_TARGETS)
        self.required_tls_targets = tuple(required_tls_targets or self.DEFAULT_REQUIRED_TLS_TARGETS)
        self.connect_timeout = connect_timeout
        self.liveness_timeout = liveness_timeout
        self.tls_timeout = tls_timeout
        self.per_proxy_tls_timeout = max(tls_timeout + 2.0, per_proxy_tls_timeout)
        self.latency_samples = max(1, latency_samples)
        self.tls_batch_size = max(1, tls_batch_size)
        self._semaphore = asyncio.Semaphore(concurrency)
        self.stats: Dict[str, int] = collections.Counter()
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    @staticmethod
    def _split_host_port(proxy: str) -> Tuple[str, int]:
        if "://" in proxy:
            proxy = proxy.split("://", 1)[1]
        host, port = proxy.rsplit(":", 1)
        return host.strip(), int(port)

    @staticmethod
    def _target_text(target: Target) -> str:
        return f"{target[0]}:{target[1]}"

    async def _negotiate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float | None = None,
    ) -> None:
        deadline = self.connect_timeout if timeout is None else timeout
        writer.write(bytes([SOCKS_VERSION, 1, 0x00]))
        await asyncio.wait_for(writer.drain(), deadline)
        resp = await asyncio.wait_for(reader.readexactly(2), deadline)
        if resp[0] != SOCKS_VERSION:
            raise ConnectionError(f"bad SOCKS version 0x{resp[0]:02x}")
        if resp[1] != 0x00:
            raise ConnectionError(f"unsupported SOCKS5 auth method 0x{resp[1]:02x}")

    async def _connect_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        packet = bytes([SOCKS_VERSION, 0x01, 0x00]) + encode_socks_address(host) + int(port).to_bytes(2, "big")
        writer.write(packet)
        await asyncio.wait_for(writer.drain(), self.connect_timeout)
        header = await asyncio.wait_for(reader.readexactly(4), self.connect_timeout)
        if header[0] != SOCKS_VERSION:
            raise ConnectionError("invalid SOCKS5 reply version")
        rep = header[1]
        if rep != 0x00:
            self.stats[f"REP=0x{rep:02x}"] += 1
            raise ConnectionError(f"CONNECT rejected REP=0x{rep:02x}")
        await asyncio.wait_for(
            consume_socks_reply_address(reader, header[3]),
            self.connect_timeout,
        )

    async def _resolve_ipv4(self, host: str) -> List[str]:
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_STREAM)
        except Exception:
            return []
        out: List[str] = []
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out[:3]

    async def _target_candidates(self, host: str) -> List[Tuple[str, str]]:
        # Runtime requests reach the SOCKS relay as hostnames. Probe the same path
        # first (ATYP=DOMAIN), then fall back to locally-resolved IPv4 addresses.
        # Some public SOCKS implementations/policies behave differently for
        # domain and literal-IP CONNECT requests, so IP-only validation can
        # incorrectly eliminate an otherwise usable relay.
        candidates: List[Tuple[str, str]] = [("domain", host)]
        for ip in await self._resolve_ipv4(host):
            candidates.append(("ipv4", ip))
        return candidates[:3]

    async def check_liveness(self, proxy: str) -> bool:
        writer = None
        try:
            host, port = self._split_host_port(proxy)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), self.liveness_timeout)
            await self._negotiate(reader, writer, timeout=self.liveness_timeout)
            return True
        except Exception:
            return False
        finally:
            await _safe_close_writer(writer)

    async def _probe_connect(self, proxy: str, target: Target, mode: str, connect_host: str) -> float:
        proxy_host, proxy_port = self._split_host_port(proxy)
        _target_host, target_port = target
        started = time.monotonic()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port), self.connect_timeout
            )
            await self._negotiate(reader, writer)
            await self._connect_request(reader, writer, connect_host, target_port)
            return (time.monotonic() - started) * 1000
        finally:
            await _safe_close_writer(writer)

    async def _probe_tls_https(
        self,
        proxy: str,
        target: Target,
        mode: str,
        connect_host: str,
    ) -> float:
        """Open SOCKS tunnel, verify TLS chain/hostname, then read HTTP status."""
        proxy_host, proxy_port = self._split_host_port(proxy)
        target_host, target_port = target
        started = time.monotonic()
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port), self.connect_timeout
            )
            await self._negotiate(reader, writer)
            await self._connect_request(reader, writer, connect_host, target_port)

            # start_tls uses the OS/Python default trust store and checks the
            # certificate against target_host.  A CONNECT relay that redirects
            # to a MITM/self-signed endpoint fails here and is never selected.
            await asyncio.wait_for(
                writer.start_tls(
                    self._ssl_context,
                    server_hostname=target_host,
                    ssl_handshake_timeout=self.tls_timeout,
                ),
                timeout=self.tls_timeout + 1.0,
            )

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                "User-Agent: AppSplitTunnel/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(request)
            await asyncio.wait_for(writer.drain(), self.tls_timeout)
            status = await asyncio.wait_for(reader.readline(), self.tls_timeout)
            if not status.startswith(b"HTTP/"):
                raise ConnectionError(f"HTTPS sem status HTTP valido: {status[:80]!r}")
            return (time.monotonic() - started) * 1000
        except ssl.SSLCertVerificationError as exc:
            self.stats["TLS_CERT_INVALID"] += 1
            raise ConnectionError(f"certificado TLS invalido: {exc.verify_message}") from exc
        except (ssl.SSLError, asyncio.IncompleteReadError) as exc:
            self.stats["TLS_HANDSHAKE_ERROR"] += 1
            raise ConnectionError(f"falha TLS: {exc}") from exc
        finally:
            await _safe_close_writer(writer)

    async def _connect_coverage(self, proxy: str) -> Tuple[Tuple[str, ...], float, str, str]:
        successes: List[Tuple[str, float, str]] = []
        for target in self.test_targets:
            target_text = self._target_text(target)
            for mode, connect_host in await self._target_candidates(target[0]):
                try:
                    latency = await self._probe_connect(proxy, target, mode, connect_host)
                    successes.append((target_text, latency, mode))
                    break
                except asyncio.TimeoutError:
                    self.stats["CONNECT_TIMEOUT"] += 1
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    self.stats["CONNECT_RESET"] += 1
                    continue
                except OSError as exc:
                    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                    self.stats[f"CONNECT_OSERROR_{code}" if code is not None else "CONNECT_OSERROR"] += 1
                    continue
                except Exception as exc:
                    name = type(exc).__name__.upper()
                    self.stats[f"CONNECT_{name}"] += 1
                    continue

        if not successes:
            return (), 0.0, "", ""
        fastest = min(successes, key=lambda item: item[1])
        mean = sum(item[1] for item in successes) / len(successes)
        return tuple(item[0] for item in successes), mean, fastest[0], fastest[2]

    async def _probe_tls_target(
        self, proxy: str, target: Target
    ) -> Tuple[Optional[Tuple[str, float, str]], List[str]]:
        """Probe one target and return the first end-to-end TLS success."""
        target_text = self._target_text(target)
        errors: List[str] = []
        for mode, connect_host in await self._target_candidates(target[0]):
            try:
                latency = await self._probe_tls_https(proxy, target, mode, connect_host)
                return (target_text, latency, mode), errors
            except Exception as exc:
                errors.append(f"{target_text}/{mode}: {exc}")
        return None, errors

    async def _tls_coverage(self, proxy: str, connect_targets: Sequence[str]) -> Tuple[Tuple[str, ...], float, str, str]:
        connect_set = set(connect_targets)
        successes: List[Tuple[str, float, str]] = []
        errors: List[str] = []

        # Gate on mandatory HTTPS endpoints first.  Most bad public relays fail
        # here, so there is no reason to spend several additional TLS timeouts
        # probing optional endpoints for a proxy that can never enter the pool.
        required_targets: List[Target] = []
        required_texts = {self._target_text(t) for t in self.required_tls_targets}
        for target in self.required_tls_targets:
            text = self._target_text(target)
            if text not in connect_set:
                logger.debug("Proxy %s rejeitado no TLS; CONNECT ausente em %s", proxy, text)
                return (), 0.0, "", ""
            required_targets.append(target)

        for target in required_targets:
            result, target_errors = await self._probe_tls_target(proxy, target)
            errors.extend(target_errors)
            if result is None:
                logger.debug(
                    "Proxy %s rejeitado no TLS obrigatorio %s; erros=%s",
                    proxy, self._target_text(target), target_errors[-3:],
                )
                return (), 0.0, "", ""
            successes.append(result)

        # Mandatory endpoints passed.  Probe the remaining targets only to rank
        # coverage/latency; their failure no longer invalidates the relay.
        for target in self.test_targets:
            target_text = self._target_text(target)
            if target_text in required_texts or target_text not in connect_set:
                continue
            result, target_errors = await self._probe_tls_target(proxy, target)
            errors.extend(target_errors)
            if result is not None:
                successes.append(result)

        fastest = min(successes, key=lambda item: item[1])
        mean = sum(item[1] for item in successes) / len(successes)
        return tuple(item[0] for item in successes), mean, fastest[0], fastest[2]

    async def check_one_connect(self, proxy: str) -> Optional[ProxyResult]:
        async with self._semaphore:
            connect_targets, mean_latency, fastest_target, mode = await self._connect_coverage(proxy)
            if not connect_targets:
                return None
            return ProxyResult(
                latency_ms=round(mean_latency, 1),
                address=proxy,
                tcp_target=fastest_target,
                mode=mode,
                connect_targets=connect_targets,
            )

    async def validate_tls_one(self, result: ProxyResult) -> Optional[ProxyResult]:
        async with self._semaphore:
            try:
                tls_targets, tls_mean, fastest_target, mode = await asyncio.wait_for(
                    self._tls_coverage(result.address, result.connect_targets),
                    timeout=self.per_proxy_tls_timeout,
                )
            except asyncio.TimeoutError:
                self.stats["TLS_PROXY_DEADLINE"] += 1
                logger.debug(
                    "Proxy %s excedeu o deadline global de TLS (%.1fs)",
                    result.address, self.per_proxy_tls_timeout,
                )
                return None

            if not tls_targets:
                return None
            return ProxyResult(
                latency_ms=round(tls_mean, 1),
                tls_latency_ms=round(tls_mean, 1),
                address=result.address,
                tcp_target=fastest_target,
                mode=mode,
                success_targets=tls_targets,
                connect_targets=result.connect_targets,
            )

    async def check_one(self, proxy: str) -> Optional[ProxyResult]:
        """Full single-proxy diagnostic: CONNECT then verified TLS/HTTPS."""
        connect_result = await self.check_one_connect(proxy)
        if connect_result is None:
            return None
        return await self.validate_tls_one(connect_result)

    async def filter_alive(self, proxies: List[str]) -> List[str]:
        async def probe(proxy: str) -> Optional[str]:
            # check_liveness already has its own timeouts.  Do not acquire the
            # same semaphore twice here (which can deadlock at concurrency=1).
            return proxy if await self.check_liveness(proxy) else None

        async def guarded(proxy: str) -> Optional[str]:
            async with self._semaphore:
                return await probe(proxy)

        results = await asyncio.gather(*(guarded(p) for p in proxies))
        return [r for r in results if r]

    async def check_connect_many(self, proxies: List[str]) -> List[ProxyResult]:
        results = await asyncio.gather(*(self.check_one_connect(p) for p in proxies))
        valid = [r for r in results if r is not None]
        valid.sort(key=lambda r: (-r.connect_coverage, r.latency_ms))
        return valid

    async def validate_tls_many(
        self,
        results: List[ProxyResult],
        desired: int | None = None,
    ) -> List[ProxyResult]:
        """Validate TLS in latency-ordered batches and stop once the pool is full.

        TLS is by far the most expensive phase. Public lists often contain over
        one hundred CONNECT-capable relays, while runtime needs only a handful.
        Candidates are already sorted by CONNECT latency, so validating them in
        small batches preserves a good chance of finding the fastest healthy
        relays without waiting for every slow public endpoint.
        """
        if not results:
            return []

        target = max(1, desired) if desired else None
        valid: List[ProxyResult] = []
        completed = 0
        total = len(results)

        for offset in range(0, total, self.tls_batch_size):
            batch = results[offset: offset + self.tls_batch_size]
            tasks = [asyncio.create_task(self.validate_tls_one(r)) for r in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                completed += 1
                if isinstance(result, ProxyResult):
                    valid.append(result)
                elif isinstance(result, Exception):
                    logger.debug("Falha isolada durante validacao TLS: %r", result)

            valid.sort(key=lambda r: (-r.coverage, r.tls_latency_ms))
            logger.info(
                "Fase 3: %d/%d candidatos TLS testados (%d aprovados)",
                completed, total, len(valid),
            )

            if target is not None and len(valid) >= target:
                logger.info(
                    "Fase 3: pool alvo de %d relay(s) atingido; encerrando validacao cedo",
                    target,
                )
                break

        return valid

    async def check_many(self, proxies: List[str]) -> List[ProxyResult]:
        connect_valid = await self.check_connect_many(proxies)
        return await self.validate_tls_many(connect_valid)

    async def check_many_fast(self, proxies: List[str], desired_tls: int | None = None) -> List[ProxyResult]:
        alive = await self.filter_alive(proxies)
        logger.info("Fase 1: %d/%d proxies responderam ao handshake SOCKS5", len(alive), len(proxies))

        connect_valid = await self.check_connect_many(alive)
        logger.info("Fase 2: %d proxies passaram no CONNECT TCP", len(connect_valid))
        if not connect_valid:
            if alive:
                logger.warning("Nenhum proxy aceitou CONNECT nos destinos de teste configurados.")
            if self.stats:
                logger.info("Motivos observados: %s", dict(self.stats))
            return []

        tls_valid = await self.validate_tls_many(connect_valid, desired=desired_tls)
        logger.info(
            "Fase 3: %d proxies passaram TLS confiavel + HTTPS nos endpoints obrigatorios",
            len(tls_valid),
        )
        if tls_valid:
            top_coverage = tls_valid[0].coverage
            logger.info("Melhor cobertura TLS observada: %d/%d destinos", top_coverage, len(self.test_targets))
        else:
            logger.warning(
                "Os proxies aceitavam CONNECT, mas nenhum passou a validacao TLS/HTTPS obrigatoria."
            )

        if self.stats:
            logger.info("Motivos observados: %s", dict(self.stats))
        return tls_valid
