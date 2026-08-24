import asyncio
import struct

import modules.udp_checker as udp_checker
from modules.udp_checker import UdpProxyChecker


class FakeUdpRelay(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Keep the SOCKS UDP header and convert the embedded DNS request into a
        # minimal response with the same transaction ID and QR=1.
        if len(data) < 10 or data[:3] != b"\x00\x00\x00":
            return
        atyp = data[3]
        pos = 4
        if atyp == 1:
            pos += 4
        elif atyp == 3:
            pos += 1 + data[pos]
        elif atyp == 4:
            pos += 16
        else:
            return
        pos += 2
        payload = data[pos:]
        if len(payload) < 12:
            return
        txid = payload[:2]
        response = txid + struct.pack("!H", 0x8180) + payload[4:]
        self.transport.sendto(data[:pos] + response, addr)


async def scenario():
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: FakeUdpRelay(), local_addr=("127.0.0.1", 0))
    relay_port = transport.get_extra_info("sockname")[1]

    async def handle(reader, writer):
        try:
            head = await reader.readexactly(2)
            await reader.readexactly(head[1])
            writer.write(b"\x05\x00")
            await writer.drain()
            req = await reader.readexactly(10)
            assert req[1] == 3
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + relay_port.to_bytes(2, "big"))
            await writer.drain()
            await reader.read()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    old = udp_checker.UDP_PROXY_DNS_TARGET
    udp_checker.UDP_PROXY_DNS_TARGET = ("1.1.1.1", 53)
    try:
        checker = UdpProxyChecker(timeout=1.0, concurrency=4, max_total_ms=5000, max_udp_rtt_ms=5000)
        result = await checker.check_many_fast([f"127.0.0.1:{port}"], desired=1)
        assert len(result) == 1
        assert result[0].address == f"127.0.0.1:{port}"
        assert result[0].relay_port == relay_port
        assert result[0].setup_ms >= 0
        assert result[0].udp_rtt_ms >= 0

        # A technically functional but extremely slow relay must be rejected.
        strict = UdpProxyChecker(timeout=1.0, concurrency=4, max_total_ms=0.001, max_udp_rtt_ms=5000)
        rejected = await strict.check_many_fast([f"127.0.0.1:{port}"], desired=1)
        assert rejected == []
        assert strict.stats["UDP_TOO_SLOW_TOTAL"] >= 1
    finally:
        udp_checker.UDP_PROXY_DNS_TARGET = old
        server.close()
        await server.wait_closed()
        transport.close()


def test_udp_associate_and_dns_probe():
    asyncio.run(scenario())
