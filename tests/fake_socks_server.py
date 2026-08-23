"""
Servidor SOCKS5 mínimo (RFC 1928, sem autenticação) usado SOMENTE para
testes de integração locais. Ele implementa o protocolo de verdade
(handshake + CONNECT real), simulando um "proxy externo" para validarmos
checker.py e tunnel.py sem depender de proxies públicos de terceiros
(o sandbox de testes não tem egress liberado para IPs arbitrários).
"""
import asyncio

SOCKS_VERSION = 0x05


async def _handle(reader, writer):
    try:
        header = await reader.readexactly(2)
        nmethods = header[1]
        await reader.readexactly(nmethods)
        writer.write(bytes([SOCKS_VERSION, 0x00]))
        await writer.drain()

        req = await reader.readexactly(4)
        atyp = req[3]
        if atyp == 0x01:
            addr_bytes = await reader.readexactly(4)
            addr = ".".join(str(b) for b in addr_bytes)
        elif atyp == 0x03:
            length = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(length)).decode()
        else:
            writer.close()
            return
        port = int.from_bytes(await reader.readexactly(2), "big")

        try:
            t_reader, t_writer = await asyncio.open_connection(addr, port)
        except OSError:
            writer.write(bytes([SOCKS_VERSION, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            writer.close()
            return

        writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, OSError):
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, t_writer), pipe(t_reader, writer))
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def start_fake_proxy(host="127.0.0.1", port=0):
    server = await asyncio.start_server(_handle, host, port)
    return server
