"""
Utilitários compartilhados do protocolo SOCKS5 (RFC 1928).

Centraliza a montagem do campo ATYP+ADDR (escolhendo automaticamente
IPv4/IPv6/domínio) e a leitura do campo BND.ADDR+BND.PORT de respostas,
para não duplicar essa lógica entre checker.py e tunnel.py.
"""
from __future__ import annotations

import asyncio
import ipaddress

SOCKS_VERSION = 0x05


def encode_socks_address(host: str) -> bytes:
    """Monta o campo ATYP+ADDR de um pedido SOCKS5, detectando
    automaticamente se `host` é um IPv4, IPv6 ou nome de domínio.

    Importante: usar sempre isso (em vez de tratar tudo como domínio)
    evita falhas ao repassar destinos que já chegam como IP literal, e
    também permite usar IPs literais (ex.: 1.1.1.1) como alvo de teste
    de latência sem risco de erro de codificação.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host_bytes = host.encode("utf-8")
        return bytes([0x03, len(host_bytes)]) + host_bytes
    if ip.version == 4:
        return bytes([0x01]) + ip.packed
    return bytes([0x04]) + ip.packed


async def consume_socks_reply_address(reader: asyncio.StreamReader, atyp: int) -> None:
    """Lê e descarta o campo BND.ADDR + BND.PORT de uma resposta SOCKS5
    de acordo com o ATYP informado no cabeçalho da resposta."""
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    else:
        raise ConnectionError(f"ATYP desconhecido na resposta SOCKS5: 0x{atyp:02x}")