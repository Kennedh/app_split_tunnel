import socket
import struct

from modules.udp_checker import _parse_stun_public_endpoint


def test_parse_xor_mapped_ipv4():
    txid = b"123456789012"
    cookie = 0x2112A442
    ip = socket.inet_aton("203.0.113.44")
    xip = bytes(a ^ b for a, b in zip(ip, struct.pack("!I", cookie)))
    port = 54321
    xport = port ^ (cookie >> 16)
    value = b"\x00\x01" + struct.pack("!H", xport) + xip
    attr = struct.pack("!HH", 0x0020, len(value)) + value
    payload = struct.pack("!HHI", 0x0101, len(attr), cookie) + txid + attr
    assert _parse_stun_public_endpoint(payload, txid) == ("203.0.113.44", 54321)
