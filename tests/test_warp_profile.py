from pathlib import Path

from modules.warp_profile import parse_wireguard_profile


def test_parse_wgcf_profile(tmp_path: Path):
    path = tmp_path / "wgcf-profile.conf"
    path.write_text(
        """[Interface]
PrivateKey = abc123=
Address = 172.16.0.2/32, 2606:4700:110::2/128
DNS = 1.1.1.1
MTU = 1280
[Peer]
PublicKey = def456=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
""",
        encoding="utf-8",
    )
    profile = parse_wireguard_profile(path)
    assert profile.private_key == "abc123="
    assert profile.ipv4_addresses == ("172.16.0.2/32",)
    assert profile.ipv4_allowed_ips == ("0.0.0.0/0",)
    assert profile.endpoint_host == "engage.cloudflareclient.com"
    assert profile.endpoint_port == 2408
    assert profile.mtu == 1280
