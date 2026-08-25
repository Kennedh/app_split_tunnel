from pathlib import Path

from modules.warp_profile import WarpProfile
from modules.warp_proxy import WarpProxyEngine


def test_warp_proxy_config_routes_socks_to_wireguard_endpoint(tmp_path: Path):
    profile = WarpProfile(
        private_key="abc=",
        addresses=("172.16.0.2/32", "2606:4700:110::2/128"),
        mtu=1280,
        peer_public_key="def=",
        allowed_ips=("0.0.0.0/0", "::/0"),
        endpoint_host="engage.cloudflareclient.com",
        endpoint_port=2408,
        profile_path=tmp_path / "wgcf-profile.conf",
    )
    config = WarpProxyEngine.build_config(profile, "127.0.0.1", 18100)
    assert config["inbounds"][0]["type"] == "socks"
    assert config["inbounds"][0]["listen_port"] == 18100
    endpoint = config["endpoints"][0]
    assert endpoint["type"] == "wireguard"
    assert endpoint["address"] == ["172.16.0.2/32"]
    assert endpoint["peers"][0]["allowed_ips"] == ["0.0.0.0/0"]
    assert config["route"]["rules"][0]["outbound"] == "warp-wg"
