from pathlib import Path

from modules.pac import build_pac
from modules.singbox import SingBoxEngine


def test_pac_is_allowlist_and_direct_by_default():
    pac = build_pac(
        proxy_host="127.0.0.1",
        proxy_port=17980,
        proxy_exact_hosts=["control.example"],
        proxy_patterns=["gateway*.example"],
        direct_exact_hosts=["updates.example"],
        direct_patterns=["*.media.example"],
        proxy_window_seconds=25,
    )
    assert 'SOCKS5 127.0.0.1:17980' in pac
    assert 'return "DIRECT";' in pac
    assert 'gateway*.example' in pac
    assert '*.media.example' in pac
    assert 'Date.now()' in pac


def test_singbox_config_has_no_tun(tmp_path: Path):
    engine = SingBoxEngine(tmp_path)
    cfg = engine.build_config(
        ["1.2.3.4:1080", "5.6.7.8:1080"],
        "https://control.example/health",
        17980,
    )
    assert cfg["inbounds"][0]["type"] == "socks"
    assert all(inbound.get("type") != "tun" for inbound in cfg["inbounds"])
    assert "auto_route" not in cfg["inbounds"][0]
    assert cfg["route"]["final"] == "proxy-auto"
