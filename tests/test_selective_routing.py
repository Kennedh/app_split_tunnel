import json
from pathlib import Path

from modules.cache import ProxyCache
from modules.pac import build_pac
from modules.singbox import SingBoxEngine


def test_generated_config_has_local_socks_only(tmp_path: Path):
    engine = SingBoxEngine(tmp_path)
    config = engine.build_config(
        ["127.0.0.1:1080"],
        "https://example.com/health",
        17980,
    )
    assert config["inbounds"] == [{
        "type": "socks",
        "tag": "local-socks",
        "listen": "127.0.0.1",
        "listen_port": 17980,
        "users": [],
    }]
    assert all(item.get("type") != "tun" for item in config["inbounds"])
    assert config["route"]["final"] == "socks-0"


def test_pac_routes_only_allowlisted_hosts():
    pac = build_pac(
        proxy_host="127.0.0.1",
        proxy_port=17980,
        proxy_exact_hosts=["control.example"],
        proxy_patterns=["gateway*.example"],
        direct_exact_hosts=["updates.example"],
        direct_patterns=["*.media.example"],
        proxy_window_seconds=20,
    )
    assert 'control.example' in pac
    assert 'gateway*.example' in pac
    assert 'updates.example' in pac
    assert '*.media.example' in pac
    assert 'return PROXY;' in pac
    # Anything that did not match the allowlist falls through to DIRECT.
    assert pac.rstrip().endswith('}')
    assert pac.count('return "DIRECT";') >= 3


def test_cache_imports_relays_from_previous_runtime_config(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    old = {
        "outbounds": [
            {"type": "socks", "server": "192.0.2.10", "server_port": 1080},
            {"type": "socks", "server": "198.51.100.20", "server_port": 4145},
            {"type": "direct", "tag": "direct"},
        ]
    }
    (runtime / "sing-box-split-tunnel.json").write_text(json.dumps(old), encoding="utf-8")

    cache = ProxyCache(tmp_path)
    assert cache.load() == ["192.0.2.10:1080", "198.51.100.20:4145"]
