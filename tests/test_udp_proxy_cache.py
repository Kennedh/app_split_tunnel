import json
from modules.cache import ProxyCache


def test_udp_proxy_cache_round_trip(tmp_path):
    cache = ProxyCache(tmp_path)
    cache.save_udp(["1.2.3.4:1080", "1.2.3.4:1080"], [{"latency_ms": 12.3}])
    assert cache.load_udp() == ["1.2.3.4:1080"]
    data = json.loads(cache.udp_path.read_text(encoding="utf-8"))
    assert data["proxies"] == ["1.2.3.4:1080"]
    assert data["details"][0]["latency_ms"] == 12.3
