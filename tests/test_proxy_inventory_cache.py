from pathlib import Path

from modules.cache import ProxyCache


def test_scanned_inventory_is_plain_ip_port_file(tmp_path: Path):
    cache = ProxyCache(tmp_path)
    stored = cache.save_scanned([
        "2.2.2.2:1080",
        "1.1.1.1:1080",
        "2.2.2.2:1080",
        "",
    ])
    assert stored == ["1.1.1.1:1080", "2.2.2.2:1080"]
    assert cache.scanned_path.read_text(encoding="utf-8") == (
        "1.1.1.1:1080\n2.2.2.2:1080\n"
    )
    assert cache.load_scanned() == stored


def test_working_and_scanned_caches_are_separate(tmp_path: Path):
    cache = ProxyCache(tmp_path)
    cache.save_scanned(["1.1.1.1:1080", "2.2.2.2:1080"])
    cache.save(["2.2.2.2:1080"])
    assert cache.load() == ["2.2.2.2:1080"]
    assert cache.load_scanned() == ["1.1.1.1:1080", "2.2.2.2:1080"]
