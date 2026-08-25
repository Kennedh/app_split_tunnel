import asyncio
from pathlib import Path

import modules.foreign_udp_scanner as scanner_mod
from modules.foreign_udp_scanner import ForeignProxySeed, ForeignUdpScanner, UdpScanHistory
from modules.udp_checker import StunProbeResult, StunSeriesResult


def test_udp_history_cooldown(tmp_path: Path):
    history = UdpScanHistory(tmp_path / "history.json", failure_cooldown_seconds=3600)
    history.mark_failure("1.2.3.4:1080", "TIMEOUT")
    history.save()
    again = UdpScanHistory(tmp_path / "history.json", failure_cooldown_seconds=3600)
    assert again.should_skip("1.2.3.4:1080") is True
    assert again.should_skip("1.2.3.4:1080", force=True) is False


def test_foreign_scanner_filters_br_and_deep_validates_foreign(monkeypatch, tmp_path: Path):
    async def fake_probe(address, timeout=1.0, **kwargs):
        if address.startswith("10.0.0.1"):
            return StunProbeResult("198.51.100.10", 50000, 40.0, address, "stun:3478")
        return StunProbeResult("203.0.113.20", 50001, 80.0, address, "stun:3478")

    async def fake_series(address, samples=5, **kwargs):
        return StunSeriesResult(
            public_ip="203.0.113.20",
            public_port=50001,
            rtts_ms=[82.0, 79.0, 85.0, 80.0, 81.0],
            samples_ok=5,
            samples_total=5,
            proxy_address=address,
            stun_server="stun:3478",
        )

    monkeypatch.setattr(scanner_mod, "probe_stun_via_socks", fake_probe)
    monkeypatch.setattr(scanner_mod, "probe_stun_series_via_socks", fake_series)
    monkeypatch.setattr(scanner_mod, "lookup_countries", lambda ips: {
        "198.51.100.10": "BR",
        "203.0.113.20": "US",
    })

    scanner = ForeignUdpScanner(
        tmp_path,
        excluded_countries={"BR"},
        concurrency=4,
        preflight_timeout=0.1,
        deep_timeout=0.1,
        max_preflight_successes=10,
    )
    results = asyncio.run(scanner.scan([
        ForeignProxySeed("10.0.0.1:1080", source="test"),
        ForeignProxySeed("10.0.0.2:1080", source="test"),
    ]))
    assert len(results) == 1
    assert results[0].address == "10.0.0.2:1080"
    assert results[0].egress_country == "US"
    assert results[0].reliability == 1.0
    assert results[0].median_rtt_ms == 81.0
