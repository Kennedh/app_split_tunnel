import asyncio

import main
from modules.checker import ProxyResult


def test_large_inventory_stops_after_pool_is_found(monkeypatch):
    calls = []

    class FakeChecker:
        test_targets = [("a", 443), ("b", 443)]

        async def check_many_fast(self, candidates, desired_tls=None):
            calls.append(len(candidates))
            if len(calls) == 1:
                return []
            return [
                ProxyResult(address="10.0.0.1:1080", latency_ms=10, tls_latency_ms=10, success_targets=("a", "b")),
                ProxyResult(address="10.0.0.2:1080", latency_ms=11, tls_latency_ms=11, success_targets=("a", "b")),
            ]

    monkeypatch.setattr(main, "build_checker", lambda: FakeChecker())

    result = asyncio.run(
        main.validate_candidates_chunked(
            [f"192.0.2.{i % 250}:{10000 + i}" for i in range(9000)],
            desired=2,
            minimum=1,
            label="Test",
            chunk_size=4000,
        )
    )

    assert result is not None
    selected, _checker = result
    assert len(selected) == 2
    assert calls == [4000, 4000]
