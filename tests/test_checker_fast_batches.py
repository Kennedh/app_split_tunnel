import asyncio

from modules.checker import ProxyChecker, ProxyResult


def test_tls_batches_stop_after_pool_target():
    async def scenario():
        checker = ProxyChecker(concurrency=50, tls_batch_size=4)
        called = []

        async def fake_validate(result):
            called.append(result.address)
            await asyncio.sleep(0)
            return ProxyResult(
                latency_ms=result.latency_ms,
                tls_latency_ms=result.latency_ms,
                address=result.address,
                success_targets=("gateway.discord.gg:443", "discord.com:443"),
                connect_targets=result.connect_targets,
            )

        checker.validate_tls_one = fake_validate  # type: ignore[method-assign]
        candidates = [
            ProxyResult(
                latency_ms=float(i + 1),
                address=f"127.0.0.{i + 1}:1080",
                connect_targets=("gateway.discord.gg:443", "discord.com:443"),
            )
            for i in range(20)
        ]

        valid = await checker.validate_tls_many(candidates, desired=2)
        assert len(valid) == 4  # one full batch completes, then early stop
        assert len(called) == 4

    asyncio.run(scenario())
