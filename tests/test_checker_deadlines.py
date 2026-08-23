import asyncio
import time

from modules.checker import ProxyChecker, ProxyResult, _safe_close_writer


class _HangingWriter:
    def __init__(self):
        self.closed = False
        self.aborted = False

        class _Transport:
            def __init__(self, owner):
                self.owner = owner

            def abort(self):
                self.owner.aborted = True

        self.transport = _Transport(self)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        await asyncio.sleep(10)


def test_safe_close_has_hard_deadline():
    async def scenario():
        writer = _HangingWriter()
        started = time.monotonic()
        await _safe_close_writer(writer, timeout=0.03)
        elapsed = time.monotonic() - started
        assert writer.closed
        assert writer.aborted
        assert elapsed < 0.5

    asyncio.run(scenario())


def test_tls_validation_has_per_proxy_deadline():
    async def scenario():
        checker = ProxyChecker(
            tls_timeout=0.05,
            per_proxy_tls_timeout=0.12,
            concurrency=1,
        )

        async def hang_forever(*_args, **_kwargs):
            await asyncio.sleep(10)

        checker._tls_coverage = hang_forever  # type: ignore[method-assign]
        candidate = ProxyResult(
            latency_ms=1.0,
            address="127.0.0.1:1",
            connect_targets=("example.com:443",),
        )
        started = time.monotonic()
        result = await checker.validate_tls_one(candidate)
        elapsed = time.monotonic() - started
        assert result is None
        assert checker.stats["TLS_PROXY_DEADLINE"] == 1
        # Constructor keeps a small safety margin over tls_timeout.
        assert elapsed < 3.0

    asyncio.run(scenario())
