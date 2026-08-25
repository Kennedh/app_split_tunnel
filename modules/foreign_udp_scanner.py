"""Fast foreign SOCKS5-UDP discovery for the RTC screen-share tunnel.

The scanner deliberately separates *discovery* from *deep validation*:

1. Fresh metadata-backed SOCKS5 seeds are tried first.
2. A one-shot STUN probe proves UDP ASSOCIATE and reveals the real UDP egress IP.
3. Egress IPs are geolocated in one batch and local/excluded countries are dropped.
4. The best foreign candidates receive a multi-sample STUN stability test.

This makes the expensive large public inventory a last resort rather than the
normal path.  The selected relay is still only a best-effort public proxy; no
credentials or private infrastructure are required.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import requests

from modules.geo import lookup_countries
from modules.udp_checker import StunProbeResult, probe_stun_via_socks, probe_stun_series_via_socks

logger = logging.getLogger("split_tunnel.foreign_udp")

PROXYSCRAPE_SOCKS5_JSON = (
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/"
    "proxies/protocols/socks5/data.json"
)


@dataclass
class ForeignProxySeed:
    address: str
    source_country: str | None = None
    source_latency_ms: float | None = None
    uptime_percent: float | None = None
    source: str = "unknown"


@dataclass
class ForeignUdpResult:
    address: str
    egress_ip: str
    egress_port: int
    egress_country: str
    setup_total_ms: float
    stun_rtt_ms: float
    median_rtt_ms: float
    p95_rtt_ms: float
    jitter_ms: float
    samples_ok: int
    samples_total: int
    reliability: float
    score: float
    source: str = "unknown"
    source_country: str | None = None
    source_latency_ms: float | None = None

    @property
    def latency_ms(self) -> float:
        # Compatibility with the older UdpProxyResult/coordinator.
        return self.setup_total_ms

    @property
    def setup_ms(self) -> float:
        return max(0.0, self.setup_total_ms - self.stun_rtt_ms)

    @property
    def udp_rtt_ms(self) -> float:
        return self.stun_rtt_ms

    @property
    def relay_host(self) -> str:
        return self.address.rsplit(":", 1)[0].strip("[]")

    @property
    def relay_port(self) -> int:
        return int(self.address.rsplit(":", 1)[1])

    def to_dict(self) -> dict:
        return asdict(self)


class UdpScanHistory:
    """Small cooldown database so immediate reruns do not retest dead relays."""

    def __init__(self, path: Path, failure_cooldown_seconds: float = 3600.0):
        self.path = path
        self.failure_cooldown_seconds = float(failure_cooldown_seconds)
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(self.data, dict):
                self.data = {}
        except (OSError, ValueError, TypeError):
            self.data = {}

    def should_skip(self, address: str, force: bool = False) -> bool:
        if force:
            return False
        item = self.data.get(address) or {}
        failed_at = float(item.get("failed_at") or 0)
        return bool(failed_at and time.time() - failed_at < self.failure_cooldown_seconds)

    def mark_failure(self, address: str, reason: str) -> None:
        item = self.data.setdefault(address, {})
        item.update({"failed_at": int(time.time()), "failure": str(reason)[:160]})

    def mark_success(self, result: ForeignUdpResult) -> None:
        self.data[result.address] = {
            "success_at": int(time.time()),
            "egress_ip": result.egress_ip,
            "country": result.egress_country,
            "median_rtt_ms": result.median_rtt_ms,
            "reliability": result.reliability,
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        tmp.replace(self.path)


def harvest_metadata_seeds(
    excluded_countries: set[str],
    timeout: float = 8.0,
    max_source_latency_ms: float = 1200.0,
    min_uptime_percent: float = 5.0,
) -> list[ForeignProxySeed]:
    """Fetch a small, very fresh SOCKS5 feed with country/latency metadata."""
    try:
        response = requests.get(
            PROXYSCRAPE_SOCKS5_JSON,
            timeout=timeout,
            headers={"User-Agent": "ApplicationSplitRouting/13.3"},
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning("Fonte SOCKS5 metadata indisponível: %s", exc)
        return []

    seeds: list[ForeignProxySeed] = []
    for item in payload if isinstance(payload, list) else []:
        try:
            ip = str(item.get("ip") or "").strip()
            port = int(item.get("port"))
            if not ip or not (1 <= port <= 65535):
                continue
            country = str(item.get("country_code") or "").upper() or None
            if country and country in excluded_countries:
                continue
            latency = float(item.get("latency_ms")) if item.get("latency_ms") is not None else None
            uptime = float(item.get("uptime_percent")) if item.get("uptime_percent") is not None else None
            # Metadata is only a prioritization hint.  Do not over-filter unknowns.
            if latency is not None and latency > max_source_latency_ms:
                continue
            if uptime is not None and uptime < min_uptime_percent:
                continue
            seeds.append(
                ForeignProxySeed(
                    address=f"{ip}:{port}",
                    source_country=country,
                    source_latency_ms=latency,
                    uptime_percent=uptime,
                    source="proxyscrape-metadata",
                )
            )
        except (TypeError, ValueError):
            continue

    seeds.sort(
        key=lambda s: (
            s.source_latency_ms if s.source_latency_ms is not None else 99999.0,
            -(s.uptime_percent if s.uptime_percent is not None else 0.0),
        )
    )
    return seeds


class ForeignUdpScanner:
    def __init__(
        self,
        runtime_dir: Path,
        excluded_countries: Iterable[str] = ("BR",),
        concurrency: int = 320,
        preflight_timeout: float = 1.6,
        deep_timeout: float = 2.0,
        max_median_rtt_ms: float = 550.0,
        max_p95_rtt_ms: float = 900.0,
        deep_samples: int = 5,
        min_deep_success: int = 4,
        max_preflight_successes: int = 24,
        failure_cooldown_seconds: float = 3600.0,
    ):
        self.runtime_dir = runtime_dir
        self.excluded_countries = {str(x).upper() for x in excluded_countries if str(x).strip()}
        self.concurrency = max(1, int(concurrency))
        self.preflight_timeout = float(preflight_timeout)
        self.deep_timeout = float(deep_timeout)
        self.max_median_rtt_ms = float(max_median_rtt_ms)
        self.max_p95_rtt_ms = float(max_p95_rtt_ms)
        self.deep_samples = max(2, int(deep_samples))
        self.min_deep_success = max(1, min(int(min_deep_success), self.deep_samples))
        self.max_preflight_successes = max(3, int(max_preflight_successes))
        self.history = UdpScanHistory(
            runtime_dir / "udp_probe_history.json",
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
        self.report_path = runtime_dir / "udp_hunt_report.json"
        self.stats: dict[str, int] = {
            "submitted": 0,
            "skipped_cooldown": 0,
            "stun_success": 0,
            "foreign_success": 0,
            "deep_success": 0,
        }

    async def _preflight_one(self, seed: ForeignProxySeed, sem: asyncio.Semaphore):
        if self.history.should_skip(seed.address):
            self.stats["skipped_cooldown"] += 1
            return seed, None, "COOLDOWN"
        self.stats["submitted"] += 1
        async with sem:
            started = time.perf_counter()
            try:
                probe = await probe_stun_via_socks(seed.address, timeout=self.preflight_timeout)
                total_ms = (time.perf_counter() - started) * 1000.0
                self.stats["stun_success"] += 1
                return seed, (probe, total_ms), None
            except Exception as exc:
                reason = str(exc) or type(exc).__name__
                self.history.mark_failure(seed.address, reason)
                return seed, None, reason

    async def preflight(self, seeds: list[ForeignProxySeed]) -> list[tuple[ForeignProxySeed, StunProbeResult, float]]:
        if not seeds:
            return []
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [asyncio.create_task(self._preflight_one(seed, sem)) for seed in seeds]
        successes: list[tuple[ForeignProxySeed, StunProbeResult, float]] = []
        try:
            for task in asyncio.as_completed(tasks):
                seed, value, _reason = await task
                if value is not None:
                    probe, total_ms = value
                    successes.append((seed, probe, total_ms))
                    if len(successes) >= self.max_preflight_successes:
                        break
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.history.save()
        return successes

    async def _deep_validate(self, seed: ForeignProxySeed, first_probe: StunProbeResult, setup_total_ms: float, country: str) -> ForeignUdpResult | None:
        try:
            series = await probe_stun_series_via_socks(
                seed.address,
                samples=self.deep_samples,
                timeout=self.deep_timeout,
                interval=0.035,
            )
        except Exception as exc:
            self.history.mark_failure(seed.address, f"SERIES_{str(exc) or type(exc).__name__}")
            return None

        if series.samples_ok < self.min_deep_success:
            self.history.mark_failure(
                seed.address, f"STABILITY_{series.samples_ok}/{series.samples_total}"
            )
            return None
        if series.public_ip != first_probe.public_ip:
            # A reconnect that changes egress may confuse RTC/NAT assumptions.
            self.history.mark_failure(seed.address, "EGRESS_CHANGED_ON_RECONNECT")
            return None

        stable_rtts = sorted(float(x) for x in series.rtts_ms)
        median = statistics.median(stable_rtts)
        p95_index = max(0, min(len(stable_rtts) - 1, math.ceil(len(stable_rtts) * 0.95) - 1))
        p95 = stable_rtts[p95_index]
        jitter = statistics.pstdev(stable_rtts) if len(stable_rtts) > 1 else 0.0
        reliability = series.samples_ok / series.samples_total
        if median > self.max_median_rtt_ms or p95 > self.max_p95_rtt_ms:
            self.history.mark_failure(seed.address, f"RTT_MEDIAN_{median:.0f}_P95_{p95:.0f}")
            return None

        score = median + (0.35 * p95) + (0.50 * jitter) + ((1.0 - reliability) * 1200.0)
        result = ForeignUdpResult(
            address=seed.address,
            egress_ip=series.public_ip,
            egress_port=series.public_port,
            egress_country=country,
            setup_total_ms=setup_total_ms,
            stun_rtt_ms=float(first_probe.rtt_ms),
            median_rtt_ms=float(median),
            p95_rtt_ms=float(p95),
            jitter_ms=float(jitter),
            samples_ok=series.samples_ok,
            samples_total=series.samples_total,
            reliability=float(reliability),
            score=float(score),
            source=seed.source,
            source_country=seed.source_country,
            source_latency_ms=seed.source_latency_ms,
        )
        self.history.mark_success(result)
        self.history.save()
        self.stats["deep_success"] += 1
        return result

    async def scan(self, seeds: list[ForeignProxySeed], desired: int = 1) -> list[ForeignUdpResult]:
        unique: dict[str, ForeignProxySeed] = {}
        for seed in seeds:
            unique.setdefault(seed.address, seed)
        preflight = await self.preflight(list(unique.values()))
        if not preflight:
            self._write_report([], [], {})
            return []

        egress_ips = list(dict.fromkeys(item[1].public_ip for item in preflight))
        countries = await asyncio.to_thread(lookup_countries, egress_ips)
        foreign: list[tuple[ForeignProxySeed, StunProbeResult, float, str]] = []
        for seed, probe, total_ms in preflight:
            country = (countries.get(probe.public_ip) or "").upper()
            if not country or country in self.excluded_countries:
                if country in self.excluded_countries:
                    self.history.mark_failure(seed.address, f"EGRESS_COUNTRY_{country}")
                continue
            foreign.append((seed, probe, total_ms, country))
        self.stats["foreign_success"] += len(foreign)
        self.history.save()

        # Fastest observed STUN first.  Deep validation is intentionally serial-ish:
        # only a handful of rare UDP-capable foreign relays reach this stage.
        foreign.sort(key=lambda item: item[1].rtt_ms)
        finalists: list[ForeignUdpResult] = []
        for seed, probe, total_ms, country in foreign[:12]:
            result = await self._deep_validate(seed, probe, total_ms, country)
            if result is not None:
                finalists.append(result)
                finalists.sort(key=lambda x: x.score)
                if len(finalists) >= max(1, desired):
                    # Keep validating one extra candidate when cheap so cache has fallback.
                    if len(finalists) >= min(2, max(1, desired + 1)):
                        break

        finalists.sort(key=lambda x: x.score)
        self._write_report(preflight, finalists, countries)
        return finalists

    def _write_report(self, preflight, finalists: list[ForeignUdpResult], countries: dict[str, str]) -> None:
        payload = {
            "updated_at": int(time.time()),
            "excluded_countries": sorted(self.excluded_countries),
            "stats": self.stats,
            "preflight_udp_successes": [
                {
                    "address": seed.address,
                    "egress_ip": probe.public_ip,
                    "country": countries.get(probe.public_ip),
                    "stun_rtt_ms": round(probe.rtt_ms, 1),
                    "source": seed.source,
                }
                for seed, probe, _total in preflight
            ],
            "finalists": [item.to_dict() for item in finalists],
        }
        try:
            tmp = self.report_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.report_path)
        except OSError:
            pass
