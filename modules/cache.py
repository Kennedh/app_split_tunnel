"""Persistent caches for validated relays and harvested proxy inventory."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable, List


def _dedupe(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        item = str(item).strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


class ProxyCache:
    """Two-tier persistent cache.

    ``working_proxies.json`` contains only the last relays that completed the
    full SOCKS/CONNECT/TLS validation.  ``scanned_proxies.txt`` is deliberately
    plain text and contains only ``IP:PORT`` entries harvested from public
    sources.  This lets a future run retry the existing inventory without
    downloading the lists again.
    """

    def __init__(self, state_root: Path):
        self.runtime_dir = state_root / "runtime"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.runtime_dir / "working_proxies.json"
        self.scanned_path = self.runtime_dir / "scanned_proxies.txt"
        self.scanned_meta_path = self.runtime_dir / "scanned_proxies.meta.json"
        self.singbox_config = self.runtime_dir / "sing-box-split-tunnel.json"
        self.local_proxy_config = self.runtime_dir / "sing-box-local-proxy.json"
        self.udp_path = self.runtime_dir / "working_udp_proxies.json"

    def load(self) -> List[str]:
        """Load the last fully validated relays.

        Older generated configurations are accepted as a migration fallback so
        an upgrade does not force a new public-list download.
        """
        candidates: List[str] = []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            candidates.extend(data.get("proxies", []))
        except (OSError, ValueError, TypeError):
            pass

        if not candidates:
            for config_path in (self.local_proxy_config, self.singbox_config):
                try:
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    for outbound in config.get("outbounds", []):
                        if outbound.get("type") != "socks":
                            continue
                        host = outbound.get("server")
                        port = outbound.get("server_port")
                        if host and port:
                            candidates.append(f"{host}:{int(port)}")
                    if candidates:
                        break
                except (OSError, ValueError, TypeError):
                    pass

        return _dedupe(candidates)

    def save(self, proxies: Iterable[str]) -> None:
        data = {
            "saved_at": int(time.time()),
            "proxies": _dedupe(proxies),
        }
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp.replace(self.path)


    def load_udp(self) -> List[str]:
        """Load the last SOCKS5 relays that passed UDP ASSOCIATE + DNS."""
        try:
            data = json.loads(self.udp_path.read_text(encoding="utf-8"))
            return _dedupe(data.get("proxies", []))
        except (OSError, ValueError, TypeError):
            return []

    def save_udp(self, proxies: Iterable[str], details: list[dict] | None = None) -> None:
        data = {
            "saved_at": int(time.time()),
            "proxies": _dedupe(proxies),
            "details": details or [],
        }
        temp = self.udp_path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp.replace(self.udp_path)

    def load_scanned(self) -> List[str]:
        """Load the harvested IP:PORT inventory without network access."""
        try:
            return _dedupe(self.scanned_path.read_text(encoding="utf-8").splitlines())
        except OSError:
            return []

    def save_scanned(self, proxies: Iterable[str]) -> List[str]:
        """Persist only normalized IP:PORT lines and return the stored list."""
        cleaned = sorted(_dedupe(proxies))
        temp = self.scanned_path.with_suffix(".tmp")
        temp.write_text("".join(f"{proxy}\n" for proxy in cleaned), encoding="utf-8")
        temp.replace(self.scanned_path)

        meta = {
            "saved_at": int(time.time()),
            "count": len(cleaned),
        }
        meta_temp = self.scanned_meta_path.with_suffix(".tmp")
        meta_temp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        meta_temp.replace(self.scanned_meta_path)
        return cleaned

    def scanned_age_seconds(self) -> float | None:
        try:
            data = json.loads(self.scanned_meta_path.read_text(encoding="utf-8"))
            saved_at = float(data.get("saved_at", 0))
            if saved_at > 0:
                return max(0.0, time.time() - saved_at)
        except (OSError, ValueError, TypeError):
            pass
        try:
            return max(0.0, time.time() - self.scanned_path.stat().st_mtime)
        except OSError:
            return None
