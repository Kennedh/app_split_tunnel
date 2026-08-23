"""Runtime/resource path helpers for source and PyInstaller builds."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DATA_DIR = "ApplicationSplitRouting"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Directory containing bundled read-only resources.

    In a PyInstaller --onefile build this points at the temporary _MEIPASS
    extraction directory.  In source mode it is the project root.
    """
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parents[1]


def _writable_state_candidate() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return resource_root()


def state_root() -> Path:
    """Persistent writable directory.

    Prefer a portable ``runtime`` folder next to the executable.  If that
    location is not writable (for example Program Files), transparently fall
    back to LOCALAPPDATA so the proxy inventory survives future launches.
    """
    candidate = _writable_state_candidate()
    try:
        runtime = candidate / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        probe = runtime / ".write-test"
        probe.write_text("ok", encoding="ascii")
        probe.unlink(missing_ok=True)
        return candidate
    except OSError:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            fallback = Path(base) / APP_DATA_DIR
        else:
            fallback = Path.home() / f".{APP_DATA_DIR}"
        (fallback / "runtime").mkdir(parents=True, exist_ok=True)
        return fallback
