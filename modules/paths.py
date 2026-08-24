"""Runtime/resource path helpers for source and PyInstaller builds."""
from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Directory containing bundled read-only resources."""
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parents[1]


def executable_root() -> Path:
    """Folder that owns persistent runtime state.

    Frozen/PyInstaller builds are deliberately portable: the state root is
    always the directory containing the executable, even when the executable
    happens to live inside a development ``dist`` folder.

    Source runs use the project root.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return resource_root()


def state_root() -> Path:
    """Return the writable portable state root.

    The application guarantees that ``runtime`` is created beside the EXE:

        <folder>/ApplicationSplitRouting.exe
        <folder>/runtime/

    There is intentionally no LOCALAPPDATA fallback. If the executable is
    placed in a read-only directory, fail clearly instead of silently storing
    state somewhere else. This keeps a copied release self-contained.
    """
    root = executable_root()
    runtime = root / "runtime"
    try:
        runtime.mkdir(parents=True, exist_ok=True)
        probe = runtime / ".write-test"
        probe.write_text("ok", encoding="ascii")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Nao foi possivel criar/gravar a pasta runtime ao lado do executavel: {runtime}. "
            "Mova o aplicativo para uma pasta com permissao de escrita."
        ) from exc
    return root
