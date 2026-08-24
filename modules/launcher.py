"""Target-application discovery and launcher for application-level split routing."""
from __future__ import annotations

import glob
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger("split_tunnel.launcher")


def find_default_executable() -> Optional[str]:
    roots = [os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA")]
    patterns = []
    for root in roots:
        if root:
            patterns.extend([
                os.path.join(root, "Discord", "app-*", "Discord.exe"),
                os.path.join(root, "DiscordPTB", "app-*", "DiscordPTB.exe"),
                os.path.join(root, "DiscordCanary", "app-*", "DiscordCanary.exe"),
            ])
    candidates = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern))
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    logger.info("Aplicativo alvo encontrado: %s", candidates[0])
    return candidates[0]


def _already_running(executable: str) -> bool:
    if os.name != "nt":
        return False
    image = os.path.basename(executable)
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image}", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return image.lower() in (proc.stdout or "").lower()
    except Exception:
        return False


def launch_application(
    executable: str,
    pac_url: str,
    extra_args: Optional[List[str]] = None,
    capture_output: bool = False,
) -> subprocess.Popen:
    if not os.path.isfile(executable):
        raise FileNotFoundError(executable)
    if _already_running(executable):
        raise RuntimeError(
            "O aplicativo alvo já está em execução. Feche todas as instâncias antes de iniciar: "
            "as opções de proxy/PAC precisam ser aplicadas ao processo principal desde o começo."
        )

    args = [executable, f"--proxy-pac-url={pac_url}"]
    if extra_args:
        args.extend(extra_args)
    logger.info("Iniciando aplicativo com PAC seletiva: %s", " ".join(args))
    if capture_output:
        return subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    return subprocess.Popen(args)


def start_output_tee(
    process: subprocess.Popen,
    line_callback: Optional[Callable[[str], None]] = None,
    log_path: Optional[Path] = None,
) -> threading.Thread:
    """Mirror captured child output to this console and an optional parser/log.

    The desktop client emits detailed RTC metadata to its inherited stdout; the
    native discord_media file does not necessarily contain those lines.  Keeping
    a tee here lets the user see the exact same output while the RTC inspector
    consumes it in real time.
    """
    if process.stdout is None:
        raise RuntimeError("O processo alvo não foi iniciado com captura de saída.")

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    def pump() -> None:
        sink = None
        try:
            if log_path is not None:
                sink = log_path.open("w", encoding="utf-8", errors="replace", buffering=1)
            for line in process.stdout:
                try:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                except Exception:
                    pass
                if sink is not None:
                    try:
                        sink.write(line)
                    except Exception:
                        pass
                if line_callback is not None:
                    try:
                        line_callback(line)
                    except Exception:
                        logger.exception("Falha ao processar uma linha da saída do aplicativo alvo")
        finally:
            try:
                process.stdout.close()
            except Exception:
                pass
            if sink is not None:
                try:
                    sink.close()
                except Exception:
                    pass

    thread = threading.Thread(target=pump, name="target-output-tee", daemon=True)
    thread.start()
    return thread


find_discord_executable = find_default_executable
