"""Target-application discovery and launcher for application-level split routing."""
from __future__ import annotations

import glob
import logging
import os
import subprocess
from typing import List, Optional

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
    return subprocess.Popen(args)


find_discord_executable = find_default_executable
