"""Userspace WARP SOCKS proxy backed by sing-box WireGuard endpoint.

This is deliberately a temporary validation backend. It does not install a
system route. The narrow RTC TUN talks to its local SOCKS5 listener, while the
WireGuard endpoint carries that SOCKS traffic over WARP.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from modules.warp_profile import WarpProfile
from modules.windows_job import KillOnCloseJob

logger = logging.getLogger("split_tunnel.warp_proxy")


class WarpProxyError(RuntimeError):
    pass


class WarpProxyEngine:
    def __init__(self, project_root: Path, state_dir: Path):
        self.project_root = project_root
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = state_dir / "sing-box-warp-proxy.json"
        self.log_path = state_dir / "sing-box-warp-proxy.log"
        self.status_path = state_dir / "warp_status.json"
        self.process: Optional[subprocess.Popen] = None
        self._log_handle = None
        self._job = KillOnCloseJob()
        self.kill_on_parent_exit = False
        self.listen_host = "127.0.0.1"
        self.listen_port: int | None = None

    def find_binary(self) -> Optional[Path]:
        candidates = [
            self.project_root / "bin" / "sing-box.exe",
            self.project_root / "sing-box.exe",
            Path.cwd() / "bin" / "sing-box.exe",
            Path.cwd() / "sing-box.exe",
        ]
        on_path = shutil.which("sing-box.exe") or shutil.which("sing-box")
        if on_path:
            candidates.append(Path(on_path))
        for path in candidates:
            if path.exists() and path.is_file():
                return path.resolve()
        return None

    @staticmethod
    def _port_available(host: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _choose_port(self) -> int:
        for port in range(18100, 18151):
            if self._port_available(self.listen_host, port):
                return port
        raise WarpProxyError("Nenhuma porta local livre entre 18100 e 18150 para o backend WARP")

    @staticmethod
    def build_config(profile: WarpProfile, listen_host: str, listen_port: int) -> dict:
        # v13.2 uses IPv4 only for the validation path. This keeps the narrow
        # Discord RTC experiment independent of host IPv6 behavior.
        address = list(profile.ipv4_addresses)
        allowed = list(profile.ipv4_allowed_ips) or ["0.0.0.0/0"]
        return {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "warp-socks-in",
                    "listen": listen_host,
                    "listen_port": int(listen_port),
                    "users": [],
                }
            ],
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "warp-wg",
                    "system": False,
                    "name": "ast-warp",
                    "mtu": int(profile.mtu),
                    "address": address,
                    "private_key": profile.private_key,
                    "peers": [
                        {
                            "address": profile.endpoint_host,
                            "port": int(profile.endpoint_port),
                            "public_key": profile.peer_public_key,
                            "allowed_ips": allowed,
                            "persistent_keepalive_interval": 25,
                        }
                    ],
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "auto_detect_interface": True,
                "rules": [
                    {
                        "inbound": ["warp-socks-in"],
                        "action": "route",
                        "outbound": "warp-wg",
                    }
                ],
                "final": "direct",
            },
        }

    def _read_tail(self, max_chars: int = 9000) -> str:
        try:
            if self._log_handle:
                self._log_handle.flush()
            return self.log_path.read_text(encoding="utf-8", errors="replace")[-max_chars:]
        except Exception:
            return ""

    def _wait_listener(self, timeout: float = 6.0) -> None:
        if self.listen_port is None:
            raise WarpProxyError("Porta local WARP não definida")
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.listen_host, self.listen_port), timeout=0.3):
                    return
            except OSError as exc:
                last = exc
                time.sleep(0.1)
        raise WarpProxyError(f"SOCKS WARP não abriu em {self.listen_host}:{self.listen_port}: {last}")

    def _write_status(self, **extra) -> None:
        data = {
            "updated_at": int(time.time()),
            "running": bool(self.process and self.process.poll() is None),
            "socks": f"{self.listen_host}:{self.listen_port}" if self.listen_port else None,
            **extra,
        }
        try:
            tmp = self.status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.status_path)
        except Exception:
            pass

    def start(self, profile: WarpProfile) -> tuple[str, int]:
        if os.name != "nt":
            raise WarpProxyError("O backend WARP experimental foi preparado para Windows")
        if self.process and self.process.poll() is None and self.listen_port is not None:
            return self.listen_host, self.listen_port

        binary = self.find_binary()
        if binary is None:
            raise WarpProxyError("sing-box.exe não encontrado")
        self.listen_port = self._choose_port()
        config = self.build_config(profile, self.listen_host, self.listen_port)
        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        checked = subprocess.run(
            [str(binary), "check", "-c", str(self.config_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if checked.returncode != 0:
            raise WarpProxyError((checked.stderr or checked.stdout or "config WARP rejeitada").strip())

        self._log_handle = open(self.log_path, "w", encoding="utf-8", buffering=1)
        self.process = subprocess.Popen(
            [str(binary), "run", "-c", str(self.config_path)],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            self._job.create()
            self._job.assign_process_handle(int(self.process._handle))
            self.kill_on_parent_exit = True
        except Exception as exc:
            self.stop()
            raise WarpProxyError(f"Falha ao vincular WARP sing-box ao Job Object: {exc}") from exc

        time.sleep(0.4)
        if self.process.poll() is not None:
            tail = self._read_tail()
            self.stop()
            raise WarpProxyError(f"Backend WARP encerrou ao iniciar: {tail.strip()}")
        try:
            self._wait_listener()
        except Exception:
            tail = self._read_tail()
            self.stop()
            raise WarpProxyError(f"Backend WARP não ficou pronto. {tail.strip()}")

        self._write_status(
            profile=str(profile.profile_path),
            wireguard_endpoint=f"{profile.endpoint_host}:{profile.endpoint_port}",
            wireguard_ipv4=list(profile.ipv4_addresses),
            mtu=profile.mtu,
        )
        logger.info("Backend WARP userspace pronto em %s:%d", self.listen_host, self.listen_port)
        return self.listen_host, self.listen_port

    def update_status(self, **extra) -> None:
        self._write_status(**extra)

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        self.kill_on_parent_exit = False
        self._job.close()
        if self._log_handle:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None
        self._write_status(stopped=True)
