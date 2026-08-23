"""Local SOCKS relay pool backed by sing-box, without a system TUN.

This engine intentionally does *not* install routes or a virtual interface.
The target Chromium/Electron network stack reaches this local SOCKS listener
only for URLs selected by a PAC file. All DIRECT traffic stays in the Windows
kernel networking path and therefore cannot inherit latency from the relay.
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
from typing import List, Optional

from config import LOCAL_SOCKS_HOST, LOCAL_SOCKS_PORT_END, LOCAL_SOCKS_PORT_START

logger = logging.getLogger("split_tunnel.singbox")


class SingBoxError(RuntimeError):
    pass


def is_windows_admin() -> bool:
    # Kept for backwards compatibility with older imports. v10 does not need
    # administrator rights because no TUN/WFP/system route is created.
    return True


class SingBoxEngine:
    def __init__(self, project_root: Path, state_dir: Path | None = None):
        self.project_root = project_root
        self.state_dir = state_dir or project_root / "runtime"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.process: Optional[subprocess.Popen] = None
        self.config_path = self.state_dir / "sing-box-local-proxy.json"
        self.log_path = self.state_dir / "sing-box.log"
        self._log_handle = None
        self.listen_host = LOCAL_SOCKS_HOST
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
    def _proxy_parts(address: str):
        host, port = address.rsplit(":", 1)
        return host, int(port)

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

    def _choose_listen_port(self) -> int:
        for port in range(LOCAL_SOCKS_PORT_START, LOCAL_SOCKS_PORT_END + 1):
            if self._port_available(self.listen_host, port):
                return port
        raise SingBoxError(
            f"Nenhuma porta local livre entre {LOCAL_SOCKS_PORT_START} e {LOCAL_SOCKS_PORT_END}."
        )

    def build_config(self, proxies: List[str], health_url: str, listen_port: int) -> dict:
        if not proxies:
            raise SingBoxError("Nenhum proxy SOCKS5 TCP válido foi selecionado")

        proxy_outbounds = []
        tags = []
        for i, address in enumerate(proxies):
            host, port = self._proxy_parts(address)
            tag = f"socks-{i}"
            tags.append(tag)
            proxy_outbounds.append({
                "type": "socks",
                "tag": tag,
                "server": host,
                "server_port": port,
                "version": "5",
                "network": "tcp",
                "connect_timeout": "6s",
                "tcp_fast_open": True,
                "domain_strategy": "prefer_ipv4",
            })

        selected = tags[0]
        outbounds = list(proxy_outbounds)
        if len(tags) > 1:
            selected = "proxy-auto"
            outbounds.append({
                "type": "urltest",
                "tag": selected,
                "outbounds": tags,
                "url": health_url,
                "interval": "3m",
                "tolerance": 50,
                "idle_timeout": "15m",
                "interrupt_exist_connections": False,
            })

        return {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [{
                "type": "socks",
                "tag": "local-socks",
                "listen": self.listen_host,
                "listen_port": listen_port,
                "users": [],
            }],
            "outbounds": outbounds,
            "route": {
                "auto_detect_interface": True,
                "final": selected,
            },
        }

    def write_config(self, proxies: List[str], health_url: str, listen_port: int) -> Path:
        config = self.build_config(proxies, health_url, listen_port)
        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return self.config_path

    def validate_binary(self, binary: Path) -> None:
        proc = subprocess.run(
            [str(binary), "check", "-c", str(self.config_path)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            raise SingBoxError((proc.stderr or proc.stdout or "sing-box config rejected").strip())

    def _read_log_tail(self, max_chars: int = 5000) -> str:
        try:
            if self._log_handle:
                self._log_handle.flush()
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
            return text[-max_chars:]
        except Exception:
            return ""

    def _wait_listener(self, timeout: float = 5.0) -> None:
        if self.listen_port is None:
            raise SingBoxError("Porta local do SOCKS ainda não foi definida")
        deadline = time.monotonic() + timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.listen_host, self.listen_port), timeout=0.25):
                    return
            except OSError as exc:
                last_error = exc
                time.sleep(0.08)
        raise SingBoxError(f"SOCKS local não abriu em {self.listen_host}:{self.listen_port}: {last_error}")

    def start(self, proxies: List[str], health_url: str) -> tuple[str, int]:
        if os.name != "nt":
            raise SingBoxError("Esta edição foi preparada para Windows")
        binary = self.find_binary()
        if binary is None:
            raise SingBoxError("sing-box.exe não encontrado. Coloque-o em .\\bin\\sing-box.exe ou no PATH.")

        self.listen_port = self._choose_listen_port()
        self.write_config(proxies, health_url, self.listen_port)
        self.validate_binary(binary)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._log_handle = open(self.log_path, "w", encoding="utf-8", buffering=1)
        self.process = subprocess.Popen(
            [str(binary), "run", "-c", str(self.config_path)],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationflags,
        )
        time.sleep(0.25)
        if self.process.poll() is not None:
            tail = self._read_log_tail()
            self.stop()
            raise SingBoxError(f"sing-box encerrou ao iniciar: {tail.strip()}")

        try:
            self._wait_listener()
        except Exception:
            tail = self._read_log_tail()
            self.stop()
            if tail:
                logger.error("Últimas linhas do sing-box: %s", tail)
            raise

        logger.info(
            "Relay local iniciado em %s:%d; nenhuma rota/TUN do Windows foi alterada",
            self.listen_host,
            self.listen_port,
        )
        return self.listen_host, self.listen_port

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        if self._log_handle:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None
