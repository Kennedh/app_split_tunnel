"""Experimental narrow TUN used only for the screen-share RTC range.

The normal startup/control-plane remains PAC + local SOCKS. This second
sing-box process is armed *after* the normal voice UDP endpoint is known. It
adds one narrow route (normally a /16 derived from the voice media server),
EXCLUDES the exact voice server IP from the Windows TUN route, and sends UDP
from the target process in the remaining range through one independently
validated UDP-capable SOCKS5 relay.

Why exclude by remote IP instead of source port? Once Windows sends a packet
into the sing-box TUN, the packet presented to routing rules has a synthetic
TUN source address/port. Therefore the application's original UDP source port
is not reliable inside sing-box. The v13 source-port exception could miss and
proxy the voice flow as well. v13.1 keeps voice outside the TUN entirely.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from config import SCREEN_TUN_ADDRESS, SCREEN_TUN_INTERFACE_NAME, SCREEN_TUN_ROUTE_PREFIX
from modules.windows_job import KillOnCloseJob

logger = logging.getLogger("split_tunnel.rtc_tunnel")


class RtcTunnelError(RuntimeError):
    pass


def is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def endpoint_parts(endpoint: str) -> tuple[str, int]:
    host, port = endpoint.rsplit(":", 1)
    return host.strip("[]"), int(port)


def derive_route_cidr(remote_ip: str, prefix: int = SCREEN_TUN_ROUTE_PREFIX) -> str:
    ip = ipaddress.ip_address(remote_ip)
    if ip.version != 4:
        raise RtcTunnelError("v13 experimental suporta apenas RTC IPv4")
    return str(ipaddress.ip_network(f"{remote_ip}/{int(prefix)}", strict=False))


class RtcTunnelEngine:
    def __init__(self, project_root: Path, state_dir: Path):
        self.project_root = project_root
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = state_dir / "sing-box-rtc-tun.json"
        self.log_path = state_dir / "sing-box-rtc-tun.log"
        self.process: Optional[subprocess.Popen] = None
        self._log_handle = None
        self._job = KillOnCloseJob()
        self.kill_on_parent_exit = False
        self.route_cidr: Optional[str] = None
        self.voice_local_port: Optional[int] = None
        self.voice_remote_ip: Optional[str] = None
        self.proxy_address: Optional[str] = None

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
    def build_config(
        udp_proxy: str,
        target_process_name: str,
        route_cidr: str,
        voice_remote_ip: str,
    ) -> dict:
        proxy_host, proxy_port_s = udp_proxy.rsplit(":", 1)
        proxy_port = int(proxy_port_s)
        exclude: list[str] = []
        # Critical v13.1 safety rule: the established default/voice server
        # never enters the TUN. This is enforced by the Windows route itself,
        # before sing-box can rewrite the packet's source tuple.
        try:
            voice_ip = ipaddress.ip_address(voice_remote_ip.strip("[]"))
            if voice_ip.version == 4:
                exclude.append(f"{voice_ip}/32")
        except ValueError as exc:
            raise RtcTunnelError(f"IP remoto da voz inválido: {voice_remote_ip}") from exc

        # Prevent the SOCKS server's own traffic from recursively entering TUN.
        try:
            proxy_ip = ipaddress.ip_address(proxy_host.strip("[]"))
            if proxy_ip.version == 4:
                proxy_cidr = f"{proxy_ip}/32"
                if proxy_cidr not in exclude:
                    exclude.append(proxy_cidr)
        except ValueError:
            pass

        tun = {
            "type": "tun",
            "tag": "rtc-tun-in",
            "interface_name": SCREEN_TUN_INTERFACE_NAME,
            "address": [SCREEN_TUN_ADDRESS],
            "mtu": 1500,
            "auto_route": True,
            "strict_route": False,
            "route_address": [route_cidr],
        }
        if exclude:
            tun["route_exclude_address"] = exclude

        return {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [tun],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "socks",
                    "tag": "screen-socks",
                    "server": proxy_host.strip("[]"),
                    "server_port": proxy_port,
                    "version": "5",
                    "network": "udp",
                    "connect_timeout": "6s",
                    "domain_strategy": "prefer_ipv4",
                },
            ],
            "route": {
                "auto_detect_interface": True,
                "find_process": True,
                "rules": [
                    {
                        "inbound": ["rtc-tun-in"],
                        "network": ["udp"],
                        "process_name": [target_process_name],
                        "ip_cidr": [route_cidr],
                        "action": "route",
                        "outbound": "screen-socks",
                    },
                ],
                "final": "direct",
            },
        }

    def _read_log_tail(self, max_chars: int = 7000) -> str:
        try:
            if self._log_handle:
                self._log_handle.flush()
            return self.log_path.read_text(encoding="utf-8", errors="replace")[-max_chars:]
        except Exception:
            return ""

    def start(
        self,
        udp_proxy: str,
        target_process_name: str,
        voice_remote_endpoint: str,
        voice_local_endpoint: str,
        route_cidr: str | None = None,
    ) -> str:
        if os.name != "nt":
            raise RtcTunnelError("O túnel RTC experimental exige Windows")
        if not is_windows_admin():
            raise RtcTunnelError(
                "--tunnel-screen exige PowerShell/Terminal executado como Administrador para criar a interface TUN"
            )
        if self.process and self.process.poll() is None:
            return self.route_cidr or ""

        remote_ip, _ = endpoint_parts(voice_remote_endpoint)
        _, local_port = endpoint_parts(voice_local_endpoint)
        route_cidr = route_cidr or derive_route_cidr(remote_ip)
        # Validate CIDR and ensure the known voice server is covered.
        net = ipaddress.ip_network(route_cidr, strict=False)
        if ipaddress.ip_address(remote_ip) not in net:
            raise RtcTunnelError(f"O CIDR {route_cidr} não contém o endpoint de voz {remote_ip}")

        binary = self.find_binary()
        if binary is None:
            raise RtcTunnelError("sing-box.exe não encontrado")

        config = self.build_config(udp_proxy, target_process_name, route_cidr, remote_ip)
        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        checked = subprocess.run(
            [str(binary), "check", "-c", str(self.config_path)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if checked.returncode != 0:
            raise RtcTunnelError((checked.stderr or checked.stdout or "config RTC TUN rejeitada").strip())

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
            raise RtcTunnelError(f"Falha ao vincular RTC sing-box ao Job Object: {exc}") from exc

        time.sleep(0.7)
        if self.process.poll() is not None:
            tail = self._read_log_tail()
            self.stop()
            raise RtcTunnelError(f"RTC TUN encerrou ao iniciar: {tail.strip()}")

        self.route_cidr = route_cidr
        self.voice_local_port = local_port
        self.voice_remote_ip = remote_ip
        self.proxy_address = udp_proxy
        logger.info(
            "RTC TUN armado em %s: UDP do processo %s usa SOCKS5-UDP; servidor de voz %s/32 foi excluído da rota TUN (DIRECT)",
            route_cidr,
            target_process_name,
            remote_ip,
        )
        return route_cidr

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
