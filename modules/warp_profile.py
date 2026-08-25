"""Temporary WARP profile bootstrap used by the UDP split validation mode.

The project keeps the generated account/profile under runtime/warp so the
experimental validation remains portable.  wgcf is only used to register the
free WARP identity and generate a standard WireGuard profile; sing-box handles
the actual userspace WireGuard transport.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class WarpProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class WarpProfile:
    private_key: str
    addresses: tuple[str, ...]
    mtu: int
    peer_public_key: str
    allowed_ips: tuple[str, ...]
    endpoint_host: str
    endpoint_port: int
    profile_path: Path

    @property
    def ipv4_addresses(self) -> tuple[str, ...]:
        out: list[str] = []
        for item in self.addresses:
            try:
                if ipaddress.ip_interface(item).version == 4:
                    out.append(item)
            except ValueError:
                continue
        return tuple(out)

    @property
    def ipv4_allowed_ips(self) -> tuple[str, ...]:
        out: list[str] = []
        for item in self.allowed_ips:
            try:
                if ipaddress.ip_network(item, strict=False).version == 4:
                    out.append(item)
            except ValueError:
                continue
        return tuple(out)


def _split_values(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_wireguard_profile(path: Path) -> WarpProfile:
    section = ""
    values: dict[str, dict[str, list[str]]] = {"interface": {}, "peer": {}}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise WarpProfileError(f"Não foi possível ler o perfil WARP: {path}") from exc

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line or section not in values:
            continue
        key, raw_value = (part.strip() for part in line.split("=", 1))
        bucket = values[section].setdefault(key.lower(), [])
        if key.lower() in {"address", "allowedips", "dns"}:
            bucket.extend(_split_values(raw_value))
        else:
            bucket.append(raw_value)

    interface = values["interface"]
    peer = values["peer"]
    private_key = (interface.get("privatekey") or [""])[-1]
    addresses = tuple(interface.get("address") or [])
    mtu_text = (interface.get("mtu") or ["1280"])[-1]
    public_key = (peer.get("publickey") or [""])[-1]
    allowed_ips = tuple(peer.get("allowedips") or ["0.0.0.0/0"])
    endpoint = (peer.get("endpoint") or [""])[-1]

    if not private_key or not public_key or not addresses or not endpoint:
        raise WarpProfileError("Perfil WARP incompleto: PrivateKey/Address/PublicKey/Endpoint são obrigatórios")

    try:
        mtu = int(mtu_text)
    except ValueError:
        mtu = 1280

    if endpoint.startswith("["):
        close = endpoint.rfind("]")
        if close <= 0 or close + 2 > len(endpoint):
            raise WarpProfileError(f"Endpoint WARP inválido: {endpoint}")
        endpoint_host = endpoint[1:close]
        endpoint_port = int(endpoint[close + 2 :])
    else:
        endpoint_host, port_text = endpoint.rsplit(":", 1)
        endpoint_port = int(port_text)

    profile = WarpProfile(
        private_key=private_key,
        addresses=addresses,
        mtu=max(576, min(1500, mtu)),
        peer_public_key=public_key,
        allowed_ips=allowed_ips,
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        profile_path=path,
    )
    if not profile.ipv4_addresses:
        raise WarpProfileError("Perfil WARP não contém Address IPv4")
    if not profile.ipv4_allowed_ips:
        raise WarpProfileError("Perfil WARP não contém AllowedIPs IPv4")
    return profile


class WarpProfileManager:
    def __init__(self, resource_root: Path, runtime_dir: Path):
        self.resource_root = resource_root
        self.data_dir = runtime_dir / "warp"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.account_path = self.data_dir / "wgcf-account.toml"
        self.profile_path = self.data_dir / "wgcf-profile.conf"
        self.bootstrap_log = self.data_dir / "wgcf-bootstrap.log"

    def find_binary(self) -> Path | None:
        candidates = [
            self.resource_root / "bin" / "wgcf.exe",
            self.resource_root / "wgcf.exe",
            Path.cwd() / "bin" / "wgcf.exe",
            Path.cwd() / "wgcf.exe",
        ]
        on_path = shutil.which("wgcf.exe") or shutil.which("wgcf")
        if on_path:
            candidates.append(Path(on_path))
        for path in candidates:
            if path.exists() and path.is_file():
                return path.resolve()
        return None

    def _run(self, binary: Path, args: Iterable[str], timeout: int = 45) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            [str(binary), *list(args)],
            cwd=self.data_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        text = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        with self.bootstrap_log.open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(f"$ {binary.name} {' '.join(args)}\n{text}\n\n")
        return proc

    def ensure_profile(self, force_regenerate: bool = False) -> WarpProfile:
        if force_regenerate:
            self.profile_path.unlink(missing_ok=True)

        if self.profile_path.exists():
            try:
                return parse_wireguard_profile(self.profile_path)
            except WarpProfileError:
                self.profile_path.unlink(missing_ok=True)

        binary = self.find_binary()
        if binary is None:
            raise WarpProfileError(
                "wgcf.exe não encontrado. Recompile com build_exe.bat (v13.2 baixa e incorpora wgcf) "
                "ou coloque wgcf.exe em .\\bin."
            )

        if not self.account_path.exists():
            proc = self._run(binary, ["register", "--accept-tos"], timeout=60)
            if proc.returncode != 0 or not self.account_path.exists():
                raise WarpProfileError(
                    "Falha ao registrar a identidade WARP. Veja runtime\\warp\\wgcf-bootstrap.log"
                )

        proc = self._run(binary, ["generate"], timeout=45)
        if proc.returncode != 0 or not self.profile_path.exists():
            raise WarpProfileError(
                "Falha ao gerar wgcf-profile.conf. Veja runtime\\warp\\wgcf-bootstrap.log"
            )
        return parse_wireguard_profile(self.profile_path)
