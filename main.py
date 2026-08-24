#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import sys
import threading
import ipaddress
import json
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from config import (
    CHECK_CONCURRENCY,
    CONNECT_TIMEOUT,
    DEFAULT_PROXY_WINDOW_SECONDS,
    LATENCY_SAMPLES,
    LIVENESS_TIMEOUT,
    MIN_PROXIES,
    PAC_DIRECT_EXACT_HOSTS,
    PAC_DIRECT_HOST_PATTERNS,
    PAC_PROXY_EXACT_HOSTS,
    PAC_PROXY_HOST_PATTERNS,
    PER_PROXY_TLS_TIMEOUT,
    PROXY_SOURCES_FALLBACK,
    PROXY_SOURCES_PRIMARY,
    SCAN_CHUNK_SIZE,
    RESCRAPE_INTERVAL,
    TLS_BATCH_SIZE,
    TLS_TIMEOUT,
    TOP_PROXIES,
    UDP_PROXY_SCAN_CHUNK_SIZE,
)
from modules.cache import ProxyCache
from modules.checker import ProxyChecker, ProxyResult
from modules.launcher import find_default_executable, launch_application, start_output_tee
from modules.pac import PacServer, build_pac
from modules.paths import resource_root, state_root
from modules.rtc_inspector import RtcInspector, find_default_media_log
from modules.rtc_tunnel import RtcTunnelEngine, RtcTunnelError, is_windows_admin
from modules.udp_checker import UdpProxyChecker, UdpProxyResult
from modules.scraper import ProxyScraper
from modules.singbox import SingBoxEngine, SingBoxError

console = Console()
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("split_tunnel.main")

CONTROL_HEALTH_URL = "https://discord.com/api/v10/gateway"


def build_checker() -> ProxyChecker:
    return ProxyChecker(
        connect_timeout=CONNECT_TIMEOUT,
        liveness_timeout=LIVENESS_TIMEOUT,
        tls_timeout=TLS_TIMEOUT,
        per_proxy_tls_timeout=PER_PROXY_TLS_TIMEOUT,
        concurrency=CHECK_CONCURRENCY,
        latency_samples=LATENCY_SAMPLES,
        tls_batch_size=TLS_BATCH_SIZE,
    )


def choose_pool(ranked: list[ProxyResult], limit: int) -> list[ProxyResult]:
    return sorted(ranked, key=lambda r: (r.tls_latency_ms, -r.coverage))[: max(1, limit)]


def show_pool(selected_results: list[ProxyResult], checker: ProxyChecker, source: str) -> None:
    console.print(
        f"[green]Pool pronto[/green] ({source}): {len(selected_results)} relay(s) "
        "para a janela de acesso"
    )
    table = Table("Proxy", "TLS/HTTPS ms", "Cobertura")
    total_targets = len(checker.test_targets)
    for result in selected_results:
        table.add_row(result.address, f"{result.tls_latency_ms:.1f}", f"{result.coverage}/{total_targets}")
    console.print(table)


async def _udp_probe_group(candidates: list[str], label: str) -> list[UdpProxyResult]:
    if not candidates:
        return []
    console.print(f"[cyan]{label}[/cyan] testando SOCKS5 UDP ASSOCIATE em {len(candidates)} relay(s)...")
    checker = UdpProxyChecker()
    found = await checker.check_many_fast(candidates, desired=1)
    if not found and checker.stats:
        console.print(f"[dim]Falhas UDP observadas: {dict(checker.stats)}[/dim]")
    return found


async def select_udp_proxy(
    cache: ProxyCache,
    preferred: list[str],
    force_scan: bool = False,
    manual_proxy: str | None = None,
) -> UdpProxyResult:
    """Find one relay that actually implements SOCKS5 UDP ASSOCIATE.

    TCP CONNECT/TLS and UDP support are intentionally separate caches.  Public
    lists frequently advertise SOCKS5 servers that only implement CONNECT.
    """
    if manual_proxy:
        found = await _udp_probe_group([manual_proxy], "UDP manual")
        if not found:
            raise RuntimeError(f"O proxy UDP informado não passou UDP ASSOCIATE: {manual_proxy}")
        cache.save_udp([found[0].address], [found[0].__dict__])
        return found[0]

    ordered_small: list[str] = []
    if not force_scan:
        ordered_small.extend(cache.load_udp())
    ordered_small.extend(preferred)
    ordered_small.extend(cache.load())
    ordered_small = list(dict.fromkeys(ordered_small))
    if ordered_small:
        found = await _udp_probe_group(ordered_small, "Cache UDP")
        if found:
            cache.save_udp([found[0].address], [found[0].__dict__])
            return found[0]

    inventory = cache.load_scanned()
    if not inventory:
        console.print("[yellow]Sem inventário local para UDP; atualizando fontes SOCKS5 prioritárias...[/yellow]")
        inventory = await asyncio.to_thread(ProxyScraper(PROXY_SOURCES_PRIMARY).harvest)
        if inventory:
            inventory = cache.save_scanned(inventory)

    shuffled = list(dict.fromkeys(inventory))
    random.SystemRandom().shuffle(shuffled)
    total = len(shuffled)
    chunk_size = max(200, int(UDP_PROXY_SCAN_CHUNK_SIZE))
    for offset in range(0, total, chunk_size):
        chunk = shuffled[offset:offset + chunk_size]
        console.print(
            f"[cyan]UDP lote {offset // chunk_size + 1}[/cyan]: "
            f"testando {offset + 1}-{offset + len(chunk)} de {total} IPs..."
        )
        found = await _udp_probe_group(chunk, "UDP")
        if found:
            cache.save_udp([found[0].address], [found[0].__dict__])
            return found[0]

    # One last chance: large feeds may not have been part of an older inventory.
    console.print("[yellow]Inventário local não produziu SOCKS5-UDP. Baixando fallback grande uma única vez...[/yellow]")
    fallback = await asyncio.to_thread(ProxyScraper(PROXY_SOURCES_FALLBACK).harvest)
    fallback = [p for p in fallback if p not in set(inventory)]
    random.SystemRandom().shuffle(fallback)
    for offset in range(0, len(fallback), chunk_size):
        chunk = fallback[offset:offset + chunk_size]
        console.print(
            f"[cyan]UDP fallback {offset // chunk_size + 1}[/cyan]: "
            f"testando {offset + 1}-{offset + len(chunk)} de {len(fallback)} IPs..."
        )
        found = await _udp_probe_group(chunk, "UDP fallback")
        if found:
            cache.save_scanned(list(dict.fromkeys(inventory + fallback)))
            cache.save_udp([found[0].address], [found[0].__dict__])
            return found[0]

    raise RuntimeError(
        "Nenhum SOCKS5 com UDP ASSOCIATE funcional foi encontrado. "
        "O startup TCP continua utilizável, mas --tunnel-screen precisa de SOCKS5-UDP."
    )


async def validate_candidates(candidates: list[str], desired: int, minimum: int, label: str):
    """Validate a small candidate set (normally the last known-good pool)."""
    if not candidates:
        return None
    console.print(f"[cyan]{label}[/cyan] Revalidando {len(candidates)} proxy(s)...")
    checker = build_checker()
    ranked = await checker.check_many_fast(candidates, desired_tls=desired)
    selected = choose_pool(ranked, desired)
    if len(selected) >= minimum:
        return selected, checker
    return None


async def validate_candidates_chunked(
    candidates: list[str],
    desired: int,
    minimum: int,
    label: str,
    chunk_size: int = SCAN_CHUNK_SIZE,
):
    """Probe huge inventories incrementally and stop as soon as a usable pool exists.

    The old checker scheduled every IP in one asyncio.gather(). With 100k+ dead
    public proxies that can legitimately take tens of minutes even at high
    concurrency. Here we shuffle the inventory, inspect bounded chunks and stop
    after MIN_PROXIES/TOP_PROXIES are found.
    """
    if not candidates:
        return None

    shuffled = list(dict.fromkeys(candidates))
    random.SystemRandom().shuffle(shuffled)
    total = len(shuffled)
    chunk_size = max(200, int(chunk_size))
    target = max(minimum, desired)
    found: list[ProxyResult] = []
    last_checker: ProxyChecker | None = None

    for offset in range(0, total, chunk_size):
        chunk = shuffled[offset: offset + chunk_size]
        end = offset + len(chunk)
        console.print(
            f"[cyan]{label}[/cyan] lote {offset // chunk_size + 1}: "
            f"testando {offset + 1}-{end} de {total} IPs..."
        )
        checker = build_checker()
        last_checker = checker
        need = max(1, target - len(found))
        ranked = await checker.check_many_fast(chunk, desired_tls=need)
        if ranked:
            known = {r.address for r in found}
            found.extend(r for r in ranked if r.address not in known)
            found = choose_pool(found, target)
            console.print(
                f"[green]{label}[/green] acumulado: {len(found)}/{target} relay(s) válido(s)."
            )

        if len(found) >= target:
            break

    if len(found) >= minimum and last_checker is not None:
        return choose_pool(found, desired), last_checker
    return None


async def validate_cached_pool(cache: ProxyCache, desired: int, minimum: int):
    cached = cache.load()
    result = await validate_candidates(cached, desired, minimum, "Cache ativo")
    if result is not None:
        selected, checker = result
        console.print(
            f"[bold green]Cache aproveitado:[/bold green] {len(selected)} relay(s); "
            "nenhuma lista grande foi testada."
        )
        return selected, checker
    if cached:
        console.print(
            f"[yellow]Relays ativos expiraram[/yellow]; tentando o inventário local de IPs antes de acessar a internet."
        )
    return None


async def validate_scanned_inventory(cache: ProxyCache, desired: int, minimum: int):
    scanned = cache.load_scanned()
    if not scanned:
        return None
    age = cache.scanned_age_seconds()
    age_text = "idade desconhecida" if age is None else f"{age / 3600:.1f}h"
    console.print(
        f"[cyan]Inventário local[/cyan] {len(scanned)} IP:PORT salvos ({age_text}); "
        f"triagem em lotes de até {SCAN_CHUNK_SIZE} sem baixar fontes públicas..."
    )
    result = await validate_candidates_chunked(scanned, desired, minimum, "Inventário")
    if result is not None:
        selected, checker = result
        console.print(
            f"[bold green]Inventário reaproveitado:[/bold green] {len(selected)} relay(s) válidos encontrados; "
            "download das listas ignorado."
        )
        return selected, checker
    console.print(
        "[yellow]Inventário local esgotado[/yellow]; nenhum conjunto mínimo permaneceu válido. "
        "As fontes públicas serão atualizadas agora."
    )
    return None


async def fresh_scan(cache: ProxyCache, desired: int, minimum: int):
    """Try compact feeds first; download 100k+ fallback feeds only if necessary."""
    console.print("[cyan]1/4[/cyan] Atualizando fontes SOCKS5 prioritárias...")
    primary_scraper = ProxyScraper(PROXY_SOURCES_PRIMARY)
    primary = await asyncio.to_thread(primary_scraper.harvest)
    if primary:
        primary = cache.save_scanned(primary)
        console.print(
            f"[dim]Inventário prioritário salvo em {cache.scanned_path} ({len(primary)} IP:PORT).[/dim]"
        )
        console.print(
            f"[cyan]2/4[/cyan] Triagem incremental; lotes de até {SCAN_CHUNK_SIZE} e parada antecipada."
        )
        result = await validate_candidates_chunked(primary, desired, minimum, "Primário")
        if result is not None:
            return result

    console.print(
        "[yellow]Fontes prioritárias não produziram relay válido.[/yellow] "
        "Baixando agora as fontes grandes de fallback..."
    )
    fallback_scraper = ProxyScraper(PROXY_SOURCES_FALLBACK)
    fallback = await asyncio.to_thread(fallback_scraper.harvest)
    combined = list(dict.fromkeys((primary or []) + fallback))
    if not combined:
        raise RuntimeError("Nenhum proxy foi coletado.")
    cache.save_scanned(combined)
    console.print(
        f"[dim]Inventário ampliado salvo ({len(combined)} IP:PORT); "
        "os feeds grandes só serão percorridos em lotes.[/dim]"
    )
    result = await validate_candidates_chunked(fallback, desired, minimum, "Fallback")
    if result is None:
        raise RuntimeError(f"Apenas 0 proxy(s) fim-a-fim permaneceram; mínimo={minimum}.")
    return result


async def rescrape_loop(scraper: ProxyScraper, cache: ProxyCache, interval: float, desired: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            raw = await asyncio.to_thread(scraper.harvest)
            raw = cache.save_scanned(raw)
            checker = build_checker()
            ranked = await checker.check_many_fast(raw, desired_tls=desired)
            selected = choose_pool(ranked, desired)
            if selected:
                cache.save(r.address for r in selected)
        except Exception as exc:
            logger.warning("Atualização opcional do cache falhou: %s", exc)


def _configure_windows_asyncio() -> None:
    if os.name == "nt" and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _install_loop_exception_filter() -> None:
    loop = asyncio.get_running_loop()
    default_handler = loop.default_exception_handler

    def handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        handle_text = repr(context.get("handle", ""))
        winerror = getattr(exc, "winerror", None)
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)) and winerror in {10053, 10054} and "_call_connection_lost" in handle_text:
            return
        default_handler(context)

    loop.set_exception_handler(handler)


def _rtc_console_event(event: dict, session) -> None:
    kind = event.get("type")
    if kind == "log_attached":
        console.print(f"[dim]RTC Inspector acompanhando: {event.get('path')}[/dim]")
    elif kind == "media_endpoint":
        console.print(
            f"[cyan]RTC {event.get('context', 'default')}[/cyan] endpoint={event.get('remote')} "
            f"audio_ssrc={event.get('audio_ssrc')}"
        )
    elif kind == "local_transport":
        console.print(
            f"[cyan]RTC {event.get('context', 'default')}[/cyan] transporte local={event.get('local')} "
            f"protocolo={event.get('protocol')}"
        )
    elif kind == "video_discovered":
        console.print(
            f"[magenta]RTC vídeo {event.get('context', 'default')}[/magenta] SSRC={event.get('ssrc')} "
            f"RTX={event.get('rtx_ssrc')} active={event.get('active')}"
        )
    elif kind == "video_activated":
        console.print(
            "[bold magenta]RTC vídeo ATIVADO[/bold magenta] "
            f"contexto={event.get('context', 'default')} SSRC={event.get('ssrc')} "
            f"RTX={event.get('rtx_ssrc')} endpoint={event.get('remote')}"
        )
    elif kind == "screen_capture_confirmed":
        console.print(
            "[bold green]Compartilhamento de tela confirmado[/bold green] "
            f"endpoint={event.get('remote')} local={event.get('local')}"
        )
    elif kind == "screen_share_candidate":
        console.print(
            "[bold green]SPLIT LIMPO DETECTADO[/bold green]: a transmissão está em uma sessão RTC/UDP "
            f"separada. remoto={event.get('remote')} local={event.get('local')} "
            f"SSRC={event.get('ssrc')} RTX={event.get('rtx_ssrc')}"
        )
        console.print(
            "[yellow]Isso permite testar no próximo passo o endpoint inteiro de screen-share por outro egress, "
            "mantendo a conexão RTC default/voz direta.[/yellow]"
        )


class ScreenTunnelCoordinator:
    """Arms the narrow RTC TUN once the default voice socket is known."""

    def __init__(self, resources: Path, runtime_dir: Path, udp_proxy: UdpProxyResult, process_name: str, route_cidr: str | None = None):
        self.engine = RtcTunnelEngine(resources, runtime_dir)
        self.udp_proxy = udp_proxy
        self.process_name = process_name
        self.route_cidr_override = route_cidr
        self._lock = threading.RLock()
        self._starting = False
        self._armed = False
        self._error: str | None = None
        self._route_cidr: str | None = None
        self.status_path = runtime_dir / "screen_tunnel_status.json"

    @property
    def armed(self) -> bool:
        with self._lock:
            return self._armed

    def _write_status(self, **extra) -> None:
        payload = {
            "updated_at": int(time.time()),
            "armed": self._armed,
            "starting": self._starting,
            "error": self._error,
            "udp_proxy": self.udp_proxy.address,
            "udp_probe_ms": self.udp_proxy.latency_ms,
            "route_cidr": self._route_cidr,
            **extra,
        }
        try:
            tmp = self.status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.status_path)
        except Exception:
            pass

    def _start_worker(self, voice_remote: str, voice_local: str) -> None:
        try:
            route_cidr = self.engine.start(
                udp_proxy=self.udp_proxy.address,
                target_process_name=self.process_name,
                voice_remote_endpoint=voice_remote,
                voice_local_endpoint=voice_local,
                route_cidr=self.route_cidr_override,
            )
            with self._lock:
                self._route_cidr = route_cidr
                self._armed = True
                self._error = None
            console.print(
                "[bold green]RTC SCREEN TUNNEL ARMADO[/bold green]: "
                f"rota={route_cidr} proxy_UDP={self.udp_proxy.address}. "
                f"O servidor da voz {voice_remote.rsplit(':',1)[0]}/32 foi EXCLUÍDO do TUN e permanece DIRECT."
            )
            console.print("[yellow]Agora pode iniciar a transmissão de tela.[/yellow]")
        except Exception as exc:
            with self._lock:
                self._error = str(exc)
            console.print(f"[bold red]Falha ao armar RTC screen tunnel:[/bold red] {exc}")
        finally:
            with self._lock:
                self._starting = False
            self._write_status(voice_remote=voice_remote, voice_local=voice_local)

    def handle_event(self, event: dict, session) -> None:
        kind = event.get("type")
        context = event.get("context", "default")
        if kind == "local_transport" and context == "default" and event.get("protocol") == "udp":
            with self._lock:
                if self._armed or self._starting:
                    return
                if not session.remote_endpoint or not session.local_endpoint:
                    return
                self._starting = True
                voice_remote = session.remote_endpoint
                voice_local = session.local_endpoint
            console.print(
                "[cyan]Voz DIRECT identificada[/cyan]; armando TUN estreito antes do screen-share..."
            )
            self._write_status(voice_remote=voice_remote, voice_local=voice_local)
            threading.Thread(
                target=self._start_worker, args=(voice_remote, voice_local),
                name="rtc-screen-tunnel-arm", daemon=True,
            ).start()
            return

        if kind == "screen_share_requested" and not self.armed:
            console.print(
                "[bold yellow]Screen-share solicitado antes do RTC TUN ficar ARMADO.[/bold yellow] "
                "Este teste pode sair DIRECT; aguarde a mensagem RTC SCREEN TUNNEL ARMADO no próximo teste."
            )

        if context == "stream" and kind in {"media_endpoint", "screen_share_candidate"}:
            remote = event.get("remote") or session.remote_endpoint
            if remote and self._route_cidr:
                try:
                    host = remote.rsplit(":", 1)[0]
                    inside = ipaddress.ip_address(host) in ipaddress.ip_network(self._route_cidr, strict=False)
                except Exception:
                    inside = False
                voice_ip = self.engine.voice_remote_ip
                stream_ip = remote.rsplit(":", 1)[0].strip("[]")
                if self.armed and voice_ip and stream_ip == voice_ip:
                    console.print(
                        f"[bold red]RTC stream caiu no MESMO IP da voz ({voice_ip}).[/bold red] "
                        "Por segurança a v13.1 não tunela esse stream, porque o /32 da voz é excluído no Windows. "
                        "Será necessário o backend WinDivert/5-tuple para separar este caso."
                    )
                    inside = False
                    self._write_status(
                        stream_remote=remote,
                        stream_in_route=False,
                        same_remote_ip_as_voice=True,
                        fallback="direct-safe",
                    )
                    return
                if inside and self.armed:
                    console.print(
                        f"[bold green]RTC stream elegível para o TUN[/bold green]: {remote} -> {self.udp_proxy.address}"
                    )
                elif self.armed:
                    console.print(
                        f"[bold red]RTC stream fora do CIDR {self._route_cidr}[/bold red]: {remote}. "
                        "Este stream provavelmente ficou DIRECT."
                    )
                self._write_status(stream_remote=remote, stream_in_route=inside)

    def stop(self) -> None:
        self.engine.stop()
        with self._lock:
            self._armed = False
            self._starting = False
        self._write_status(stopped=True)


async def run_rtc_inspect_only(args: argparse.Namespace) -> None:
    state = state_root()
    runtime = state / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    explicit_log = Path(args.rtc_log).expanduser() if args.rtc_log else None
    found = explicit_log or find_default_media_log()
    if found:
        console.print(f"[green]RTC Inspector[/green] log inicial: {found}")
    else:
        console.print("[yellow]RTC Inspector aguardando o log de mídia aparecer...[/yellow]")
    inspector = RtcInspector(runtime, log_path=explicit_log, on_event=_rtc_console_event)
    inspector.start()
    console.print(
        "[bold]Teste sugerido:[/bold] entre em uma chamada com câmera desligada; "
        "aguarde o endpoint UDP aparecer; então inicie o compartilhamento de tela."
    )
    console.print(f"Relatório: {inspector.report_path}")
    console.print(f"Candidato de split: {inspector.candidate_path}")
    started = asyncio.get_running_loop().time()
    try:
        while True:
            await asyncio.sleep(0.5)
            if args.rtc_duration > 0 and asyncio.get_running_loop().time() - started >= args.rtc_duration:
                break
    finally:
        inspector.stop()


async def run(args: argparse.Namespace) -> None:
    _install_loop_exception_filter()
    if os.name != "nt":
        raise RuntimeError("Esta edição foi preparada para Windows 10/11 64-bit.")

    if args.rtc_inspect_only:
        await run_rtc_inspect_only(args)
        return

    if args.tunnel_screen:
        args.rtc_inspect = True
        if args.no_launch:
            raise RuntimeError("--tunnel-screen precisa iniciar o aplicativo; não use junto com --no-launch")
        if not is_windows_admin():
            raise RuntimeError(
                "--tunnel-screen é experimental e precisa de Terminal/PowerShell executado como Administrador "
                "para criar a interface TUN estreita."
            )

    resources = resource_root()
    state = state_root()
    target_exe = args.app or find_default_executable()
    if not target_exe:
        raise RuntimeError("O executável alvo não foi encontrado. Use --app com o caminho completo.")

    cache = ProxyCache(state)
    scraper = ProxyScraper(PROXY_SOURCES_PRIMARY)
    selected_results = None
    checker = None
    source = ""

    # Tier 1: only the tiny pool that worked last time.
    if not args.force_scan and not args.force_refresh:
        cached_result = await validate_cached_pool(cache, args.top_proxies, args.min_proxies)
        if cached_result is not None:
            selected_results, checker = cached_result
            source = "relays revalidados"

    # Tier 2: the previously harvested IP:PORT list, entirely offline.
    if selected_results is None and not args.force_refresh:
        inventory_result = await validate_scanned_inventory(cache, args.top_proxies, args.min_proxies)
        if inventory_result is not None:
            selected_results, checker = inventory_result
            source = "inventário local"

    # Tier 3: refresh public sources only when both local tiers failed.
    if selected_results is None:
        selected_results, checker = await fresh_scan(
            cache, args.top_proxies, args.min_proxies
        )
        source = "fontes públicas atualizadas"

    selected = [r.address for r in selected_results]
    cache.save(selected)
    show_pool(selected_results, checker, source)

    udp_proxy_result = None
    if args.tunnel_screen:
        console.print("[bold cyan]v13 experimental:[/bold cyan] procurando 1 SOCKS5 com UDP ASSOCIATE real para a transmissão...")
        udp_proxy_result = await select_udp_proxy(
            cache,
            preferred=selected,
            force_scan=args.force_udp_scan,
            manual_proxy=args.udp_proxy,
        )
        console.print(
            f"[bold green]Proxy UDP pronto:[/bold green] {udp_proxy_result.address} "
            f"(setup {udp_proxy_result.setup_ms:.1f} ms, UDP RTT {udp_proxy_result.udp_rtt_ms:.1f} ms, "
            f"total {udp_proxy_result.latency_ms:.1f} ms)"
        )

    engine = SingBoxEngine(resources, state_dir=cache.runtime_dir)
    proxy_host, proxy_port = engine.start(selected, CONTROL_HEALTH_URL)
    if engine.kill_on_parent_exit:
        console.print(
            "[dim]Proteção de ciclo de vida ativa: o processo sing-box será encerrado automaticamente "
            "se este aplicativo/terminal for fechado.[/dim]"
        )
    pac_text = build_pac(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_exact_hosts=PAC_PROXY_EXACT_HOSTS,
        proxy_patterns=PAC_PROXY_HOST_PATTERNS,
        direct_exact_hosts=PAC_DIRECT_EXACT_HOSTS,
        direct_patterns=PAC_DIRECT_HOST_PATTERNS,
        proxy_window_seconds=max(0, args.proxy_window),
    )
    pac_file = cache.runtime_dir / "selective-routing.pac"
    pac_file.write_text(pac_text, encoding="utf-8")
    pac_server = PacServer(pac_text)
    pac_url = pac_server.start()

    child = None
    task = None
    rtc_inspector = None
    output_thread = None
    screen_coordinator = None
    if args.tunnel_screen and udp_proxy_result is not None:
        screen_coordinator = ScreenTunnelCoordinator(
            resources=resources,
            runtime_dir=cache.runtime_dir,
            udp_proxy=udp_proxy_result,
            process_name=Path(target_exe).name,
            route_cidr=args.screen_route_cidr,
        )
    try:
        console.print(f"[dim]Dados persistentes: {cache.runtime_dir}[/dim]")
        if args.proxy_window > 0:
            console.print(
                f"[green]3/4[/green] Relay disponível somente para a janela inicial de {args.proxy_window}s. "
                "Todo destino fora da allowlist é DIRECT desde o primeiro pacote."
            )
        else:
            console.print(
                "[green]3/4[/green] Relay seletivo ativo durante toda a sessão; somente a allowlist usa SOCKS5."
            )
        if args.tunnel_screen:
            console.print(
                "[dim]Startup continua sem TUN. O TUN RTC estreito só será criado depois que a porta UDP da voz DIRECT for identificada.[/dim]"
            )
        else:
            console.print(
                "[dim]Sem TUN, sem rota default e sem interceptação de UDP: mídia, CDN, imagens, anexos e tráfego não listado permanecem no Windows.[/dim]"
            )
        console.print("[green]4/4[/green] Iniciando aplicativo alvo...")

        if args.rtc_inspect:
            explicit_log = Path(args.rtc_log).expanduser() if args.rtc_log else None
            def rtc_event_handler(event, session):
                _rtc_console_event(event, session)
                if screen_coordinator is not None:
                    screen_coordinator.handle_event(event, session)

            rtc_inspector = RtcInspector(
                cache.runtime_dir,
                log_path=explicit_log,
                on_event=rtc_event_handler,
            )
            if args.no_launch:
                # Without a child process we can only tail an explicitly supplied
                # or discoverable log.  Normal --rtc-inspect uses process stdout,
                # which is where the detailed RTC Connection(...) lines appear.
                rtc_inspector.start()
            else:
                rtc_inspector.attach_external_source("process-stdout")

        if not args.no_launch:
            child = launch_application(
                target_exe,
                pac_url,
                capture_output=bool(args.rtc_inspect),
            )
            if args.rtc_inspect and rtc_inspector is not None:
                output_thread = start_output_tee(
                    child,
                    line_callback=rtc_inspector.feed_external_line,
                    log_path=cache.runtime_dir / "target_stdout.log",
                )
            console.print(
                "[bold green]Aplicativo iniciado com split no nível da aplicação. "
                "O caminho DIRECT não passa pelo engine local.[/bold green]"
            )

        if args.rtc_inspect and rtc_inspector is not None:
            console.print(
                f"[green]RTC Inspector ativo[/green]. Relatório: {rtc_inspector.report_path}"
            )
            if args.no_launch:
                console.print(
                    "[dim]Inspector em fallback de arquivo. Para capturar Connection(default)/Connection(stream) "
                    "com máxima confiabilidade, execute sem --no-launch para ler diretamente o stdout.[/dim]"
                )
            else:
                console.print(
                    "[dim]Inspector v13 lendo o stdout do aplicativo em tempo real e gravando "
                    f"{cache.runtime_dir / 'target_stdout.log'}.[/dim]"
                )
            if args.tunnel_screen:
                console.print(
                    "[bold yellow]Entre primeiro na voz e aguarde 'RTC SCREEN TUNNEL ARMADO'. "
                    "Só então inicie o compartilhamento.[/bold yellow]"
                )
            else:
                console.print(
                    "[dim]Entre na voz e depois inicie o compartilhamento; se a tela abrir outro UDP 5-tuple, "
                    "ele será salvo como candidato de split.[/dim]"
                )

        if args.rescrape_interval > 0:
            task = asyncio.create_task(rescrape_loop(scraper, cache, args.rescrape_interval, args.top_proxies))

        while True:
            await asyncio.sleep(1)
            if child and child.poll() is not None:
                logger.info("Aplicativo alvo encerrou (code=%s)", child.returncode)
                break
    finally:
        if task:
            task.cancel()
        if rtc_inspector:
            rtc_inspector.stop()
        if screen_coordinator:
            screen_coordinator.stop()
        pac_server.stop()
        engine.stop()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Split routing no nível da aplicação: pequena allowlist via SOCKS5; restante DIRECT sem TUN"
    )
    p.add_argument("--app", help="Caminho para o executável alvo")
    p.add_argument("--no-launch", action="store_true")
    p.add_argument("--top-proxies", type=int, default=TOP_PROXIES)
    p.add_argument("--min-proxies", type=int, default=MIN_PROXIES)
    p.add_argument(
        "--proxy-window",
        type=int,
        default=DEFAULT_PROXY_WINDOW_SECONDS,
        help="Segundos em que novas conexões da allowlist podem usar o relay; 0 mantém durante toda a sessão",
    )
    p.add_argument("--rescrape-interval", type=float, default=RESCRAPE_INTERVAL)
    p.add_argument(
        "--force-scan",
        action="store_true",
        help="Ignora apenas o pool de relays ativos e retesta o inventário IP:PORT local",
    )
    p.add_argument(
        "--force-refresh",
        action="store_true",
        help="Ignora caches e baixa novamente todas as fontes públicas",
    )
    p.add_argument(
        "--rtc-inspect",
        action="store_true",
        help="Acompanha o log RTC e identifica endpoint/SSRCs de áudio e vídeo sem alterar pacotes",
    )
    p.add_argument(
        "--rtc-inspect-only",
        action="store_true",
        help="Executa somente o RTC Inspector; não inicia proxy nem aplicativo",
    )
    p.add_argument(
        "--tunnel-screen",
        action="store_true",
        help=(
            "EXPERIMENTAL: mantém a porta UDP da voz DIRECT e tenta enviar a sessão RTC de screen-share "
            "por um SOCKS5 que passou UDP ASSOCIATE. Exige Administrador."
        ),
    )
    p.add_argument(
        "--udp-proxy",
        help="SOCKS5 IP:PORT específico para o screen tunnel; ainda será validado com UDP ASSOCIATE",
    )
    p.add_argument(
        "--force-udp-scan",
        action="store_true",
        help="Ignora working_udp_proxies.json e procura novamente um relay SOCKS5-UDP",
    )
    p.add_argument(
        "--screen-route-cidr",
        help="CIDR RTC opcional para o TUN estreito; padrão deriva /16 do endpoint de voz",
    )
    p.add_argument(
        "--rtc-log",
        help="Caminho opcional para um log de mídia específico",
    )
    p.add_argument(
        "--rtc-duration",
        type=float,
        default=0.0,
        help="No modo --rtc-inspect-only, encerra após N segundos; 0 fica acompanhando",
    )
    return p.parse_args()


if __name__ == "__main__":
    try:
        _configure_windows_asyncio()
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        pass
    except (RuntimeError, SingBoxError, RtcTunnelError) as exc:
        console.print(f"[bold red]Erro:[/bold red] {exc}")
        sys.exit(1)
