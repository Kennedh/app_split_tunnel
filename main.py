#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
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
    PROXY_SOURCES,
    RESCRAPE_INTERVAL,
    TLS_BATCH_SIZE,
    TLS_TIMEOUT,
    TOP_PROXIES,
)
from modules.cache import ProxyCache
from modules.checker import ProxyChecker, ProxyResult
from modules.launcher import find_default_executable, launch_application
from modules.pac import PacServer, build_pac
from modules.paths import resource_root, state_root
from modules.rtc_inspector import RtcInspector, find_default_media_log
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


async def validate_candidates(candidates: list[str], desired: int, minimum: int, label: str):
    if not candidates:
        return None
    console.print(f"[cyan]{label}[/cyan] Revalidando {len(candidates)} proxy(s)...")
    checker = build_checker()
    ranked = await checker.check_many_fast(candidates, desired_tls=desired)
    selected = choose_pool(ranked, desired)
    if len(selected) >= minimum:
        return selected, checker
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
        "testando sem baixar fontes públicas..."
    )
    result = await validate_candidates(scanned, desired, minimum, "Inventário")
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


async def fresh_scan(scraper: ProxyScraper, cache: ProxyCache, desired: int, minimum: int):
    console.print("[cyan]1/4[/cyan] Atualizando inventário público SOCKS5...")
    raw = await asyncio.to_thread(scraper.harvest)
    if not raw:
        raise RuntimeError("Nenhum proxy foi coletado.")
    raw = cache.save_scanned(raw)
    console.print(
        f"[dim]Inventário salvo em {cache.scanned_path} ({len(raw)} IP:PORT).[/dim]"
    )
    console.print(
        f"[cyan]2/4[/cyan] Triagem rápida de {len(raw)} proxies "
        "(SOCKS5 -> CONNECT -> TLS apenas até completar o pool)..."
    )
    checker = build_checker()
    ranked = await checker.check_many_fast(raw, desired_tls=desired)
    selected = choose_pool(ranked, desired)
    if len(selected) < minimum:
        raise RuntimeError(f"Apenas {len(selected)} proxy(s) fim-a-fim permaneceram; mínimo={minimum}.")
    return selected, checker


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
            f"[cyan]RTC[/cyan] endpoint={event.get('remote')} "
            f"audio_ssrc={event.get('audio_ssrc')}"
        )
    elif kind == "local_transport":
        console.print(
            f"[cyan]RTC[/cyan] transporte local={event.get('local')} "
            f"protocolo={event.get('protocol')}"
        )
    elif kind == "video_discovered":
        console.print(
            f"[magenta]RTC vídeo[/magenta] SSRC={event.get('ssrc')} "
            f"RTX={event.get('rtx_ssrc')} active={event.get('active')}"
        )
    elif kind == "video_activated":
        console.print(
            "[bold magenta]RTC vídeo ATIVADO[/bold magenta] "
            f"SSRC={event.get('ssrc')} RTX={event.get('rtx_ssrc')} "
            f"endpoint={event.get('remote')}"
        )
        console.print(
            "[yellow]Se a câmera estava desligada e você acabou de iniciar o compartilhamento, "
            "este SSRC é um forte candidato da transmissão de tela.[/yellow]"
        )


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

    resources = resource_root()
    state = state_root()
    target_exe = args.app or find_default_executable()
    if not target_exe:
        raise RuntimeError("O executável alvo não foi encontrado. Use --app com o caminho completo.")

    cache = ProxyCache(state)
    scraper = ProxyScraper(PROXY_SOURCES)
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
            scraper, cache, args.top_proxies, args.min_proxies
        )
        source = "fontes públicas atualizadas"

    selected = [r.address for r in selected_results]
    cache.save(selected)
    show_pool(selected_results, checker, source)

    engine = SingBoxEngine(resources, state_dir=cache.runtime_dir)
    proxy_host, proxy_port = engine.start(selected, CONTROL_HEALTH_URL)
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
        console.print(
            "[dim]Sem TUN, sem rota default e sem interceptação de UDP: mídia, CDN, imagens, anexos e tráfego não listado permanecem no Windows.[/dim]"
        )
        console.print("[green]4/4[/green] Iniciando aplicativo alvo...")
        if not args.no_launch:
            child = launch_application(target_exe, pac_url)
            console.print(
                "[bold green]Aplicativo iniciado com split no nível da aplicação. "
                "O caminho DIRECT não passa pelo engine local.[/bold green]"
            )

        if args.rtc_inspect:
            explicit_log = Path(args.rtc_log).expanduser() if args.rtc_log else None
            rtc_inspector = RtcInspector(
                cache.runtime_dir,
                log_path=explicit_log,
                on_event=_rtc_console_event,
            )
            rtc_inspector.start()
            console.print(
                f"[green]RTC Inspector ativo[/green]. Relatório: {rtc_inspector.report_path}"
            )
            console.print(
                "[dim]Para identificar tela: câmera OFF -> entrar na voz -> iniciar compartilhamento. "
                "O primeiro SSRC de vídeo que mudar para active=true será destacado.[/dim]"
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
    except (RuntimeError, SingBoxError) as exc:
        console.print(f"[bold red]Erro:[/bold red] {exc}")
        sys.exit(1)
