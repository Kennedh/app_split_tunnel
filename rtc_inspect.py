#!/usr/bin/env python3
"""Standalone read-only RTC log inspector."""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from rich.console import Console

from modules.paths import state_root
from modules.rtc_inspector import RtcInspector, find_default_media_log

console = Console()


def on_event(event, session):
    kind = event.get("type")
    if kind == "media_endpoint":
        console.print(f"[cyan]RTC[/cyan] {event.get('remote')} audio_ssrc={event.get('audio_ssrc')}")
    elif kind == "local_transport":
        console.print(f"[cyan]RTC[/cyan] local={event.get('local')} protocol={event.get('protocol')}")
    elif kind == "video_discovered":
        console.print(f"[magenta]Vídeo[/magenta] SSRC={event.get('ssrc')} RTX={event.get('rtx_ssrc')} active={event.get('active')}")
    elif kind == "video_activated":
        console.print(f"[bold magenta]VÍDEO ATIVADO[/bold magenta] SSRC={event.get('ssrc')} RTX={event.get('rtx_ssrc')}")
        console.print("[yellow]Se a câmera estava OFF, marque este evento como candidato do compartilhamento de tela.[/yellow]")


def main():
    p = argparse.ArgumentParser(description="Read-only RTC media log inspector")
    p.add_argument("--log")
    p.add_argument("--duration", type=float, default=0)
    args = p.parse_args()
    runtime = state_root() / "runtime"
    explicit = Path(args.log).expanduser() if args.log else None
    console.print(f"Log: {explicit or find_default_media_log() or 'aguardando...'}")
    inspector = RtcInspector(runtime, explicit, on_event=on_event)
    inspector.start()
    console.print("Entre na chamada com câmera OFF e depois inicie o compartilhamento de tela.")
    started = time.monotonic()
    try:
        while True:
            time.sleep(0.5)
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        inspector.stop()
        console.print(f"Relatório: {inspector.report_path}")
        console.print(f"Candidato: {inspector.candidate_path}")


if __name__ == "__main__":
    main()
