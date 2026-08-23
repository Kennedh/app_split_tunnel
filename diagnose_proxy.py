#!/usr/bin/env python3
"""Diagnose one SOCKS5 relay end-to-end against the configured profile."""
import asyncio
import sys
from modules.checker import ProxyChecker


async def main(proxy: str):
    checker = ProxyChecker(concurrency=1, connect_timeout=10, liveness_timeout=5, tls_timeout=12)
    print(f"Proxy: {proxy}")
    print("Handshake SOCKS5:", "OK" if await checker.check_liveness(proxy) else "FAIL")

    connect = await checker.check_one_connect(proxy)
    if not connect:
        print("CONNECT TCP: FAIL em todos os destinos configurados")
        return

    print(
        f"CONNECT TCP: OK | media={connect.latency_ms:.1f} ms | "
        f"cobertura={connect.connect_coverage}/{len(checker.test_targets)}"
    )
    for target in connect.connect_targets:
        print(f"  CONNECT OK  {target}")

    tls = await checker.validate_tls_one(connect)
    if not tls:
        print("TLS/HTTPS: FAIL — CONNECT abre, mas certificado/handshake/resposta HTTPS nao e confiavel")
        if checker.stats:
            print("Motivos:", dict(checker.stats))
        return

    print(
        f"TLS/HTTPS: OK | media={tls.tls_latency_ms:.1f} ms | "
        f"cobertura={tls.coverage}/{len(checker.test_targets)}"
    )
    for target in tls.success_targets:
        print(f"  TLS OK      {target}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python diagnose_proxy.py IP:PORTA")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1]))
