"""
Módulo Scraper (Proxy Harvester)
=================================
Baixa listas públicas de proxies SOCKS5 hospedadas no GitHub (raw.githubusercontent.com),
extrai os pares IP:PORTA via regex, remove duplicatas e devolve uma lista
única e normalizada.

Cada fonte é tratada de forma isolada: uma falha de rede/timeout em uma
URL não derruba a coleta das demais.
"""
from __future__ import annotations

import logging
import re
from typing import List, Set

import requests

logger = logging.getLogger("split_tunnel.scraper")

# Casa qualquer ocorrência de IPv4:PORTA dentro do texto bruto do arquivo,
# independente de outras colunas/():comentários que a lista possa conter.
_PROXY_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b:\d{2,5}\b"
)


class ProxyScraper:
    """Coleta e normaliza proxies SOCKS5 a partir de múltiplas fontes públicas."""

    def __init__(self, sources: List[str], timeout: float = 10.0):
        self.sources = sources
        self.timeout = timeout

    def _fetch_source(self, url: str) -> List[str]:
        """Baixa uma única fonte e extrai os proxies encontrados no texto."""
        try:
            resp = requests.get(url, timeout=self.timeout, headers={
                "User-Agent": "Mozilla/5.0 (compatible; ProxyHarvester/1.0)"
            })
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.warning("Falha ao baixar %s: %s", url, exc)
            return []

        found = _PROXY_PATTERN.findall(resp.text)
        return found

    def harvest(self) -> List[str]:
        """Baixa todas as fontes configuradas e retorna uma lista deduplicada
        e ordenada de proxies no formato ``IP:PORTA``."""
        unique: Set[str] = set()
        for url in self.sources:
            found = self._fetch_source(url)
            logger.info("%s -> %d proxies encontrados", url, len(found))
            unique.update(found)

        result = sorted(unique)
        logger.info("Total de proxies únicos coletados: %d", len(result))
        return result


if __name__ == "__main__":
    # Execução direta para depuração rápida: `python -m modules.scraper`
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    import sys
    sys.path.insert(0, "..")
    from config import PROXY_SOURCES  # noqa: E402

    scraper = ProxyScraper(PROXY_SOURCES)
    proxies = scraper.harvest()
    print(f"\n{len(proxies)} proxies coletados. Amostra:")
    for p in proxies[:10]:
        print(" -", p)
