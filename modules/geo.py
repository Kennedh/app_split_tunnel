"""
Módulo de Geolocalização (opcional)
=====================================
A distância física até o proxy é o maior fator que determina a latência.
Este módulo usa a API pública e gratuita ip-api.com (endpoint em lote,
sem necessidade de chave) para descobrir o país de cada proxy já
validado, permitindo priorizar os que estão mais perto do usuário.

Se a API estiver fora do ar, com rate-limit atingido, ou sem conexão
disponível, a função simplesmente retorna um dicionário vazio/parcial —
o pipeline principal trata isso normalmente e apenas segue sem a
priorização geográfica (a ordenação por latência real continua valendo).
"""
from __future__ import annotations

import logging
from typing import Dict, List

import requests

logger = logging.getLogger("split_tunnel.geo")

_BATCH_URL = "http://ip-api.com/batch"
_BATCH_SIZE = 100  # limite da API gratuita por requisição


def lookup_countries(ips: List[str], timeout: float = 8.0) -> Dict[str, str]:
    """Recebe uma lista de IPs (sem porta) e retorna ``{ip: country_code}``
    para os que puderam ser resolvidos. Nunca levanta exceção — falhas
    de rede/API resultam em entradas ausentes, não em erro."""
    result: Dict[str, str] = {}
    if not ips:
        return result

    for i in range(0, len(ips), _BATCH_SIZE):
        chunk = ips[i:i + _BATCH_SIZE]
        payload = [{"query": ip, "fields": "query,countryCode,status"} for ip in chunk]
        try:
            resp = requests.post(_BATCH_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            for item in data:
                if item.get("status") == "success" and item.get("query"):
                    result[item["query"]] = item.get("countryCode", "??")
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning(
                "Geolocalização indisponível (%s); seguindo sem priorização geográfica", exc
            )
            break

    logger.info("Geolocalização resolvida para %d/%d IPs", len(result), len(ips))
    return result