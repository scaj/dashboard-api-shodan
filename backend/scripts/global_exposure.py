"""Exporta a JSON"""
from __future__ import annotations

import sys
from pathlib import Path
import argparse
import shodan
from typing import List, Dict, Any
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parent.parent))

from shodan_common import load_api_key, save_json, setup_logger

SCRIPT_METADATA = {
    "description": "Realiza búsquedas con filtros en Shodan y paginación automática. Recopila y normaliza los resultados según IP, puerto, organización y ubicación, y exporta un JSON con todos los datos, incluyendo el número de coincidencias y filtrados por país, organización, sistema operativo y puerto.",
    "params": [
        {"name": "query", "label": "Query:", "required": True, "placeholder": "http.title:'Home Assistant' port:8123"},
        {"name": "limit", "label": "Limit:", "required": False, "placeholder": 10},
    ],
    "timeout": 600,
    "accepts_log": True
}


def normalizar(match: Dict[str, Any]) -> Dict[str, Any]:
    ubicacion = match.get('location') or {}
    return {
        'ip_str': match.get('ip_str'),
        'port': match.get('port'),
        'org': match.get('org'),
        'hostnames': match.get('hostnames', []),
        'ciudad': ubicacion.get('city'),
        'codigoPais': ubicacion.get('country_code'),
        'latitud': ubicacion.get('latitude'),
        'longitud': ubicacion.get('longitude'),
        'data': (match.get('data') or '').replace('\n', ' '),
        'opciones': match.get('opts', {})
    }


def realizarBusqueda(api: shodan.Shodan, query: str, facetas: List[str], limite: int, logger):
    logger.info('Ejecutando query: %s', query)
    recogidas: List[Dict[str, Any]] = []
    facetasRes = {}
    try:
        resultados = api.search(query, facets=facetas)
        facetasRes = resultados.get('facets', {})
        for m in resultados.get('matches', []):
            recogidas.append(normalizar(m))
        pagina = 2
        while len(recogidas) < limite and resultados.get('matches') and len(resultados.get('matches')) >= 100:
            resultados = api.search(query, page=pagina, facets=facetas)
            for m in resultados.get('matches', []):
                if len(recogidas) >= limite:
                    break
                recogidas.append(normalizarCoincidencia(m))
            pagina += 1
    except shodan.APIError as e:
        logger.error('APIError: %s', e)
        raise

    return {
        'queried_at': datetime.utcnow().isoformat() + 'Z',
        'query': query,
        'requested_limit': limite,
        'collected': len(recogidas),
        'facets': facetasRes,
        'matches': recogidas
    }


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--query', required=True)
    parser.add_argument('--limit', type=int, default=200)
    parser.add_argument('--out', required=True)
    parser.add_argument('--log', default='shodan_global.log')
    parser.add_argument('--facets', nargs='*', default=['country','org','os','port'])
    args = parser.parse_args()

    logger = setup_logger('exposicion_global', log_file=args.log)
    api = shodan.Shodan(load_api_key())
    res = realizarBusqueda(api, args.query, args.facets, args.limit, logger)
    save_json(args.out, res)
    logger.info('Guardado en %s', args.out)


if __name__ == '__main__':
    cli()
