from __future__ import annotations
import argparse
import os
import json
import shodan
import sys
import time
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import Counter


sys.path.append(str(Path(__file__).resolve().parent.parent))
from shodan_common import load_api_key, save_json, setup_logger


SCRIPT_METADATA = {
    "description": (
        "Enumeración pasiva con Shodan. "
        "Permite buscar servicios o analizar una IP concreta."
    ),
    "params": [
          {
            "name": "query",
            "type": "string",
            "required": True,
            "placeholder": "apache port:80, nginx port:80, ssl:true port:443, port:22,23,3389 o 8.8.8.8",
            "label": "Query"
        },
        {
            "name": "limit",
            "type": "number",
            "required": False,
            "placeholder": "10",
            "label": "Límite de resultados"
        }
    ],
    "accepts_log": True,
    "timeout": 600
}



def horaIso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except:
        return False





def filtrarBanners(banners):  
    seen = set()
    filtered = []

    for b in banners:
        key = (b.get("port"), b.get("transport"), b.get("first_line", ""))
        if key not in seen:
            seen.add(key)
            filtered.append(b)
    return filtered


def llamadaSeguraShodan(api_call, logger, retries=4, cooldown=3):
    for i in range(retries):
        try:
            return api_call()
        except shodan.APIError as e:
            if "429" in str(e):
                wait = cooldown * (i + 1)
                logger.warning(f"Rate-limit (429). Reintentando en {wait}s…")
                time.sleep(wait)
            else:
                logger.error(f"Shodan API error: {e}")
                return None
        except Exception as e:
            logger.error(f"Error inesperado: {e}")
            return None
    return None



def analizar(api, ip, logger):   
    logger.info(f"Consultando host {ip}")

    host = llamadaSeguraShodan(lambda: api.host(ip, minify=False), logger)

    if not host:
        return None

    banners = []
    for item in host.get("data", []):
        banners.append({
            'ip': host.get('ip_str', ip),
            'port': item.get('port'),
            'transport': item.get('transport'),
            'org': host.get('org'),
            'isp': host.get('isp'),
            'os': host.get('os'),
            'city': (host.get('location') or {}).get('city'),
            'country_code': (host.get('location') or {}).get('country_code'),
            'first_line': (item.get('data') or '').splitlines()[0] if item.get('data') else '',
            'ssl': item.get('ssl'),
            'http': item.get('http'),
            'raw_data': item.get('data'),
        })

    banners = filtrarBanners(banners)

    return {
        'queried_at': horaIso(),
        'ip': host.get('ip_str', ip),
        'summary': {
            'org': host.get('org'),
            'isp': host.get('isp'),
            'os': host.get('os'),
            'location': host.get('location', {}),
            'banners_count': len(banners),
        },
        'results': banners
    }



def ejecutar(params, logger):
    query = params.get("query")
    limit = int(params.get("limit", 10))

    api = shodan.Shodan(load_api_key())

    if is_ip(query):
        host_info = analizar(api, query, logger)
        return host_info if host_info else {"error": "No se pudo obtener información del host"}

    logger.info(f"Ejecutando búsqueda Shodan: {query}")
    r = llamadaSeguraShodan(lambda: api.search(query, limit=limit), logger)

    if not r:
        return {"error": "No hay resultados o fallo en API"}

    matches = r.get("matches", [])
    results = []

    for m in matches:
        ip = m.get("ip_str")
        info = analizar(api, ip, logger)
        if info:
            results.append(info)

    return {
        "queried_at": horaIso(),
        "query": query,
        "total_hosts": len(results),
        "results": results
    }



def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", required=True)
    parser.add_argument("--limit", default="10")
    parser.add_argument("--out", required=True)
    parser.add_argument("--log", default="shodan_enum.log")

    args = parser.parse_args()
    logger = setup_logger("shodan_enum", log_file=args.log)

    result = ejecutar(vars(args), logger)
    save_json(args.out, result)

    logger.info(f"Resultados guardados en {args.out}")


if __name__ == "__main__":
    cli()
    
    