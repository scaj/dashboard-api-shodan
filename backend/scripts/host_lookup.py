from __future__ import annotations
import argparse
import os
import shodan
import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone
import traceback

sys.path.append(str(Path(__file__).resolve().parent.parent))
from shodan_common import load_api_key, save_json, setup_logger

SCRIPT_METADATA = {
    "description": "Consulta información detallada de un host en Shodan usando su IP. Exporta un JSON con datos de banners, puerto, transporte, organización, ISP, sistema operativo, ubicación y otros metadatos relevantes.",
    "params": [
        {
            "name": "ip",
            "type": "string",
            "required": True,
            "placeholder": "8.8.8.8, propia o con permiso",
            "label": "IP address:"
        }
    ],
    "accepts_log": True,
    "timeout": 600
}

def horaIso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"

def filrarBanners(banners):
    seen = set()
    filtered = []
    for b in banners:
        key = (b.get("port"), b.get("transport"), b.get("first_line", ""))
        if key not in seen:
            seen.add(key)
            filtered.append(b)
    return filtered

def procesar(raw, ip: str):
    banners = []
    for item in raw.get("data", []):
        banners.append({
            "ip": raw.get("ip_str", ip),
            "port": item.get("port"),
            "transport": item.get("transport"),
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "os": raw.get("os"),
            "city": (raw.get("location") or {}).get("city"),
            "country_code": (raw.get("location") or {}).get("country_code"),
            "first_line": (item.get("data") or '').splitlines()[0] if item.get("data") else '',
            "ssl": item.get("ssl"),
            "http": item.get("http"),
            "raw_data": item.get("data")
        })
    banners = filrarBanners(banners)
    return {
        "queried_at": horaIso(),
        "ip": raw.get("ip_str", ip),
        "summary": {
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "os": raw.get("os"),
            "location": raw.get("location", {}),
            "banners_count": len(banners)
        },
        "results": banners
    }

def escanear(ip: str):
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY no definida")
    api = shodan.Shodan(api_key)

    try:
        host_info = api.host(ip, minify=False)
        host_data = procesar(host_info, ip)
    except shodan.exception.APIError as e:
        host_data = {"error": str(e)}
    except Exception as e:
        host_data = {"error": str(e), "traceback": traceback.format_exc()}

    
    resultado = {
        "scanned_target": ip,
        "timestamp": horaIso(),
        "host_data": host_data
    }
    return resultado

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--log", required=False, help="Ruta para guardar el log")
    args = parser.parse_args()

    logger = setup_logger("host_lookup", log_file=args.log) if args.log else None
    resultado = escanear(args.ip)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(out_path, resultado)

    if logger:
        logger.info(f"Resultados guardados en {out_path}")
    print(f"[INFO] Resultados guardados en {out_path}")

if __name__ == "__main__":
    main()
