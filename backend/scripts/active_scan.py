import argparse
import json
from datetime import datetime, timezone
import time
from pathlib import Path
import sys
import traceback
import os

SCRIPT_METADATA = {
    "description": "No permitido para el plan Membership !!! Permite iniciar un escaneo activo sobre una IP para detectar puertos, servicios y certificados, consumiendo créditos de la API. Los resultados se esperan con un timeout, se guardan en JSON y luego pueden procesarse en tu dashboard React.",
    "params": [
        {"name": "target", "label": "Target IP (propia o con permiso)", "type": "text", "required": True, "placeholder": "1.2.3.4"},
        {"name": "wait_interval", "label": "Espera entre checks (segundos)", "type": "number", "required": False, "placeholder": 10},
        {"name": "timeout", "label": "Timeout máximo (segundos)", "type": "number", "required": False, "placeholder": 600}
    ]
}

try:
    import shodan
except ImportError:
    print("Falta la dependencia 'shodan'. Instálala con: pip install shodan", file=sys.stderr)
    raise


def ahoraIso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"


def escaneoActivo(api: shodan.Shodan, ip: str):
    try:
        escaneo = api.scan(ip)
        scanId = escaneo.get("id")
        print(f"[INFO] Scan iniciado para {ip}, scanId={scanId}")
        return scanId
    except shodan.exception.APIError as e:
        return {"ip": ip, "error": str(e)}
    except Exception as e:
        return {"ip": ip, "error": str(e), "traceback": traceback.format_exc()}


def esperarFinalizacion(api: shodan.Shodan, scanId: str, waitInterval: int = 10, timeout: int = 600):
    tiempoInicio = time.time()
    while True:
        try:
            estado = api.scan_status(scanId)
        except shodan.exception.APIError as e:
            return {"status": "ERROR", "error": str(e)}
        estadoActual = estado.get("status", "").upper()
        if estadoActual == "DONE":
            return estado
        if time.time() - tiempoInicio > timeout:
            return {"status": "TIMEOUT", "scanId": scanId}
        time.sleep(waitInterval)


def procesarDatos(raw):
    listaResultados = []

    for item in raw.get("data", []):
        first_line = (item.get("data") or "").splitlines()[0] if item.get("data") else ""

        elemento = {
            "ip": raw.get("ip_str", "N/A"),
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "os": raw.get("os"),
            "location": raw.get("location", {}),

            # 🔥 CAMPOS QUE QUIERES QUE APAREZCAN EN LA TABLA
            "port": item.get("port"),
            "transport": item.get("transport"),
            "ssl": item.get("ssl"),
            "http": item.get("http"),
            "data": item.get("data"),
            "first_line": first_line,

            # Mantenemos banners por compatibilidad
            "banners": [
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "ssl": item.get("ssl"),
                    "http": item.get("http"),
                    "data": item.get("data"),
                    "first_line": first_line
                }
            ]
        }

        listaResultados.append(elemento)

    return listaResultados



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--wait_interval", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    claveApi = os.environ.get("SHODAN_API_KEY")
    if not claveApi:
        print("ERROR: SHODAN_API_KEY no definida", file=sys.stderr)
        sys.exit(1)
    api = shodan.Shodan(claveApi)

    scanId = escaneoActivo(api, args.target)
    if not isinstance(scanId, str):
        resultadosTabla = [{"error": scanId}]
    else:
        esperarFinalizacion(api, scanId, args.wait_interval, args.timeout)
        try:
            infoHost = api.host(args.target, minify=False)
            resultadosTabla = procesarDatos(infoHost)
        except Exception as e:
            resultadosTabla = [{"error": str(e)}]

    rutaSalida = Path(args.out)
    rutaSalida.parent.mkdir(parents=True, exist_ok=True)
    rutaSalida.write_text(json.dumps(resultadosTabla, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[INFO] Resultados guardados en {rutaSalida}")


if __name__ == "__main__":
    main()