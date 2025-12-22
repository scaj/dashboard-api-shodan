from __future__ import annotations
import argparse
import time
import sys
import json
from pathlib import Path
import shodan
sys.path.append(str(Path(__file__).resolve().parent.parent))
from shodan_common import load_api_key, save_json, setup_logger
from datetime import datetime

SCRIPT_METADATA = {
    "description": (
        "Crea una alerta temporal en Shodan, devuelve JSON inicial, "
        "espera la duración y genera JSON final con eventos recopilados."
    ),
    "params": [
        {"name": "network", "label": "Ip o rango de red (CIDR):", "type": "text", "required": True, "placeholder": "8.8.8.0/24"},
        {"name": "name", "label": "Nombre de la alerta:", "type": "text", "required": True, "placeholder": "ShodanMonitor"},
        {"name": "duration", "label": "Duración (segundos):", "type": "number", "required": False, "placeholder": 300}
    ],
    "timeout": 600,
    "accepts_log": True
}

def normalizarBanner(banner):
    return {
        'timestamp': banner.get('timestamp'),
        'ip_str': banner.get('ip_str'),
        'port': banner.get('port'),
        'module': banner.get('shodan', {}).get('module'),
        'data': (banner.get('data') or '').splitlines(),
        'opts': banner.get('opts', {})
    }

def alerta(api: shodan.Shodan, alert_id: str, duration: int, logger, final_out_file: str):    
    events = []
    start = time.time()

    while time.time() - start < duration:
        try:            
            banner_list = api.stream.alert(alert_id, timeout=1)
            for banner in banner_list:
                evt = normalizarBanner(banner)
                events.append(evt)
                logger.info('Evento detectado: %s:%s', evt.get('ip_str'), evt.get('port'))
        except Exception:            
            time.sleep(1)
            continue

   
    try:
        api.delete_alert(alert_id)
        logger.info('Alerta eliminada %s', alert_id)
    except Exception:
        logger.exception('No se pudo eliminar la alerta')

    
    final_json = {
        "status": "finished",
        "data": [
            {
                "message": "Monitoreo finalizado",
                "events_collected": len(events),
                "events": events
            }
        ]
    }
    save_json(final_out_file, final_json)
    print(json.dumps(final_json), flush=True)
    logger.info("Fin del monitoreo. %d eventos recopilados", len(events))


def configurarAlerta(api: shodan.Shodan, network_range: str, alert_name: str, duration: int, logger, out_file: str):    
    try:
        alert = api.create_alert(alert_name, network_range)
    except shodan.exception.APIError as e:
        logger.error("Shodan APIError creando la alerta: %s", e)
        err = {
            "status": "error",
            "data": [
                {
                    "message": str(e),
                    "events_collected": 0,
                    "events": []
                }
            ]
        }
        save_json(out_file, err)
        print(json.dumps(err), flush=True)
        return

    alert_id = alert.get('id')
    final_json_path = out_file.replace(".json", "_final.json")

    initial_json = {
        "status": "started",
        "data": [
            {
                "message": "Alerta creada y monitoreando. Los resultados de las alertas están en el Json final generado.",
                "alert_id": alert_id,
                "final_json": final_json_path
            }
        ]
    }
    save_json(out_file, initial_json)
    print(json.dumps(initial_json), flush=True)  
    logger.info('JSON inicial creado y guardado en %s', out_file)
  
    alerta(api, alert_id, duration, logger, final_json_path)

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--network', required=True, help='Rango de red (CIDR)')
    parser.add_argument('--name', default='ShodanMonitor', help='Nombre de la alerta')
    parser.add_argument('--duration', type=int, default=300, help='Duración en segundos')
    parser.add_argument('--out', required=True, help='Archivo de salida JSON')
    parser.add_argument('--log', default='shodan_realtime.log', help='Archivo de log')

    args = parser.parse_args()

    logger = setup_logger('realtime_monitor', log_file=args.log)
    api = shodan.Shodan(load_api_key())

    configurarAlerta(api, args.network, args.name, args.duration, logger, args.out)

if __name__ == '__main__':
    cli()
