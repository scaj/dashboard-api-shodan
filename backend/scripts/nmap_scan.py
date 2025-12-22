import argparse, json, datetime, time, subprocess, sys
from pathlib import Path
from datetime import datetime as dt
import ipaddress
import xml.etree.ElementTree as ET
import re, requests



SCRIPT_METADATA = {
    "description": """Escanea con Nmap y genera un JSON compatible con los scripts de Shodan para correlación.
  Argumentos Nmap más frecuentes:
    -sS : TCP SYN Scan (rápido y sigiloso). El más recomendado para escaneos estándar.
    -sV : Detecta versiones de servicios (banner grabbing).
    -A  : Modo agresivo: incluye OS detection, traceroute y scripts NSE básicos.
    -O  : Detección del sistema operativo (OS detection) sin habilitar el modo -A.
    -F  : Escaneo rápido de puertos comunes (fast mode).
    -p- : Escanea todos los puertos (1–65535).
    -p <rango> : Escanea puertos concretos, ej.: -p 22,80,443 o -p 1-1000
    -T<0-5> : Nivel de agresividad/velocidad del escaneo (4 recomendado para uso general).
    -Pn : Desactiva la detección de host discovery (asume que todos los hosts están vivos).
    -n  : Evita resoluciones DNS para acelerar el escaneo.
    --open : Muestra solo puertos abiertos.
    -oX - : Salida en XML hacia stdout (necesaria para parseo del script).
    -oN <file> : Guarda salida en formato normal.
    -oG <file> : Guarda salida en formato grepable.

    Ejemplos útiles:
    - Escaneo rápido:            -sS -F -T4 -oX -
    - Identificación de servicios: -sS -sV -T4 -oX -
    - Escaneo completo(agresivo):          -sS -sV -A -p- -T4 -oX -
    - Escaneo completo con versiones(agresivo): -sV -A -p- --open -oX -
Nota: La detección de vulnerabilidades se realizará automáticamente si has proporcionado tu API Key de Vulners en los parámetros del script.
    """,
        "params": [
            {"name": "target", "label": "Target (IP o CIDR):", "required": True, "placeholder": "1.2.3.4/32"},
            {"name": "delay", "label": "Delay entre hosts (s):", "required": False, "placeholder": 0.5},
            {"name": "max", "label": "Max hosts a escanear:", "required": False, "placeholder": 0},
            {"name": "nmap_args",
             "label": "Argumentos Nmap:",
             "required": False,
             "placeholder": "-sS -sV -A -T4 -oX -",
             "help": "Parámetros pasados directamente a Nmap."
            },
            {"name": "nvd_api_key",
             "label": "API Key NVD",
             "required": False,
             "placeholder": "Tu API Key NVD"
            },
            {"name": "vulners_api_key",
             "label": "API Key Vulners",
             "required": False,
             "placeholder": "Tu API Key Vulners"
            }
        ],
        "timeout": 1200,
        "accepts_log": True
    }


CACHE_NVD = {}


def normalizar_producto(p):
    if not p:
        return ""
    p = p.strip()

    mapa = {
        "openssh": "OpenSSH",
        "ssh": "OpenSSH",
        "nginx": "nginx",
        "mariadb": "MariaDB",
        "mysql": "MariaDB",
        "apache": "Apache HTTP Server",
        "httpd": "Apache HTTP Server"
    }

    p_lower = p.lower()
    for key, val in mapa.items():
        if key in p_lower:
            return val

    return p.title()


def normalizar_version(raw):
    if not raw:
        return ""
    raw = raw.strip()   
    m = re.search(r"([\d\w\.\-]+)", raw)
    return m.group(1) if m else raw



def buscar_cves_nvd(product, version=""):
    key = f"{product}_{version}"
    if key in CACHE_NVD:
        return CACHE_NVD[key]

    queries = []
    if version:
        queries.append(f"{product} {version}")
    queries.append(product)

    vulns = []

    for query in queries:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": query,
            "resultsPerPage": 80
        }
        headers = {"apiKey": NVD_API_KEY}

        try:
            r = requests.get(url, params=params, headers=headers, timeout=10)
            if r.status_code != 200:
                continue

            data = r.json()
            found = data.get("vulnerabilities", [])
            if found:
                for item in found[:10]: 
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"]

                    metrics = item["cve"].get("metrics", {})
                    cvss = None
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    vulns.append({
                        "cve": cve_id,
                        "description": desc,
                        "cvss": cvss or 0,
                    })

                break

        except:
            pass

    CACHE_NVD[key] = vulns
    return vulns



def buscar_exploits_vulners_batch(cve_list):
    if not cve_list:
        return []

    url = "https://vulners.com/api/v3/search/id/"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": VULNERS_API_KEY
    }
    payload = {
        "id": cve_list,
        "fields": ["*"]
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code != 200:
            return []

        docs = r.json().get("data", {}).get("documents", {})
        exploits = []

        for _, d in docs.items():
            if d.get("type") == "exploit":
                exploits.append({
                    "title": d.get("title"),
                    "href": d.get("href"),
                    "type": d.get("type"),
                    "cve": d.get("cvelist", ["N/A"])[0]
                })

        return exploits

    except:
        return []
        

def cve_afecta_version(cve_item, version_detectada):  
    if not version_detectada:
        return True  

    metrics = cve_item.get("configurations", {}).get("nodes", [])
    version_detectada = version_detectada.strip()

    for node in metrics:
        for match in node.get("cpeMatch", []):
            vstart = match.get("versionStartIncluding")
            vend   = match.get("versionEndIncluding")

            if vstart and version_detectada < vstart:
                continue
            if vend and version_detectada > vend:
                continue

            return True

    return False



def criticidad(cvss):
    if cvss >= 9:
        return "Crítico"
    elif cvss >= 7:
        return "Alto"
    elif cvss >= 4:
        return "Medio"
    else:
        return "Bajo"
   
        

def log_write(logfile, msg):  
    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(f"[{dt.utcnow().isoformat()}] {msg}\n")


def expand_targets(target):
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 4096:
                raise ValueError("CIDR demasiado grande")
            return [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
        else:
            return [target]
    except Exception:
        return [target]




def scan_ip_with_nmap(ip, nmap_args):      
    cmd = f"nmap {nmap_args} {ip}"

    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=180
        )
        out = proc.stdout
    except Exception as e:
        return {"ip": ip, "error": str(e)}

    
    ports = []
    banners = []

    try:
        root = ET.fromstring(out)
    except Exception:
        return {"ip": ip, "error": "No XML output from Nmap", "raw": out[:10000]}

    all_vulns = [] 

    all_vulns = [] 

    for host in root.findall("host"):
        for p in host.findall("ports/port"):
            portnum = int(p.get("portid"))
            service_elem = p.find("service")
            service = service_elem.get("name") if service_elem is not None else ""
            product_raw = service_elem.get("product") if service_elem is not None else None
            version_raw = service_elem.get("version") if service_elem is not None else None

            prod_norm = normalizar_producto(product_raw)
            ver_norm = normalizar_version(version_raw)

          
            if not ver_norm:
                continue

           
            cves = buscar_cves_nvd(prod_norm, ver_norm)
            cve_ids = [c["cve"] for c in cves]
            exploits = buscar_exploits_vulners_batch(cve_ids)

            vulns = []
            for c in cves:
                entry = {
                    "cve": c["cve"],
                    "cvss": c["cvss"],
                    "description": c["description"],
                    "port": portnum,
                    "service": service,
                    "product": prod_norm,
                    "version": ver_norm,
                    "exploits": [e for e in exploits if e["cve"] == c["cve"]]
                }
                vulns.append(entry)
                all_vulns.append(entry)

            ports.append(portnum)
            banners.append({
                "timestamp": dt.utcnow().isoformat() + "Z",
                "port": portnum,
                "transport": p.get("protocol"),
                "module": "nmap",
                "data_preview": f"service={service}",
                "ssl": False,
                "product": prod_norm,
                "version": ver_norm,
                "vulns": vulns
            })


    
    for v in all_vulns:
        nivel = criticidad(v["cvss"])
        product  = v.get("product") or "unknown"
        version  = v.get("version") or "unknown"
        service  = v.get("service") or "unknown"
        port     = v.get("port") or "unknown"

        print(
            f"{v['cve']} ({product} {version}, CVSS {v['cvss']}, {nivel}) – Port {port} / Service {service}"
        )
    
    vulnsFront = {}
    for v in all_vulns:
        vulnsFront[v["cve"]] = {
            "cvss": v["cvss"],
            "port": v["port"],
            "service": v["service"],
            "product": v["product"],
            "version": v["version"],
            "description": v["description"],
            "exploits": v["exploits"]
        }

    return {
        "ip": ip,
        "ip_str": ip,
        "org": "",
        "os": "",
        "hostnames": [],
        "last_update": dt.utcnow().isoformat() + "Z",
        "ports": ports,
        "banners_count": len(banners),
        "banners": banners,
        "vulns_nvd": all_vulns,  
        "vulns": vulnsFront,    
        "raw": out[:10000]
    }




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--max", type=int, default=0)

   
    parser.add_argument("--nvd-api-key", "--nvd_api_key",
                        dest="nvd_api_key",
                        required=False,
                        help="API Key NVD")
    parser.add_argument("--vulners-api-key", "--vulners_api_key",
                        dest="vulners_api_key",
                        required=False,
                        help="API Key Vulners")

    
    parser.add_argument("--nmap-args", "--nmap_args",
                        dest="nmap_args",
                        required=False,
                        default="-sS -sV -A -T4 -oX -",
                        help="Argumentos pasados directamente a nmap")

    parser.add_argument("--log", required=False)

    args = parser.parse_args()

    global NVD_API_KEY, VULNERS_API_KEY

  
    if args.nvd_api_key:
        NVD_API_KEY = args.nvd_api_key
    if args.vulners_api_key:
        VULNERS_API_KEY = args.vulners_api_key

    logfile = args.log
    log_write(logfile, f"Inicio del escaneo: target={args.target}")

    targets = expand_targets(args.target)
    if args.max > 0:
        targets = targets[:args.max]

    results = {
        "scanned_target": args.target,
        "timestamp": dt.utcnow().isoformat() + "Z",
        "results": []
    }

    for i, ip in enumerate(targets, start=1):
        log_write(logfile, f"Escaneando {ip} ({i}/{len(targets)})")
        print(f"[{i}/{len(targets)}] nmap -> {ip}")

        res = scan_ip_with_nmap(ip, args.nmap_args)
        results["results"].append(res)

        if i != len(targets):
            time.sleep(args.delay)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Saved", out_path)
    log_write(logfile, f"Escaneo finalizado. Resultados en {args.out}")



if __name__ == "__main__":
    main()
