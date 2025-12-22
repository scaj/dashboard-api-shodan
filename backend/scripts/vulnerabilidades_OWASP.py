#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
from datetime import datetime


SCRIPT_METADATA = {
    "description": "Clasifica vulnerabilidades según OWASP IoT Top 10. Analiza los archivos json generados con el script escaneo_activo_cve.",
    "version": "1.0.0",
    "params": [
        {"name": "input_file", "label": "Archivo JSON de entrada: escaneo_activo_cve_fecha.json", "required": True,  "placeholder": "ej: results/escaneo_activo_cve_20251128T160232Z.json",}
    ],
    "timeout": 120,
    "accepts_log": True
}


OWASP_IOT = {
    "A01 – Contraseñas débiles o codificadas": ["password", "credential", "hardcoded", "weak password", "salt", "authentication"],
    "A02 – Servicios de red inseguros": ["network service", "open port", "service", "telnet", "ftp", "ssh", "port scan", "remote access"],
    "A03 – Interfaces inseguras del ecosistema": ["api", "interface", "ecosystem", "web interface", "endpoint", "rest"],
    "A04 – Falta de mecanismo seguro de actualización": ["update", "firmware", "patch", "upgrade", "version check"],
    "A05 – Uso de componentes inseguros o desactualizados": ["outdated", "version", "component", "library", "mysql", "mariadb", "openssh"],
    "A06 – Protección insuficiente de la privacidad": ["privacy", "data exposure", "personal data", "user data", "leak", "pii"],
    "A07 – Transferencia y almacenamiento de datos inseguros": ["storage", "transfer", "unencrypted", "http", "ftp", "plaintext"],
    "A08 – Falta de gestión del dispositivo": ["management", "configuration", "admin interface", "policy", "access control"],
    "A09 – Configuración predeterminada insegura": ["default", "misconfiguration", "factory settings", "default credentials"],
    "A10 – Falta de endurecimiento físico": ["physical", "tamper", "device access", "console"]
}

def clasificarOwasp(vuln_info: dict) -> dict:
    combined_text = " ".join(
    str(vuln_info.get(f, "")).lower()
    for f in ["description", "service", "product", "version", "cve_id"]
    )

    category_scores = {}
    matched_keywords = {}

    for categoria, keywords in OWASP_IOT.items():
        score = sum(1 for k in keywords if k.lower() in combined_text)
        if score > 0:
            category_scores[categoria] = score
            matched_keywords[categoria] = [k for k in keywords if k.lower() in combined_text]

    if category_scores:
        best_category = max(category_scores, key=category_scores.get)
        return {"category": best_category, "matched": matched_keywords[best_category]}

    return {"category": "Sin categorizar", "matched": []}


def main():
    parser = argparse.ArgumentParser(description=SCRIPT_METADATA["description"])
    parser.add_argument("--input_file", required=True)
    parser.add_argument("--out", required=False)
    parser.add_argument("--log", required=False)
    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_path = Path(args.out) if args.out else Path("results") / f"{input_path.stem}_classified.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def write_log(msg):
        if args.log:
            with open(args.log, "a", encoding="utf-8") as lf:
                lf.write(msg + "\n")

    write_log(f"[{datetime.utcnow().isoformat()}] Inicio del análisis")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    salida = []
    for host in data:
        ip = host.get("ip")
        org = host.get("org")
        hostnames = host.get("hostnames", [])
        banners = host.get("banners", [])
        vulns = host.get("vulns", {})

        #crea un diccionario con la info de los puertos a partir de banners
        puerto_info = {int(b.get("port", -1)): b for b in banners if b.get("port")}

        for cve_id, vuln in vulns.items():
            port = vuln.get("port")
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                port_int = None

            service_info = puerto_info.get(port_int, {}) if port_int else {}

            vuln_info = {
                "description": vuln.get("description", ""),
                "service": service_info.get("service"),
                "product": service_info.get("product"),
                "version": service_info.get("version"),
                "cve_id": cve_id
            }

            owasp_result = clasificarOwasp(vuln_info)

            salida.append({
                "ip": ip,
                "org": org,
                "hostnames": hostnames,
                "cve": cve_id,
                "cvss": vuln.get("cvss", "N/D"),
                "port": port,
                "service": vuln_info.get("service"),
                "product": vuln_info.get("product"),
                "version": vuln_info.get("version"),
                "description": vuln_info.get("description"),
                "owasp_category": owasp_result["category"],
                "matched_keywords": owasp_result["matched"]
            })



    print(f"[DEBUG] Guardando resultados en: {output_path}")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(salida, f, indent=4, ensure_ascii=False)

    write_log(f"[{datetime.utcnow().isoformat()}] Archivo generado: {output_path}")
    print(f"[OK] Clasificación completada. Archivo: {output_path}")

if __name__ == "__main__":
    main()
