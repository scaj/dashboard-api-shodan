from __future__ import annotations
import argparse
import json
import time
import re
from pathlib import Path
from datetime import datetime as dt
import requests
import shodan
import sys
import os
import concurrent.futures

sys.path.append(str(Path(__file__).resolve().parent.parent))

from shodan_common import load_api_key, save_json, setup_logger

SCRIPT_METADATA = {
    "description": "Escaneo activo con Shodan + correlación de CVEs (NVD) y exploits (Vulners).",
    "params": [
        {"name": "target", "label": "IP objetivo (propia o con permiso)", "type": "text", "required": True},
        {"name": "wait_interval", "label": "Intervalo entre checks (s)", "type": "number", "required": False, "placeholder": 5},
        {"name": "timeout", "label": "Timeout máximo (s)", "type": "number", "required": False, "placeholder": 600},
        {"name": "max_workers", "label": "Hilos para consultas", "type": "number", "required": False, "placeholder": 5},       
        {"name": "nvd_api_key", "label": "API Key de NVD", "type": "password", "required": False},
        {"name": "vulners_api_key", "label": "API Key de Vulners", "type": "password", "required": False}
    ]
}




def normalizarVersion(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    m = re.search(r"(\d+(?:\.\d+){0,3})", raw)
    if m:
        return m.group(1)
    m2 = re.search(r"v?([\d\.]+[a-zA-Z0-9\-]*)", raw)
    return m2.group(1) if m2 else raw


CACHE_NVD = {}


def buscarCvesNvd(product: str, version: str, nvdKey: str = "") -> list:
    key = f"{product}_{version}"
    if key in CACHE_NVD:
        return CACHE_NVD[key]

    queries = []
    if version:
        queries.append(f"{product} {version}")
    queries.append(product)

    vulns = []

    for query in queries:
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": query, "resultsPerPage": 80},
                headers={"apiKey": nvdKey} if nvdKey else {},
                timeout=10
            )
            if r.status_code != 200:
                continue

            data = r.json()
            found = data.get("vulnerabilities", [])
            if found:
                for item in found[:10]:
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"] if item["cve"]["descriptions"] else ""
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
                        "raw_item": item
                    })
                break
        except:
            pass

    CACHE_NVD[key] = vulns
    return vulns


def buscarExploitsVulners(cveList: list, vulnersKey: str = "") -> list:
    if not cveList:
        return []

    url = "https://vulners.com/api/v3/search/id/"
    headers = {"Content-Type": "application/json"}
    if vulnersKey:
        headers["X-Api-Key"] = vulnersKey

    payload = {"id": cveList, "fields": ["*"]}

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


def parseBannerVersion(banner: str) -> tuple[str, str]:
    if not banner:
        return "", ""
    b = banner.lower()

    if "nginx" in b:
        m = re.search(r"nginx\/?([0-9\.]+)?", banner, re.I)
        version = m.group(1) if m and m.group(1) else ""
        return "nginx", version

    if "apache" in b or "httpd" in b:
        m = re.search(r"apache\/?([0-9\.]+)?", banner, re.I)
        version = m.group(1) if m and m.group(1) else ""
        return "Apache HTTP Server", version

    if "openssh" in b or "ssh" in b:
        m = re.search(r"openssh[_-]?([0-9\.]+)?", banner, re.I)
        version = m.group(1) if m and m.group(1) else ""
        return "OpenSSH", version

    if "mysql" in b or "mariadb" in b:
        m = re.search(r"(mysql|mariadb)\/?([0-9\.]+)?", banner, re.I)
        version = m.group(2) if m and m.group(2) else ""
        return "MariaDB", version

    m = re.search(r"([A-Za-z\-\_]+)[/ ]v?([0-9\.]+)", banner)
    if m:
        return m.group(1), m.group(2)

    return "", ""


def analizar(item: dict, nvdKey: str, vulnersKey: str):
    port = item.get("port")
    bannerRaw = item.get("data") or item.get("banner") or ""

    productRaw = item.get("product") or item.get("service") or ""
    versionRaw = item.get("version") or ""

    if not productRaw or not versionRaw:
        pFromBanner, vFromBanner = parseBannerVersion(bannerRaw)
        if not productRaw:
            productRaw = pFromBanner
        if not versionRaw:
            versionRaw = vFromBanner

    verNorm = normalizarVersion(versionRaw)

    invalidVersions = ["", "0", "0.0", "1", "1.0", "1.1"]
    if verNorm in invalidVersions:
        verNorm = ""

    if verNorm:
        cves = buscarCvesNvd(productRaw, verNorm, nvdKey)
        cveIds = [c["cve"] for c in cves]
        exploits = buscarExploitsVulners(cveIds, vulnersKey) if cveIds else []
    else:
        cves = []
        exploits = []

    bannerOut = {
        "port": port,
        "product": productRaw,
        "version": verNorm,
        "banner": bannerRaw
    }

    vulns = []
    for c in cves:
        cvssScore = c.get("cvss", 0)

        if cvssScore >= 9.0:
            cvssSeverity = "Crítico"
        elif cvssScore >= 7.0:
            cvssSeverity = "Alto"
        elif cvssScore >= 4.0:
            cvssSeverity = "Medio"
        else:
            cvssSeverity = "Bajo"

        vulns.append({
            "cve": c["cve"],
            "description": c["description"],
            "cvss": cvssScore,
            "severity": cvssSeverity,
            "product": productRaw,
            "version": verNorm,
            "service": productRaw,
            "port": port,
            "exploits": [e for e in exploits if e.get("cve") == c["cve"]]
        })

    return bannerOut, vulns, port


def scan(api, target: str, waitInterval: int = 5, timeout: int = 600, maxWorkers: int = 5, nvdKey: str = "", vulnersKey: str = ""):
    try:
        scan = api.scan(target)
        scanId = scan.get("id")
    except Exception as e:
        return {"error": f"Scan start error: {e}"}

    start = time.time()
    while True:
        try:
            status = api.scan_status(scanId)
        except Exception as e:
            return {"error": f"Scan status error: {e}"}

        if status.get("status") == "DONE":
            break

        if time.time() - start > timeout:
            return {"error": "TIMEOUT"}

        time.sleep(waitInterval)

    try:
        host = api.host(target, minify=False)
    except Exception as e:
        return {"error": f"Host fetch error: {e}"}

    dataItems = host.get("data", [])

    banners = []
    allVulns = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorkers) as ex:
        futures = [ex.submit(analizar, it, nvdKey, vulnersKey) for it in dataItems]
        for f in concurrent.futures.as_completed(futures):
            try:
                bannerOut, vulns, port = f.result()
                banners.append(bannerOut)
                allVulns.extend(vulns)
            except:
                pass

    vulnsFront = {}
    for v in allVulns:
        vulnsFront[v["cve"]] = {
            "cvss": v.get("cvss"),
            "port": v.get("port"),
            "service": v.get("service"),
            "product": v.get("product"),
            "version": v.get("version"),
            "description": v.get("description"),
            "exploits": v.get("exploits", [])
        }

    ports = sorted({b["port"] for b in banners if b.get("port") is not None})

    result = {
        "ip": host.get("ip_str", target),
        "ip_str": host.get("ip_str", target),
        "org": host.get("org", ""),
        "os": host.get("os", ""),
        "hostnames": host.get("hostnames", []),
        "last_update": dt.utcnow().isoformat() + "Z",
        "ports": ports,
        "banners_count": len(banners),
        "banners": banners,
        "vulns_nvd": allVulns,
        "vulns": vulnsFront,
        "raw": json.dumps(host)[:10000]
    }

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--wait_interval", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--max_workers", type=int, default=5)
    parser.add_argument("--nvd_api_key", required=False)
    parser.add_argument("--vulners_api_key", required=False)

    args = parser.parse_args()

    nvdKey = args.nvd_api_key or os.getenv("NVD_API_KEY")
    vulnersKey = args.vulners_api_key or os.getenv("VULNERS_API_KEY")
    shodanKey = load_api_key() or os.getenv("SHODAN_API_KEY")

    if not shodanKey:
        print("ERROR: No se ha encontrado API key de Shodan (ni en archivo ni en variable de entorno)", file=sys.stderr)
        sys.exit(1)

    api = shodan.Shodan(shodanKey)

    processed = scan(
        api,
        args.target,
        args.wait_interval,
        args.timeout,
        args.max_workers,
        nvdKey,
        vulnersKey
    )

    out = [processed]

    outPath = Path(args.out)
    outPath.parent.mkdir(parents=True, exist_ok=True)
    outPath.write_text(
        json.dumps(out, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"[INFO] Resultados guardados en {outPath}")


if __name__ == "__main__":
    main()
