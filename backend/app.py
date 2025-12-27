from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
import subprocess, shlex, os, uuid, json, re, datetime, pathlib, asyncio, traceback, subprocess, shodan 
from typing import Dict, Any, List
from fastapi.middleware.cors import CORSMiddleware
import ast

app = FastAPI(title="Shodan API Backend")

#pera permitir solicitudes desde el frontend
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       
    allow_credentials=True,
    allow_methods=["*"],         
    allow_headers=["*"],         
)



RESULTS_DIR = pathlib.Path("results")
SCRIPTS_DIR = pathlib.Path("scripts")
RESULTS_DIR.mkdir(exist_ok=True)



CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

class RunRequest(BaseModel):
    params: Dict[str, Any] = {}
    

def read_script_metadata(script_path: str) -> dict:  
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            source = f.read()      
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if getattr(target, 'id', None) == "SCRIPT_METADATA":
                        return ast.literal_eval(node.value)
    except Exception as e:
        print(f"[WARN] Cannot read metadata from {script_path}: {e}")
    return {}
    
    

def _save_result_file(prefix: str, data: Dict[str,Any]) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"{prefix}_{ts}_{uuid.uuid4().hex[:6]}.json"
    path = RESULTS_DIR / fname
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return str(path)

def extract_cves_from_obj(obj) -> List[str]:
    found = set()
    text = json.dumps(obj, ensure_ascii=False)
    for m in CVE_RE.findall(text):
        found.add(m.upper())
    return sorted(found)

async def _run_script_and_capture(cmd: str, timeout: int = 120, env: Dict[str, str] | None = None) -> Dict[str,Any]:
  
    print(f"[DEBUG] _run_script_and_capture -> launching (in thread): {cmd} (timeout={timeout}s)")
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            cmd,
            shell=True,
            capture_output=True,
            text=True,     
            timeout=timeout,
            env=env
        )
        return {
            "timeout": False,
            "exception": False,
            "returncode": proc.returncode,
            "stdout": ensure_str(proc.stdout),
            "stderr": ensure_str(proc.stderr)
        }
    except subprocess.TimeoutExpired as te:       
        print("[DEBUG] _run_script_and_capture -> TimeoutExpired")
        return {
            "timeout": True,
            "exception": False,
            "returncode": None,
            "stdout": ensure_str(getattr(te, "output", "") or getattr(te, "stdout", "")),
            "stderr": ensure_str(getattr(te, "stderr", "") or getattr(te, "stderr", ""))
        }
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[DEBUG] _run_script_and_capture -> Exception: {e}\n{tb}")
        return {
            "timeout": False,
            "exception": True,
            "error": str(e),
            "traceback": tb,
            "returncode": None,
            "stdout": "",
            "stderr": ""
        }

        
#para crear mapa dinámico 
def get_available_scripts() -> Dict[str, pathlib.Path]:
    """
    devuelve un dict {script_name: script_path} con todos los scripts .py
    en la carpeta scripts.
    """
    scripts = {}
    for f in SCRIPTS_DIR.glob("*.py"):
        scripts[f.stem] = f.resolve()
    return scripts

#mapa global cacheado (se puede refrescar si se agregan scripts nuevos dinámicamente)
AVAILABLE_SCRIPTS = get_available_scripts()



@app.post("/run/{script_name}")
async def run_script(script_name: str, req: RunRequest, background_tasks: BackgroundTasks):
    """
    ejecuta el script Python de la carpeta SCRIPTS_DIR tomando parámetros
    desde el frontend. Devuelve resultado en JSON.
    """
    try:
        print(f"[DEBUG] Received params: {req.params}")
        available_scripts = get_available_scripts()
        if script_name not in available_scripts:
            raise HTTPException(400, f"Invalid script name: {script_name}")

        script_path = available_scripts[script_name]
        meta = read_script_metadata(str(script_path))
        params_schema = meta.get("params", [])

        base_env = os.environ.copy()
        if api_key := req.params.get("api_key"):
            base_env["SHODAN_API_KEY"] = api_key

        cmd = f'python "{script_path}"'

        #construiye argumentos dinámicamente según SCRIPT_METADATA
        for p in params_schema:
            name = p["name"]
            value = req.params.get(name)

            #normalizar valores vacíos
            if isinstance(value, str):
                value = value.strip() or None

            if value is None:
                if p.get("required", False):
                    raise HTTPException(400, f"Missing required parameter: {name}")
                value = p.get("placeholder")

            #convertir Python a CLI
            if isinstance(value, bool):
                if value:
                    cmd += f" --{name}"
            elif value is not None:
                cmd += f' --{name} "{value}"'


        #archivos de salida y log
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_file = RESULTS_DIR / f"{script_name}_{ts}.json"
        cmd += f' --out "{out_file}"'

        log_file_abs = None
        if meta.get("accepts_log", False):
            log_file = RESULTS_DIR / f"{script_name}_{ts}.log"
            log_file_abs = log_file.resolve()
            cmd += f' --log "{log_file}"'

        #mostrar comando final
        print(f"[DEBUG] CMD to run: {cmd}")

        #ejecuta el script
        timeout = meta.get("timeout", 600)
        res = await _run_script_and_capture(cmd, timeout=timeout, env=base_env)

        success = not res.get("timeout") and not res.get("exception") and res.get("returncode") == 0

        if success and out_file.exists():
            data = json.loads(out_file.read_text(encoding="utf-8"))
            _save_result_file(f"meta_{script_name}", {
                "cmd": cmd,
                "stdout": res.get("stdout"),
                "stderr": res.get("stderr"),
                "returncode": res.get("returncode"),
                "data": data
            })
            return {
                "status": "finished",
                "out_path": str(out_file.resolve()),
                "log_path": str(log_file_abs) if log_file_abs else None,
                "result": res,
                "data": data
            }
        else:
            err_path = _save_result_file(f"error_{script_name}", {
                "cmd": cmd,
                "stdout": res.get("stdout"),
                "stderr": res.get("stderr"),
                "timeout": res.get("timeout"),
                "exception": res.get("exception")
            })
            return {"status": "error", "error_file": err_path, "result": res}

    except Exception as e:
        tb = traceback.format_exc()
        raise HTTPException(500, f"Internal server error: {e}\n{tb}")




def ensure_str(x):    
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    return str(x)



@app.get("/scripts/schema")
def get_scripts_schema():
    schema = {}
    for script_file in SCRIPTS_DIR.glob("*.py"):
        name = script_file.stem
        meta = read_script_metadata(script_file)       
        schema[name] = {
            "description": meta.get("description", ""),
            "params": meta.get("params", [])
        }
    return schema


@app.get("/shodan/api-info")
def shodan_api_info(api_key: str):
    try:
        url = f"https://api.shodan.io/api-info?key={api_key}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise HTTPException(500, f"Error fetching Shodan API info: {e}")



@app.post("/upload-json")
async def upload_json(file: UploadFile = File(...)):
    content = await file.read()
    try:
        obj = json.loads(content)
    except Exception as e:
        raise HTTPException(400, f"Invalid JSON: {e}")
    path = _save_result_file(file.filename.rsplit('.',1)[0], obj)
    cves = extract_cves_from_obj(obj)
    return {"path": path, "cves": cves}

@app.get("/results")
def list_results():
    files = sorted(RESULTS_DIR.glob("*.json"), reverse=True)
    return [{"name": f.name, "path": str(f)} for f in files]


@app.get("/results/file")
def get_result_file(path: str):
    p = pathlib.Path(path)
    if not p.exists() or not p.is_file():
        raise HTTPException(404, f"File not found: {path}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(500, f"Error reading file: {e}")


@app.get("/extract-cves")
def extract_cves(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        raise HTTPException(404, "File not found")
    obj = json.loads(p.read_text(encoding="utf-8"))
    cves = extract_cves_from_obj(obj)
    severity_map = {}
    for c in cves:
        severity_map[c] = {"severity": "Unknown", "suggested": []}
    return {"cves": cves, "count": len(cves), "severity_map": severity_map}
    


@app.post("/alerts/list")
def list_alerts(req: RunRequest):
    """Lista las alertas activas de la cuenta Shodan."""
    api_key = req.params.get("api_key")
    if not api_key:
        raise HTTPException(400, "Missing api_key")

    try:
        api = shodan.Shodan(api_key)
        alerts = api.alerts()
        return alerts
    except Exception as e:
        raise HTTPException(500, f"Error fetching alerts: {e}")

@app.post("/alerts/delete")
def delete_alert(req: RunRequest):   
    api_key = req.params.get("api_key")
    alert_id = req.params.get("alert_id")
    if not api_key or not alert_id:
        raise HTTPException(400, "Missing parameters: api_key and alert_id required")

    try:
        api = shodan.Shodan(api_key)
        api.delete_alert(alert_id)
        return {"status": "deleted", "id": alert_id}
    except Exception as e:
        raise HTTPException(500, f"Error deleting alert: {e}")   
    
     
    
    
    

import time
import requests

_nvd_cache = {}
_nvd_cache_ttl = 60 * 60 * 24

@app.get("/nvd/cve")
def nvd_cve(cve: str):  
    key = cve.upper()
    now = time.time()
    if key in _nvd_cache:
        entry = _nvd_cache[key]
        if now - entry['fetched_at'] < _nvd_cache_ttl:
            return entry['data']
    #Query NVD
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{key}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        payload = r.json()       
        desc = ''
        try:
            desc = payload.get('result', {}).get('CVE_Items', [])[0].get('cve', {}).get('description', {}).get('description_data', [])[0].get('value', '')
        except Exception:
            desc = ''
        impact = payload.get('result', {}).get('CVE_Items', [])[0].get('impact', {})
        data = {'cve': key, 'description': desc, 'impact': impact, 'raw': payload}
        _nvd_cache[key] = {'fetched_at': now, 'data': data}
        return data
    except Exception as e:
        return {'cve': key, 'error': str(e)}
