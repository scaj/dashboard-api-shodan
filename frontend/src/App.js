import React, { useState, useEffect } from 'react';
import JsonManager from './components/JsonManager';
import RunPanel from './components/RunPanel';
import SummaryPanel from './components/SummaryPanel';
import TableView from './components/TableView';
import ChartsPanel from './components/ChartsPanel';
import VulnerabilitiesPanel from './components/VulnerabilitiesPanel';
import ReportExport from './components/ReportExport';
import './index.css'; 
import API_BASE, { listResults, getResultFile, normalizeData } from './utils';



export default function App() {
  const [selected, setSelected] = useState({ name: '', data: null, path: '' });
  const [lastRun, setLastRun] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [runStatus, setRunStatus] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [scriptsMeta, setScriptsMeta] = useState({});
  const [script, setScript] = useState('');
 
  useEffect(() => {
    async function loadInitialResults() { /* ... */ }
    loadInitialResults();
  }, []);
  
 
	useEffect(() => {
	  async function loadScripts() {
		try {
		  console.log(`[DEBUG] Fetching scripts from: ${API_BASE}/scripts/schema`);
		  const res = await fetch(`${API_BASE}/scripts/schema`);
		  console.log('[DEBUG] fetch response status:', res.status);

		  if (!res.ok) throw new Error(`HTTP error ${res.status}`);
		  
		  const data = await res.json();
		  console.log('[DEBUG] scriptsMeta loaded:', data);

		  setScriptsMeta(data);

		  const firstScript = Object.keys(data)[0];
		  if (firstScript) setScript(firstScript);
		} catch (err) {
		  console.error('[DEBUG] Error al cargar metadatos de scripts:', err);
		}
	  }

	  loadScripts();
	}, []);


  
  
  useEffect(() => {
  async function loadInitialResults() {
    console.log("[App] Cargando resultados iniciales...");
    setLoading(true);
    try {
      const resList = await listResults();
      console.log("[App] listResults =>", resList);

      setResults(resList);

      if (resList.length > 0) {
        const latest = resList[resList.length - 1];
        console.log("[App] Cargando el último archivo:", latest);

        const data = await getResultFile(latest.path || latest);
        console.log("[App] Contenido del archivo cargado:", data);

        const norm = normalizeData(data);
        console.log("[App] normalizado:", norm);

        setSelected({
          name: latest.name || latest.path?.split('/').pop(),
          data: norm,
          path: latest.path || latest,
        });
      }
    } catch (e) {
      console.error('Error al cargar los resultados iniciales:', e);
    } finally {
      setLoading(false);
    }
  }
  loadInitialResults();
}, []);


  useEffect(() => {
    if (!lastRun) return;
    (async () => {
      try {
        const res = await listResults();
        setResults(res);
      } catch (e) {
        console.error('Error al obtener los resultados:', e);
      }
    })();
  }, [lastRun]);
  


  async function handleRunFinished(res) {
		console.log("[App] handleRunFinished recibido:", res);

		setLastRun(res);
		if (!res) return;

		const rc = res.result?.returncode;
		console.log("[App] returncode:", rc);

		const isError = res.status === 'error' && rc !== 0;
		if (isError) {
		console.error("[App] ERROR:", res);
		const errMsg = res.result?.stderr || res.result?.error || 'Error desconocido';
		setRunStatus(`Error: ${errMsg}`);
		return;
		}

		if (res.result?.error && !rc) {
		console.warn("[App] WARNING:", res);
		const msg = `Warning: ${res.result.error}. Info: ${res.result.stderr || ''}`;
		setRunStatus(msg);
		return;
		}
	  

		let rawData = null;


		if (res.data) {
		  rawData = res.data;
		}


		else if (res.out_path) {
		  try {
			rawData = await getResultFile(res.out_path);
		  } catch (e) {
			console.error("[App] Error al obtener el archivo de resultados:", e);
		  }
		}


		else if (
		  res &&
		  typeof res === "object" &&
		  Object.values(res).some(v => Array.isArray(v))
		) {
		  rawData = res;
		}

		if (!rawData) {
		  console.warn("[App] No se encontraron datos utilizables:", res);
		  return;
		}

		const norm = normalizeData(rawData);
		console.log("[App] normalized (final):", norm);

		setSelected({
		  name: res.filename || res.out_path || "last_run",
		  data: norm,
		  path: res.out_path || "",
		});

		setRunStatus("Finished");		

	}



  return (
    <div className="app-container">
      <header className="app-header">
        <h1>🔍 Dashboard API SHODAN</h1>
      </header>

     <main className="app-main-container">
		  <div className="panels-row">
			
			<div className="left-panel">
			   <RunPanel onStarted={handleRunFinished} apiKey={apiKey} setApiKey={setApiKey} status={runStatus} setStatus={setRunStatus} />
			</div>

			
			<div className="right-panel">
			  <JsonManager
			    apiKey={apiKey}
				setApiKey={setApiKey}
				onSelect={(n, d, p) =>
				  setSelected({ name: n, data: normalizeData(d), path: p })
				}
				normalizeData={normalizeData}
				lastRun={lastRun}
				vulnerabilitiesPath={selected.path}
				reportData={selected.data?.items}
				reportName={selected.name || 'report'}
				results={results}
			  />
			</div>
		  </div>

		  
		  <div className="results-panel">
			{loading ? (
			  <div className="loading">
				<strong>Cargando datos...</strong>
			  </div>
			) : selected.data ? (
			  <>
			  
				<SummaryPanel data={selected.data.raw} />
				<ChartsPanel data={selected.data.items} />
				<TableView data={selected.data.items} />
			  </>
			) : (
			  <div className="no-data">
				<em>Aún no se han cargado datos. Ejecute un análisis o seleccione un resultado.</em>
			  </div>
			)}
		  </div>
	</main>



    </div>
  );
}
