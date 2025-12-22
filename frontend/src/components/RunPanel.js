import React, { useState, useEffect } from 'react';
import { runScript, getResultFile } from '../utils';
import ShodanAlertsPanel from './ShodanAlertsPanel';

export default function RunPanel({ onStarted, apiKey, setApiKey }) {
  const [script, setScript] = useState('');
  const [params, setParams] = useState({});  
  const [status, setStatus] = useState(null);
  const [running, setRunning] = useState(false);
  const [scriptsMeta, setScriptsMeta] = useState({});
  const [delay, setDelay] = useState(1.0);
  const [maxIps, setMaxIps] = useState(0);
 
 
  useEffect(() => {
    const saved = localStorage.getItem('SHODAN_API_KEY') || '';
    setApiKey(saved);
  }, []);

  useEffect(() => {
    if (apiKey) localStorage.setItem('SHODAN_API_KEY', apiKey);
    else localStorage.removeItem('SHODAN_API_KEY');
  }, [apiKey]);


  useEffect(() => {
    async function loadScripts() {
      try {
        const res = await fetch(`${process.env.REACT_APP_API_BASE || 'http://localhost:8000'}/scripts/schema`);
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        setScriptsMeta(data);
 console.log('scriptsMeta', data);
        const firstScript = Object.keys(data)[0];
        if (firstScript) setScript(firstScript);
      } catch (err) {
        console.error('Error loading scripts metadata:', err);
      }
    }
    loadScripts();
  }, []);

  const handleParamChange = (name, value) => {
    setParams(prev => ({ ...prev, [name]: value }));
  };

  const handleRun = async () => {
    setStatus('Starting...');
    setRunning(true);

    try {
      if (!script) throw new Error('Select a script');

      const metaParams = scriptsMeta[script]?.params || [];

      const payload = {};

      for (const p of metaParams) {
        let val = params[p.name];
        if (typeof val === 'string') val = val.trim();
        if (!val && p.required) throw new Error(`Missing required parameter: ${p.name}`);
        payload[p.name] = val ?? p.placeholder ?? null;
      }

      if (apiKey?.trim()) payload.api_key = apiKey.trim();

      setStatus('Requesting backend...');
      const res = await runScript(script, payload);

      if (res?.error) {
        setStatus(`Error: ${res.error}`);
        onStarted?.({ error: res.error });
        return;
      }

      if (res.status !== 'finished') {
        setStatus(res.status || 'Unknown');
        onStarted?.(null);
        return;
      }

      setStatus('Finished');

      let data = null;
      if (res.data) data = res.data;
      else if (res.out_path) data = await getResultFile(res.out_path);
      else if (looksLikeDataObject(res)) data = res;

      if (!data) {
        console.warn('[RunPanel] No data to show');
        onStarted?.(null);
        return;
      }

      if (isTabularData(data)) onStarted?.({ data });
      else onStarted?.(null);

    } catch (e) {
      setStatus(`Error: ${e.message}`);
      onStarted?.({ error: String(e) });
    } finally {
      setRunning(false);
    }
  };

  function looksLikeDataObject(obj) {
    if (!obj || typeof obj !== 'object') return false;
    if (Array.isArray(obj)) return false;
    return Object.values(obj).some(v => Array.isArray(v) && v.length > 0);
  }

  function isTabularData(data) {
    if (!data) return false;
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') return true;
    for (const key of Object.keys(data)) {
      const val = data[key];
      if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') return true;
    }
    return false;
  }
  
  
  
  

  return (
    <div style={{ border: '1px solid #ccc', padding: 8, marginBottom: 8, borderRadius: 12 }}>
      <h4>Ejecución de scripts</h4>

      <div style={{ marginBottom: 8 }}>
        <label style={{ fontSize: 12 }}>SHODAN API key (optional):</label>
        <input
          type="password"
          placeholder="sk-your-key..."
          value={apiKey}
          onChange={e => setApiKey(e.target.value)}
          style={{ width: '100%' }}
          disabled={running}
        />
      </div>

      <div style={{ marginTop: 8 }}>
        <label htmlFor="scriptSelect" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>
          Selección de script:
        </label>
        <select
          id="scriptSelect"
          value={script}
          onChange={e => { setScript(e.target.value); setParams({}); }}
          disabled={running}
          style={{ width: '100%' }}
        >
          {Object.keys(scriptsMeta).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
	  
	  
	 
		{script && scriptsMeta[script] && (
		  <div
			style={{
			  border: '1px solid #c19a6b',
			  backgroundColor: '#f5f0eb',
			  borderRadius: 8,
			  padding: 8,
			  marginTop: 12,
			  fontSize: 12,
			  lineHeight: 1.4,
			}}
		  >
			<strong>{script}</strong>
			<pre style={{ whiteSpace: "pre-wrap", fontSize: "14px" }}>{scriptsMeta[script].description || 'Sin descripción disponible'}</pre>

			{Array.isArray(scriptsMeta[script].params) && scriptsMeta[script].params.length > 0 && (
			  <div style={{ marginTop: 6 }}>
				<strong>Parámetros:</strong>
				<ul style={{ margin: 4, paddingLeft: 16 }}>
				  {scriptsMeta[script].params.map(p => (
					<li key={p.name}>
					  <strong>{p.name}</strong>: {p.label} {p.required ? '(obligatorio)' : '(opcional)'}
					</li>
				  ))}
				</ul>
			  </div>
			)}
		  </div>
		)}

	  
      {script && (scriptsMeta[script]?.params || []).map(p => (
		  <div key={p.name} style={{ marginTop: 8 }}>
			<label style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>
			  {p.label} {p.required ? '*' : ''}
			</label>
			<input
			  type={typeof p.placeholder === 'number' ? 'number' : 'text'}
			  placeholder={p.placeholder ?? ''}
			  value={params[p.name] ?? ''}
			  onChange={e => handleParamChange(p.name, e.target.value)}
			  disabled={running}
			  style={{ width: '100%' }}
			/>
		  </div>
		))}


      <div style={{ marginTop: 8 }}>
        <button onClick={handleRun} disabled={running}>{running ? 'Running...' : 'Run'}</button>
        <span style={{
          marginLeft: 8,
          color: status?.startsWith('Error') ? 'red' : status === 'Finished' ? 'green' : 'blue'
        }}>
          {status}
        </span>
      </div>
		
	<ShodanAlertsPanel apiKey={apiKey} />
	  
    </div>
	
	
  );
}
