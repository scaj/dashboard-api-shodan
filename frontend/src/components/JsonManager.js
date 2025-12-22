import React, { useEffect, useState } from 'react';
import VulnerabilitiesPanel from './VulnerabilitiesPanel';
import ReportExport from './ReportExport';
import { listResults, getResultFile, uploadJSON } from '../utils';
import { JsonView } from 'react-json-view-lite';
import 'react-json-view-lite/dist/index.css';


export default function JsonManager({ onSelect, lastRun, vulnerabilitiesPath, reportData, reportName, apiKey }) {
  const [files, setFiles] = useState([]);
  const [credits, setCredits] = useState(null);
  const [fetchingCredits, setFetchingCredits] = useState(false);
  const [publicIp, setPublicIp] = useState('');
  const [fetchingIp, setFetchingIp] = useState(false);
  const [apiInfo, setApiInfo] = useState(null);


  useEffect(() => refresh(), []);

  async function refresh() {
    const r = await listResults();
    setFiles(r);
  }

  async function handleSelect(p, n) {
    const d = await getResultFile(p);
    onSelect(n, d, p);
  }

  async function handleUpload(e) {
    const f = e.target.files[0];
    if (!f) return;
    const r = await uploadJSON(f);
    await refresh();
    const d = await getResultFile(r.path);
    onSelect(f.name, d, r.path);
  }
  
  
  const handleGetPublicIp = async () => {
	  setFetchingIp(true);
	  try {
		const res = await fetch('https://api.ipify.org?format=json'); 
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const data = await res.json();
		setPublicIp(data.ip);
	  } catch (e) {
		console.error('Error obteniendo IP pública:', e);
		setPublicIp('Error');
	  } finally {
		setFetchingIp(false);
	  }
	};
  
  
  
	const handleGetApiCredits = async () => {
	  if (!apiKey?.trim()) {
		setCredits('No API key');
		return;
	  }

	  setFetchingCredits(true);

	  try {
		const res = await fetch(
		  'https://api.shodan.io/api-info?key=' + apiKey.trim()
		);

		if (!res.ok) throw new Error(`HTTP ${res.status}`);

		const data = await res.json();
		console.log("data",data);
		
		setApiInfo(data);
		
		const creditsTotal = data.query_credits ?? data.credits ?? 0;
		setCredits(creditsTotal);
	  } catch (e) {
		console.error('Error obteniendo créditos:', e);
		setCredits('Error');
	  } finally {
		setFetchingCredits(false);
	  }
	};
  

  return (
    <div
      style={{
        border: '1px solid #ccc',
        padding: 8,
        marginBottom: 10,
        borderRadius: 8,
        boxShadow: '0 2px 6px rgba(0,0,0,0.1)',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      }}
    >
	
	<div style={{ marginTop: 8, marginBottom: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
	  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
		<button onClick={handleGetPublicIp} disabled={fetchingIp}>
		  {fetchingIp ? 'Obteniendo IP...' : 'Obtener mi IP pública'}
		</button>
		{publicIp && (
		  <span style={{ fontSize: 12 }}>
			IP pública: <strong>{publicIp}</strong>
		  </span>
		)}
	  </div>

	  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
		<button onClick={handleGetApiCredits} disabled={fetchingCredits}>
		  {fetchingCredits ? 'Obteniendo información...' : 'Ver información de la APIKEY'}
		</button>
		
	  </div>
	</div>
	{apiInfo && (
	  <div >		
		<div
		  style={{
			backgroundColor: '#f5e6d3', 
			paddingBottom: '10px',
			paddingLeft: '10px',
			paddingRight: '10px',
			borderRadius: '6px',
		  }}
		>
		  <h4 style={{
			backgroundColor: '#f5e6d3', 
			marginBottom: '5px',
			marginTop:'0px',
			paddingLeft: '5px',
			
			
		  }}>Datos APIKEY </h4>
		  <JsonView data={apiInfo} collapsed={2} />
		</div>
	  </div>
	)}

	<div>
        <label
          htmlFor="fileUpload"
		  style={{
			display: 'inline-block',
			background: '#d2b48c',   
			color: 'white',
			padding: '6px 10px',
			borderRadius: 6,
			cursor: 'pointer',
			boxShadow: '0 2px 4px rgba(0,0,0,0.15)',
			transition: 'background 0.2s, transform 0.1s',
		  }}
		  onMouseOver={(e) => (e.currentTarget.style.background = 'linear-gradient(135deg, #F0DFC9,#c19a6b)')}
		  onMouseOut={(e) => (e.currentTarget.style.background = '#d2b48c')} 
		  onMouseDown={(e) => (e.currentTarget.style.transform = 'scale(0.98)')}
		  onMouseUp={(e) => (e.currentTarget.style.transform = 'scale(1)')}
		>
          📁 Elegir archivo JSON
        </label>
        <input
          id="fileUpload"
          type="file"
          accept=".json"
          onChange={handleUpload}
          style={{ display: 'none' }}
        />
      </div>

	  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
	  <h4 style={{ color: '#1e3a8a', margin: 0 }}>Archivos del servidor</h4>
	  {files.length === 0 ? (
		<em>No hay archivos disponibles</em>
	  ) : (
		<select
		  style={{			
			width: '100%',
			padding: '6px 12px',
			borderRadius: 6,
			border: '1px solid #ccc',
			boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
		  }}
		  defaultValue=""
		  onChange={e => {
			const path = e.target.value;
			const name = files.find(f => f.path === path)?.name;
			if (path && name) handleSelect(path, name);
		  }}
		>
		  <option value="" disabled>
			-- Selecciona un archivo --
		  </option>
		  {files.map(f => (
			<option key={f.path} value={f.path}>
			  {f.name}
			</option>
		  ))}
		</select>
	  )}
	</div>	
	
	{vulnerabilitiesPath && (
		<div
			style={{
			padding: '8px',
			maxHeight: '200px',
			background: "#fff",
			}}
		>
			<VulnerabilitiesPanel path={vulnerabilitiesPath} />
		</div>
	 )}
     
      {lastRun && (
        <div className="last-run" style={{ border: '1px solid #ccc', padding: 8, borderRadius: 6 }}>
          <strong>Last run:</strong>
          <pre>{JSON.stringify(lastRun, null, 2)}</pre>
        </div>
      )}
	  
      {reportData && <ReportExport data={reportData} name={reportName} />}

    </div>
  );
}
