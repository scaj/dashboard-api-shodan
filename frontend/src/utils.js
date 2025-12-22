
const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:8000'
console.log('[DEBUG] Using API base:', API_BASE);


export async function listResults() {
  const r = await fetch(`${API_BASE}/results`);
  return r.json();
}

export async function getResultFile(path) {
  const r = await fetch(`${API_BASE}/results/file?path=${encodeURIComponent(path)}`);
  return r.json();
}

export async function uploadJSON(file) {
  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch(`${API_BASE}/upload-json`, { method: 'POST', body: fd });
  return r.json();
}

export async function extractCVEs(path) {
  const r = await fetch(`${API_BASE}/extract-cves?path=${encodeURIComponent(path)}`);
  return r.json();
}

export async function runScript(name, params) {
  const res = await fetch(`${API_BASE}/run/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ params })
  });


  return res.json(); 
}


export async function getApiCredits(apiKey) {
  const r = await fetch(`${API_BASE}/shodan/api-info?api_key=${apiKey}`);
  return r.json();
}





export function normalizeData(raw) {
  let items = [];
  if (Array.isArray(raw)) {
    items = raw;
  } else if (raw && Array.isArray(raw.results)) {
    items = raw.results;
  } else if (raw && Array.isArray(raw.data)) {
    items = raw.data;
  } else if (raw && raw.matches) {
    items = raw.matches;
  }
  return { raw: raw || null, items };
}


export default API_BASE;
