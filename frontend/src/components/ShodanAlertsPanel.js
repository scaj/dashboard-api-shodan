import React, { useState } from 'react';

export default function ShodanAlertsPanel({ apiKey }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchAlerts = async () => {
    if (!apiKey) {
      setError("Falta la API key");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/alerts/list", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ params: { api_key: apiKey } }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Error al obtener alertas");
      setAlerts(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const deleteAlert = async (id) => {
    if (!window.confirm("¿Eliminar esta alerta?")) return;
    try {
      const res = await fetch("http://127.0.0.1:8000/alerts/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ params: { api_key: apiKey, alert_id: id } }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Error al eliminar alerta");
      setAlerts(alerts.filter(a => a.id !== id));
    } catch (e) {
      alert(`Error: ${e.message}`);
    }
  };

  return (
    <div style={{ border: "1px solid #ccc", padding: 10, borderRadius: 8, marginTop: 10 }}>
      <h4>📡 Alertas de Shodan</h4>
      <button onClick={fetchAlerts} disabled={loading}>
        {loading ? "Cargando..." : "Ver alertas"}
      </button>
      {error && <p style={{ color: "red" }}>{error}</p>}

      {alerts.length > 0 && (
        <ul style={{ marginTop: 10 }}>
          {alerts.map(a => (
            <li key={a.id} style={{ marginBottom: 6 }}>
              <strong>{a.name}</strong> — {a.filters?.ip || "sin filtro"}
              <button
                onClick={() => deleteAlert(a.id)}
                style={{
                  marginLeft: 10,
                  background: "#dc2626",
                  color: "white",
                  borderRadius: 6,
                  padding: "4px 8px",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                Eliminar
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
