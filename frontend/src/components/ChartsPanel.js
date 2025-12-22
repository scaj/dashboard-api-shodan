import React from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function ChartsPanel({ data }) {
  if (!data || !Array.isArray(data) || data.length === 0) return null;

 
  const BAD_FIELDS = [
    "favicon", "html", "data_preview", "raw_html",
    "timestamp", "last_update"
  ];

  const sample = data[0];
  const keys = Object.keys(sample).filter((k) => !BAD_FIELDS.includes(k));


  let groupField =
    keys.find((k) => k.includes("country")) ||
    keys.find((k) => k.includes("port")) ||
    keys.find((k) => k.includes("org")) ||
    keys.find((k) => k.includes("ip")) ||
    keys.find((k) => typeof sample[k] === "string" || typeof sample[k] === "number") ||
    keys[0];


  const counts = {};
  data.forEach((row) => {
    let val = row[groupField];

    if (Array.isArray(val)) val = val.join(", ");
    if (!val) val = "Unknown";

    counts[val] = (counts[val] || 0) + 1;
  });

  const chartData = Object.entries(counts).map(([name, value]) => ({ name, value }));

  if (chartData.length < 2) {
    return (
      <div style={{ padding: 12, fontStyle: "italic", color: "#555" }}>
        Datos insuficientes para un gráfico de barras
      </div>
    );
  }

  return (
    <div style={{ height: 300 }}>
      <h4>Distribution by {groupField}</h4>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData}>
          <XAxis dataKey="name" hide={chartData.length > 15} />
          <YAxis />
          <Tooltip />
          <Bar dataKey="value" fill="#82ca9d" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
