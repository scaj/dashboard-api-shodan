import React from "react";

export default function TableView({ data }) {
  if (!data || !Array.isArray(data) || data.length === 0) {
    return <p style={{ textAlign: "center" }}>No data to display.</p>;
  }

  const IGNORED_FIELDS = ["favicon", "html", "data_preview", "raw_html"];

 
  const criticidad = (cvss) => {
    if (cvss == null) return "Desconocido";
    if (cvss >= 9) return "Crítico";
    if (cvss >= 7) return "Alto";
    if (cvss >= 4) return "Medio";
    return "Bajo";
  };

  
  const colorCriticidad = (level) => {
    switch (level) {
      case "Crítico":
        return "#ffcccc";
      case "Alto":
        return "#ffd9b3";
      case "Medio":
        return "#fff2b3";
      case "Bajo":
        return "#d6f5d6";
      default:
        return "#e6e6e6";
    }
  };

  const flatten = (obj, prefix = "") => {
	  let out = {};

	  const isEmpty = (value) =>
		value === null ||
		value === undefined ||
		value === "" ||
		(Array.isArray(value) && value.length === 0) ||
		(typeof value === "object" && Object.keys(value).length === 0);

	  const shouldExclude = (keyPath) =>
		keyPath === "banners" ||
		keyPath.endsWith(".data") && keyPath.includes("banners") ||
		keyPath.startsWith("ssl.cert.extensions");

	  for (const key in obj) {
		if (!obj.hasOwnProperty(key)) continue;
		if (IGNORED_FIELDS.includes(key)) continue;

		const newKey = prefix ? `${prefix}.${key}` : key;
		const value = obj[key];

		
		if (shouldExclude(newKey)) continue;
		if (isEmpty(value)) continue;

		
		if (Array.isArray(value)) {
		  if (value.length > 0 && typeof value[0] === "object" && "cve" in value[0]) {
			out[newKey] = value.map((v) => {
			  const cvss = v.cvss ?? "N/A";
			  const sev = criticidad(v.cvss);
			  const summary = v.description ?? "";
			  const product = v.product ?? "unknown";
			  const version = v.version ?? "unknown";

			  return {
				text: `${v.cve} (${product} ${version}, CVSS ${cvss}, ${sev}) – ${summary}`,
				criticidad: sev
			  };
			});
		  } else {			
			out[newKey] = value
			  .map((item) =>
				typeof item === "object" ? JSON.stringify(item) : String(item)
			  )
			  .join(", ");
		  }
		}
		
		else if (typeof value === "object") {
		  Object.assign(out, flatten(value, newKey));
		}
		
		else {
		  out[newKey] = value;
		}
	  }

	  return out;
	};



  const flatData = data.map((item) => flatten(item));
  const keys = Array.from(new Set(flatData.flatMap(Object.keys)));

  return (
    <div>
      <h4>Tabla de datos</h4>
      <div style={{ overflowX: "auto", maxHeight: 400 }}>
        <table
          border="1"
          cellPadding="4"
          cellSpacing="0"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead>
            <tr>
              {keys.map((k) => (
                <th
                  key={k}
                  style={{
                    background: "#f0f0f0",
                    minWidth: k.toLowerCase().includes("vuln") ? "400px" : "auto",
                  }}
                >
                  {k}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flatData.map((item, i) => (
              <tr key={i}>
                {keys.map((k) => (
                  <td
                    key={k}
                    style={{
                      whiteSpace: "pre-wrap",
                      verticalAlign: "top",
                      minWidth: k.toLowerCase().includes("vuln") ? "400px" : "auto",
                    }}
                  >
                    {Array.isArray(item[k]) ? (
					  item[k].map((v, idx) => (
						<div
						  key={idx}
						  style={{
							marginBottom: "8px",
							borderBottom: "1px solid #ccc",
							paddingBottom: "4px",
							backgroundColor: colorCriticidad(v.criticidad),
						  }}
						>
						  {v.text}
						</div>
					  ))
					) : (
					  (() => {						
						const value = item[k];
						if (k.toLowerCase().includes("cvss") && !isNaN(Number(value))) {
						  const sev = criticidad(Number(value));
						  return (
							<span
							  style={{
								padding: "4px",
								display: "inline-block",
								backgroundColor: colorCriticidad(sev),
							  }}
							>
							  {value} ({sev})
							</span>
						  );
						}

						return String(value ?? "");
					  })()
					)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
