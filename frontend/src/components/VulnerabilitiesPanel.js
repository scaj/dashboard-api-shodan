import React, { useEffect, useState } from 'react';
import { getResultFile } from '../utils';

export default function VulnerabilitiesPanel({ path }) {
  const [vulns, setVulns] = useState(null);

  useEffect(() => {
    if (!path) return;

    getResultFile(path)
      .then((r) => {
        console.log('[DEBUG] JSON loaded from file:', r);

        //función recursiva para encontrar todos los objetos con cve
        const extractVulns = (obj) => {
          let results = [];

          if (Array.isArray(obj)) {
            obj.forEach((item) => {
              results.push(...extractVulns(item));
            });
          } else if (obj && typeof obj === 'object') {
            if (obj.cve) {
              results.push(obj);
            }           
            Object.values(obj).forEach((val) => {
              results.push(...extractVulns(val));
            });
          }

          return results;
        };

        const normalized = extractVulns(r);
        setVulns(normalized);
      })
      .catch((err) => {
        console.error('[ERROR] Failed to load file:', err);
        setVulns([]);
      });
  }, [path]);

  if (!path) return <div>Select a JSON to analyze vulnerabilities</div>;
  if (!vulns) return <div>Loading...</div>;

  return (
    <div
      style={{
        border: '1px solid #ccc',
        padding: '0.5rem',
        borderRadius: 6,
        backgroundColor: '#f9f9f9',
        minHeight: '60px',
        maxHeight: vulns.length === 0 ? '60px' : '250px',
        overflowY: 'auto',
        overflowX: 'hidden',
        wordBreak: 'break-word',
        fontSize: '0.75rem',
      }}
    >
      <h4 style={{ margin: '0 0 8px 0', textDecoration: 'underline' }}>
        Vulnerabilities ({vulns.length})
      </h4>

      {vulns.map((item, index) => (
        <div key={index} style={{ marginBottom: '0.5rem' }}>
          <div><strong>IP:</strong> {item.ip || '-'}</div>
          <div><strong>CVE:</strong> {item.cve || '-'}</div>
          <div><strong>CVSS:</strong> {item.cvss ?? '-'}</div>
          <div><strong>Port:</strong> {item.port ?? '-'}</div>
          <div><strong>Product:</strong> {item.product || '-'}</div>
          <div><strong>Version:</strong> {item.version || '-'}</div>
          <div><strong>OWASP Category:</strong> {item.owasp_category || '-'}</div>
        </div>
      ))}
    </div>
  );
}
