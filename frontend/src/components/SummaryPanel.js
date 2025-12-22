import React from 'react';
export default function SummaryPanel({data}){ if(!data) return null; return (<div style={{border:'1px solid #ccc',padding:8,marginBottom:8}}>
    <h3>Resumen</h3>
    {data.query && <div>Query: {data.query}</div>}
    {data.collected!==undefined && <div>Hosts: {data.collected}</div>}
    {data.data_count!==undefined && <div>Banners: {data.data_count}</div>}
    {data.events_collected!==undefined && <div>Events: {data.events_collected}</div>}
    {data.ip && <div>IP: {data.ip}</div>}
</div>)}
