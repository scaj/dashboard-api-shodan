import React from 'react';

function download(filename,text){ 
	const el=document.createElement('a'); 
	el.setAttribute('href','data:application/json;charset=utf-8,'+encodeURIComponent(text)); 
	el.setAttribute('download',filename); 
	document.body.appendChild(el); el.click(); 
	document.body.removeChild(el); 
}

export default function ReportExport({data,name}){ 
	if(!data) return null; 
	return (
		<div style={{marginTop:8}}>
		<button onClick={()=>download((name||'report')+'.json',JSON.stringify(data,null,2))}>Download JSON</button></div>
	)}
