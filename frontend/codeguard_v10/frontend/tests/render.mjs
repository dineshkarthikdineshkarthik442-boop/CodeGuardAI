import {createServer} from 'vite';
import React from 'react';
import {renderToString} from 'react-dom/server';
import assert from 'node:assert/strict';
globalThis.localStorage={getItem:()=>null};
const server=await createServer({server:{middlewareMode:true},appType:'custom'});
try {
 const {default:App,Dashboard,History,NewScan}=await server.ssrLoadModule('/src/App.jsx');
 const {default:Report}=await server.ssrLoadModule('/src/Report.jsx');
 const render=(component,props={})=>renderToString(React.createElement(component,props));
 assert.match(render(App),/Welcome back/);
 assert.match(render(Dashboard,{scans:[],onHistory(){},onScan(){}}),/Security|security/);
 assert.match(render(History,{scans:[],token:''}),/Your scan history is empty/);
 assert.match(render(History,{scans:[{id:1,target:'app.zip',score:55,status:'FAIL',created_at:'2026-10-06'}],token:''}),/View report: app.zip/);
 assert.match(render(NewScan,{token:'',onDone(){}}),/RUN SECURITY SCAN/);
 const html=render(Report,{result:{findings:[{file:'app.py',line:2,severity:'HIGH',message:'Unsafe input',recommendation:'Validate',rule_id:'test'}]}});
 assert.match(html,/Unsafe input/);assert.match(html,/Download JSON/);
 console.log('6 frontend render checks passed (login, dashboard, empty history, saved history, new scan, report).');
} finally {await server.close()}
