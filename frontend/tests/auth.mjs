import {createServer} from 'vite';
import React from 'react';
import {create,act} from 'react-test-renderer';
import assert from 'node:assert/strict';
const server=await createServer({optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
let widget,options,logoutCalls=0,meCalls=0,mode='ok',signedIn=false,failHistory=false;
const user={id:1,name:'Google User',email:'test@example.com'};
globalThis.window={google:{accounts:{id:{initialize:c=>{widget=c},renderButton:(_t,o)=>{options=o},disableAutoSelect(){}}}}};
globalThis.ResizeObserver=class{observe(){} disconnect(){}};
globalThis.localStorage={setItem(){throw Error('Storage unavailable')},removeItem(){throw Error('Storage unavailable')}};
const response=(status,data)=>({status,ok:status<400,json:async()=>data});
globalThis.fetch=async url=>{
 if(url.endsWith('/config'))return response(200,{enabled:true,client_id:'test',nonce:'nonce'});
 if(url.endsWith('/auth/google')){if(mode==='link')return response(409,{detail:'Enter its password to link securely.'});signedIn=true;return response(200,{success:true,user,token:'cookie-session'})}
 if(url.endsWith('/me')){meCalls++;return signedIn&&mode!=='cookie'?response(200,{success:true,user}):response(401,{detail:'Sign in'})}
 if(url.endsWith('/logout')){logoutCalls++;signedIn=false;return response(200,{success:true})}
 if(url.endsWith('/scans')){if(failHistory)throw Error('network');return response(200,{success:true,scans:[]})}
 throw Error('Unexpected URL '+url);
};
const flush=async()=>{await new Promise(r=>setTimeout(r,0))};
let tree;
const mount=async App=>{await act(async()=>{tree=create(React.createElement(App),{createNodeMock:()=>({clientWidth:320,replaceChildren(){}})});await flush()})};
const text=()=>JSON.stringify(tree.toJSON());
try{
 const {default:App}=await server.ssrLoadModule('/src/App.jsx');
 await mount(App);
 assert.match(text(),/Welcome back/);assert.equal(logoutCalls,0,'An anonymous restore must never call logout');
 assert.equal(options.shape,'pill');assert.equal(options.width,320);assert.equal(options.text,'continue_with');
 await act(async()=>{await widget.callback({credential:'mock'});await flush()});
 assert.match(text(),/Security Dashboard/);assert.equal(logoutCalls,0);
 await act(async()=>tree.unmount());await mount(App);assert.match(text(),/Security Dashboard/,'Refresh restores cookie session');
 const signout=tree.root.findAllByType('button').find(n=>n.children.includes('Sign out'));
 await act(async()=>{await signout.props.onClick();await flush()});assert.match(text(),/Welcome back/);assert.equal(logoutCalls,1);
 mode='link';await act(async()=>{await widget.callback({credential:'mock'});await flush()});assert.match(text(),/Enter its password/);
 mode='cookie';await act(async()=>{await widget.callback({credential:'mock'});await flush()});assert.match(text(),/session could not be saved/);assert.doesNotMatch(text(),/Security Dashboard/);
 mode='ok';failHistory=true;await act(async()=>{await widget.callback({credential:'mock'});await flush()});assert.match(text(),/Security Dashboard/);assert.equal(logoutCalls,1,'Scan failures must not revoke login');
 console.log('Auth interaction checks passed: restore, Google success, reload, explicit logout, account-link error, blocked cookie, history failure, rounded responsive button; localStorage disabled.');
}finally{if(tree)await act(async()=>tree.unmount());await server.close()}
