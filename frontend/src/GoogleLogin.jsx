import React,{useEffect,useRef,useState} from 'react';
import {apiFetch as fetch} from './api';
const API=import.meta.env.VITE_API_URL??(import.meta.env.PROD?'':'http://127.0.0.1:8000');
let library;
function loadGoogle(){if(window.google?.accounts?.id)return Promise.resolve();if(!library)library=new Promise((resolve,reject)=>{const script=document.createElement('script');script.src='https://accounts.google.com/gsi/client';script.async=true;script.onload=resolve;script.onerror=()=>reject(Error('Google sign-in could not load.'));document.head.appendChild(script)});return library}
export default function GoogleLogin({onLogin,linkPassword}){
 const target=useRef(null),password=useRef(linkPassword),callback=useRef(onLogin);password.current=linkPassword;callback.current=onLogin;
 const [message,setMessage]=useState('Loading Google sign-in…');
 useEffect(()=>{let active=true;async function setup(){try{await loadGoogle();if(!active)return;const r=await fetch(API+'/api/v14/auth/google/config');const c=await r.json();if(!active)return;if(!c.enabled){setMessage(c.message);return}window.google.accounts.id.initialize({client_id:c.client_id,nonce:c.nonce,auto_select:false,callback:async response=>{try{setMessage('Signing in…');const r=await fetch(API+'/api/v14/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:response.credential,link_password:password.current})});const d=await r.json();if(!r.ok||!d.success)throw Error(d.detail||d.error||'Google sign-in failed');callback.current(d)}catch(e){setMessage(e.message)}}});window.google.accounts.id.renderButton(target.current,{theme:'outline',size:'large',text:'signin_with',shape:'rectangular',width:300});setMessage('Use Google or your existing CodeGuard password.')}catch(e){if(active)setMessage(e.message)}}setup();return()=>{active=false}},[]);
 return <div className="google-login"><div ref={target}/><p className="muted" role="status">{message}</p></div>
}
