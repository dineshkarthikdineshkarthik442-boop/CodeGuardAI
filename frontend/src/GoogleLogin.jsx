import React,{useEffect,useRef,useState} from 'react';
import {apiFetch as fetch} from './api';
const API=import.meta.env.VITE_API_URL??(import.meta.env.PROD?'':'http://127.0.0.1:8000');
let library;
function loadGoogle(){
 if(window.google?.accounts?.id)return Promise.resolve();
 if(!library)library=new Promise((resolve,reject)=>{
  const script=document.createElement('script');script.src='https://accounts.google.com/gsi/client';script.async=true;
  script.onload=resolve;script.onerror=()=>{script.remove();library=null;reject(Error('Google sign-in could not load. Check your connection and retry.'))};
  document.head.appendChild(script);
 });return library;
}
export default function GoogleLogin({onLogin,linkPassword}){
 const target=useRef(null),password=useRef(linkPassword),callback=useRef(onLogin);
 password.current=linkPassword;callback.current=onLogin;
 const [message,setMessage]=useState('Loading Google sign-in…');
 const [error,setError]=useState(false),[attempt,setAttempt]=useState(0),[busy,setBusy]=useState(false);
 useEffect(()=>{
  let active=true,inFlight=false,observer,timer;
  async function setup(){try{
   setError(false);setMessage('Loading Google sign-in…');await loadGoogle();if(!active)return;
   const r=await fetch(API+'/api/v14/auth/google/config');const c=await r.json();if(!active)return;
   if(!r.ok)throw Error(c.detail||'Google sign-in is unavailable.');
   if(!c.enabled){setMessage(c.message);return}
   window.google.accounts.id.initialize({client_id:c.client_id,nonce:c.nonce,auto_select:false,ux_mode:'popup',callback:async response=>{
    if(!active||inFlight)return;inFlight=true;setBusy(true);setError(false);setMessage('Signing in securely…');
    try{
     const r=await fetch(API+'/api/v14/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:response.credential,link_password:password.current})});
     const d=await r.json();if(!r.ok||!d.success)throw Error(d.detail||d.error||'Google sign-in failed.');
     if(active)await callback.current(d);
    }catch(e){if(active){setError(true);setMessage(e.message)}}
    finally{inFlight=false;if(active)setBusy(false)}
   }});
   let lastWidth=0;
   const render=()=>{if(!active||!target.current)return;const width=Math.min(400,Math.floor(target.current.clientWidth));if(width===lastWidth||width<1)return;lastWidth=width;target.current.replaceChildren();window.google.accounts.id.renderButton(target.current,{type:'standard',theme:'outline',size:'large',text:'continue_with',shape:'pill',logo_alignment:'left',width})};
   render();observer=new ResizeObserver(render);observer.observe(target.current);
   setMessage('');
   timer=setTimeout(()=>{if(active&&!inFlight){setError(true);setMessage('Google sign-in timed out. Refresh the Google button below.')}},600000);
  }catch(e){if(active){setError(true);setMessage(e.message)}}}
  setup();return()=>{active=false;observer?.disconnect();clearTimeout(timer)};
 },[attempt]);
 return <div className="google-login"><div className="auth-divider"><span>or</span></div><div className="google-button-wrap" aria-busy={busy} style={busy?{pointerEvents:'none',opacity:.65}:undefined}><div ref={target} className="google-button-target"/></div>{message&&<p className={error?'google-error':'google-status'} role={error?'alert':'status'}>{message}</p>}{error&&<button type="button" className="google-retry" disabled={busy} onClick={()=>setAttempt(x=>x+1)}>Refresh Google sign-in</button>}</div>
}
