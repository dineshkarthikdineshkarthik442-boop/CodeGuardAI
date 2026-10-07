export function apiFetch(url,options={}){
 return globalThis.fetch(url,{...options,credentials:'include',cache:'no-store'});
}
// A distinct URL also avoids an anonymous response cached before sign-in.
let sessionCheck=0;
export async function verifyLoginSession(api){
 let lastError;
 for(let attempt=0;attempt<3;attempt++){
  if(attempt)await new Promise(resolve=>setTimeout(resolve,attempt===1?150:400));
  try{
   const r=await apiFetch(`${api}/api/v9/me?check=${Date.now()}-${++sessionCheck}`);
   const d=await r.json();
   if(r.ok&&d.success&&d.user)return d.user;
   lastError=new Error(`Could not confirm your session (HTTP ${r.status}). ${d.detail||'Please try again.'}`);
   if(r.status!==401&&r.status<500)break;
  }catch{lastError=new Error('Could not reach CodeGuard to confirm your session. Please try again.');}
 }
 throw lastError;
}
