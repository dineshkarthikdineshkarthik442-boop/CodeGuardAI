export function apiFetch(url,options={}){return globalThis.fetch(url,{...options,credentials:'include'})}
