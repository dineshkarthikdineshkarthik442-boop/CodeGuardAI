import os
import time
from http.cookies import SimpleCookie
from collections import defaultdict,deque
from starlette.responses import JSONResponse
from cloud_store import user_from_token

class RequestSecurity:
    def __init__(self,app):
        self.app=app
        self.attempts=defaultdict(deque)
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        path=scope['path'];headers=dict(scope['headers'])
        if scope['method']=='OPTIONS':return await self.app(scope,receive,send)
        async def reject(status,message):await JSONResponse({'detail':message},status_code=status,headers={'Cache-Control':'no-store','Pragma':'no-cache','Vary':'Cookie, Authorization'})(scope,receive,send)
        public=('/api/v9/auth/login','/api/v9/auth/register','/api/v14/auth/google/config','/api/v14/auth/google')
        allowed={x.strip() for x in os.getenv('CODEGUARD_ALLOWED_ORIGINS','http://localhost:5173,http://127.0.0.1:5173').split(',')}
        origin=headers.get(b'origin',b'').decode('latin-1')
        if scope['method'] in ('POST','PUT','PATCH','DELETE') and origin and origin not in allowed:return await reject(403,'Request origin is not allowed.')
        cookie=SimpleCookie()
        try:cookie.load(headers.get(b'cookie',b'').decode('latin-1'))
        except Exception:return await reject(400,'Invalid cookie.')
        auth=headers.get(b'authorization',b'').decode('latin-1')
        browser_cookie=cookie.get('cg_session')
        if browser_cookie and (not auth or auth=='Bearer cookie-session'):
            if scope['method'] in ('POST','PUT','PATCH','DELETE') and origin not in allowed:return await reject(403,'Browser request requires a trusted origin.')
            auth='Bearer '+browser_cookie.value
            scope=dict(scope);scope['headers']=[(k,v) for k,v in scope['headers'] if k.lower()!=b'authorization']+[(b'authorization',auth.encode())]
        if path.startswith('/api/') and path not in public:
            if not auth.startswith('Bearer ') or not user_from_token(auth[7:]):return await reject(401,'Authentication required. Sign in again if your session expired.')
        if path in public and (scope['method']=='POST' or path.endswith('/config')):
            ip=scope.get('client',('unknown',0))[0];clock=time.monotonic()
            if len(self.attempts)>10000:
                self.attempts={k:v for k,v in self.attempts.items() if v and clock-v[-1]<60}
                self.attempts=defaultdict(deque,self.attempts)
            q=self.attempts[ip]
            while q and clock-q[0]>60:q.popleft()
            if len(q)>=20:return await reject(429,'Too many authentication attempts. Try again in one minute.')
            q.append(clock)
        limit=55*1024*1024 if ('zip' in path or path.endswith('/gate') or path.endswith('/security-gate')) else 1024*1024
        body=bytearray()
        if scope['method'] in ('POST','PUT','PATCH'):
            while True:
                message=await receive()
                if message['type']=='http.disconnect':return
                body.extend(message.get('body',b''))
                if len(body)>limit:return await reject(413,'Request exceeds the size limit.')
                if not message.get('more_body'):break
        supplied=False
        async def replay():
            nonlocal supplied
            if not supplied:
                supplied=True
                return {'type':'http.request','body':bytes(body),'more_body':False}
            return await receive()
        async def secure_send(message):
            if message['type']=='http.response.start':
                message['headers']=list(message.get('headers',[]))+[(b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),(b'referrer-policy',b'strict-origin-when-cross-origin'),(b'cache-control',b'no-store')]
                message['headers'].append((b'cross-origin-opener-policy',b'same-origin-allow-popups'))
                if os.getenv('CODEGUARD_PRODUCTION','0')=='1':
                    message['headers'].extend([(b'strict-transport-security',b'max-age=31536000'),(b'content-security-policy',b"default-src 'self'; script-src 'self' https://accounts.google.com/gsi/client; style-src 'self' 'unsafe-inline' https://accounts.google.com; frame-src https://accounts.google.com; connect-src 'self' https://accounts.google.com; img-src 'self' data: https://*.googleusercontent.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")])
            await send(message)
        await self.app(scope,replay,secure_send)
