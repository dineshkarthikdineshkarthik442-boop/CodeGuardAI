import hashlib
import hmac
import os
import secrets
import time
from fastapi import APIRouter,HTTPException,Request
from fastapi.responses import JSONResponse
import cloud_store as store
from browser_auth import auth_response
router=APIRouter()

@router.get('/api/v14/auth/google/config')
def config():
    client_id=os.getenv('GOOGLE_CLIENT_ID','').strip()
    if not client_id:return {'enabled':False,'message':'Google sign-in is not configured on this server.'}
    challenge=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32)
    with store.conn() as c:
        c.execute('DELETE FROM google_challenges WHERE expires<?',(time.time(),))
        c.execute('INSERT INTO google_challenges VALUES(?,?,?)',(hashlib.sha256(challenge.encode()).hexdigest(),nonce,time.time()+600))
    response=JSONResponse({'enabled':True,'client_id':client_id,'nonce':nonce})
    response.set_cookie('cg_google_challenge',challenge,httponly=True,secure=os.getenv('CODEGUARD_COOKIE_SECURE','0')=='1',samesite='lax',max_age=600,path='/')
    return response

def verify_token(credential,client_id):
    from google.oauth2 import id_token
    from google.auth.transport.requests import Request as GoogleRequest
    return id_token.verify_oauth2_token(credential,GoogleRequest(),client_id)

@router.post('/api/v14/auth/google')
def google_auth(payload:dict,request:Request):
    client_id=os.getenv('GOOGLE_CLIENT_ID','').strip()
    if not client_id:raise HTTPException(503,'Google sign-in is not configured.')
    challenge=request.cookies.get('cg_google_challenge','')
    challenge_hash=hashlib.sha256(challenge.encode()).hexdigest()
    with store.conn() as c:row=c.execute('SELECT * FROM google_challenges WHERE id=? AND expires>?',(challenge_hash,time.time())).fetchone()
    if not row:raise HTTPException(400,'Google sign-in expired. Refresh the page and try again.')
    credential=payload.get('credential')
    if not isinstance(credential,str) or len(credential)>16000:raise HTTPException(400,'Invalid Google credential.')
    try:claims=verify_token(credential,client_id)
    except Exception:raise HTTPException(401,'Could not verify Google sign-in. Try again.')
    if claims.get('iss') not in ('accounts.google.com','https://accounts.google.com') or claims.get('aud')!=client_id or claims.get('email_verified') is not True or not isinstance(claims.get('sub'),str) or not claims.get('sub') or not isinstance(claims.get('nonce'),str) or not hmac.compare_digest(claims['nonce'],row['nonce']):raise HTTPException(401,'Google identity validation failed.')
    subject=claims['sub'];email=str(claims.get('email','')).lower().strip();name=str(claims.get('name') or 'Developer')[:100]
    if not email or len(email)>254:raise HTTPException(400,'Google email unavailable.')
    with store.conn() as c:
        identity=c.execute('SELECT user_id FROM google_identities WHERE subject=?',(subject,)).fetchone()
        if identity:uid=identity['user_id']
        else:
            user=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
            if user:
                password=payload.get('link_password','')
                if not isinstance(password,str) or len(password)>256 or not password or not store.verify(password,user['password_hash']):raise HTTPException(409,'This email already has a CodeGuard account. Enter its password in the password field, then try Google again to link securely.')
                uid=user['id']
            else:
                if os.getenv('CODEGUARD_ALLOW_SIGNUP','1')!='1':raise HTTPException(403,'New account registration is disabled.')
                uid=c.execute('INSERT INTO users(email,password_hash,name,created_at) VALUES(?,?,?,?)',(email,store.ph(secrets.token_urlsafe(48)),name,store.now())).lastrowid
            c.execute('INSERT INTO google_identities VALUES(?,?)',(subject,uid))
        consumed=c.execute('DELETE FROM google_challenges WHERE id=? AND expires>?',(challenge_hash,time.time())).rowcount
        if consumed!=1:raise HTTPException(400,'Google sign-in has already been used. Refresh and try again.')
    response=auth_response(store.issue_session(uid))
    response.delete_cookie('cg_google_challenge',path='/')
    return response
