from test_v10 import client,auth
import google_login
import cloud_store
import time

def setup_google(client,monkeypatch,email='google@example.com',subject='google-sub'):
 monkeypatch.setenv('GOOGLE_CLIENT_ID','test-client')
 c=client.get('/api/v14/auth/google/config').json()
 claims={'aud':'test-client','iss':'https://accounts.google.com','email_verified':True,'email':email,'sub':subject,'nonce':c['nonce'],'exp':time.time()+3600}
 monkeypatch.setattr(google_login,'verify_token',lambda *args:claims)
 return claims

def test_google_signup_cookie_nonce(client,monkeypatch):
 setup_google(client,monkeypatch)
 r=client.post('/api/v14/auth/google',json={'credential':'mock'})
 assert r.json()['success'] and r.json()['token']=='cookie-session'
 assert 'HttpOnly' in r.headers['set-cookie']
 assert client.get('/api/v9/me').json()['user']['email']=='google@example.com'
 assert client.post('/api/v14/auth/google',json={'credential':'mock'}).status_code==400
 assert client.post('/api/v13/logout').json()['success']
 assert client.get('/api/v9/me').status_code==401

def test_google_claims_and_link(client,monkeypatch):
 auth(client,'existing@example.com')
 claims=setup_google(client,monkeypatch,email='existing@example.com')
 claims['nonce']='wrong'
 assert client.post('/api/v14/auth/google',json={'credential':'mock'}).status_code==401
 c=client.get('/api/v14/auth/google/config').json();claims['nonce']=c['nonce']
 assert client.post('/api/v14/auth/google',json={'credential':'mock'}).status_code==409
 r=client.post('/api/v14/auth/google',json={'credential':'mock','link_password':'test-password'})
 assert r.json()['success']
 with cloud_store.conn() as db:assert db.execute('SELECT COUNT(*) FROM users WHERE email=?',('existing@example.com',)).fetchone()[0]==1

def test_browser_origin_secure_cookie(client,monkeypatch):
 monkeypatch.setenv('CODEGUARD_COOKIE_SECURE','1')
 r=client.post('/api/v9/auth/register',json={'email':'secure@example.com','password':'test-password'})
 assert 'Secure' in r.headers['set-cookie'] and 'HttpOnly' in r.headers['set-cookie']
 assert client.post('/api/v9/auth/login',headers={'Origin':'https://attacker.example'},json={}).status_code==403
