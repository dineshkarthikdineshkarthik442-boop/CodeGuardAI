from test_v10 import client,auth,archive
import cloud_store
import hashlib
from datetime import datetime,timedelta,timezone

def test_legacy_migration(client):
 with cloud_store.conn() as c:
  c.execute('INSERT INTO users(email,password_hash,name,created_at) VALUES(?,?,?,?)',('legacy@example.com',hashlib.sha256(b'oldpass').hexdigest(),'Legacy',cloud_store.now()))
 r=client.post('/api/v9/auth/login',json={'email':'legacy@example.com','password':'oldpass'})
 assert r.json()['success']
 with cloud_store.conn() as c:
  stored=c.execute('SELECT password_hash FROM users WHERE email=?',('legacy@example.com',)).fetchone()[0]
  token=c.execute('SELECT token FROM sessions').fetchone()[0]
 assert stored.startswith('pbkdf2_sha256$') and token!=r.cookies['cg_session']

def test_sessions(client):
 h=auth(client,'session@example.com')
 assert client.get('/api/v9/me',headers=h).status_code==200
 assert client.post('/api/v13/logout',headers=h).json()['success']
 assert client.get('/api/v9/me',headers=h).status_code==401
 h=auth(client,'expire@example.com')
 with cloud_store.conn() as c:c.execute('UPDATE sessions SET created_at=?',((datetime.now(timezone.utc)-timedelta(days=2)).isoformat(),))
 assert client.get('/api/v9/me',headers=h).status_code==401

def test_legacy_routes_and_limits(client):
 for route in ['/api/analyze','/api/v4/github-scan','/api/v5/ai-fix','/api/v7/pr-review','/api/v8/security-gate']:
  assert client.post(route,json={}).status_code==401
 h=auth(client,'bounds@example.com')
 assert client.post('/api/v7/ai-summary',headers=h,content=b'x'*(1024*1024+1)).status_code==413
 assert client.get('/health').headers['x-content-type-options']=='nosniff'

def test_cors_signup_rate(client,monkeypatch):
 r=client.options('/api/v9/me',headers={'Origin':'https://untrusted.example','Access-Control-Request-Method':'GET'})
 assert 'access-control-allow-origin' not in r.headers
 monkeypatch.setenv('CODEGUARD_ALLOW_SIGNUP','0')
 assert client.post('/api/v9/auth/register',json={'email':'x@y.com','password':'longpassword'}).status_code==403
 for _ in range(21):r=client.post('/api/v9/auth/login',json={'email':'bad','password':'bad'})
 assert r.status_code==429
