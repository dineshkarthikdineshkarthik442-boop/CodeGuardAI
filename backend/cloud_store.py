import hashlib, secrets, sqlite3, json, os, hmac
from datetime import timedelta
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(os.getenv('CODEGUARD_DB_PATH', str(Path(__file__).with_name('codeguard.db'))))
SESSION_HOURS = 24

def conn():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=15)
    c.execute("PRAGMA foreign_keys=ON")
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=conn(); c.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, scan_type TEXT NOT NULL, target TEXT NOT NULL, score INTEGER, status TEXT, result_json TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS google_identities(subject TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS google_challenges(id TEXT PRIMARY KEY,nonce TEXT NOT NULL,expires REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS security_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    ''')
    if not c.execute("SELECT 1 FROM security_metadata WHERE key='v13_sessions'").fetchone():
        c.execute('DELETE FROM sessions')
        c.execute("INSERT INTO security_metadata VALUES('v13_sessions','hashed')")
    c.commit(); c.close()

def now(): return datetime.now(timezone.utc).isoformat()
def ph(password):
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000).hex()
    return 'pbkdf2_sha256$600000$'+salt+'$'+digest

def verify(password,stored):
    if stored.startswith('pbkdf2_sha256$'):
        try:
            _,rounds,salt,digest=stored.split('$')
            return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(rounds)).hex(),digest)
        except (ValueError,TypeError): return False
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(),stored)

def register(email,password,name):
    if not 10<=len(password)<=256: return None,'Password must contain 10–256 characters.'
    if len(email)>254 or len(name)>100: return None,'Email or name is too long.'
    with conn() as c:
        try:
            c.execute('INSERT INTO users(email,password_hash,name,created_at) VALUES(?,?,?,?)',(email.lower().strip(),ph(password),name.strip() or 'Developer',now()))
            c.commit()
        except sqlite3.IntegrityError: return None,'An account with that email already exists.'
    return login(email,password)

def login(email,password):
    if len(password)>256: return None,'Invalid email or password.'
    c=conn(); u=c.execute('SELECT * FROM users WHERE email=?',(email.lower().strip(),)).fetchone()
    if not u or not verify(password,u['password_hash']): c.close();return None,'Invalid email or password.'
    if not u['password_hash'].startswith('pbkdf2_sha256$'):
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(ph(password),u['id']))
    token=secrets.token_urlsafe(32)
    token_hash=hashlib.sha256(token.encode()).hexdigest()
    c.execute('DELETE FROM sessions WHERE created_at<?',((datetime.now(timezone.utc)-timedelta(hours=SESSION_HOURS)).isoformat(),))
    c.execute('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)',(token_hash,u['id'],now()));c.commit();c.close()
    return {'token':token,'user':{'id':u['id'],'email':u['email'],'name':u['name']}},None

def user_from_token(token):
    if not token or len(token)>200:return None
    token_hash=hashlib.sha256(token.encode()).hexdigest()
    cutoff=(datetime.now(timezone.utc)-timedelta(hours=SESSION_HOURS)).isoformat()
    c=conn();row=c.execute('SELECT u.id,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at>?',(token_hash,cutoff)).fetchone();c.close()
    return dict(row) if row else None

def revoke_token(token):
    with conn() as c:c.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(token.encode()).hexdigest(),))

def save_scan(user_id,scan_type,target,result):
    c=conn(); cur=c.execute('INSERT INTO scans(user_id,scan_type,target,score,status,result_json,created_at) VALUES(?,?,?,?,?,?,?)',(user_id,scan_type,target,int(result.get('score',result.get('security_score',0)) or 0),str(result.get('status','COMPLETED')),json.dumps(result),now())); c.commit(); sid=cur.lastrowid; c.close(); return sid

def list_scans(user_id,limit=50):
    c=conn(); rows=c.execute('SELECT id,scan_type,target,score,status,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?',(user_id,limit)).fetchall(); c.close(); return [dict(r) for r in rows]

def get_scan(user_id,sid):
    c=conn(); r=c.execute('SELECT * FROM scans WHERE id=? AND user_id=?',(sid,user_id)).fetchone(); c.close()
    if not r:return None
    d=dict(r); d['result']=json.loads(d.pop('result_json')); return d


def issue_session(uid):
    token=secrets.token_urlsafe(32)
    with conn() as c:
        row=c.execute('SELECT id,email,name FROM users WHERE id=?',(uid,)).fetchone()
        c.execute('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),uid,now()))
    return {'token':token,'user':dict(row)}
