import io
import zipfile
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
import cloud_store
import main
from ci_gate import scan_uploaded_archive

def archive(files):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as z:
        for name,source in files.items(): z.writestr(name,source)
    return output.getvalue()

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(cloud_store,'DB_PATH',tmp_path/'test.db')
    cloud_store.init_db()
    monkeypatch.setattr(main.app,"middleware_stack",None)
    return TestClient(main.app,headers={'Origin':'http://localhost:5173'})

def auth(client,email):
    r=client.post('/api/v9/auth/register',json={'email':email,'password':'test-password','name':'Test'})
    assert r.json()['success']
    token=r.cookies['cg_session']
    client.cookies.clear()
    return {'Authorization':'Bearer '+token}

def test_python_ast_zip_rules():
    r=scan_uploaded_archive(archive({'unsafe.py':'import subprocess\nsubprocess.run("whoami", shell=True)\n'}),'test.zip')
    assert any(f['rule_id']=='CG-CMD-001' and f['line']==2 and f['file']=='unsafe.py' for f in r['findings'])
    assert r['status']=='FAIL'

def test_syntax_and_empty_archives():
    r=scan_uploaded_archive(archive({'broken.py':'def !'}),'test.zip')
    assert r['syntax_errors'] and not r['passed']
    with pytest.raises(HTTPException): scan_uploaded_archive(archive({'readme.txt':'hello'}),'test.zip')

def test_archive_expansion_limit():
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('large.py',b' '* (101*1024*1024))
    with pytest.raises(HTTPException) as error:scan_uploaded_archive(output.getvalue(),'large.zip')
    assert error.value.status_code==413

def test_scan_persistence_and_isolation(client):
    first=auth(client,'first@example.com');second=auth(client,'second@example.com')
    r=client.post('/api/v9/scan/zip',headers=first,files={'file':('test.zip',archive({'app.py':'eval(input())'}),'application/zip')})
    assert r.status_code==200 and r.json()['findings']
    sid=r.json()['scan_id']
    saved=client.get(f'/api/v9/scans/{sid}',headers=first)
    assert saved.json()['scan']['result']['findings']==r.json()['findings']
    assert client.get(f'/api/v9/scans/{sid}',headers=second).status_code==404
    assert client.get(f'/api/v9/scans/{sid}').status_code==401
    assert len(client.get('/api/v9/scans',headers=first).json()['scans'])==1

def test_github_route_with_local_fixture(client,monkeypatch):
    headers=auth(client,'repo@example.com')
    monkeypatch.setattr(main,'scan_repository',lambda url:{'success':True,'score':70,'findings':[{'file':'app.py','line':1,'severity':'CRITICAL','message':'Unsafe evaluation'}]})
    r=client.post('/api/v9/scan/github',headers=headers,json={'url':'https://github.com/example/project'})
    assert r.json()['status']=='REVIEW' and r.json()['scan_id']
