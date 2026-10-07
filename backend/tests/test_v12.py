from test_v10 import client,auth,archive
import main
from ci_gate import scan_uploaded_archive

def test_gate_policy(client):
 h=auth(client,'gate@example.com');zipdata=archive({'app.py':'password="test"\n'})
 assert client.post('/api/v12/gate',files={'file':('app.zip',zipdata)}).status_code==401
 r=client.post('/api/v12/gate',headers=h,data={'threshold':80,'max_high':1,'max_critical':0},files={'file':('app.zip',zipdata)})
 assert r.json()['passed'] and r.json()['scan_id'] and '_sources' not in r.json()
 assert scan_uploaded_archive(zipdata,'app.zip')['status']=='FAIL'
 assert client.post('/api/v12/gate',headers=h,data={'threshold':101},files={'file':('app.zip',zipdata)}).status_code==400

def test_pr_saved(client,monkeypatch):
 h=auth(client,'pr@example.com')
 monkeypatch.setattr(main,'review_pull_request',lambda url:{'success':True,'score':100,'files':[],'python_files_changed':1,'findings':[],'introduced_findings':[]})
 assert client.post('/api/v12/pr-review',json={'url':'x'}).status_code==401
 r=client.post('/api/v12/pr-review',headers=h,json={'url':'https://github.com/example/repo/pull/1'})
 assert r.json()['status']=='PASS' and r.json()['scan_id']
 assert client.get('/api/v9/scans',headers=h).json()['scans'][0]['scan_type']=='Pull Request'
