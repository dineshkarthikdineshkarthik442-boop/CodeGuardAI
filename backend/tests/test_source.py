from test_v10 import client,auth,archive
import main

def test_automatic_source(client,monkeypatch):
 headers=auth(client,'auto@example.com');other=auth(client,'otherauto@example.com')
 scan=client.post('/api/v9/scan/zip',headers=headers,files={'file':('app.zip',archive({'nested/app.py':'eval(input())\n'}),'application/zip')}).json()
 assert '_sources' not in scan
 index=next(i for i,f in enumerate(scan['findings']) if f['rule_id']=='CG-CODE-001')
 sid=scan['scan_id'];url=f'/api/v11/scans/{sid}/source/{index}'
 assert client.get(url).status_code==401
 assert client.get(url,headers=other).status_code==404
 assert client.get(url,headers=headers).json()['code']=='eval(input())\n'
 assert '_sources' not in client.get(f'/api/v9/scans/{sid}',headers=headers).json()['scan']['result']
 def fix(source,finding):
  assert source=='eval(input())\n'
  return {'available':True,'fixed_code':'print(input())\n','summary':'Preview'}
 monkeypatch.setattr(main,'generate_secure_fix',fix)
 r=client.post('/api/v11/fix',headers=headers,json={'scan_id':sid,'finding_index':index,'consent':True})
 assert r.json()['validation']['target_rule_cleared']
