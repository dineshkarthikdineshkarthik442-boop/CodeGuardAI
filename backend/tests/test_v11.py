from test_v10 import client,auth,archive
from fix_validation import validate_fix
import main

def test_validation():
 r=validate_fix('eval(input())\n','print(input())\n',{'rule_id':'CG-CODE-001'})
 assert r['syntax_valid'] and r['target_rule_cleared'] and r['patch']
 assert not validate_fix('eval(input())','def !',{'rule_id':'CG-CODE-001'})['syntax_valid']
 assert not validate_fix('eval(input())','eval(input())',{'rule_id':'CG-CODE-001'})['target_rule_cleared']

def test_fix_endpoint(client,monkeypatch):
 headers=auth(client,'fix@example.com')
 scan=client.post('/api/v9/scan/zip',headers=headers,files={'file':('app.zip',archive({'app.py':'eval(input())\n'}),'application/zip')}).json()
 index=next(i for i,f in enumerate(scan['findings']) if f['rule_id']=='CG-CODE-001')
 payload={'scan_id':scan['scan_id'],'finding_index':index,'code':'eval(input())\n','consent':True}
 monkeypatch.setattr(main,'generate_secure_fix',lambda source,finding:{'available':True,'summary':'Use explicit output','fixed_code':'print(input())\n'})
 assert client.post('/api/v11/fix',json=payload).status_code==401
 assert client.post('/api/v11/fix',headers=headers,json={**payload,'consent':False}).status_code==400
 assert client.post('/api/v11/fix',headers=headers,json={**payload,'code':'print(1)'}).json()['original_code']=='eval(input())\n'
 other=auth(client,'other@example.com')
 assert client.post('/api/v11/fix',headers=other,json=payload).status_code==404
 r=client.post('/api/v11/fix',headers=headers,json=payload)
 assert r.json()['validation']['target_rule_cleared']
 monkeypatch.setattr(main,'generate_secure_fix',lambda *args:{'available':False,'summary':'Missing API key'})
 assert client.post('/api/v11/fix',headers=headers,json=payload).json()['error']=='Missing API key'
