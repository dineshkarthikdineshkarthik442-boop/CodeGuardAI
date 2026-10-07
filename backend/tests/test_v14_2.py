from test_v10 import client

def test_anonymous_session_is_never_cached(client):
    r=client.get('/api/v9/me')
    assert r.status_code==401
    assert r.headers['cache-control']=='no-store'
    assert 'Cookie' in r.headers['vary']
