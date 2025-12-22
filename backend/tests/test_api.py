from fastapi.testclient import TestClient
from app import app
import tempfile, json

client = TestClient(app)

def test_upload_and_list():
    data = {'hello':'world'}
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
        json.dump(data, tf)
        tfpath = tf.name
    with open(tfpath, 'rb') as fh:
        r = client.post('/upload-json', files={'file': ('test.json', fh, 'application/json')})
        assert r.status_code == 200
        j = r.json()
        assert 'path' in j
        r2 = client.get('/results')
        assert r2.status_code == 200
        assert any('test' in item['name'] for item in r2.json())
