
import pytest
from src.app import app

def test_home_page():
    client = app.test_client()
    resp = client.get('/')
    assert resp.status_code == 302
    assert '/evidence' in resp.headers['Location']

def test_health_endpoint():
    client = app.test_client()
    resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'ok'
    assert data['version'] == '1.0.0'