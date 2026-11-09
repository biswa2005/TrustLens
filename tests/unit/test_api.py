from fastapi.testclient import TestClient
from main import app
from links.services import analyser
from links import routes
import asyncio

def test_api_analysis_response_has_eleven_checks(monkeypatch):
    async def unavailable(*args,**kwargs): return 'unavailable',[], 'offline'
    monkeypatch.setattr(analyser,'dns_check',unavailable); monkeypatch.setattr(analyser,'rdap_check',unavailable)
    monkeypatch.setattr(analyser,'safe_browsing',unavailable); monkeypatch.setattr(analyser,'virustotal',unavailable)
    monkeypatch.setattr(analyser,'urlhaus_run',unavailable)
    monkeypatch.setattr(routes,'save_report',lambda report: asyncio.sleep(0,result='00000000-0000-4000-8000-000000000001'))
    with TestClient(app) as client:
        response=client.post('/api/v1/analyse/url',json={'url':'http://example.com','skip_third_party_reputation':True})
    assert response.status_code==200
    body=response.json()
    assert body['coverage']['planned']==11 and len(body['coverage']['checks'])==11
    assert body['coverage']['checks'][9]['check_id']=='intel_urlhaus'
    assert body['coverage']['checks'][7]['status']=='skipped' and body['coverage']['checks'][8]['status']=='skipped'
    assert body['coverage']['checks'][9]['status']=='unavailable'
    assert body['coverage']['checks'][10]['check_id']=='tls_certificate'
    assert body['coverage']['checks'][10]['status']=='skipped'
    assert body['report_id']=='00000000-0000-4000-8000-000000000001'

def test_api_invalid_input_is_clean_400():
    with TestClient(app) as client:
        response=client.post('/api/v1/analyse/url',json={'url':'javascript:alert(1)'})
    assert response.status_code==400 and response.json()=={'detail':'Invalid URL'}

def test_get_report_validates_id_and_returns_storage_result(monkeypatch):
    monkeypatch.setattr(routes.db,'get_report',lambda report_id: asyncio.sleep(0,result={'report_id':report_id}))
    with TestClient(app) as client:
        assert client.get('/api/v1/reports/nope').status_code==400
        response=client.get('/api/v1/reports/00000000-0000-4000-8000-000000000001')
    assert response.status_code==200 and response.json()['report_id']=='00000000-0000-4000-8000-000000000001'

def test_healthz_is_unhealthy_without_postgres(monkeypatch):
    monkeypatch.setenv('DATABASE_URL','postgresql://invalid')
    monkeypatch.setattr(routes.db,'healthy',lambda: asyncio.sleep(0,result=False))
    with TestClient(app) as client:
        response=client.get('/healthz')
    assert response.status_code==503
