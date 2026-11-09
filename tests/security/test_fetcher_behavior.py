from fastapi.testclient import TestClient
import pytest
import fetcher.app as service
from fetcher.guard import Blocked

class FakeSocket:
    def __init__(self): self.sent=b''; self.closed=False
    def settimeout(self,value): self.timeout=value
    def sendall(self,data): self.sent+=data
    def close(self): self.closed=True
class FakeResponse:
    def __init__(self,sock): pass
    def begin(self): pass
    def getheaders(self): return [('Content-Type','text/html; charset=utf-8')]
    status=200
    def read(self,n): return b'x'*(n)

def test_request_uses_validated_ip_and_original_tls_name(monkeypatch):
    made=[]; tls=[]; fake=FakeSocket()
    monkeypatch.setattr(service,'validate_and_resolve',lambda url: (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8'))
    monkeypatch.setattr(service.socket,'create_connection',lambda addr,timeout: (made.append((addr,timeout)) or fake))
    class Context:
        def wrap_socket(self,sock,server_hostname): tls.append(server_hostname); return sock
    monkeypatch.setattr(service.ssl,'create_default_context',lambda:Context())
    monkeypatch.setattr(service.http.client,'HTTPResponse',FakeResponse)
    monkeypatch.setattr(service,'MAX_BODY',16)
    result=service.request_one('https://site.example/')
    assert made[0][0]==('8.8.8.8',443) and tls==['site.example']
    assert result['truncated'] and len(result['body'])==16 and fake.closed

def test_fetcher_records_redirect_to_blocked_private_host(monkeypatch):
    calls=0
    def request(url,deadline=None,resolved=None):
        nonlocal calls; calls+=1
        if calls==1: return {'status':302,'headers':{'location':'http://127.0.0.1/'},'body':'','truncated':False,'ip':'8.8.8.8','elapsed_ms':1}
        raise Blocked('private_ip')
    monkeypatch.setattr(service,'request_one',request)
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client:
        response=client.post('/fetch',json={'url':'https://public.example'})
    data=response.json()
    assert response.status_code==200 and len(data['hops'])==2
    assert data['hops'][1]['blocked_reason']=='private_ip'
    assert 'redirect_to_blocked_destination' in data['errors']

def test_fetcher_retains_html_from_intermediate_redirect(monkeypatch):
    calls=0
    def request(url,deadline=None,resolved=None):
        nonlocal calls; calls+=1
        if calls==1: return {'status':302,'headers':{'location':'https://final.example/'},'body':'<form><input type="password"></form>','truncated':False,'ip':'8.8.8.8','elapsed_ms':1}
        return {'status':200,'headers':{'content-type':'text/html'},'body':'<p>final</p>','truncated':False,'ip':'8.8.4.4','elapsed_ms':1}
    monkeypatch.setattr(service,'request_one',request)
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client: data=client.post('/fetch',json={'url':'https://start.example'}).json()
    assert data['chain_complete'] and len(data['html_by_hop'])==2
    assert 'password' in data['html_by_hop'][0]['html']

@pytest.mark.parametrize(('headers','body','expected'),[
    ({'refresh':'0; url=https://final.example/'},'', 'refresh_header'),
    ({'content-type':'text/html'},'<meta http-equiv="refresh" content="0; url=https://final.example/">','meta_refresh'),
    ({'content-type':'text/html'},'<script>location.replace("https://final.example/")</script>','js_literal'),
])
def test_fetcher_follows_static_redirect_forms(monkeypatch,headers,body,expected):
    calls=[]
    def request(url,deadline=None,resolved=None):
        calls.append(url)
        if len(calls)==1: return {'status':200,'headers':headers,'body':body,'truncated':False,'ip':'8.8.8.8','elapsed_ms':1}
        return {'status':200,'headers':{'content-type':'text/html'},'body':'ok','truncated':False,'ip':'8.8.4.4','elapsed_ms':1}
    monkeypatch.setattr(service,'request_one',request)
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client: data=client.post('/fetch',json={'url':'https://start.example'}).json()
    assert data['chain_complete'] and data['hops'][0]['via']==expected
    assert calls[1]=='https://final.example/'

def test_fetcher_records_certificate_failure_without_disabling_tls(monkeypatch):
    import ssl
    monkeypatch.setattr(service,'request_one',lambda *a,**k: (_ for _ in ()).throw(ssl.SSLError('certificate verify failed')))
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client: data=client.post('/fetch',json={'url':'https://start.example'}).json()
    assert not data['chain_complete'] and data['hops'][0]['blocked_reason']=='tls_error:SSLError'

def test_fetcher_rejects_oversized_location_without_echoing_it(monkeypatch):
    monkeypatch.setattr(service,'request_one',lambda *a,**k:{'status':302,'headers':{'location':'https://'+('a'*2100)},'body':'','truncated':False,'ip':'8.8.8.8','elapsed_ms':1})
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client: data=client.post('/fetch',json={'url':'https://start.example'}).json()
    assert not data['chain_complete'] and data['hops'][0]['location'] is None
    assert data['hops'][0]['location_too_long'] and 'location_too_long' in data['errors']

def test_fetcher_stops_at_hop_limit(monkeypatch):
    monkeypatch.setattr(service,'MAX_HOPS',2)
    monkeypatch.setattr(service,'request_one',lambda url,deadline=None,resolved=None:{'status':302,'headers':{'location':'https://next.example/'+str(len(url))},'body':'','truncated':False,'ip':'8.8.8.8','elapsed_ms':1})
    async def resolve(url,timeout=3): return (__import__('urllib.parse').parse.urlsplit(url),443,'8.8.8.8')
    monkeypatch.setattr(service,'validate_and_resolve_async',resolve)
    with TestClient(service.app) as client: data=client.post('/fetch',json={'url':'https://start.example'}).json()
    assert not data['chain_complete'] and len(data['hops'])==2 and 'excessive_hops' in data['errors']


