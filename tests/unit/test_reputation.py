import asyncio, json, httpx
from links.services.checks import reputation
from links.services import db

REAL_ASYNC_CLIENT=httpx.AsyncClient
def mock_client(monkeypatch, handler):
    def factory(*args,**kwargs): return REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler),*args,**kwargs)
    monkeypatch.setattr(reputation.httpx,'AsyncClient',factory)

def test_safe_browsing_cache_and_match(monkeypatch):
    monkeypatch.setenv('SAFE_BROWSING_API_KEY','key')
    cache={}; requests=[]
    async def get(source,query): return cache.get((source,query))
    async def put(source,query,response,ttl): cache[(source,query)]=response
    monkeypatch.setattr(db,'cache_get',get)
    monkeypatch.setattr(db,'cache_put',put)
    def handler(req): requests.append(req); return httpx.Response(200,json={'matches':[{'threatType':'MALWARE','threat':{'url':'https://bad.test'}}]})
    mock_client(monkeypatch,handler)
    status,findings,_=asyncio.run(reputation.safe_browsing(['https://bad.test']))
    again=asyncio.run(reputation.safe_browsing(['https://bad.test']))
    assert status=='ok' and len(findings)==1 and findings[0].evidence['match_level']=='exact_url'
    assert again[0]=='ok' and len(again[1])==1 and len(requests)==1

def test_virustotal_excludes_gsb_before_threshold(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','key'); monkeypatch.setenv('VT_CONFIRM_THRESHOLD','5')
    monkeypatch.setattr(db,'cache_get',lambda *a: asyncio.sleep(0,result=None))
    monkeypatch.setattr(db,'cache_put',lambda *a: asyncio.sleep(0))
    monkeypatch.setattr(db,'increment_usage',lambda *a: asyncio.sleep(0,result=1))
    engines={f'e{i}':{'category':'malicious'} for i in range(5)}; engines['Google Safe Browsing']={'category':'malicious'}
    def handler(req): return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':6},'last_analysis_results':engines}}})
    mock_client(monkeypatch,handler)
    status,findings,_=asyncio.run(reputation.virustotal(['https://bad.test']))
    assert status=='ok' and findings[0].evidence['malicious_excl_gsb']==5 and findings[0].severity=='strong'

def test_reputation_missing_key_is_unavailable(monkeypatch):
    monkeypatch.delenv('SAFE_BROWSING_API_KEY',raising=False)
    assert asyncio.run(reputation.safe_browsing(['https://example.com']))[0]=='unavailable'

def test_virustotal_404_is_clean_and_429_is_unavailable(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','key')
    monkeypatch.setattr(db,'cache_get',lambda *a: asyncio.sleep(0,result=None))
    monkeypatch.setattr(db,'cache_put',lambda *a: asyncio.sleep(0))
    monkeypatch.setattr(db,'increment_usage',lambda *a: asyncio.sleep(0,result=1))
    mock_client(monkeypatch,lambda req:httpx.Response(404))
    assert asyncio.run(reputation.virustotal(['https://unknown.test']))[:2]==('ok',[])
    mock_client(monkeypatch,lambda req:httpx.Response(429))
    status,findings,reason=asyncio.run(reputation.virustotal(['https://unknown.test']))
    assert status=='unavailable' and findings==[] and 'rate limit' in reason.lower()

def test_virustotal_thresholds_and_registered_domain_cap(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','key')
    monkeypatch.setenv('VT_CONFIRM_THRESHOLD','5')
    monkeypatch.setattr(db,'cache_get',lambda *a: asyncio.sleep(0,result=None))
    monkeypatch.setattr(db,'cache_put',lambda *a: asyncio.sleep(0))
    monkeypatch.setattr(db,'increment_usage',lambda *a: asyncio.sleep(0,result=1))
    reputation._vt_times.clear()
    async def query(url,domains=(),count=0):
        engines={f'e{i}':{'category':'malicious'} for i in range(count)}
        mock_client(monkeypatch,lambda req:httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':count},'last_analysis_results':engines}}}))
        return await reputation.virustotal([url],domains)
    status,none,_=asyncio.run(query('https://zero.test',count=0))
    assert status=='ok' and none==[]
    reputation._vt_times.clear()
    status,three,_=asyncio.run(query('https://three.test',count=3))
    assert status=='ok' and three[0].severity=='moderate'
    reputation._vt_times.clear()
    status,eight,_=asyncio.run(query('https://eight.test',count=8))
    assert status=='ok' and eight[0].severity=='strong'
    reputation._vt_times.clear()
    status,domain,_=asyncio.run(query('https://origin.test',('example.test',),count=8))
    registered=next(item for item in domain if item.evidence['match_level']=='registered_domain')
    assert status=='ok' and registered.severity=='moderate'

def test_safe_browsing_clean_cache_and_rate_limit(monkeypatch):
    monkeypatch.setenv('SAFE_BROWSING_API_KEY','key')
    monkeypatch.setenv('SB_REQUESTS_PER_MINUTE','1')
    reputation._sb_times.clear()
    cache={}; requests=[]
    async def get(source,query): return cache.get((source,query))
    async def put(source,query,response,ttl): cache[(source,query)]=response
    monkeypatch.setattr(db,'cache_get',get); monkeypatch.setattr(db,'cache_put',put)
    mock_client(monkeypatch,lambda req:(requests.append(req) or httpx.Response(200,json={})))
    status,findings,_=asyncio.run(reputation.safe_browsing(['https://clean.test']))
    assert status=='ok' and findings==[]
    status,findings,_=asyncio.run(reputation.safe_browsing(['https://clean.test']))
    assert status=='ok' and findings==[] and len(requests)==1
    status,findings,reason=asyncio.run(reputation.safe_browsing(['https://other.test']))
    assert status=='unavailable' and findings==[] and 'rate limit' in reason.lower()
