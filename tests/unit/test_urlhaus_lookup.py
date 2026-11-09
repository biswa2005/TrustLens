from pathlib import Path
import sys, fakeredis, asyncio
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from scripts.import_urlhaus import import_file
from links.services import redis_store
from links.services.checks import urlhaus
from links.services import analyser
from links.services.registry import Context
from links.services.checks.normalise import normalize

def write_feed(path,entries):
    path.write_text('id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'+''.join(f'{i},2026-01-01,{url},{status},,malware,tag,https://urlhaus.abuse.ch/host/{i}/,test\n' for i,url,status in entries))

def test_redis_check_distinguishes_active_and_historical(monkeypatch,tmp_path):
    temp=tmp_path
    feed=temp/'u.csv'; write_feed(feed,[('a','https://mal.test/a','online'),('h','https://old.test/a','offline')])
    store=fakeredis.FakeRedis(decode_responses=True); import_file(feed,store)
    monkeypatch.setattr(redis_store,'client',lambda:store)
    status,active,_=asyncio.run(urlhaus.run('https://mal.test/a'))
    assert status=='ok' and active[0].evidence['active_confirmation_eligible'] is True
    status,old,_=asyncio.run(urlhaus.run('https://old.test/a'))
    assert status=='ok' and old[0].evidence['record_status']=='historical' and not old[0].evidence['active_confirmation_eligible']

def test_redis_check_miss_is_ok_not_clean_evidence(monkeypatch):
    store=fakeredis.FakeRedis(decode_responses=True); store.set('urlhaus:v1:active_generation','g')
    monkeypatch.setattr(redis_store,'client',lambda:store)
    status,findings,_=asyncio.run(urlhaus.run('https://clean.test/'))
    assert status=='ok' and findings==[]

def test_redis_unavailable_is_unavailable(monkeypatch):
    def fail(): raise ConnectionError('offline')
    monkeypatch.setattr(redis_store,'client',fail)
    status,findings,reason=asyncio.run(urlhaus.run('https://example.com'))
    assert status=='unavailable' and findings==[] and reason

def test_analysis_deduplicates_urlhaus_ioc_across_input_and_hops(monkeypatch,tmp_path):
    feed=tmp_path/'u.csv'; write_feed(feed,[('a','https://bad.test/start','online')])
    store=fakeredis.FakeRedis(decode_responses=True); import_file(feed,store)
    monkeypatch.setattr(redis_store,'client',lambda:store)
    ctx=Context('https://bad.test/start',nurl=normalize('https://bad.test/start'),fetch_result={
        'final_url':'https://bad.test/start','hops':[{'url':'https://bad.test/start'}],
    })
    findings=asyncio.run(analyser.check_urlhaus(ctx))
    assert len(findings)==1
    assert set(findings[0].evidence['observed_targets'])=={'input','hop','final_destination'}

