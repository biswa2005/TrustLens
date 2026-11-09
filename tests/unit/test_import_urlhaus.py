from pathlib import Path
import sys, fakeredis, pytest, csv, io, hashlib
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from scripts.import_urlhaus import rows, import_file, POINTER

HEADER='id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
def line(i,url,status='online'):
    out=io.StringIO(); csv.writer(out,lineterminator='\n').writerow([i,'2026-01-01',url,status,'','malware','tag',f'https://urlhaus.abuse.ch/host/{i}/','tester']); return out.getvalue()
def test_comments_quotes_and_statuses(tmp_path):
    p=tmp_path/'feed.txt'; p.write_text('# comment\n'+HEADER+line('1','https://evil.test/a,b')+line('2','http://old.test/','offline'))
    data=list(rows(p)); assert len(data)==2
    r=fakeredis.FakeRedis(decode_responses=True); result=import_file(p,r)
    assert result['active']==1 and result['historical']==1 and r.get(POINTER)==result['generation']

def test_official_headerless_dump_with_comment_preamble(tmp_path):
    p=tmp_path/'urlhaus.txt'
    p.write_text('# abuse.ch URLhaus Database Dump (CSV)\n# generated for test\n'+line('1','https://evil.test/a,b'))
    data=list(rows(p))
    assert len(data)==1 and data[0]['id']=='1' and data[0]['url']=='https://evil.test/a,b'
    r=fakeredis.FakeRedis(decode_responses=True)
    result=import_file(p,r)
    assert result['active']==1 and result['historical']==0

def test_full_dump_ftp_ioc_is_imported_for_host_lookup(tmp_path):
    p=tmp_path/'ftp.csv'
    p.write_text(HEADER+line('ftp-1','ftp://files.evil.test/payload','online'))
    r=fakeredis.FakeRedis(decode_responses=True)
    result=import_file(p,r)
    assert result['active']==1
    digest=hashlib.sha256(b'files.evil.test').hexdigest()
    stored=r.hvals(f"urlhaus:v1:{result['generation']}:active:host:{digest}")
    assert stored and 'ftp://files.evil.test/payload' in stored[0]
def test_duplicate_rows_idempotent_rerun(tmp_path):
    p=tmp_path/'feed.csv'; record=line('1','https://evil.test/')
    p.write_text(HEADER+record+record); r=fakeredis.FakeRedis(decode_responses=True)
    a=import_file(p,r); b=import_file(p,r)
    assert a['duplicate']==1 and b['active']==1 and a['generation']!=b['generation'] and r.get(POINTER)==b['generation']
def test_bad_header_or_row_does_not_switch_generation(tmp_path):
    r=fakeredis.FakeRedis(decode_responses=True); r.set(POINTER,'old')
    p=tmp_path/'bad.csv'; p.write_text(HEADER+line('x','file:///etc/passwd'))
    with pytest.raises(ValueError): import_file(p,r)
    assert r.get(POINTER)=='old'
    p.write_text('wrong,header\nx,y\n')
    with pytest.raises(ValueError): import_file(p,r)
    assert r.get(POINTER)=='old'
def test_redis_write_failure_keeps_old_pointer(tmp_path):
    class Broken(fakeredis.FakeRedis):
        fail_switch=False
        def set(self,*a,**kw):
            if a[0]==POINTER and self.fail_switch: raise RuntimeError('switch failure')
            return super().set(*a,**kw)
    p=tmp_path/'feed.csv'; p.write_text(HEADER+line('1','https://evil.test/'))
    r=Broken(decode_responses=True); r.set(POINTER,'old'); r.fail_switch=True
    with pytest.raises(RuntimeError): import_file(p,r)
    assert r.get(POINTER)=='old'
