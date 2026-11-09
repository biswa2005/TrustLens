import asyncio
from links.models import Finding, CheckResult
from links.services import analyser
from links.services.risk import classify

def test_eleven_registered_checks_with_tls_last():
    from links.services.risk import GATING_CHECKS
    assert len(analyser.CHECK_IDS)==11 and analyser.CHECK_IDS[-1]=='tls_certificate'
    assert len(GATING_CHECKS)==10 and 'tls_certificate' not in GATING_CHECKS

def test_risk_active_and_historical_urlhaus():
    active=Finding(id='u',check_id='intel_urlhaus',category='intel',title='hit',severity='strong',evidence={'active_confirmation_eligible':True},evidence_group='urlhaus',evidence_class='reputation')
    old=active.model_copy(update={'evidence':{'active_confirmation_eligible':False},'severity':'moderate'})
    assert classify([active],[])[0]=='confirmed_malicious'
    assert classify([old],[])[0]!='confirmed_malicious'

def test_risk_vt_registered_domain_does_not_confirm():
    f=Finding(id='v',check_id='intel_virustotal',category='intel',title='hit',severity='strong',evidence={'malicious_excl_gsb':9,'match_level':'registered_domain'},evidence_group='reputation_virustotal',evidence_class='reputation')
    assert classify([f],[])[0]!='confirmed_malicious'

def test_analysis_report_has_11_slots(monkeypatch):
    async def unavailable(*a,**k): return 'unavailable',[], 'offline'
    monkeypatch.setattr(analyser,'dns_check',unavailable); monkeypatch.setattr(analyser,'rdap_check',unavailable)
    monkeypatch.setattr(analyser,'safe_browsing',unavailable); monkeypatch.setattr(analyser,'virustotal',unavailable)
    async def uh(*a,**k): return 'unavailable',[], 'offline'
    monkeypatch.setattr(analyser,'urlhaus_run',uh)
    report=asyncio.run(analyser.analyse('http://example.com',True))
    assert report.coverage.planned==11
    assert [c.check_id for c in report.coverage.checks]==analyser.CHECK_IDS
    assert report.coverage.checks[-1].check_id=='tls_certificate'
