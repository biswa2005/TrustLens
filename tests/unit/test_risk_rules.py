from links.models import Finding, CheckResult
from links.services.risk import classify, confidence_for, explain
from hypothesis import given, strategies as st

def f(check,sev,group,cls,evidence=None):
    return Finding(id=f'{check}.{group}',check_id=check,category='test',title='test',severity=sev,evidence=evidence or {},evidence_group=group,evidence_class=cls)

def test_high_requires_independent_classes_for_two_strong_groups():
    a=f('lexical','strong','a','static'); b=f('rdap','strong','b','infrastructure')
    assert classify([a,b],[])[0]=='high'
    b=b.model_copy(update={'evidence_class':'static'})
    assert classify([a,b],[])[0]=='suspicious'

def test_high_mixed_strong_and_moderate_groups():
    items=[f('lexical','strong','a','static'),f('dns','moderate','b','infrastructure'),f('password_form','moderate','c','behavioural')]
    assert classify(items,[])[0]=='high'

def test_vt_one_to_four_requires_non_reputation_moderate_evidence():
    vt=f('intel_virustotal','moderate','vt','reputation',{'malicious_excl_gsb':3,'match_level':'exact_url'})
    infra=f('dns','moderate','dns','infrastructure')
    assert classify([vt,infra],[])[0]=='high'
    assert classify([vt],[])[0]=='suspicious'

def test_three_weak_groups_become_suspicious():
    assert classify([f('a','weak','a','static'),f('b','weak','b','static'),f('c','weak','c','static')],[])[0]=='suspicious'

def test_confidence_and_low_risk_require_external_reputation():
    gating=['normalise','lexical','brand_impersonation','redirect_chain','password_form','dns','rdap']
    seven=[CheckResult(check_id=cid,status='ok') for cid in gating]
    assert classify([],seven)[0]=='inconclusive'
    seven[0]=CheckResult(check_id='intel_safebrowsing',status='ok')
    assert classify([],seven)[0]=='low'
    assert confidence_for(seven,False)=='medium'
    assert confidence_for(seven+[CheckResult(check_id='intel_virustotal',status='ok')],True)=='high'

def test_single_class_suspicious_reason_mentions_no_corroboration():
    msg=explain('suspicious',[{'evidence_class':'static'}],[])
    assert 'no independent corroboration' in msg

def test_urlhaus_confirmation_requires_active_url_or_host_evidence():
    active=f('intel_urlhaus','strong','urlhaus','reputation',{'active_confirmation_eligible':True,'matched_value_type':'host'})
    historical=active.model_copy(update={'evidence':{'active_confirmation_eligible':False}})
    domain_only=active.model_copy(update={'evidence':{'active_confirmation_eligible':False,'matched_value_type':'registered_domain'}})
    assert classify([active],[])[0]=='confirmed_malicious'
    assert classify([historical],[])[0]!='confirmed_malicious'
    assert classify([domain_only],[])[0]!='confirmed_malicious'

def test_safe_browsing_host_match_confirms_and_carries_target_reason():
    item=f('intel_safebrowsing','strong','sb','reputation',{'match_level':'host'})
    item=item.model_copy(update={'target':'final_destination'})
    risk,groups=classify([item],[])
    assert risk=='confirmed_malicious'
    assert 'final_destination' in explain(risk,groups,[item])

def test_virus_total_threshold_excludes_domain_and_small_counts():
    exact=f('intel_virustotal','strong','vt','reputation',{'malicious_excl_gsb':5,'match_level':'exact_url'})
    domain=f('intel_virustotal','moderate','vt','reputation',{'malicious_excl_gsb':20,'match_level':'registered_domain'})
    four=f('intel_virustotal','moderate','vt','reputation',{'malicious_excl_gsb':4,'match_level':'exact_url'})
    assert classify([exact],[])[0]=='confirmed_malicious'
    assert classify([domain],[])[0]!='confirmed_malicious'
    assert classify([four],[])[0]=='suspicious'

def test_low_risk_requires_seven_ok_and_external_reputation():
    checks=[CheckResult(check_id=cid,status='ok') for cid in ['normalise','brand_impersonation','redirect_chain','password_form','dns','rdap']]
    checks[0]=CheckResult(check_id='intel_safebrowsing',status='ok')
    assert classify([],checks)[0]=='inconclusive'
    checks.append(CheckResult(check_id='lexical',status='ok'))
    assert classify([],checks)[0]=='low'

def test_low_reason_records_incomplete_redirect_chain():
    msg=explain('low',[],[],[],False)
    assert 'could not be followed to its end' in msg

@given(st.lists(st.tuples(st.sampled_from(['weak','moderate','strong']),st.sampled_from(['static','behavioural','infrastructure','reputation']),st.integers(min_value=0,max_value=5)),max_size=20))
def test_risk_class_is_independent_of_finding_order(specs):
    findings=[f(f'check{i}',severity,f'group{i}',cls) for i,(severity,cls,group) in enumerate(specs)]
    expected=classify(findings,[])[0]
    assert classify(list(reversed(findings)),[])[0]==expected

@given(st.lists(st.tuples(st.sampled_from(['weak','moderate','strong']),st.sampled_from(['static','behavioural','infrastructure','reputation']),st.integers(min_value=0,max_value=5)),max_size=16),st.tuples(st.sampled_from(['weak','moderate','strong']),st.sampled_from(['static','behavioural','infrastructure','reputation']),st.integers(min_value=0,max_value=5)))
def test_adding_evidence_never_lowers_risk(specs,extra):
    rank={'inconclusive':0,'low':1,'suspicious':2,'high':3,'confirmed_malicious':4}
    findings=[f(f'check{i}',severity,f'group{i}',cls) for i,(severity,cls,group) in enumerate(specs)]
    severity,cls,group=extra
    before=classify(findings,[])[0]
    after=classify(findings+[f('extra',severity,'extra_group',cls)],[])[0]
    assert rank[after]>=rank[before]
