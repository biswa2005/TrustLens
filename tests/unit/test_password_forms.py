import asyncio
from links.services.analyser import check_password
from links.services.checks.normalise import normalize
from links.services.registry import Context, CheckUnavailable


def run(action,url="https://example.com/login"):
    actions=[] if action is None else [action]
    ctx=Context(url,nurl=normalize(url),fetch_result={"password_forms_by_hop":[{"url":url,"password_form_actions":actions,"actions_truncated":False}]})
    return asyncio.run(check_password(ctx))

def test_password_form_cross_domain_action_on_intermediate_page_is_strong():
    findings=run('https://capture.evil.com/post')
    assert len(findings)==1 and findings[0].id.endswith(".cross_domain")
    assert findings[0].severity=="strong" and findings[0].evidence_group=="credential_harvesting"

def test_password_form_insecure_same_domain_action_is_moderate():
    findings=run('http://example.com/submit')
    assert len(findings)==1 and findings[0].id.endswith(".insecure_submission") and findings[0].severity=="moderate"

def test_non_password_forms_do_not_trigger():
    assert run(None)==[]

def test_missing_fetcher_html_is_unavailable():
    ctx=Context("https://example.com",nurl=normalize("https://example.com"),fetch_result={})
    try: asyncio.run(check_password(ctx))
    except CheckUnavailable as exc: assert "no HTML" in str(exc)
    else: raise AssertionError("password check should be unavailable without HTML")
