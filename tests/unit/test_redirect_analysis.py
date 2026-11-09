import asyncio
import httpx
import pytest
from links.services import analyser
from links.services.checks.normalise import normalize
from links.services.registry import Context

REAL_ASYNC_CLIENT=httpx.AsyncClient

def run_redirect(monkeypatch,start,hops,errors=None,complete=True):
    payload={"hops":hops,"chain_complete":complete,"errors":errors or [],"password_forms_by_hop":[]}
    def factory(*args,**kwargs):
        return REAL_ASYNC_CLIENT(transport=httpx.MockTransport(lambda req:httpx.Response(200,json=payload)),*args,**kwargs)
    monkeypatch.setattr(analyser.httpx,"AsyncClient",factory)
    monkeypatch.setenv("FETCHER_URL","http://fetcher.test")
    monkeypatch.setenv("FETCHER_TOKEN","test-token")
    ctx=Context(start,nurl=normalize(start))
    findings=asyncio.run(analyser.check_redirect(ctx))
    return findings,ctx.fetch_result

def hop(url,via="http3xx",location=None,blocked_reason=None):
    item={"url":url,"status":302,"location":location,"resolved_ip":"8.8.8.8","registered_domain":None,"scheme":url.split(":",1)[0],"content_type":None,"elapsed_ms":1,"via":via}
    if blocked_reason: item["blocked_reason"]=blocked_reason
    return item

def ids(findings): return {f.id.rsplit(".",1)[-1] for f in findings}

def test_same_site_and_known_good_redirect_relations_do_not_flag_cross_domain(monkeypatch):
    findings,data=run_redirect(monkeypatch,"https://www.example.com/",[hop("https://www.example.com/"),hop("https://example.com/")])
    assert "cross_domain_redirect" not in ids(findings) and data["hops"][1]["relation"]=="same_site"
    findings,data=run_redirect(monkeypatch,"https://google.com/",[hop("https://google.com/"),hop("https://microsoft.com/")])
    assert "cross_domain_redirect" not in ids(findings) and data["hops"][1]["relation"]=="known_pair"

def test_unknown_shortener_brand_mismatch_and_shared_host_findings(monkeypatch):
    findings,_=run_redirect(monkeypatch,"https://bit.ly/a",[hop("https://bit.ly/a"),hop("https://landing.example.net/")])
    cross=next(f for f in findings if f.id.endswith("cross_domain_redirect"))
    assert cross.severity=="moderate"
    findings,_=run_redirect(monkeypatch,"https://paypal-login.evil.example.com/",[hop("https://paypal-login.evil.example.com/"),hop("https://account.example.net/")])
    assert "redirect_brand_mismatch" in ids(findings)
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",[hop("https://start.example.com/"),hop("https://malicious.github.io/")])
    assert "redirect_via_private_suffix_host" in ids(findings)

def test_blocked_destination_and_https_downgrade_findings(monkeypatch):
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",[
        hop("https://start.example.com/",location="http://127.0.0.1/"),
        hop("http://127.0.0.1/",blocked_reason="private_ip"),
    ])
    assert {"redirect_to_ip","redirect_to_blocked_destination","scheme_downgrade"}.issubset(ids(findings))

def test_static_redirect_and_embedded_open_redirect_findings(monkeypatch):
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",[
        hop("https://start.example.com/",via="js_literal"),hop("https://final.example.net/")
    ])
    assert "redirect_js_or_meta" in ids(findings)
    findings,_=run_redirect(monkeypatch,"https://google.com/redirect?next=https%3A%2F%2Fevil.example.net/",[
        hop("https://google.com/redirect?next=https%3A%2F%2Fevil.example.net/"),hop("https://evil.example.net/")
    ])
    assert "redirect_open_redirector" in ids(findings)

def test_loop_excessive_and_overlong_location_findings(monkeypatch):
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",[hop("https://start.example.com/")],errors=["redirect_loop"],complete=False)
    assert "redirect_loop" in ids(findings)
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",[hop("https://start.example.com/")],errors=["excessive_hops"],complete=False)
    assert "excessive_hops" in ids(findings)
    hops=[hop("https://start.example.com/",location=None)]; hops[0]["location_too_long"]=True
    findings,_=run_redirect(monkeypatch,"https://start.example.com/",hops,errors=["location_too_long"],complete=False)
    assert "redirect_location_too_long" in ids(findings)
