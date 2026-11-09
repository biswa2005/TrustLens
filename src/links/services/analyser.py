from __future__ import annotations
import asyncio
import os
import json, math
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urljoin
import httpx
from selectolax.lexbor import LexborHTMLParser
from links.models import CheckResult, Finding, Coverage, Report
from links.services.checks.normalise import normalize
from links.services.checks import network
from links.services.checks.network import dns_check, rdap_check
from links.services.checks.reputation import safe_browsing, virustotal
from links.services.checks.urlhaus import run as urlhaus_run
from links.services.registry import Context, CheckUnavailable, register_check, CHECKS, run_all
from links.services.risk import classify, confidence_for, explain
from confusable_homoglyphs import confusables
from rapidfuzz.distance import DamerauLevenshtein

FETCH_RESPONSE_CAP=5*1024*1024

async def fetcher_response(client,url,payload):
    async with client.stream("POST",url,json=payload) as response:
        response.raise_for_status(); body=bytearray()
        async for chunk in response.aiter_bytes():
            if len(body)+len(chunk)>FETCH_RESPONSE_CAP: raise ValueError("fetcher response exceeded size limit")
            body.extend(chunk)
    data=json.loads(body)
    if not isinstance(data,dict) or not isinstance(data.get("hops"),list) or len(data["hops"])>MAX_HOPS_RESPONSE:
        raise ValueError("invalid fetcher response")
    if not isinstance(data.get("chain_complete"),bool) or not isinstance(data.get("errors",[]),list):
        raise ValueError("invalid fetcher response")
    for hop in data["hops"]:
        if not isinstance(hop,dict) or not isinstance(hop.get("url"),str) or len(hop["url"])>2048:
            raise ValueError("invalid fetcher hop")
        if hop.get("location") is not None and (not isinstance(hop["location"],str) or len(hop["location"])>2048):
            raise ValueError("invalid fetcher location")
    pages=data.get("html_by_hop",[])
    if not isinstance(pages,list) or len(pages)>MAX_HOPS_RESPONSE:
        raise ValueError("invalid fetcher page list")
    if any(not isinstance(p,dict) or not isinstance(p.get("html",""),str) or len(p.get("html",""))>524288 for p in pages):
        raise ValueError("invalid fetcher page")
    return data

MAX_HOPS_RESPONSE=8

CHECK_IDS=["normalise","lexical","brand_impersonation","redirect_chain","password_form","dns","rdap","intel_safebrowsing","intel_virustotal","intel_urlhaus","tls_certificate"]
DATA=Path(__file__).resolve().parents[1]/"data"
BRANDS=json.loads((DATA/"brands.json").read_text(encoding="utf-8-sig"))
RISKY_TLDS=set(json.loads((DATA/"risky_tlds.json").read_text(encoding="utf-8-sig")))
SHORTENERS=set(json.loads((DATA/"shorteners.json").read_text(encoding="utf-8-sig")))
KNOWN_REDIRECT_PAIRS=json.loads((DATA/"known_redirect_pairs.json").read_text(encoding="utf-8-sig")) if (DATA/"known_redirect_pairs.json").exists() else []
SHARED_HOSTING_SUFFIXES={"github.io","netlify.app","pages.dev","vercel.app","web.app","firebaseapp.com","cloudfront.net"}
KEYWORDS=set(json.loads((DATA/"keywords.json").read_text(encoding="utf-8-sig")))
KNOWN_GOOD=set(json.loads((DATA/"known_good.json").read_text(encoding="utf-8-sig")))

def finding(cid,rule,title,severity,group,cls,evidence):
    return Finding(id=f"{cid}.{rule}",check_id=cid,category=cid,title=title,severity=severity,evidence_group=group,evidence_class=cls,evidence=evidence)

@register_check("normalise",timeout=2)
async def check_normalise(ctx):
    try: ctx.nurl=normalize(ctx.raw_input)
    except ValueError as exc: raise CheckUnavailable(str(exc))
    return []

@register_check("lexical",depends_on=("normalise",),timeout=2)
async def check_lexical(ctx):
    n=ctx.nurl; findings=[]
    if n.is_ip_host: findings.append(finding("lexical","ip_host","IP address used as host","moderate","url_structure","static",{"host":n.host}))
    if "userinfo_present" in n.obfuscation_flags: findings.append(finding("lexical","userinfo_deception","URL contains user information before host","moderate","url_structure","static",{}))
    ip_flags=[flag for flag in n.obfuscation_flags if flag.startswith("ip_")]
    if ip_flags: findings.append(finding("lexical","obfuscated_ip","Obfuscated URL representation was canonicalised","moderate","url_obfuscation","static",{"flags":ip_flags}))
    url_obfuscation=[flag for flag in n.obfuscation_flags if flag in {"defanged_input","backslash_authority","embedded_whitespace","hidden_characters","percent_encoded_host","unicode_dot","scheme_repaired","double_encoding"}]
    if url_obfuscation: findings.append(finding("lexical","url_obfuscation","URL contains an alternate or obscured representation","moderate","url_obfuscation","static",{"flags":url_obfuscation}))
    if "nonstandard_port" in n.obfuscation_flags: findings.append(finding("lexical","nonstandard_port","URL uses a nonstandard HTTP port","moderate","url_structure","static",{"port":n.port}))
    if n.embedded_urls: findings.append(finding("lexical","embedded_redirect","URL contains a nested destination parameter","weak","url_structure","static",{"count":len(n.embedded_urls)}))
    if "embedded_encoded_url" in n.obfuscation_flags: findings.append(finding("lexical","embedded_encoded_url","URL contains a base64-encoded HTTP destination","weak","url_obfuscation","static",{"count":len(n.embedded_urls)}))
    if len(n.host)>50: findings.append(finding("lexical","long_host","Unusually long hostname","weak","url_structure","static",{"length":len(n.host)}))
    if n.host.count("-")>=3: findings.append(finding("lexical","many_hyphens","Hostname contains several hyphens","weak","url_structure","static",{}))
    if n.suffix.lower() in RISKY_TLDS: findings.append(finding("lexical","risky_tld","Hostname uses a higher-risk TLD","weak","tld_keywords","static",{"tld":n.suffix}))
    tokens=set((n.host+" "+n.path+" "+n.query).lower().replace("%2f","/").replace("-"," ").replace("_"," ").replace("."," ").split())
    matched=sorted(tokens & KEYWORDS)
    if matched: findings.append(finding("lexical","phishing_keywords","URL contains credential or payment language","weak","tld_keywords","static",{"keywords":matched[:6]}))
    if n.registered_domain in SHORTENERS: findings.append(finding("lexical","shortener","URL uses a known link shortener","weak","url_structure","static",{"domain":n.registered_domain}))
    if len(n.subdomain.split("."))>=3 and n.subdomain: findings.append(finding("lexical","many_subdomains","Hostname has several subdomain labels","weak","url_structure","static",{"count":len(n.subdomain.split("."))}))
    label=n.registered_domain.split(".")[0]
    if len(label)>=10:
        counts=Counter(label); entropy=-sum((v/len(label))*math.log2(v/len(label)) for v in counts.values())
        if entropy>=3.5: findings.append(finding("lexical","high_entropy","Registered-domain label has high character entropy","weak","url_structure","static",{"entropy":round(entropy,2)}))
    dampened=[]
    if n.registered_domain in KNOWN_GOOD and n.suffix not in {"github.io","pages.dev","vercel.app"}:
        order=["weak","moderate","strong"]
        for item in findings:
            if item.evidence_group in {"url_structure","tld_keywords"} and item.severity in order:
                ev={**item.evidence,"dampened_from":item.severity}; idx=order.index(item.severity)
                dampened.append(item.model_copy(update={"severity":order[max(0,idx-1)],"evidence":ev,"dampenable":True}))
            else: dampened.append(item)
        findings=dampened
    return findings

@register_check("brand_impersonation",depends_on=("normalise",),timeout=3)
async def check_brand(ctx):
    n=ctx.nurl; label=n.registered_domain.split(".")[0].lower(); unicode_label=n.host_unicode.split(".")[0].lower()
    path_tokens=set(__import__("re").findall(r"[a-z0-9]+",(n.path+" "+n.query).lower()))
    sub_tokens=set(n.subdomain.lower().replace("-",".").split(".")); findings=[]
    for brand,domains in BRANDS.items():
        if n.registered_domain in domains: continue
        if unicode_label!=label and confusables.is_mixed_script(unicode_label) and confusables.is_confusable(unicode_label,brand):
            findings.append(finding("brand_impersonation","homograph","Possible mixed-script brand homograph","strong","brand_impersonation","static",{"brand":brand,"host_unicode":unicode_label,"host":n.host}))
        if brand in sub_tokens:
            findings.append(finding("brand_impersonation","brand_in_subdomain","Brand name appears in a subdomain of an unrelated registered domain","strong","brand_impersonation","static",{"brand":brand,"host":n.host}))
        if label==brand: continue
        typo_token=next((part for part in label.replace("_","-").split("-") if len(brand)>=5 and DamerauLevenshtein.distance(part,brand)<=1),None)
        if typo_token:
            found=finding("brand_impersonation","typosquat",f"Possible {brand} typosquat","strong","brand_impersonation","static",{"brand":brand,"host":n.host,"token":typo_token,"distance":DamerauLevenshtein.distance(typo_token,brand)})
            findings.append(dampen(found,n))
        if DamerauLevenshtein.distance(label,brand)<=1 and len(brand)>=5:
            found=finding("brand_impersonation","typosquat",f"Possible {brand} typosquat","strong","brand_impersonation","static",{"brand":brand,"host":n.host,"distance":DamerauLevenshtein.distance(label,brand)})
            if not any(item.id.endswith(".typosquat") and item.evidence.get("brand")==brand for item in findings): findings.append(dampen(found,n))
        if (brand in label or typo_token) and any(k in label for k in KEYWORDS):
            findings.append(finding("brand_impersonation","combosquat",f"Possible {brand} brand combosquat","strong","brand_impersonation","static",{"brand":brand,"host":n.host}))
        if brand in path_tokens and brand not in label:
            found=finding("brand_impersonation","brand_claim","URL claims a brand on a non-official domain","moderate","brand_impersonation","static",{"brand":brand,"host":n.host})
            findings.append(dampen(found,n))
    dedup={item.id:item for item in findings}
    return list(dedup.values())

def dampen(item,n):
    if n.registered_domain not in KNOWN_GOOD or n.suffix in {"github.io","pages.dev","vercel.app"}: return item
    order=["weak","moderate","strong"]
    if item.severity not in order: return item
    original=item.severity; severity=order[max(0,order.index(original)-1)]
    return item.model_copy(update={"severity":severity,"dampenable":True,"evidence":{**item.evidence,"dampened_from":original}})

@register_check("redirect_chain",depends_on=("normalise",),timeout=25,needs_network=True)
async def check_redirect(ctx):
    fetch_url=os.getenv("FETCHER_URL")
    if not fetch_url: raise CheckUnavailable("fetcher not configured")
    try:
        async with httpx.AsyncClient(timeout=23) as client:
            data=await fetcher_response(client,fetch_url.rstrip("/")+"/fetch",{"url":ctx.nurl.normalised,"options":{"max_hops":8}})
        ctx.fetch_result=data
        findings=[]; hops=data["hops"]
        parsed=[]
        for hop in hops:
            try: parsed.append(normalize(hop.get("url","")))
            except ValueError: parsed.append(None)
        known_pairs={frozenset(pair) for pair in KNOWN_REDIRECT_PAIRS if isinstance(pair,list) and len(pair)==2}
        for i,hop in enumerate(hops):
            current=parsed[i] if i<len(parsed) else None
            previous=parsed[i-1] if i>0 and i-1<len(parsed) else None
            if i==0: relation="start"
            elif current and previous and current.registered_domain==previous.registered_domain: relation="same_site"
            elif current and previous and (current.registered_domain in KNOWN_GOOD and previous.registered_domain in KNOWN_GOOD or frozenset((current.registered_domain,previous.registered_domain)) in known_pairs): relation="known_pair"
            else: relation="cross_site"
            hop["relation"]=relation
        final=parsed[-1] if parsed else None
        pair=frozenset((ctx.nurl.registered_domain,final.registered_domain)) if final else frozenset()
        known_pair=bool(final and (ctx.nurl.registered_domain in KNOWN_GOOD and final.registered_domain in KNOWN_GOOD or pair in known_pairs))
        if final and final.registered_domain!=ctx.nurl.registered_domain and not known_pair:
            severity="moderate" if ctx.nurl.registered_domain in SHORTENERS and ctx.nurl.registered_domain not in KNOWN_GOOD else "weak"
            findings.append(finding("redirect_chain","cross_domain_redirect","Redirect chain crosses to another registered domain",severity,"redirect_behaviour","behavioural",{"start_domain":ctx.nurl.registered_domain,"final_domain":final.registered_domain}))
            start_brand=next((brand for brand,domains in BRANDS.items() if brand in (ctx.nurl.host+ctx.nurl.path).lower() or any(part==brand for part in ctx.nurl.host.split(".")) ),None)
            if start_brand and final.registered_domain not in BRANDS[start_brand]:
                findings.append(finding("redirect_chain","redirect_brand_mismatch","Redirect destination does not match the brand claimed by the starting URL","strong","redirect_behaviour","behavioural",{"brand":start_brand,"final_domain":final.registered_domain}))
        if any(parsed[i] and parsed[i+1] and parsed[i].scheme=="https" and parsed[i+1].scheme=="http" for i in range(len(parsed)-1)):
            findings.append(finding("redirect_chain","scheme_downgrade","Redirect chain downgrades from HTTPS to HTTP","moderate","redirect_behaviour","behavioural",{}))
        if any(p and p.is_ip_host for p in parsed):
            findings.append(finding("redirect_chain","redirect_to_ip","Redirect chain includes an IP literal","moderate","redirect_behaviour","behavioural",{}))
        if any(h.get("blocked_reason") for h in hops):
            findings.append(finding("redirect_chain","redirect_to_blocked_destination","Redirect attempted to reach a destination blocked by the fetcher guard","moderate","redirect_behaviour","behavioural",{"blocked_reason":next(h.get("blocked_reason") for h in hops if h.get("blocked_reason"))}))
        if "redirect_loop" in data.get("errors",[]): findings.append(finding("redirect_chain","redirect_loop","Redirect loop detected","moderate","redirect_behaviour","behavioural",{}))
        if "excessive_hops" in data.get("errors",[]) or len(hops)>=8 and not data.get("chain_complete"):
            findings.append(finding("redirect_chain","excessive_hops","Redirect chain exceeded the hop limit","moderate","redirect_behaviour","behavioural",{"hop_count":len(hops)}))
        obfuscated=[]
        for hop in hops:
            try:
                if hop.get("location") and normalize(urljoin(hop.get("url",""),hop["location"])).obfuscation_flags: obfuscated.append(hop["location"])
            except ValueError: obfuscated.append(hop.get("location"))
        if obfuscated: findings.append(finding("redirect_chain","redirect_chain_obfuscated","Redirect contains an obfuscated destination","moderate","redirect_behaviour","behavioural",{"locations":obfuscated[:4]}))
        if any(h.get("location_too_long") for h in hops) or "location_too_long" in data.get("errors",[]):
            findings.append(finding("redirect_chain","redirect_location_too_long","Redirect destination exceeded the fetcher location limit","moderate","redirect_behaviour","behavioural",{}))
        if final and final.suffix in SHARED_HOSTING_SUFFIXES:
            findings.append(finding("redirect_chain","redirect_via_private_suffix_host","Redirect lands on a shared-hosting domain","weak","redirect_behaviour","behavioural",{"suffix":final.suffix}))
        if hops and hops[0].get("via") in {"meta_refresh","js_literal"}:
            findings.append(finding("redirect_chain","redirect_js_or_meta","First destination is a static HTML or JavaScript redirect","weak","redirect_behaviour","behavioural",{"via":hops[0].get("via")}))
        if len(hops)>1 and parsed[0] and parsed[1] and parsed[0].registered_domain==ctx.nurl.registered_domain:
            embedded=set()
            for value in ctx.nurl.embedded_urls:
                try: embedded.add(normalize(value).normalised)
                except ValueError: continue
            try: second=normalize(hops[1].get("url","")).normalised
            except ValueError: second=""
            if second and second in embedded:
                severity="moderate" if ctx.nurl.registered_domain in KNOWN_GOOD and final and final.registered_domain not in KNOWN_GOOD else "weak"
                findings.append(finding("redirect_chain","redirect_open_redirector","Redirector forwards to an embedded URL parameter","moderate" if severity=="moderate" else "weak","redirect_behaviour","behavioural",{"destination":second}))
        return findings
    except Exception as exc: raise CheckUnavailable(f"fetcher unavailable ({type(exc).__name__})")

@register_check("password_form",depends_on=("redirect_chain",),timeout=3)
async def check_password(ctx):
    data=ctx.fetch_result or {}; pages=data.get("html_by_hop") or ([{"url":data.get("final_url") or ctx.nurl.normalised,"html":data.get("final_html")}] if data.get("final_html") else [])
    if not pages: raise CheckUnavailable("fetcher returned no HTML")
    findings=[]
    for page in pages:
        body=page.get("html"); final=page.get("url") or data.get("final_url") or ctx.nurl.normalised
        if not body: continue
        tree=LexborHTMLParser(body)
        for form in tree.css("form"):
            if not form.css('input[type="password"]'): continue
            action=urljoin(final,form.attributes.get("action") or final); parsed=normalize(action)
            if parsed.registered_domain!=normalize(final).registered_domain:
                findings.append(finding("password_form","cross_domain","Password form submits to a different registered domain","strong","credential_harvesting","behavioural",{"action_host":parsed.host,"page_host":urlsplit(final).hostname,"page_url":final}))
            elif parsed.scheme=="http":
                findings.append(finding("password_form","insecure_submission","Password form submits over HTTP","moderate","credential_harvesting","behavioural",{"action_host":parsed.host}))
    return findings

@register_check("dns",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=7,needs_network=True)
async def check_dns(ctx):
    targets=[(ctx.nurl.host,ctx.nurl.registered_domain,"input")]
    final=(ctx.fetch_result or {}).get("final_url")
    if final:
        try:
            parsed=normalize(final)
            if parsed.registered_domain!=ctx.nurl.registered_domain:
                targets.append((parsed.host,parsed.registered_domain,"final_destination"))
        except ValueError: pass
    findings=[]; unavailable=[]
    for host,domain,target in targets:
        status,items,reason=await dns_check(host,domain)
        if status!="ok": unavailable.append(reason or "DNS unavailable"); continue
        findings.extend(item.model_copy(update={"target":target}) for item in items)
    if unavailable and not findings: raise CheckUnavailable(unavailable[0])
    return findings

@register_check("rdap",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=7,needs_network=True)
async def check_rdap(ctx):
    domains=[(ctx.nurl.registered_domain,"input")]
    final=(ctx.fetch_result or {}).get("final_url")
    if final:
        try:
            parsed=normalize(final)
            if parsed.registered_domain!=ctx.nurl.registered_domain: domains.append((parsed.registered_domain,"final_destination"))
        except ValueError: pass
    findings=[]; unavailable=[]
    for domain,target in domains:
        status,items,reason=await rdap_check(domain)
        if status!="ok": unavailable.append(reason or "RDAP unavailable"); continue
        findings.extend(item.model_copy(update={"target":target}) for item in items)
    if unavailable and not findings: raise CheckUnavailable(unavailable[0])
    return findings

@register_check("intel_safebrowsing",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=7,needs_network=True)
async def check_safe_browsing(ctx):
    urls=[ctx.nurl.normalised]
    urls.extend(h.get("url") for h in (ctx.fetch_result or {}).get("hops",[]) if isinstance(h.get("url"),str))
    status,items,reason=await safe_browsing(list(dict.fromkeys(urls)))
    if status!="ok": raise CheckUnavailable(reason or "Safe Browsing unavailable")
    return items

@register_check("intel_virustotal",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=12,needs_network=True)
async def check_virustotal(ctx):
    urls=[ctx.nurl.normalised]
    final=(ctx.fetch_result or {}).get("final_url")
    domains=[]
    if final and final!=urls[0]: urls.append(final)
    try:
        final_domain=normalize(final).registered_domain if final else ctx.nurl.registered_domain
        if final_domain!=ctx.nurl.registered_domain: domains.append(final_domain)
    except ValueError: pass
    status,items,reason=await virustotal(urls,domains)
    if status!="ok": raise CheckUnavailable(reason or "VirusTotal unavailable", findings=items)
    return items

@register_check("intel_urlhaus",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=4,needs_network=True)
async def check_urlhaus(ctx):
    fetch=ctx.fetch_result or {}; final=fetch.get("final_url") or ctx.nurl.normalised
    target_urls=[(ctx.nurl.normalised,"input")]
    target_urls.extend((h.get("url"),"hop") for h in fetch.get("hops",[]) if isinstance(h.get("url"),str))
    target_urls.append((final,"final_destination"))
    result={}; failures=[]
    for url,target in dict.fromkeys(target_urls):
        status,items,reason=await urlhaus_run(url)
        if status!="ok": failures.append(reason or "Redis unavailable"); continue
        for item in items:
            old=result.get(item.id)
            targets=set(old.evidence.get("observed_targets",[])) if old else set()
            targets.add(target)
            result[item.id]=item.model_copy(update={"target":target,"evidence":{**item.evidence,"observed_targets":sorted(targets)}})
    if failures:
        ctx.values["urlhaus_partial_targets"]=len(failures)
        raise CheckUnavailable("URLhaus lookup unavailable for one or more targets", findings=list(result.values()))
    return list(result.values())


@register_check("tls_certificate",depends_on=("normalise","redirect_chain"),requires_success=("normalise",),timeout=10.0,needs_network=True)
async def check_tls_certificate(ctx):
    from datetime import date, datetime, timezone
    import binascii
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from links.models_tls import (CADistrustClassification as D, CertificateDetails,
        ChainStatus as C, HostnameStatus as H, RevocationStatus as R, TLSReport, TrustVerdict,
        inconclusive_report)
    from links.services.tls._probe_models import TLSProbeRequest
    from links.services.authority import canonical_authority
    from links.services.tls.distrust import load_dataset
    from links.services.tls.findings import finding
    from links.services.tls.fetcher_client import BoundsError, decode_chain, decode_ocsp_staple, post_probe_tls
    from links.services.tls.ct import inspect_embedded_scts
    from links.services.tls.ocsp import evaluate_ocsp
    from links.services.tls.hostname_verifier import verify_hostname
    from links.services.tls.path_validator import validate_chain
    from links.services.tls.verdict import compute_trust_verdict
    from links.services.tls.weak_crypto import inspect_crypto
    from links.services.tls.validity import excessive_lifetime
    from links.services.tls.trust_store import get_trust_store

    if ctx.nurl.scheme != "https":
        ctx.values["tls_reports"] = {}
        return CheckResult(check_id="tls_certificate",status="skipped",reason="input is not HTTPS; no TLS analysis performed"), []
    candidates=[(ctx.nurl.host,ctx.nurl.port or 443,"input")]
    final=(ctx.fetch_result or {}).get("final_url")
    if final:
        try:
            parsed=normalize(final)
            if parsed.scheme=="https": candidates.append((parsed.host,parsed.port or 443,"final_destination"))
        except ValueError: pass
    authorities=[]; limits=[]; seen=set()
    for host,port,target in candidates:
        if port!=443:
            limits.append(f"tls_non_default_port_not_analysed:{port}"); continue
        key=canonical_authority(host,port)
        if key not in seen: authorities.append((host,port,target,key)); seen.add(key)
    ctx.values["tls_reports"]={}
    if limits: ctx.values.setdefault("limitations",[]).extend(limits)
    if not authorities:
        ctx.values.setdefault("limitations",[]).extend(limits)
        return CheckResult(check_id="tls_certificate",status="skipped",reason="no eligible HTTPS authority"), []

    timeout_budget=float(os.getenv("TLS_PROBE_TIMEOUT_BUDGET","7.0"))
    deadline=asyncio.get_running_loop().time()+timeout_budget
    base=os.getenv("FETCHER_URL","").rstrip("/")
    token=os.getenv("FETCHER_TOKEN","")
    reports={}; all_findings=[]; succeeded=0
    try: distrust_data=load_dataset()
    except Exception: distrust_data=None
    try: trust_store=get_trust_store()
    except Exception: trust_store=None

    async def one(client,host,port,target,key):
        if not base or not token:
            return inconclusive_report(host,port,"internal_error","fetcher TLS probe is not configured",target), []
        try:
            req=TLSProbeRequest(host=host,port=port,timeout_budget=timeout_budget)
            raw=await post_probe_tls(client,base+"/probe/tls",req.model_dump(mode="json"),deadline,token)
            if not raw.ok:
                return TLSReport(canonical_authority=key,target_kind=target,probe_ok=False,
                    probe_error_kind=raw.error_kind or "internal_error",probe_error_detail=(raw.error_detail or "probe failed")[:120],
                    limitations=tuple(raw.limitations)+(raw.error_kind or "probe_error",),
                    trust_store_version=trust_store.version if trust_store else None,
                    distrust_dataset_version=distrust_data.version if distrust_data else None), []
            der_chain=decode_chain(raw)
            staple=decode_ocsp_staple(raw)
            certs=[x509.load_der_x509_certificate(der) for der in der_chain]
            if not certs: raise ValueError("empty_chain")
            now=datetime.now(timezone.utc); leaf=certs[0]; cert_details=[]; fired=set(); fs=[]
            revocation,ocsp_rule,ocsp_evidence=evaluate_ocsp(staple,leaf,certs[1:],now)
            if ocsp_rule:
                fs.append(finding(ocsp_rule,target,ocsp_evidence)); fired.add(ocsp_rule)
            ct_status,ct_evidence=inspect_embedded_scts(leaf)
            if ct_status=="embedded_present_malformed":
                fs.append(finding("probe_error",target,{"ct_reason":ct_evidence.get("reason")})); fired.add("probe_error")
            host_status,host_evidence=verify_hostname(leaf,host)
            chain_status,chain_evidence=(validate_chain(leaf,certs[1:],host,now,trust_store)
                                          if trust_store else (C.INCONCLUSIVE,{"reason":"trust_store_unavailable"}))
            if distrust_data is None: distrust=D.NOT_EVALUATED
            else:
                matches=[]
                for cert in certs:
                    fp=cert.fingerprint(hashes.SHA256()); pub=cert.public_key().public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER,__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo); spki=hashes.Hash(hashes.SHA256()); spki.update(pub); spki_hash=spki.finalize()
                    for record in distrust_data.records:
                        if fp!=record.fingerprint and spki_hash!=record.spki_hash: continue
                        scope=record.scope or {"type":"all"}
                        if scope.get("type")=="leaf_not_before_gte":
                            cutoff=date.fromisoformat(scope["cutoff"][:10])
                            if leaf.not_valid_before_utc.date() < cutoff: continue
                        elif scope.get("type")!="all": continue
                        matches.append(record)
                distrust=(D.COMPROMISED if any(r.classification=="compromised" for r in matches)
                          else D.DISTRUSTED if matches else D.TRUSTED)
                if distrust==D.COMPROMISED: fs.append(finding("compromised_ca",target,{})); fired.add("compromised_ca")
                elif distrust==D.DISTRUSTED: fs.append(finding("distrusted_ca",target,{})); fired.add("distrusted_ca")
            for idx,cert in enumerate(certs):
                try: san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                except x509.ExtensionNotFound: san=None
                pub=cert.public_key()
                try: key_size=pub.key_size
                except AttributeError: key_size=None
                try: key_algo=type(pub).__name__
                except Exception: key_algo="unknown"
                try: sig=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
                except Exception: sig=None
                try: usage=cert.extensions.get_extension_for_class(x509.KeyUsage).value
                except x509.ExtensionNotFound: usage=None
                usages=tuple(name for name in ("digital_signature","content_commitment","key_encipherment","data_encipherment","key_agreement","key_cert_sign","crl_sign") if usage and getattr(usage,name,False))
                cert_details.append(CertificateDetails(subject=cert.subject.rfc4514_string(),issuer=cert.issuer.rfc4514_string(),serial_number=hex(cert.serial_number),not_before=cert.not_valid_before_utc,not_after=cert.not_valid_after_utc,san_dns=tuple(san.get_values_for_type(x509.DNSName)) if san else (),san_ip=tuple(str(ip) for ip in san.get_values_for_type(x509.IPAddress)) if san else (),key_usage=usages,public_key_algorithm=key_algo,public_key_size=key_size,signature_hash=sig,is_ca=idx>0))
                for rule,evidence in inspect_crypto(cert,is_anchor=idx==len(certs)-1 and cert.subject==cert.issuer):
                    fs.append(finding(rule,target,evidence)); fired.add(rule)
            if chain_status==C.EXPIRED: fs.append(finding("cert_expired",target,chain_evidence))
            elif chain_status==C.NOT_YET_VALID: fs.append(finding("cert_not_yet_valid",target,chain_evidence))
            elif chain_status==C.SIGNATURE_INVALID: fs.append(finding("signature_invalid",target,chain_evidence)); fired.add("signature_invalid")
            elif chain_status==C.SELF_SIGNED: fs.append(finding("self_signed",target,chain_evidence))
            elif chain_status==C.UNTRUSTED_ROOT: fs.append(finding("untrusted_root",target,chain_evidence))
            elif chain_status==C.INCOMPLETE_CHAIN: fs.append(finding("chain_incomplete",target,chain_evidence))
            elif chain_status==C.PATH_CONSTRAINT_VIOLATED: fs.append(finding("path_constraint_violated",target,chain_evidence))
            elif chain_status==C.RESOURCE_LIMIT_EXCEEDED: fs.append(finding("resource_limit",target,chain_evidence))
            if host_status not in (H.MATCHED,H.NOT_EVALUATED): fs.append(finding("hostname_mismatch",target,host_evidence)); fired.add("hostname_mismatch")
            validity=excessive_lifetime(leaf,chain_trusted=chain_status==C.VALID_TRUSTED)
            if validity: fs.append(finding("excessive_validity_period",target,validity)); fired.add("excessive_validity_period")
            limits_local=tuple(raw.limitations)+(
                "OCSP checks use authenticated direct-issuer staples only; active OCSP, delegated responders, and CRLs are not implemented.",
                "CT checks parse embedded SCT structure only; SCT signatures, CT logs, and issuance monitoring are not checked.",
            )
            if chain_status==C.UNTRUSTED_ROOT:
                limits_local+=("A URL alone cannot reveal internal CA key-generation weaknesses; this certificate is untrusted and no verified distrust record matched.",)
            ocsp_affects_verdict=os.getenv("OCSP_AFFECTS_VERDICT","true").lower() in {"1","true","yes"}
            verdict=compute_trust_verdict(chain=chain_status,hostname=host_status,
                revocation=revocation if ocsp_affects_verdict else R.NOT_EVALUATED,distrust=distrust,fired=fired)
            transport_eligibility=(chain_status==C.VALID_TRUSTED and host_status==H.MATCHED
                                   and verdict in (TrustVerdict.VALID,TrustVerdict.CONFIGURATION_ISSUES))
            report=TLSReport(canonical_authority=key,target_kind=target,probe_ok=True,limitations=limits_local,
                trust_store_version=trust_store.version if trust_store else None,distrust_dataset_version=distrust_data.version if distrust_data else None,
                chain_status=chain_status,hostname_status=host_status,distrust=distrust,revocation=revocation,trust_verdict=verdict,
                transport_eligibility=transport_eligibility,
                certificates=tuple(cert_details),findings=tuple(f.id for f in fs),negotiated_protocol=raw.negotiated_protocol,negotiated_cipher=raw.negotiated_cipher,
                ct_status=ct_status)
            return report,fs
        except TimeoutError: kind,reason="timeout","deadline"
        except (BoundsError,binascii.Error,ValueError) as exc: kind,reason="resource_limit",str(exc)[:120]
        except httpx.HTTPError as exc: kind,reason="connection_refused",type(exc).__name__
        except Exception as exc: kind,reason="internal_error",type(exc).__name__
        report=inconclusive_report(host,port,kind,reason,target).model_copy(update={"canonical_authority":key,"trust_store_version":trust_store.version if trust_store else None,"distrust_dataset_version":distrust_data.version if distrust_data else None})
        return report,[finding("probe_error",target,{"kind":kind,"reason":reason})]

    async with httpx.AsyncClient(timeout=None) as client:
        outcomes=await asyncio.gather(*(one(client,*args) for args in authorities))
    for (host,port,target,key),(report,items) in zip(authorities,outcomes):
        reports[key]=report; all_findings.extend(items); succeeded+=int(report.probe_ok)
        ctx.values.setdefault("limitations",[]).extend(report.limitations)
    ctx.values["tls_reports"]=reports
    if succeeded==0:
        reason="; ".join(dict.fromkeys(r.probe_error_kind or "probe failed" for r in reports.values()))
        return CheckResult(check_id="tls_certificate",status="unavailable",reason=reason),all_findings
    return CheckResult(check_id="tls_certificate",status="ok"),all_findings

async def analyse(raw: str, skip_third_party_reputation: bool=False) -> Report:
    ctx=Context(raw_input=raw,options={"skip_checks": {"intel_safebrowsing","intel_virustotal"} if skip_third_party_reputation else set()})
    results,findings=await run_all(ctx,CHECK_IDS)
    if not ctx.nurl:
        return Report(input=raw,risk_class="inconclusive",coverage=Coverage(completed=0,planned=11,checks=results),limitations=["URL could not be safely normalised"])
    fetch=ctx.fetch_result or {}; chain=bool(fetch.get("chain_complete",False)); hops=fetch.get("hops",[]); limitations=list(fetch.get("limitations",[])); limitations.extend(ctx.values.get("limitations",[]))
    final_url=fetch.get("final_url") or ctx.nurl.normalised
    candidate_urls=[(ctx.nurl.normalised,"input"),(final_url,"final_destination")]
    candidate_urls.extend((h.get("url"),"hop") for h in hops if isinstance(h.get("url"),str))
    unique=[]; seen_domains=set()
    for url,target in candidate_urls:
        try: parsed=normalize(url)
        except ValueError: continue
        if parsed.registered_domain in seen_domains: continue
        seen_domains.add(parsed.registered_domain); unique.append((url,target,parsed))
    cap=max(2,int(os.getenv("MAX_TARGET_DOMAINS","4")))
    if len(unique)>cap:
        keep=[unique[0]]
        if unique[-1] not in keep: keep.append(unique[-1])
        keep.extend(item for item in unique[1:-1] if item[2].registered_domain in SHORTENERS)
        keep.extend(item for item in unique[1:-1] if item not in keep)
        unique=keep[:cap]
        limitations.append(f"{max(0,len(seen_domains)-len(unique))} intermediate domains were not individually analysed")
    for url,target,parsed in unique:
        if target=="input": continue
        local=Context(raw_input=url,options=ctx.options,nurl=parsed,fetch_result=ctx.fetch_result,values=ctx.values)
        for check in (check_lexical,check_brand):
            try:
                items=await check(local)
                findings.extend(item.model_copy(update={"target":target}) for item in items)
            except Exception: continue
    target_by_url={url:target for url,target,_ in unique}
    target_by_url.update({parsed.normalised:target for url,target,parsed in unique})
    retargeted=[]
    for item in findings:
        value=item.evidence.get("target_url") or item.evidence.get("url")
        target=target_by_url.get(value,item.target)
        retargeted.append(item.model_copy(update={"target":target}))
    findings=retargeted
    risk,groups=classify(findings,results,chain)
    completed=sum(r.status=="ok" for r in results)
    confidence=confidence_for(results,chain)
    if not chain: limitations.append("Redirect chain could not be verified to completion")
    if ctx.values.get("urlhaus_partial_targets"): limitations.append("URLhaus lookup was unavailable for some redirect targets")
    try: final_domain=normalize(final_url).registered_domain if final_url else None
    except ValueError: final_domain=None
    summary={"start_registered_domain":ctx.nurl.registered_domain,"final_registered_domain":final_domain,"hop_count":len(hops),"chain_complete":chain,"cross_site":bool(final_domain and final_domain!=ctx.nurl.registered_domain),"via_shortener":ctx.nurl.registered_domain in SHORTENERS,"blocked":any(h.get("blocked_reason") for h in hops),"target_domains_analysed":[item[2].registered_domain for item in unique]}
    from links.services.risk import RECOMMENDATIONS
    return Report(input=raw,normalised_url=ctx.nurl,risk_class=risk,risk_reasoning=[explain(risk,groups,findings,results,chain)],confidence=confidence,evidence_groups=groups,redirect_summary=summary,coverage=Coverage(completed=completed,planned=11,checks=results),findings=findings,redirect_chain=hops,limitations=limitations,recommendations=RECOMMENDATIONS[risk],tls_reports=ctx.values.get("tls_reports"))

