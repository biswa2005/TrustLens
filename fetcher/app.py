from __future__ import annotations
import asyncio, http.client, socket, ssl, time, os, threading, hmac
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from fetcher.guard import validate_and_resolve, validate_and_resolve_async, Blocked
from fetcher.models import TLSProbeRequest, TLSProbeResponse
from fetcher.tls_probe import run_tls_probe

app=FastAPI(title="TrustLens isolated fetcher")
_tls_sem = asyncio.Semaphore(4)
_fetch_sem = asyncio.Semaphore(4)
MAX_BODY=min(524288,max(1024,int(os.getenv("FETCH_BODY_CAP_BYTES","524288"))))
MAX_HOPS=min(8,max(1,int(os.getenv("FETCH_MAX_HOPS","8"))))
TOTAL_BUDGET=min(20.0,max(1.0,float(os.getenv("FETCH_TOTAL_BUDGET","20"))))
CONNECT_TIMEOUT=min(3.0,max(0.1,float(os.getenv("FETCH_CONNECT_TIMEOUT","3"))))
READ_TIMEOUT=min(5.0,max(0.1,float(os.getenv("FETCH_READ_TIMEOUT","5"))))
MAX_HEADER_BYTES=65536
HOP_BUDGET=min(8.0,max(0.1,float(os.getenv("FETCH_HOP_BUDGET","8"))))
MAX_FORMS_PER_PAGE=32
MAX_FORM_ACTION_LENGTH=2048

class FetchOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_hops:int=Field(default=8,ge=1,le=8)

class FetchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url:str=Field(min_length=1,max_length=2048)
    options:FetchOptions=Field(default_factory=FetchOptions)

class _PasswordFormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._forms=[]
        self.actions=[]
        self.truncated=False

    def _finish_form(self, form):
        if not form["has_password"]:
            return
        if len(self.actions)>=MAX_FORMS_PER_PAGE or len(form["action"])>MAX_FORM_ACTION_LENGTH:
            self.truncated=True
            return
        self.actions.append(form["action"])

    def handle_starttag(self, tag, attrs):
        values={key.lower():(value or "") for key,value in attrs if key}
        if tag.lower()=="form":
            self._forms.append({"action":values.get("action",""),"has_password":False})
        elif tag.lower()=="input" and values.get("type","").lower()=="password" and self._forms:
            self._forms[-1]["has_password"]=True

    def handle_endtag(self, tag):
        if tag.lower()=="form" and self._forms:
            self._finish_form(self._forms.pop())

    def close(self):
        super().close()
        while self._forms:
            self._finish_form(self._forms.pop())

def _password_form_evidence(html):
    parser=_PasswordFormParser()
    parser.feed(html)
    parser.close()
    return parser.actions,parser.truncated

def request_one(url,deadline=None,resolved=None):
    p,port,ip=resolved or validate_and_resolve(url); started=time.monotonic(); raw=None; timer=None
    budget=HOP_BUDGET if deadline is None else min(HOP_BUDGET,deadline-started)
    if budget<=0: raise TimeoutError("fetch total budget exhausted")
    try:
        raw=socket.create_connection((ip,port),timeout=min(CONNECT_TIMEOUT,budget))
        def abort_socket():
            try: raw.close()
            except OSError: pass
        timer=threading.Timer(budget,abort_socket); timer.daemon=True; timer.start()
        raw.settimeout(min(READ_TIMEOUT,max(.05,budget-(time.monotonic()-started))))
        if p.scheme=="https": raw=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
        remaining=budget-(time.monotonic()-started)
        if remaining<=0: raise TimeoutError("fetch hop budget exhausted")
        raw.settimeout(min(READ_TIMEOUT,remaining))
        path=p.path or "/"
        if p.query: path+="?"+p.query
        req=(f"GET {path} HTTP/1.1\r\nHost: {p.hostname}\r\nUser-Agent: TrustLensFetcher/1.0\r\nAccept: text/html,*/*;q=0.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
        raw.sendall(req); response=http.client.HTTPResponse(raw); response.begin()
        raw_headers=response.getheaders()
        if len(raw_headers)>100 or sum(len(k)+len(v) for k,v in raw_headers)>MAX_HEADER_BYTES:
            raise http.client.HTTPException("response headers exceed limit")
        headers={k.lower():v for k,v in raw_headers}
        body=b""
        if headers.get("content-type","").lower().startswith("text/html"):
            body=response.read(MAX_BODY+1)
        return {"status":response.status,"headers":headers,"body":body[:MAX_BODY].decode("utf-8","replace"),"truncated":len(body)>MAX_BODY,"ip":ip,"elapsed_ms":int((time.monotonic()-started)*1000)}
    finally:
        if timer: timer.cancel()
        if raw:
            try: raw.close()
            except OSError: pass

@app.post("/fetch")
async def fetch(req:FetchRequest, x_fetcher_token: str = Header(default="")):
    _authorize(x_fetcher_token)
    try:
        await asyncio.wait_for(_fetch_sem.acquire(),0.5)
    except TimeoutError:
        raise HTTPException(status_code=429,detail="fetcher busy")
    try:
        return await _fetch(req)
    finally:
        _fetch_sem.release()

async def _fetch(req:FetchRequest):
    current=req.url; hops=[]; seen=set(); pages=[]; max_hops=min(MAX_HOPS,req.options.max_hops); complete=False; errors=[]; started=time.monotonic(); domain_visits={}
    for i in range(max_hops):
        if time.monotonic()-started>=TOTAL_BUDGET:
            errors.append("total_budget_exceeded"); break
        try:
            deadline=started+TOTAL_BUDGET
            parsed,port,pinned=await validate_and_resolve_async(current,timeout=min(CONNECT_TIMEOUT,max(.05,deadline-time.monotonic())))
            data=await asyncio.to_thread(request_one,current,deadline,(parsed,port,pinned))
            p=urlsplit(current); loc=data["headers"].get("location")
            hop={"url":current,"status":data["status"],"location":loc,"resolved_ip":data["ip"],"registered_domain":p.hostname,"scheme":p.scheme,"content_type":data["headers"].get("content-type"),"elapsed_ms":data["elapsed_ms"],"via":"start" if i==0 else "http3xx"}
            hops.append(hop)
            if data["body"]:
                actions,actions_truncated=_password_form_evidence(data["body"])
                pages.append({"url":current,"password_form_actions":actions,"actions_truncated":actions_truncated})
            if data["truncated"]: errors.append("html_truncated")
            if data["status"] in (403,429): errors.append("destination_may_block_automated_clients")
            domain_visits[p.hostname]=domain_visits.get(p.hostname,0)+1
            via="http3xx"
            if not loc and data["headers"].get("refresh"):
                match=re.fullmatch(r"\s*\d+\s*;\s*url\s*=\s*['\"]?([^'\"]+)['\"]?\s*",data["headers"]["refresh"],re.I)
                if match: loc=match.group(1); via="refresh_header"
            if data["status"] in (300,301,302,303,304,305,307,308) and not loc:
                hop["notes"]=["redirect_without_location"]
            if not loc and data["body"] and data["status"]==200:
                meta=re.search(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"][^;]+;\s*url\s*=\s*([^'\"]+)['\"]",data["body"],re.I)
                if meta:
                    content=re.search(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"]([^'\"]+)['\"]",data["body"],re.I)
                    try: delay=float(content.group(1).split(";",1)[0].strip()) if content else 0
                    except ValueError: delay=999999
                    if delay<=5: loc=meta.group(1); via="meta_refresh"
                    else: hop.setdefault("notes",[]).append("delayed_meta_refresh_not_followed")
                else:
                    js=re.search(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*(['\"])([^'\"\r\n]{1,2048})\1|location\.(?:assign|replace)\(\s*(['\"])([^'\"\r\n]{1,2048})\3\s*\)",data["body"],re.I)
                    if js: loc=js.group(2) or js.group(4); via="js_literal"
                    if not loc and re.search(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(",data["body"],re.I):
                        hop.setdefault("notes",[]).append("possible_script_driven_redirect")
            if loc and (data["status"] in (301,302,303,307,308) or via in ("refresh_header","meta_refresh","js_literal")):
                if len(loc)>2048:
                    hop["location"]=None; hop["location_too_long"]=True
                    errors.append("location_too_long"); break
                hop["via"]=via
                next_url=urljoin(current,loc)
                if next_url in seen or domain_visits[p.hostname]>2: errors.append("redirect_loop"); break
                seen.add(current); current=next_url; continue
            complete=True; break
        except Blocked as e:
            hops.append({"url":current,"status":None,"location":None,"resolved_ip":None,"registered_domain":urlsplit(current).hostname,"scheme":urlsplit(current).scheme,"content_type":None,"elapsed_ms":0,"via":"http3xx" if hops else "start","blocked_reason":e.reason})
            errors.append("redirect_to_blocked_destination" if hops else e.reason); break
        except (OSError,ssl.SSLError,http.client.HTTPException,ValueError) as e:
            tls_error=isinstance(e,ssl.SSLError)
            reason=f"tls_error:{type(e).__name__}" if tls_error else "fetch_error"
            hops.append({"url":current,"status":None,"location":None,"resolved_ip":None,"registered_domain":urlsplit(current).hostname,"scheme":urlsplit(current).scheme,"content_type":None,"elapsed_ms":0,"via":"start" if not hops else "http3xx","blocked_reason":reason})
            errors.append("tls_error" if tls_error else "fetch_error"); break
    else:
        errors.append("excessive_hops")
    limitations=[] if complete else ["final_url is last reachable hop, not necessarily true destination"]
    if "destination_may_block_automated_clients" in errors: limitations.append("destination may serve different content to automated clients")
    return {"hops":hops,"final_url":hops[-1]["url"] if hops else None,"password_forms_by_hop":pages,"html_truncated":"html_truncated" in errors,"chain_complete":complete,"errors":errors,"limitations":limitations}

@app.get("/healthz")
async def healthz(): return {"status":"ok"}

def _authorize(x_fetcher_token: str) -> None:
    expected=os.getenv("FETCHER_TOKEN","")
    if not expected or not hmac.compare_digest(x_fetcher_token.encode("utf-8"),expected.encode("utf-8")):
        raise HTTPException(status_code=401)

@app.post("/probe/tls", response_model=TLSProbeResponse)
async def probe_tls(req: TLSProbeRequest, x_fetcher_token: str = Header(default="")):
    _authorize(x_fetcher_token)
    try:
        await asyncio.wait_for(_tls_sem.acquire(), 0.5)
    except TimeoutError:
        raise HTTPException(status_code=429)
    try:
        return await run_tls_probe(req)
    finally:
        _tls_sem.release()
