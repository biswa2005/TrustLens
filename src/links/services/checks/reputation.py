from __future__ import annotations
import os, base64, json, asyncio, time
from collections import deque
import httpx
from links.models import Finding
from links.services import db

_vt_times=deque()
_vt_lock=asyncio.Lock()
_sb_times=deque()
_sb_lock=asyncio.Lock()

async def _minute_permit(queue,lock,limit):
    now=time.monotonic()
    async with lock:
        while queue and now-queue[0]>=60: queue.popleft()
        if len(queue)>=limit: return False
        queue.append(now); return True

async def _vt_permit():
    now=time.monotonic(); per_min=max(1,int(os.getenv("VT_REQUESTS_PER_MINUTE","4")))
    async with _vt_lock:
        while _vt_times and now-_vt_times[0]>=60: _vt_times.popleft()
        if len(_vt_times)>=per_min: return False
        daily=await db.increment_usage("virustotal")
        if daily is not None and daily>int(os.getenv("VT_DAILY_LIMIT","500")): return False
        _vt_times.append(now); return True

async def safe_browsing(urls):
    key=os.getenv("SAFE_BROWSING_API_KEY")
    if not key: return "unavailable",[],"Safe Browsing key not configured"
    urls=list(dict.fromkeys(urls))[:50]; cache_query=json.dumps(urls,separators=(",",":"))
    try:
        cached=await db.cache_get("safebrowsing",cache_query)
        if cached is not None: return "ok",[Finding.model_validate(x) for x in cached],None
    except Exception: pass
    if not await _minute_permit(_sb_times,_sb_lock,int(os.getenv("SB_REQUESTS_PER_MINUTE","20"))):
        return "unavailable",[],"Safe Browsing rate limit reached"
    body={"client":{"clientId":"trustlens","clientVersion":"0.1.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":u} for u in urls]}}
    try:
        async with httpx.AsyncClient(timeout=5) as c: r=await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",params={"key":key},json=body)
        r.raise_for_status(); data=r.json()
        fs=[Finding(id="intel_safebrowsing."+str(i),check_id="intel_safebrowsing",category="intel",title="Google Safe Browsing threat match",severity="strong",source="google_safe_browsing",evidence_group="reputation_safebrowsing",evidence_class="reputation",evidence={"match_level":"exact_url","threat_type":m.get("threatType"),"url":m.get("threat",{}).get("url")}) for i,m in enumerate(data.get("matches",[]))]
        try: await db.cache_put("safebrowsing",cache_query,[x.model_dump(mode="json") for x in fs],int(os.getenv("CACHE_TTL_HIT_SECONDS" if fs else "CACHE_TTL_CLEAN_SECONDS","3600" if fs else "21600")))
        except Exception: pass
        return "ok",fs,None
    except httpx.HTTPStatusError as exc:
        return "unavailable",[],"Safe Browsing rejected the request" if exc.response.status_code in (400,403) else "Safe Browsing service error"
    except Exception: return "unavailable",[],"Safe Browsing request failed"

async def virustotal(urls, domains=()):
    key=os.getenv("VIRUSTOTAL_API_KEY")
    if not key: return "unavailable",[],"VirusTotal key not configured"
    fs=[]
    try:
        async with httpx.AsyncClient(timeout=6,headers={"x-apikey":key}) as c:
            queries=[("url",u) for u in list(dict.fromkeys(urls))[:2]]
            queries.extend(("registered_domain",d) for d in list(dict.fromkeys(domains))[:1])
            for query_type,url in queries:
                query=f"{query_type}:{url}"
                cached=None
                try: cached=await db.cache_get("virustotal",query)
                except Exception: pass
                if cached is not None:
                    fs.extend(Finding.model_validate(x) for x in cached); continue
                if not await _vt_permit(): return "unavailable",fs,"VirusTotal rate limit reached"
                if query_type=="url":
                    vid=base64.urlsafe_b64encode(url.encode()).decode().rstrip("="); endpoint=f"https://www.virustotal.com/api/v3/urls/{vid}"
                else: endpoint=f"https://www.virustotal.com/api/v3/domains/{url}"
                r=await c.get(endpoint)
                if r.status_code==429: return "unavailable",fs,"VirusTotal rate limit reached"
                if r.status_code==404:
                    try: await db.cache_put("virustotal",query,[],int(os.getenv("CACHE_TTL_CLEAN_SECONDS","21600")))
                    except Exception: pass
                    continue
                r.raise_for_status(); attrs=r.json().get("data",{}).get("attributes",{})
                stats=attrs.get("last_analysis_stats",{}); engines=attrs.get("last_analysis_results",{})
                malicious=sum(1 for name,result in engines.items() if not ("google" in name.lower() and "safe" in name.lower() and "brows" in name.lower()) and result.get("category")=="malicious")
                found=[]
                if malicious:
                    level="exact_url" if query_type=="url" else "registered_domain"
                    severity="strong" if query_type=="url" and malicious>=int(os.getenv("VT_CONFIRM_THRESHOLD","5")) else "moderate"
                    found=[Finding(id=f"intel_virustotal.{query_type}.{len(fs)}",check_id="intel_virustotal",category="intel",title="VirusTotal reports malicious engines",severity=severity,source="virustotal",evidence_group="reputation_virustotal",evidence_class="reputation",evidence={"malicious_excl_gsb":malicious,"match_level":level,"total_malicious":stats.get("malicious",0),"target_url":url})]
                fs.extend(found)
                try: await db.cache_put("virustotal",query,[x.model_dump(mode="json") for x in found],int(os.getenv("CACHE_TTL_HIT_SECONDS" if found else "CACHE_TTL_CLEAN_SECONDS","3600" if found else "21600")))
                except Exception: pass
        return "ok",fs,None
    except httpx.HTTPStatusError as exc:
        return "unavailable",fs,"VirusTotal quota exhausted" if exc.response.status_code==429 else "VirusTotal service error"
    except Exception: return "unavailable",fs,"VirusTotal request failed"
