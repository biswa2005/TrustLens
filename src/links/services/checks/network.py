from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
import dns.asyncresolver
import dns.exception
import dns.resolver
from links.models import Finding
from links.services import db

async def dns_check(host: str, registered_domain: str|None=None):
    domain=registered_domain or host; resolver=dns.asyncresolver.Resolver(); findings=[]; records={}; errors=[]
    for name,types in ((host,("A","AAAA")),(domain,("MX","NS","TXT"))):
        for kind in types:
            try:
                answer=await resolver.resolve(name,kind,lifetime=3,raise_on_no_answer=False)
                if answer.rrset is None: continue
                records.setdefault(kind,[]).extend(str(x) for x in answer)
                if kind=="A": records.setdefault("ttl",[]).append(answer.rrset.ttl)
            except dns.resolver.NXDOMAIN:
                errors.append("nxdomain")
            except (dns.resolver.NoAnswer,dns.resolver.NoNameservers):
                continue
            except (dns.exception.Timeout,OSError):
                errors.append("timeout")
    if records:
        for kind in ("A","AAAA","MX","NS"):
            for value in dict.fromkeys(records.get(kind,[])):
                findings.append(Finding(id=f"dns.{kind.lower()}.{len(findings)}",check_id="dns",category="dns",title=f"DNS {kind} record present",severity="info",evidence_group="dns_hosting",evidence_class="infrastructure",evidence={"record_type":kind,"value":value[:255]}))
        if records.get("ttl") and min(records["ttl"])<60:
            findings.append(Finding(id="dns.low_ttl",check_id="dns",category="dns",title="DNS records have a low TTL",severity="weak",evidence_group="dns_hosting",evidence_class="infrastructure",evidence={"minimum_ttl":min(records["ttl"])}))
        return "ok",findings,None
    if "nxdomain" in errors:
        return "ok",[Finding(id="dns.no_dns_records",check_id="dns",category="dns",title="Domain has no DNS records",severity="moderate",evidence_group="dns_hosting",evidence_class="infrastructure",evidence={"host":host})],None
    return "unavailable",[],"DNS resolution timed out or returned no records"

async def rdap_check(domain: str):
    try:
        bootstrap=await db.cache_get("rdap_bootstrap","iana-dns-v1")
        async with httpx.AsyncClient(timeout=5,follow_redirects=False,headers={"Accept":"application/rdap+json"}) as client:
            if bootstrap is None:
                r=await client.get("https://data.iana.org/rdap/dns.json"); r.raise_for_status(); bootstrap=r.json()
                await db.cache_put("rdap_bootstrap","iana-dns-v1",bootstrap,86400)
            tld=domain.rsplit(".",1)[-1].lower(); base=None
            for tlds,urls in bootstrap.get("services",[]):
                if tld in [x.lower() for x in tlds]:
                    base=next((u for u in urls if u.startswith("https://")),None); break
            if not base: return "unavailable",[],f"no RDAP service for .{tld}"
            response=await client.get(base.rstrip("/")+"/domain/"+domain)
        if response.status_code!=200: return "unavailable",[],f"RDAP status {response.status_code}"
        data=response.json(); created=None
        for event in data.get("events",[]):
            if event.get("eventAction","").lower() in ("registration","registered","created"):
                created=datetime.fromisoformat(event["eventDate"].replace("Z","+00:00")); break
        if created is None: return "unavailable",[],"registration date unavailable"
        age=max(0,(datetime.now(timezone.utc)-created).days); findings=[]
        if age<30: findings.append(Finding(id="rdap.newly_registered",check_id="rdap",category="infrastructure",title="Recently registered domain",severity="strong",evidence_group="domain_age",evidence_class="infrastructure",evidence={"age_days":age,"created":created.isoformat()}))
        elif age<=90: findings.append(Finding(id="rdap.recently_registered",check_id="rdap",category="infrastructure",title="Recently registered domain",severity="weak",evidence_group="domain_age",evidence_class="infrastructure",evidence={"age_days":age,"created":created.isoformat()}))
        return "ok",findings,None
    except Exception as exc: return "unavailable",[],f"RDAP lookup unavailable ({type(exc).__name__})"
