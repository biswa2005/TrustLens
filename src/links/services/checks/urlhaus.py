from links.models import Finding
from links.services.redis_store import lookup

async def run(url: str):
    try: records=await lookup(url)
    except Exception as exc: return "unavailable", [], str(exc)
    findings=[]
    for rec in records:
        active=rec.get("record_status")=="active"
        match=rec.get("matched_value_type","host")
        findings.append(Finding(id=f"intel_urlhaus.{rec.get('id')}",check_id="intel_urlhaus",category="intel",title="URLhaus indicator match",severity="strong" if active else "moderate",source="urlhaus",evidence_group="urlhaus",evidence_class="reputation",evidence={**rec,"active_confirmation_eligible":active and match in {"url","host"}}))
    return "ok",findings,None
