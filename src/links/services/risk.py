from collections import defaultdict

ORDER={"info":0,"weak":1,"moderate":2,"strong":3}
GATING_CHECKS: frozenset[str] = frozenset({"normalise", "lexical", "brand_impersonation", "redirect_chain", "password_form", "dns", "rdap", "intel_safebrowsing", "intel_virustotal", "intel_urlhaus"})

def _ok_gating(coverage):
    return {c.check_id for c in coverage if c.check_id in GATING_CHECKS and c.status=="ok"}

def classify(findings, checks, chain_complete=True):
    groups=defaultdict(list)
    for f in findings:
        if f.severity!="info": groups[f.evidence_group or f.check_id].append(f)
    summary=[]
    for name,items in groups.items(): summary.append({"group":name,"evidence_class":items[0].evidence_class,"severity":max((x.severity for x in items),key=ORDER.get),"rules":[x.id for x in items],"targets":sorted({x.target for x in items})})
    s=[g for g in summary if g["severity"]=="strong"]; m=[g for g in summary if g["severity"]=="moderate"]; w=[g for g in summary if g["severity"]=="weak"]
    confirm=any(f.check_id=="intel_safebrowsing" and f.evidence.get("match_level") in ("exact_url","host") for f in findings) or any(f.check_id=="intel_virustotal" and f.evidence.get("malicious_excl_gsb",0)>=5 and f.evidence.get("match_level") in ("exact_url","host") for f in findings) or any(f.check_id=="intel_urlhaus" and f.evidence.get("active_confirmation_eligible") for f in findings)
    vt_minor=any(f.check_id=="intel_virustotal" and 1<=f.evidence.get("malicious_excl_gsb",0)<=4 for f in findings)
    classes=lambda gs:len({g["evidence_class"] for g in gs})
    if confirm: risk="confirmed_malicious"
    elif (len(s)>=2 and classes(s)>=2) or (len(s)>=1 and len(m)>=2 and classes(s+m)>=2) or (vt_minor and any(g["evidence_class"]!="reputation" for g in m+s)): risk="high"
    elif s or m or len(w)>=3: risk="suspicious"
    else:
        ok=_ok_gating(checks)
        external=bool(ok & {"intel_safebrowsing","intel_virustotal"})
        risk="low" if len(ok)>=7 and external else "inconclusive"
    return risk,summary

def confidence_for(checks,chain_complete=False):
    ok=_ok_gating(checks)
    completed=len(ok)
    external=bool(ok & {"intel_safebrowsing","intel_virustotal"})
    if completed>=8 and chain_complete and external: return "high"
    if completed>=6 and (chain_complete or external or "intel_urlhaus" in ok): return "medium"
    return "low"

def explain(risk,groups,findings,checks=(),chain_complete=True):
    if risk=="confirmed_malicious":
        match=next((f for f in findings if
            (f.check_id=="intel_safebrowsing" and f.evidence.get("match_level") in ("exact_url","host")) or
            (f.check_id=="intel_virustotal" and f.evidence.get("malicious_excl_gsb",0)>=5 and f.evidence.get("match_level") in ("exact_url","host")) or
            (f.check_id=="intel_urlhaus" and f.evidence.get("active_confirmation_eligible"))),None)
        return f"Confirmed Malicious: authoritative reputation match at {match.target if match else 'an analysed target'}."
    if risk=="high":
        strong=[g for g in groups if g["severity"]=="strong"]
        names=[]
        for group in groups:
            rules=", ".join(rule.rsplit(".",1)[-1] for rule in group["rules"])
            targets=", ".join(group["targets"])
            names.append(f"{group['group']} ({group['evidence_class']}: {rules}; target: {targets})")
        return f"High Risk: {len(strong)} Strong groups across {len({g['evidence_class'] for g in strong})} classes. " + "; ".join(names)
    classes={g["evidence_class"] for g in groups}
    if risk=="suspicious" and len(classes)==1:
        label=next(iter(classes))
        source={"static":"the URL text","behavioural":"redirect or page behaviour","infrastructure":"domain infrastructure","reputation":"reputation sources"}.get(label,label)
        return f"Suspicious: all indicators derive from {source}, with no independent corroboration."
    if risk=="inconclusive":
        if any(c.status=="skipped" and c.check_id in {"intel_safebrowsing","intel_virustotal"} for c in checks):
            return "Inconclusive: reputation checks were skipped; no clean bill of health can be inferred."
        return "Inconclusive: insufficient independent evidence or coverage to assess this URL."
    if risk=="low":
        reason="Low Risk: no significant indicators were found and the minimum reputation coverage gate was met."
        if not chain_complete: reason += " The redirect chain could not be followed to its end."
        return reason
    return f"{risk.replace('_',' ').title()}: evidence warrants caution."

RECOMMENDATIONS={
    "confirmed_malicious":["Do not open the link or enter credentials. If you already entered a password, change it and enable MFA; report the link to the impersonated organisation."],
    "high":["Do not enter credentials or payment details. Navigate to the organisation by typing its known address."],
    "suspicious":["Verify the sender and URL through a separate channel before proceeding."],
    "inconclusive":["Treat the link with caution. Some checks could not run; retry later."],
    "low":["Use standard caution. No significant malicious indicators were found within the checks completed; this does not guarantee the site is safe."],
}
