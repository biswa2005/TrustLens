from links.services.checks.normalise import normalize
from links.services.risk import classify
from links.models import (
    CheckResult, Coverage, DomainInfo, EvidenceGroup, Finding, IntelMatch,
    RedirectSummary, Report, Target,
)
import pytest

def test_normalize_domain():
    n=normalize("example.com/path")
    assert n.host == "example.com" and n.scheme == "https"

def test_normalize_rejects_unsafe_scheme():
    import pytest
    with pytest.raises(ValueError): normalize("javascript:alert(1)")

def test_urlhaus_active_confirms_but_historical_does_not():
    active=Finding(id="u1",check_id="intel_urlhaus",category="intel",title="match",severity="strong",evidence={"active_confirmation_eligible":True},evidence_group="urlhaus",evidence_class="reputation")
    old=active.model_copy(update={"evidence":{"active_confirmation_eligible":False}})
    assert classify([active],[])[0] == "confirmed_malicious"
    assert classify([old],[])[0] != "confirmed_malicious"

def test_plan_models_validate_and_round_trip_as_report_components():
    target = Target(url="https://example.com/", host="example.com", registered_domain="example.com", target="input")
    match = IntelMatch(source="urlhaus", match_level="host", raw_summary={"status": "active"})
    domain = DomainInfo(age_days=120, nameservers=["ns.example.com"])
    group = EvidenceGroup(group="urlhaus", evidence_class="reputation", severity="strong", rules=["intel_urlhaus.active_host"], targets=["input"])
    redirect = RedirectSummary(start_registered_domain="example.com", final_registered_domain="example.net", hop_count=2, cross_site=True)
    report = Report(
        input=target.url,
        risk_class="suspicious",
        coverage=Coverage(completed=1, planned=10, checks=[CheckResult(check_id="normalise", status="ok")]),
        intel_matches=[match], domain_info=domain, evidence_groups=[group], redirect_summary=redirect,
    )
    restored = Report.model_validate(report.model_dump(mode="json"))
    assert restored.intel_matches[0].match_level == "host"
    assert restored.domain_info.age_days == 120
    assert restored.evidence_groups[0].targets == ["input"]
    assert restored.redirect_summary.cross_site

def test_plan_models_reject_invalid_report_enums():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Report(input="x", risk_class="safe", coverage=Coverage(completed=0, checks=[]))
