import asyncio, time
import pytest
from links.models import CheckResult
from links.services.registry import CheckSpec, Context, execute, CHECKS
from links.services import analyser  # import the module that registers the production checks

@pytest.mark.parametrize('check_id', ['normalise','lexical','brand_impersonation','redirect_chain','password_form','dns','rdap','intel_safebrowsing','intel_virustotal','intel_urlhaus'])
def test_all_ten_checks_are_registered(check_id):
    assert check_id in CHECKS

def test_dependency_failure_marks_unavailable():
    async def fn(ctx): return []
    spec=CheckSpec('child',fn,depends_on=('parent',),requires_success=('parent',))
    result,findings=asyncio.run(execute(spec,Context('x'),{'parent':CheckResult(check_id='parent',status='error')}))
    assert result.status=='unavailable' and 'parent' in result.reason and findings==[]

def test_ordering_dependency_does_not_require_success_when_declared_independent():
    async def fn(ctx): return []
    spec=CheckSpec('independent',fn,depends_on=('fetch',),requires_success=())
    result,findings=asyncio.run(execute(spec,Context('x'),{'fetch':CheckResult(check_id='fetch',status='unavailable')}))
    assert result.status=='ok' and findings==[]

def test_check_timeout_is_reported_without_stack_trace():
    async def fn(ctx): await asyncio.sleep(.05); return []
    spec=CheckSpec('slow',fn,timeout=.001)
    result,_=asyncio.run(execute(spec,Context('x'),{}))
    assert result.status=='unavailable' and result.reason=='check timed out'

