"""Registered Module 1 check runner with dependency and timeout semantics."""
from __future__ import annotations
import asyncio, time
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from links.models import CheckResult, Finding

CheckFn=Callable[["Context"],Awaitable[list[Finding] | tuple[CheckResult,list[Finding]]]]

class CheckUnavailable(Exception):
    def __init__(self, reason: str, findings=None):
        super().__init__(reason)
        self.findings=list(findings or [])

@dataclass
class Context:
    raw_input:str
    options:dict=field(default_factory=dict)
    nurl:object|None=None
    fetch_result:dict|None=None
    values:dict=field(default_factory=dict)

@dataclass(frozen=True)
class CheckSpec:
    check_id:str
    fn:CheckFn
    depends_on:tuple[str,...]=()
    requires_success:tuple[str,...]=()
    timeout:float=10.0
    needs_network:bool=False

CHECKS:dict[str,CheckSpec]={}

def register_check(check_id:str,*,depends_on=(),requires_success=None,timeout=10.0,needs_network=False):
    def decorate(fn:CheckFn):
        if check_id in CHECKS: raise ValueError(f"duplicate check id: {check_id}")
        required=tuple(depends_on) if requires_success is None else tuple(requires_success)
        CHECKS[check_id]=CheckSpec(check_id,fn,tuple(depends_on),required,timeout,needs_network)
        return fn
    return decorate

async def execute(spec:CheckSpec,ctx:Context,prior:dict[str,CheckResult]):
    for dep in spec.requires_success:
        if prior.get(dep) is None or prior[dep].status!="ok":
            return CheckResult(check_id=spec.check_id,status="unavailable",reason=f"dependency {dep} did not complete"),[]
    if spec.check_id in ctx.options.get("skip_checks",set()):
        return CheckResult(check_id=spec.check_id,status="skipped",reason="skipped by request"),[]
    started=time.monotonic()
    try:
        output=await asyncio.wait_for(spec.fn(ctx),timeout=spec.timeout)
        if isinstance(output, tuple) and len(output)==2 and isinstance(output[0], CheckResult):
            result, findings = output
            result.check_id=spec.check_id
            result.duration_ms=int((time.monotonic()-started)*1000)
            return result, findings
        findings=output
        return CheckResult(check_id=spec.check_id,status="ok",duration_ms=int((time.monotonic()-started)*1000)),findings
    except CheckUnavailable as exc:
        return CheckResult(check_id=spec.check_id,status="unavailable",reason=str(exc),duration_ms=int((time.monotonic()-started)*1000)),exc.findings
    except asyncio.TimeoutError:
        return CheckResult(check_id=spec.check_id,status="unavailable",reason="check timed out",duration_ms=int((time.monotonic()-started)*1000)),[]
    except Exception as exc:
        return CheckResult(check_id=spec.check_id,status="error",reason=f"{type(exc).__name__}",duration_ms=int((time.monotonic()-started)*1000)),[]

async def run_all(ctx:Context,order:list[str]):
    results={}; findings=[]
    if not order or order[0]!="normalise": raise ValueError("normalise must run first")
    first=CHECKS["normalise"]
    result,found=await execute(first,ctx,results); results[first.check_id]=result; findings.extend(found)
    if result.status!="ok":
        return [results[first.check_id]]+[CheckResult(check_id=cid,status="skipped",reason="normalisation failed") for cid in order[1:]],findings
    remaining=set(order[1:])
    while remaining:
        ready=[cid for cid in order if cid in remaining and all(dep in results for dep in CHECKS[cid].depends_on)]
        if not ready: raise ValueError("check dependencies contain a cycle or unknown check")
        outputs=await asyncio.gather(*(execute(CHECKS[cid],ctx,results) for cid in ready))
        for cid,(result,found) in zip(ready,outputs): results[cid]=result; findings.extend(found)
        remaining.difference_update(ready)
    return [results[cid] for cid in order],findings
