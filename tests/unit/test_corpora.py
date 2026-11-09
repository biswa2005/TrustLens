import asyncio, json
from pathlib import Path
from links.services.registry import Context
from links.services.checks.normalise import normalize
from links.services.analyser import check_lexical, check_brand
from links.services.risk import classify

ROOT=Path(__file__).resolve().parents[1]/'corpus'
def corpus(name): return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))
async def scan(url):
    ctx=Context(url); ctx.nurl=normalize(url)
    return await check_lexical(ctx)+await check_brand(ctx)

def test_suspicious_offline_corpus_has_expected_static_only_class():
    for case in corpus('suspicious.json'):
        assert case['fetch'] is False
        findings=asyncio.run(scan(case['input']))
        risk,_=classify(findings,[])
        assert risk==case['expected_class_min'],(case['input'],risk,findings)

def test_benign_corpus_never_gets_high_from_static_only_evidence():
    for case in corpus('benign.json'):
        findings=asyncio.run(scan(case['input']))
        risk,_=classify(findings,[])
        assert risk in case['expected_classes'],(case['input'],risk,findings)
        assert risk!='high'
