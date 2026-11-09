import asyncio
from links.services.checks.normalise import normalize
from links.services.analyser import Context, check_brand, check_lexical, BRANDS
from hypothesis import given, strategies as st

def test_brand_dataset_has_sixty_plus_entries():
    assert len(BRANDS)>=60

def test_typosquat_and_official_brand():
    async def check(url):
        ctx=Context(url); ctx.nurl=normalize(url); return await check_brand(ctx)
    assert asyncio.run(check('https://paypa1-login.com'))
    assert asyncio.run(check('https://paypal.com'))==[]

def test_cyrillic_homograph_detected():
    async def check():
        ctx=Context('https://раypal.example'); ctx.nurl=normalize(ctx.raw_input); return await check_brand(ctx)
    findings=asyncio.run(check())
    assert findings and findings[0].id.endswith('homograph')

def test_obfuscated_numeric_ipv4_forms():
    for value,expected,flag in [('2130706433','127.0.0.1','ip_decimal'),('0x7f.1','127.0.0.1','ip_hex'),('0177.0.0.1','127.0.0.1','ip_octal'),('127.1','127.0.0.1','ip_short')]:
        n=normalize('http://'+value)
        assert n.host==expected and flag in n.obfuscation_flags

def test_path_keyword_lexical_finding():
    async def check():
        ctx=Context('https://example.com/secure-login'); ctx.nurl=normalize(ctx.raw_input); return await check_lexical(ctx)
    assert any(f.id.endswith('phishing_keywords') for f in asyncio.run(check()))

def test_brand_claim_in_path_is_detected():
    async def check():
        ctx=Context('https://unrelated.example.com/paypal/login'); ctx.nurl=normalize(ctx.raw_input); return await check_brand(ctx)
    assert any(f.id.endswith('brand_claim') for f in asyncio.run(check()))

def test_normalizer_handles_defanged_userinfo_whitespace_and_unicode_dot():
    defanged=normalize('hxxps://evil[.]com/login')
    assert defanged.host=='evil.com' and 'defanged_input' in defanged.obfuscation_flags
    userinfo=normalize('https://paypal.com@evil.com/')
    assert userinfo.host=='evil.com' and '@' not in userinfo.normalised and 'userinfo_present' in userinfo.obfuscation_flags
    whitespace=normalize('https://pay\tpal.com/')
    assert whitespace.host=='paypal.com' and 'embedded_whitespace' in whitespace.obfuscation_flags
    unicode_dot=normalize('https://evil。com/')
    assert unicode_dot.host=='evil.com' and 'unicode_dot' in unicode_dot.obfuscation_flags

def test_normalizer_flags_scheme_port_and_mapped_ipv4():
    repaired=normalize('https:/evil.com')
    assert repaired.host=='evil.com' and 'scheme_repaired' in repaired.obfuscation_flags
    port=normalize('https://example.com:8443')
    assert 'nonstandard_port' in port.obfuscation_flags
    mapped=normalize('http://[::ffff:7f00:1]/')
    assert mapped.host=='127.0.0.1' and 'ip_ipv4_mapped' in mapped.obfuscation_flags

def test_normalizer_rejects_bidi_host_and_caps_embedded_url_scanning():
    import pytest
    with pytest.raises(ValueError,match='bidi_in_host'): normalize('https://exa\u202emple.com')
    nested='&'.join(f'next=https://host{i}.example/' for i in range(7))
    parsed=normalize('https://example.com/?'+nested)
    assert len(parsed.embedded_urls)<=5 and 'embedded_url_scan_capped' in parsed.obfuscation_flags

def test_browser_parser_disagreement_path_normalization_and_base64_destination():
    import base64
    disagreement=normalize(r'https://evil.com\@paypal.com/')
    assert disagreement.host=='evil.com' and 'parser_disagreement' in disagreement.obfuscation_flags
    path=normalize('https://good.com/a/%2e%2e/b')
    assert path.path=='/b' and path.normalised=='https://good.com/b'
    encoded=base64.urlsafe_b64encode(b'https://evil.example/path').decode().rstrip('=')
    parsed=normalize('https://good.com/?next='+encoded)
    assert parsed.embedded_urls==['https://evil.example/path']
    assert 'embedded_encoded_url' in parsed.obfuscation_flags
    async def check():
        ctx=Context('https://good.com/?next='+encoded); ctx.nurl=parsed
        return await check_lexical(ctx)
    assert any(item.id.endswith('embedded_encoded_url') for item in asyncio.run(check()))

@given(st.text(max_size=2048))
def test_normalizer_fuzz_returns_canonical_url_or_value_error(raw):
    try:
        parsed=normalize(raw)
        assert parsed.host and parsed.normalised.startswith(('http://','https://'))
    except ValueError:
        pass

