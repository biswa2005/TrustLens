import socket, pytest
from fetcher.guard import validate_and_resolve, Blocked

def addr(ip): return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]
def test_guard_blocks_loopback(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('127.0.0.1'))
    with pytest.raises(Blocked): validate_and_resolve('http://127.0.0.1')
def test_guard_blocks_mixed_dns(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('8.8.8.8')+addr('10.0.0.3'))
    with pytest.raises(Blocked) as e: validate_and_resolve('https://mixed.test')
    assert e.value.reason=='mixed_records'
def test_guard_rejects_nonstandard_port_without_resolution(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:pytest.fail('must not resolve'))
    with pytest.raises(Blocked) as e: validate_and_resolve('https://example.com:8080')
    assert e.value.reason=='port_not_allowed'
def test_guard_pins_public_resolution(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('8.8.8.8'))
    p,port,ip=validate_and_resolve('https://example.com')
    assert ip=='8.8.8.8' and p.hostname=='example.com' and port==443

@pytest.mark.parametrize('url',['http://2130706433','http://0x7f.1','http://0177.0.0.1','http://127.1','http://[::ffff:127.0.0.1]'])
def test_guard_blocks_obfuscated_loopback_literals(url):
    with pytest.raises(Blocked): validate_and_resolve(url)
