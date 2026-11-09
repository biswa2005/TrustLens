import ipaddress, socket, pytest
from fetcher.guard import validate_and_resolve, Blocked

def addr(value):
    ip=ipaddress.ip_address(value)
    if ip.version==4: return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(value,443))]
    return [(socket.AF_INET6,socket.SOCK_STREAM,6,'',(value,443,0,0))]
def test_guard_blocks_loopback(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('127.0.0.1'))
    with pytest.raises(Blocked): validate_and_resolve('http://127.0.0.1')
def test_guard_blocks_mixed_dns(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('8.8.8.8')+addr('10.0.0.3'))
    with pytest.raises(Blocked) as e: validate_and_resolve('https://mixed.test')
    assert e.value.reason=='mixed_records'

def test_guard_blocks_mixed_public_ipv4_and_private_ipv6(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr('8.8.8.8')+addr('fd00::1'))
    with pytest.raises(Blocked) as e: validate_and_resolve('https://mixed-v6.test')
    assert e.value.reason=='mixed_records'

@pytest.mark.parametrize('ip',[
    '10.0.0.1','100.100.100.200','127.0.0.1','169.254.169.254',
    '172.16.0.1','192.168.1.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1',
])
def test_guard_blocks_non_public_dns_results(monkeypatch,ip):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:addr(ip))
    with pytest.raises(Blocked): validate_and_resolve('https://unsafe.example')
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
