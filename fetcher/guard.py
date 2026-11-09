import ipaddress, socket, asyncio
from urllib.parse import urlsplit

ALLOWED_PORTS={"http":80,"https":443}

class Blocked(Exception):
    def __init__(self, reason): self.reason=reason

def _numeric_ip(host):
    value=host.rstrip("."); parts=value.split(".")
    def numeric(part): return part.isdecimal() or part.lower().startswith("0x") or (len(part)>1 and part.startswith("0"))
    if not parts or not all(numeric(x) for x in parts): return None
    if len(parts)>4: raise Blocked("invalid_ip")
    try:
        nums=[]
        for part in parts:
            if part.lower().startswith("0x"): n=int(part[2:] or "0",16)
            elif len(part)>1 and part.startswith("0"):
                if any(c not in "01234567" for c in part[1:]): raise ValueError
                n=int(part[1:] or "0",8)
            else: n=int(part,10)
            nums.append(n)
        if any(n>255 for n in nums[:-1]) or nums[-1]>=256**(5-len(nums)): raise ValueError
        assembled=sum(n<<(8*(3-i)) for i,n in enumerate(nums[:-1]))+nums[-1]
        return ipaddress.IPv4Address(assembled)
    except ValueError: raise Blocked("invalid_ip")

def parse_url(url: str):
    p=urlsplit(url)
    if p.scheme not in ALLOWED_PORTS: raise Blocked("scheme_not_allowed")
    if p.username is not None or p.password is not None: raise Blocked("userinfo")
    try: port=p.port or ALLOWED_PORTS[p.scheme]
    except ValueError: raise Blocked("port_not_allowed")
    if port!=ALLOWED_PORTS[p.scheme]: raise Blocked("port_not_allowed")
    if not p.hostname: raise Blocked("dns_failure")
    numeric=_numeric_ip(p.hostname)
    if numeric is not None:
        if not numeric.is_global: raise Blocked("private_ip")
        return p,port,str(numeric)
    try:
        literal=ipaddress.ip_address(p.hostname.split("%",1)[0])
        mapped=getattr(literal,"ipv4_mapped",None)
        if mapped: literal=mapped
        if not literal.is_global or literal.is_multicast: raise Blocked("private_ip")
        return p,port,str(literal)
    except ValueError: pass
    return p,port

def validate_records(records):
    ips=[]
    for record in records:
        ip=ipaddress.ip_address(record[4][0].split("%",1)[0])
        mapped=getattr(ip,"ipv4_mapped",None)
        if mapped: ip=mapped
        if not ip.is_global or ip.is_multicast: raise Blocked("mixed_records" if ips else "private_ip")
        ips.append(str(ip))
    if not ips: raise Blocked("dns_failure")
    return sorted(set(ips))[0]

def validate_and_resolve(url: str):
    p,port=parse_url(url)
    try: records=socket.getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM)
    except OSError: raise Blocked("dns_failure")
    return p,port,validate_records(records)

async def validate_and_resolve_async(url: str,timeout:float=3):
    p,port=parse_url(url)
    numeric=_numeric_ip(p.hostname)
    if numeric is not None:
        if not numeric.is_global: raise Blocked("private_ip")
        return p,port,str(numeric)
    try:
        literal=ipaddress.ip_address(p.hostname.split("%",1)[0]); mapped=getattr(literal,"ipv4_mapped",None)
        if mapped: literal=mapped
        if not literal.is_global or literal.is_multicast: raise Blocked("private_ip")
        return p,port,str(literal)
    except ValueError: pass
    try:
        infos=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM),timeout=timeout)
    except Exception: raise Blocked("dns_failure")
    return p,port,validate_records(infos)
