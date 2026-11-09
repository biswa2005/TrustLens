from __future__ import annotations
import ipaddress, re
import base64
from urllib.parse import urlsplit, urlunsplit, unquote, parse_qsl
import idna
import tldextract
from links.models import NormalisedURL

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

def _number_component(value:str)->int:
    if value.lower().startswith("0x"): return int(value[2:] or "0",16)
    if len(value)>1 and value.startswith("0"): return int(value[1:] or "0",8)
    return int(value,10)

def _whatwg_ipv4(host:str)->tuple[str|None,str|None]:
    """Canonicalize decimal, octal, hexadecimal, and shortened IPv4 forms."""
    candidate=host[:-1] if host.endswith(".") else host
    parts=candidate.split(".")
    numeric=lambda x: x.isdecimal() or x.lower().startswith("0x") or (len(x)>1 and x.startswith("0") and all(c in "01234567" for c in x[1:]))
    if not parts or not all(numeric(x) for x in parts): return None,None
    if len(parts)>4: raise ValueError("invalid_ipv4")
    nums=[_number_component(x) for x in parts]
    if any(n>255 for n in nums[:-1]) or nums[-1]>=256**(5-len(nums)): raise ValueError("invalid_ipv4")
    value=sum(n<<(8*(3-i)) for i,n in enumerate(nums[:-1]))+nums[-1]
    flags=[]
    if len(nums)<4: flags.append("ip_short")
    if any(x.lower().startswith("0x") for x in parts): flags.append("ip_hex")
    if any(len(x)>1 and x.startswith("0") and not x.lower().startswith("0x") for x in parts): flags.append("ip_octal")
    if all(x.isdecimal() for x in parts) and len(parts)==1: flags.append("ip_decimal")
    return str(ipaddress.IPv4Address(value)),",".join(flags) or None

def _whatwg_path(path:str)->str:
    """Resolve literal and percent-encoded dot segments like a browser URL parser."""
    if not path: return "/"
    absolute=path.startswith("/"); trailing=path.endswith("/")
    stack=[]
    for segment in path.split("/"):
        dots=segment.lower().replace("%2e",".")
        if dots=="." or dots=="":
            if segment=="": trailing=True
            continue
        if dots=="..":
            if stack: stack.pop()
            trailing=True
            continue
        stack.append(segment); trailing=False
    result=("/" if absolute else "")+"/".join(stack)
    if trailing and result and not result.endswith("/"): result+="/"
    return result or "/"

def normalize(raw: str) -> NormalisedURL:
    original=raw.strip()
    value=original
    if not value or len(value)>2048 or "\x00" in value: raise ValueError("invalid_url")
    flags=[]
    cleaned=value.replace("\t","").replace("\r","").replace("\n","")
    if cleaned!=value: flags.append("embedded_whitespace")
    value=cleaned
    for hidden in ("\u200b","\u200c","\u200d","\ufeff"):
        if hidden in value: value=value.replace(hidden,""); flags.append("hidden_characters")
    if re.match(r"^hxxps?://",value,re.I):
        value=re.sub(r"^hxxps?://",lambda m:"https://" if m.group(0).lower().startswith("hxxps") else "http://",value,flags=re.I)
        flags.append("defanged_input")
    if "[.]" in value or "(.)" in value:
        value=value.replace("[.]",".").replace("(.)","."); flags.append("defanged_input")
    if value.startswith("//"): value="https:"+value; flags.append("scheme_repaired")
    repaired=re.sub(r"^(https?):/{1}(?!/)",r"\1://",value,flags=re.I)
    repaired=re.sub(r"^(https?):(?!//)",r"\1://",repaired,flags=re.I)
    if repaired!=value: flags.append("scheme_repaired")
    value=repaired
    candidate=value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",value) else "https://"+value
    if "\\" in candidate:
        before=urlsplit(candidate).hostname
        candidate=candidate.replace("\\","/"); flags.append("backslash_authority")
        after=urlsplit(candidate).hostname
        if before and after and before.lower()!=after.lower():
            flags.append("parser_disagreement")
    p=urlsplit(candidate)
    if p.scheme.lower() not in ("http","https") or not p.hostname: raise ValueError("scheme_or_host_not_allowed")
    if any(ch in p.hostname for ch in ("\u202a","\u202b","\u202c","\u202d","\u202e","\u2066","\u2067","\u2068","\u2069")): raise ValueError("bidi_in_host")
    if "@" in p.netloc: flags.append("userinfo_present")
    if "%" in p.hostname: flags.append("percent_encoded_host")
    if any(ch in p.hostname for ch in ("。","．","｡")): flags.append("unicode_dot")
    if p.hostname.endswith("."): flags.append("trailing_dot")
    rawhost=unquote(p.hostname).rstrip(".").lower().replace("。",".").replace("．",".").replace("｡",".")
    try:
        canonical,flag=_whatwg_ipv4(rawhost)
        if canonical:
            rawhost=canonical
            if flag: flags.extend(flag.split(","))
        try: ip=ipaddress.ip_address(rawhost)
        except ValueError: ip=None
        if ip is not None and getattr(ip,"ipv4_mapped",None): ip=ip.ipv4_mapped; rawhost=str(ip); flags.append("ip_ipv4_mapped")
        host=str(ip) if ip else idna.encode(rawhost,uts46=True).decode().lower()
    except (ValueError,idna.IDNAError): raise ValueError("invalid_host")
    ext=_extract(host); registered=".".join(x for x in (ext.domain,ext.suffix) if x) or host; sub=ext.subdomain
    try: unicode_host=idna.decode(host)
    except idna.IDNAError: unicode_host=host
    try: port=p.port
    except ValueError: raise ValueError("invalid_port")
    if port not in (None,80,443): flags.append("nonstandard_port")
    netloc=host+(f":{port}" if port else "")
    path=_whatwg_path(p.path)
    norm=urlunsplit((p.scheme.lower(),netloc,path,p.query,""))
    query=unquote(p.query)
    embedded=re.findall(r"https?%3A%2F%2F[^&\s]+|https?://[^&\s]+",query,re.I)[:5]
    for _,item in parse_qsl(p.query,keep_blank_values=True):
        if len(embedded)>=5: break
        token=item.strip()
        if not token or len(token)>4096: continue
        try:
            decoded=base64.urlsafe_b64decode(token+"="*((-len(token))%4)).decode("utf-8")
        except (ValueError,UnicodeDecodeError): continue
        if decoded.lower().startswith(("http://","https://")):
            embedded.append(decoded)
            flags.append("embedded_encoded_url")
    if len(re.findall(r"https?://|https?%3a%2f%2f",query,re.I))>5: flags.append("embedded_url_scan_capped")
    if "%25" in p.query.lower(): flags.append("double_encoding")
    return NormalisedURL(original=original,normalised=norm,scheme=p.scheme.lower(),host=host,host_unicode=unicode_host,registered_domain=registered,subdomain=sub,suffix=ext.suffix,port=port,path=path,query=p.query,is_idn=host!=unicode_host,is_ip_host=ip is not None,canonical_host=host,ip_value=host if ip else None,obfuscation_flags=list(dict.fromkeys(flags)),embedded_urls=embedded[:5])
