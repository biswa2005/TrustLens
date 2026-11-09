"""Manually import URLhaus CSV records into a staged Redis generation."""
from __future__ import annotations
import argparse, csv, hashlib, json, os, sys, uuid
from datetime import datetime, timezone
from itertools import filterfalse
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

REQUIRED={"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"}
URLHAUS_COLUMNS=["id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"]
POINTER="urlhaus:v1:active_generation"

def rows(path:Path):
    def clean(lines):
        for line in lines:
            if line.strip() and not line.lstrip().startswith("#"):
                yield line
    with path.open("r",encoding="utf-8-sig",newline="") as stream:
        reader=csv.reader(clean(stream))
        try: first=next(reader)
        except StopIteration: raise ValueError("CSV is empty")
        headers=[name.strip() for name in first]
        has_header=REQUIRED.issubset(set(headers))
        if has_header:
            columns=headers
        elif len(first)==len(URLHAUS_COLUMNS):
            # The official full database dump is comment-prefixed and
            # headerless; its documented columns are emitted in this order.
            columns=URLHAUS_COLUMNS
        else:
            raise ValueError("CSV is missing required URLhaus columns")
        for values in ([first] if not has_header else []):
            yield dict(zip(columns,values))
        for values in reader:
            record=dict(zip(columns,values))
            if len(values)>len(columns): record[None]=values[len(columns):]
            yield record

def import_file(path:Path, client):
    client.ping()
    generation=uuid.uuid4().hex; prefix=f"urlhaus:v1:{generation}"
    counts={"read":0,"active":0,"historical":0,"rejected":0,"duplicate":0}
    seen={}; pipe=client.pipeline(transaction=False)
    try:
        for row in rows(path):
            counts["read"]+=1
            try:
                if None in row or any(not isinstance(row.get(k),str) for k in REQUIRED): raise ValueError("malformed CSV row")
                rec={k:row[k].strip() for k in REQUIRED}
                parts=urlsplit(rec["url"])
                if not rec["id"] or parts.scheme not in {"http","https","ftp"} or not parts.hostname or parts.username or parts.password or len(rec["url"])>4096 or rec["url_status"] not in {"online","offline"}: raise ValueError("invalid IOC")
                prior=seen.get(rec["id"])
                if prior:
                    counts["duplicate"]+=1
                    if prior!=rec: raise ValueError("conflicting duplicate record id")
                    continue
                seen[rec["id"]]=rec
                kind="active" if rec["url_status"]=="online" else "historical"
                data=json.dumps(rec,separators=(",",":"))
                for typ,val in (("url",rec["url"]),("host",parts.hostname.lower())):
                    key=f"{prefix}:{kind}:{typ}:{hashlib.sha256(val.encode()).hexdigest()}"
                    pipe.hset(key,rec["id"],data)
                counts[kind]+=1
                if counts["read"]%500==0: pipe.execute()
            except (ValueError,TypeError,AttributeError): counts["rejected"]+=1
        pipe.execute()
        if counts["read"]==0: raise ValueError("empty feed")
        if counts["rejected"]: raise ValueError(f"{counts['rejected']} rejected rows; refusing partial activation")
        client.set(f"{prefix}:metadata",json.dumps({"source":path.name,"imported_at":datetime.now(timezone.utc).isoformat(),**counts}))
        client.set(POINTER,generation)
        return {"generation":generation,**counts}
    except Exception:
        try:
            for key in client.scan_iter(f"{prefix}:*"): client.delete(key)
        finally: raise

def main():
    load_dotenv(Path(__file__).resolve().parents[1]/".env")
    default_feed=Path(__file__).resolve().parents[1]/"data"/"feeds"/"urlhaus.csv"
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file",type=Path,default=default_feed,help=f"URLhaus CSV dump (default: {default_feed})")
    parser.add_argument("--redis-url",default=None); args=parser.parse_args()
    if not args.file.is_file(): parser.error("input file does not exist")
    try:
        import redis
        url=args.redis_url or os.environ["REDIS_URL"]
        result=import_file(args.file,redis.Redis.from_url(url,decode_responses=True,socket_connect_timeout=2,socket_timeout=5))
        print(json.dumps({"source":args.file.name,**result})); return 0
    except Exception as exc:
        print(f"Import failed; active generation unchanged: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
