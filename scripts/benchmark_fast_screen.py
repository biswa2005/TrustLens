"""Measure warm fast-screen p95 over the committed 45-URL offline corpus."""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv
from links.services import redis_store
from links.services.analyser import screen_url


def load_corpus() -> list[str]:
    urls = []
    for name in ("benign.json", "suspicious.json"):
        cases = json.loads((ROOT / "tests" / "corpus" / name).read_text(encoding="utf-8-sig"))
        if any(case.get("fetch") is not False for case in cases):
            raise ValueError(f"{name} includes an entry that is not marked fetch=false")
        urls.extend(case["input"] for case in cases)
    if len(urls) != 45:
        raise ValueError(f"Expected 45 corpus URLs, found {len(urls)}")
    return urls


def require_loopback_redis() -> None:
    raw = os.environ.get("REDIS_URL")
    if not raw:
        raise RuntimeError("REDIS_URL is not configured")
    host = urlsplit(raw).hostname
    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("Fast-screen benchmark requires loopback Redis")


async def measure() -> list[float]:
    urls = load_corpus()
    await asyncio.gather(*(screen_url(url, "full") for url in urls))
    samples = []
    for url in urls:
        started = time.perf_counter()
        result = await screen_url(url, "full")
        samples.append(float(result["elapsed_ms"]))
        # Keep the outer measurement as a sanity check for pathological stalls.
        if (time.perf_counter() - started) > 1.0:
            raise RuntimeError("Fast-screen request exceeded the 1 second safety bound")
    return samples


async def run() -> list[float]:
    try:
        return await measure()
    finally:
        await redis_store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit-ms", type=float, default=50.0)
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")
    require_loopback_redis()
    samples = asyncio.run(run())
    ordered = sorted(samples)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1]
    median = statistics.median(samples)
    print(f"samples={len(samples)} median_ms={median:.2f} p95_ms={p95:.2f} limit_ms={args.limit_ms:.2f}")
    if p95 >= args.limit_ms:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
