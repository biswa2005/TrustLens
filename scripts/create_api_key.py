from __future__ import annotations

import argparse
import asyncio
import hashlib
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from links.services import db
from links.services.runtime import event_loop_factory
from dotenv import load_dotenv


async def create(owner_id: str, label: str) -> str:
    raw_key = "tl_live_" + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    await db.open_pool()
    try:
        if not db.pool:
            raise RuntimeError("Database pool was not initialized")
        async with db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO api_keys(key_hash,owner_id,label) VALUES (%s,%s,%s)",
                (key_hash, owner_id, label),
            )
    finally:
        await db.close_pool()
    return raw_key


def main() -> None:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    parser = argparse.ArgumentParser(description="Create a TrustLens monitoring API key")
    parser.add_argument("owner_id")
    parser.add_argument("label")
    args = parser.parse_args()
    # This is the only display of the raw key; it is never written to the database.
    factory = event_loop_factory()
    if factory:
        raw_key = asyncio.run(create(args.owner_id, args.label), loop_factory=factory)
    else:
        raw_key = asyncio.run(create(args.owner_id, args.label))
    print(raw_key)


if __name__ == "__main__":
    main()
