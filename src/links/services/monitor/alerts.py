from __future__ import annotations

from psycopg.types.json import Jsonb


async def emit_alert(conn, *, owner_id: str, watch_id, kind: str, severity: str,
                     target: str, dedupe_key: str, evidence: dict, source: str,
                     limitations: list[str] | None = None) -> bool:
    """Insert a self-contained alert, returning true only for a new row."""
    row = await (await conn.execute(
        "INSERT INTO monitoring_alerts(owner_id,watch_id,kind,severity,target,dedupe_key,evidence,source,limitations) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(dedupe_key) DO NOTHING RETURNING id",
        (owner_id, watch_id, kind, severity, target, dedupe_key, Jsonb(evidence), source, Jsonb(limitations or [])),
    )).fetchone()
    return row is not None
