import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from ...db import get_db, new_id, now
from ...hashing import compute_nonce, fingerprint
from ...chain import ChainClient

router = APIRouter(prefix="/threat-reports", tags=["threat-reports"])


def _to_report_id_bytes32(report_uuid: str) -> str:
    return (report_uuid.replace("-", "") + "0" * 32)[:64]


def _get_chain() -> Optional[ChainClient]:
    try:
        return ChainClient()
    except Exception:
        return None


def _loads(value, default):
    if value is None:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _as_bool_int(value) -> int:
    return 1 if bool(value) else 0


@router.post("")
def create_report(payload: Dict[str, Any], db=Depends(get_db)):
    nonce = compute_nonce()
    indicators = payload.get("indicators", {})
    campaign = payload.get("campaign_summary")
    incident = payload.get("incident_summary")
    evidence_refs = payload.get("evidence_refs", []) or []

    canon_payload = {
        "indicators": indicators,
        "campaign_summary": campaign,
        "incident_summary": incident,
        "evidence_refs": evidence_refs,
    }
    commitment = fingerprint(canon_payload, nonce)

    report_id = new_id()
    ts = now()
    db.execute(
        """INSERT INTO threat_reports
           (id, reporter_pseudonym, status, current_commitment, canonical_nonce,
            indicators_json, campaign_summary, incident_summary, evidence_refs_json, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            report_id,
            payload.get("reporter_pseudonym"),
            "pending",
            commitment,
            nonce,
            json.dumps(indicators),
            campaign,
            incident,
            json.dumps(evidence_refs),
            ts,
            ts,
        ),
    )

    rid_bytes32 = _to_report_id_bytes32(report_id)

    chain = _get_chain()
    tx_info = None
    if chain is not None:
        try:
            tx_info = chain.submit_report(rid_bytes32, commitment)
        except Exception as exc:
            db.rollback() if hasattr(db, "rollback") else None
            raise HTTPException(status_code=502, detail=f"on-chain submit failed: {exc}")

    db.execute(
        """INSERT INTO report_revisions
           (id, report_id, commitment, version, tx_hash, block_number, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            new_id(),
            report_id,
            commitment,
            1,
            (tx_info or {}).get("tx_hash"),
            (tx_info or {}).get("block_number"),
            ts,
        ),
    )

    if tx_info:
        db.execute(
            """INSERT INTO onchain_refs
               (id, report_id, entity_type, tx_hash, block_number, contract_address, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                new_id(),
                report_id,
                "submit",
                tx_info["tx_hash"],
                tx_info["block_number"],
                os.getenv("CONTRACT_ADDRESS", ""),
                ts,
            ),
        )

    db.commit()
    return {
        "report_id": report_id,
        "commitment": commitment,
        "status": "pending",
        "tx_hash": (tx_info or {}).get("tx_hash"),
        "block_number": (tx_info or {}).get("block_number"),
        "on_chain_report_id": rid_bytes32,
    }


@router.get("/{report_id}")
def get_report(report_id: str, db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")
    return {
        "report_id": row["id"],
        "reporter_pseudonym": row["reporter_pseudonym"],
        "status": row["status"],
        "commitment": row["current_commitment"],
        "indicators": _loads(row["indicators_json"], {}),
        "campaign_summary": row["campaign_summary"],
        "incident_summary": row["incident_summary"],
        "evidence_refs": _loads(row["evidence_refs_json"], []),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@router.post("/{report_id}/revise")
def revise_report(report_id: str, payload: Dict[str, Any], db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")

    nonce = compute_nonce()
    indicators = payload.get("indicators", _loads(row["indicators_json"], {}))
    campaign = payload.get("campaign_summary", row["campaign_summary"])
    incident = payload.get("incident_summary", row["incident_summary"])
    evidence_refs = payload.get("evidence_refs", _loads(row["evidence_refs_json"], []))

    canon = {"indicators": indicators, "campaign_summary": campaign, "incident_summary": incident, "evidence_refs": evidence_refs}
    new_commitment = fingerprint(canon, nonce)

    rid_bytes32 = _to_report_id_bytes32(report_id)
    chain = _get_chain()
    tx_info = None
    if chain is not None:
        try:
            tx_info = chain.revise_report(rid_bytes32, new_commitment)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"on-chain revise failed: {exc}")

    ts = now()
    version_count = db.execute("SELECT COUNT(*) AS c FROM report_revisions WHERE report_id=?", (report_id,)).fetchone()["c"]
    db.execute(
        """UPDATE threat_reports SET indicators_json=?, campaign_summary=?, incident_summary=?,
           evidence_refs_json=?, canonical_nonce=?, current_commitment=?, status=?, updated_at=? WHERE id=?""",
        (
            json.dumps(indicators),
            campaign,
            incident,
            json.dumps(evidence_refs),
            nonce,
            new_commitment,
            "under_review",
            ts,
            report_id,
        ),
    )
    db.execute(
        """INSERT INTO report_revisions
           (id, report_id, commitment, version, tx_hash, block_number, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            new_id(),
            report_id,
            new_commitment,
            version_count + 1,
            (tx_info or {}).get("tx_hash"),
            (tx_info or {}).get("block_number"),
            ts,
        ),
    )
    if tx_info:
        db.execute(
            """INSERT INTO onchain_refs
               (id, report_id, entity_type, tx_hash, block_number, contract_address, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (new_id(), report_id, "revise", tx_info["tx_hash"], tx_info["block_number"], os.getenv("CONTRACT_ADDRESS", ""), ts),
        )
    db.commit()
    return {
        "report_id": report_id,
        "commitment": new_commitment,
        "tx_hash": (tx_info or {}).get("tx_hash"),
        "block_number": (tx_info or {}).get("block_number"),
    }


@router.post("/{report_id}/dispute")
def dispute_report(report_id: str, payload: Dict[str, Any], db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")

    reason = payload.get("reason", "")
    reason_hash = hashlib.sha256(reason.encode("utf-8")).hexdigest()

    rid_bytes32 = _to_report_id_bytes32(report_id)
    chain = _get_chain()
    tx_info = None
    if chain is not None:
        try:
            tx_info = chain.dispute_report(rid_bytes32, reason_hash)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"on-chain dispute failed: {exc}")

    ts = now()
    db.execute(
        """INSERT INTO report_disputes
           (id, report_id, disputant, reason_hash, tx_hash, block_number, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            new_id(),
            report_id,
            payload.get("disputant"),
            reason_hash,
            (tx_info or {}).get("tx_hash"),
            (tx_info or {}).get("block_number"),
            ts,
        ),
    )
    db.execute("UPDATE threat_reports SET status=?, updated_at=? WHERE id=?", ("disputed", ts, report_id))
    if tx_info:
        db.execute(
            """INSERT INTO onchain_refs
               (id, report_id, entity_type, tx_hash, block_number, contract_address, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (new_id(), report_id, "dispute", tx_info["tx_hash"], tx_info["block_number"], os.getenv("CONTRACT_ADDRESS", ""), ts),
        )
    db.commit()
    return {
        "report_id": report_id,
        "reason_hash": reason_hash,
        "tx_hash": (tx_info or {}).get("tx_hash"),
        "block_number": (tx_info or {}).get("block_number"),
    }


@router.post("/{report_id}/validate")
def validate_report(report_id: str, payload: Dict[str, Any], db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")

    verdict = bool(payload.get("verdict", False))

    rid_bytes32 = _to_report_id_bytes32(report_id)
    chain = _get_chain()
    tx_info = None
    if chain is not None:
        try:
            tx_info = chain.validate_report(rid_bytes32, verdict)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"on-chain validate failed: {exc}")

    ts = now()
    db.execute(
        """INSERT INTO report_validations
           (id, report_id, validator, verdict, tx_hash, block_number, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            new_id(),
            report_id,
            payload.get("validator"),
            _as_bool_int(verdict),
            (tx_info or {}).get("tx_hash"),
            (tx_info or {}).get("block_number"),
            ts,
        ),
    )
    db.execute(
        "UPDATE threat_reports SET status=?, updated_at=? WHERE id=?",
        ("validated" if verdict else "disputed", ts, report_id),
    )
    if tx_info:
        db.execute(
            """INSERT INTO onchain_refs
               (id, report_id, entity_type, tx_hash, block_number, contract_address, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (new_id(), report_id, "validate", tx_info["tx_hash"], tx_info["block_number"], os.getenv("CONTRACT_ADDRESS", ""), ts),
        )
    db.commit()
    return {
        "report_id": report_id,
        "verdict": verdict,
        "tx_hash": (tx_info or {}).get("tx_hash"),
        "block_number": (tx_info or {}).get("block_number"),
    }


@router.get("/{report_id}/verify")
def verify_report(report_id: str, commitment: Optional[str] = None, db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")

    rid_bytes32 = _to_report_id_bytes32(report_id)
    chain = _get_chain()
    onchain_commitment = None
    status = None
    if chain is not None:
        try:
            onchain_commitment = chain.fetch_commitment(rid_bytes32)
            status = chain.fetch_status(rid_bytes32)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"on-chain read failed: {exc}")

    supplied = commitment or row["current_commitment"]
    supplied_norm = supplied.replace("0x", "").lower().zfill(64)
    onchain_norm = (onchain_commitment or "").replace("0x", "").lower().zfill(64)

    match = onchain_norm == supplied_norm if onchain_norm else None

    return {
        "report_id": report_id,
        "on_chain_commitment": onchain_commitment,
        "supplied_commitment": supplied,
        "match": match,
        "on_chain_status": status,
        "off_chain_commitment": row["current_commitment"],
    }


@router.get("/{report_id}/provenance")
def provenance(report_id: str, db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")

    revisions = db.execute(
        "SELECT * FROM report_revisions WHERE report_id=? ORDER BY created_at", (report_id,)
    ).fetchall()
    disputes = db.execute(
        "SELECT * FROM report_disputes WHERE report_id=? ORDER BY created_at", (report_id,)
    ).fetchall()
    validations = db.execute(
        "SELECT * FROM report_validations WHERE report_id=? ORDER BY created_at", (report_id,)
    ).fetchall()
    refs = db.execute(
        "SELECT * FROM onchain_refs WHERE report_id=? ORDER BY created_at", (report_id,)
    ).fetchall()

    return {
        "report_id": report_id,
        "current_commitment": row["current_commitment"],
        "status": row["status"],
        "revisions": [
            {"id": r["id"], "commitment": r["commitment"], "version": r["version"], "tx_hash": r["tx_hash"], "block_number": r["block_number"], "created_at": r["created_at"]}
            for r in revisions
        ],
        "disputes": [
            {"id": d["id"], "reason_hash": d["reason_hash"], "tx_hash": d["tx_hash"], "block_number": d["block_number"], "created_at": d["created_at"]}
            for d in disputes
        ],
        "validations": [
            {"id": v["id"], "verdict": bool(v["verdict"]), "tx_hash": v["tx_hash"], "block_number": v["block_number"], "created_at": v["created_at"]}
            for v in validations
        ],
        "onchain_refs": [
            {"entity_type": r["entity_type"], "tx_hash": r["tx_hash"], "block_number": r["block_number"], "contract_address": r["contract_address"], "created_at": r["created_at"]}
            for r in refs
        ],
    }


@router.get("/{report_id}/onchain")
def onchain_view(report_id: str, db=Depends(get_db)):
    row = db.execute("SELECT * FROM threat_reports WHERE id=?", (report_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")
    refs = db.execute("SELECT * FROM onchain_refs WHERE report_id=?", (report_id,)).fetchall()
    return {
        "report_id": report_id,
        "commitment": row["current_commitment"],
        "contract_address": os.getenv("CONTRACT_ADDRESS"),
        "references": [{"entity_type": r["entity_type"], "tx_hash": r["tx_hash"], "block_number": r["block_number"]} for r in refs],
        "note": "Integrity/history only; raw URLs and sensitive data remain off-chain.",
    }
