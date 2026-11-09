import os
import sqlite3
import uuid
from contextlib import closing
from typing import Any, Iterator, Optional, Tuple
from urllib.parse import urlparse, unquote

DEFAULT_DB = os.getenv("DATABASE_URL", "sqlite:///./trustlens.db")


class DictCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def description(self):
        return self._cursor.description

    def execute(self, sql, params=()):
        return self._cursor.execute(sql, params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None or self._cursor.description is None:
            return None
        columns = [d[0] for d in self._cursor.description]
        return dict(zip(columns, row))

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows or self._cursor.description is None:
            return []
        columns = [d[0] for d in self._cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    def __iter__(self):
        for row in self._cursor:
            columns = [d[0] for d in self._cursor.description]
            yield dict(zip(columns, row))

    def close(self):
        self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)


class PgConnection:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        cur = self._conn.cursor()
        cur.execute(sql.replace("?", "%s"), params or ())
        return DictCursor(cur)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


class SQLiteConnection:
    def __init__(self, path):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")

    def execute(self, sql, params=()):
        cur = self._conn.execute(sql, params or ())
        # Wrap sqlite row access into dict-like objects
        class SqliteDictCursor:
            def __init__(self, cur):
                self._cur = cur
            def fetchone(self):
                r = self._cur.fetchone()
                return dict(r) if r is not None else None
            def fetchall(self):
                return [dict(r) for r in self._cur.fetchall()]
            def close(self):
                self._cur.close()
            @property
            def rowcount(self):
                return self._cur.rowcount
        return SqliteDictCursor(cur)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS threat_reports (
        id TEXT PRIMARY KEY,
        reporter_pseudonym TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        current_commitment TEXT NOT NULL,
        canonical_nonce TEXT NOT NULL,
        indicators_json TEXT NOT NULL,
        campaign_summary TEXT,
        incident_summary TEXT,
        evidence_refs_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS report_revisions (
        id TEXT PRIMARY KEY,
        report_id TEXT NOT NULL,
        commitment TEXT NOT NULL,
        version INTEGER NOT NULL,
        tx_hash TEXT,
        block_number INTEGER,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS report_disputes (
        id TEXT PRIMARY KEY,
        report_id TEXT NOT NULL,
        disputant TEXT,
        reason_hash TEXT NOT NULL,
        tx_hash TEXT,
        block_number INTEGER,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS report_validations (
        id TEXT PRIMARY KEY,
        report_id TEXT NOT NULL,
        validator TEXT,
        verdict INTEGER NOT NULL,
        tx_hash TEXT,
        block_number INTEGER,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS onchain_refs (
        id TEXT PRIMARY KEY,
        report_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        block_number INTEGER,
        contract_address TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
]


def _pg_connect(url: str):
    try:
        import pg8000
    except ImportError as exc:
        raise RuntimeError(
            "pg8000 is required for PostgreSQL support. Install with: uv add pg8000"
        ) from exc

    parsed = urlparse(url.replace("postgresql+psycopg://", "postgresql://", 1).replace("postgresql+pg8000://", "postgresql://", 1))
    conn = pg8000.connect(
        host=parsed.hostname or "localhost",
        port=parsed.port or 5432,
        database=(parsed.path or "/postgres").lstrip("/") or "postgres",
        user=unquote(parsed.username or "postgres"),
        password=unquote(parsed.password or ""),
    )
    conn.autocommit = False
    return PgConnection(conn)


def _sqlite_connect(url: str):
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "", 1)
    elif url.startswith("sqlite://"):
        path = url.replace("sqlite://", "", 1)
    else:
        path = "./trustlens.db"
    return SQLiteConnection(path)


def connect():
    if DEFAULT_DB.lower().startswith("postgres") or DEFAULT_DB.lower().startswith("postgresql"):
        return _pg_connect(DEFAULT_DB)
    return _sqlite_connect(DEFAULT_DB)


def init_db(conn):
    for stmt in SCHEMA:
        conn.execute(stmt)
    conn.commit()


def get_db() -> Iterator[Any]:
    conn = connect()
    try:
        init_db(conn)
        yield conn
    finally:
        conn.close()


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
