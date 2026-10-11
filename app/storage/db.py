"""SQLite connection handling and schema.

Every statement in the storage layer uses ``?`` placeholders. Identifiers
(table/column names) are never built from user input.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inventories (
    inventory_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_items (
    item_id TEXT PRIMARY KEY,
    inventory_id TEXT NOT NULL REFERENCES inventories(inventory_id),
    asset_id TEXT NOT NULL,
    software_name TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_asset ON inventory_items(asset_id);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    last_modified TEXT,
    content_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    first_ingested_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id TEXT PRIMARY KEY,
    retrieved_at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id TEXT PRIMARY KEY,
    retrieved_at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS osv_advisories (
    osv_id TEXT PRIMARY KEY,
    retrieved_at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS osv_aliases (
    alias TEXT NOT NULL,
    osv_id TEXT NOT NULL REFERENCES osv_advisories(osv_id),
    PRIMARY KEY (alias, osv_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    software_name TEXT NOT NULL,
    status TEXT NOT NULL,
    priority_tier TEXT NOT NULL,
    priority_score REAL NOT NULL,
    first_seen TEXT NOT NULL,
    last_assessed TEXT NOT NULL,
    scan_id TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_rank ON findings(priority_score DESC);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS http_cache (
    cache_key TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    body BLOB NOT NULL
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    # WAL + NORMAL stays consistent after a crash; only the last commits before a
    # power loss may be lost, which is acceptable for re-derivable scan data.
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


_local = threading.local()


def _thread_connection(db_path: Path) -> sqlite3.Connection:
    """One connection per thread and database (sqlite3 connections are thread-bound)."""
    conns: dict[str, sqlite3.Connection] = getattr(_local, "conns", None) or {}
    _local.conns = conns
    key = str(Path(db_path).resolve())
    conn = conns.get(key)
    if conn is None:
        conn = conns[key] = connect(db_path)
    return conn


@contextmanager
def transaction(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = _thread_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with transaction(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
