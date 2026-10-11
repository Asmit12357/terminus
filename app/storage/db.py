"""SQLite connection handling, schema and schema upgrades.

Every statement in the storage layer uses ``?`` placeholders. Identifiers
(table/column names) are never built from user input.

Upgrades are additive: ``MIGRATIONS`` maps a schema version to the SQL that
brings the previous version up to it. Before any migration runs, the existing
file is copied to ``<name>.v<old>.bak``. A database written by a newer
Terminus, or a SQLite file that is not a Terminus database, is refused rather
than modified.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.paths import ensure_dir

SCHEMA_VERSION = 1

# version -> SQL upgrading (version - 1) to version. Empty until the schema changes.
MIGRATIONS: dict[int, str] = {}


class StorageError(RuntimeError):
    """The database cannot be used (unreadable, foreign, or from a newer release)."""


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
    try:
        conn = sqlite3.connect(str(db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        # WAL + NORMAL stays consistent after a crash; only the last commits before a
        # power loss may be lost, which is acceptable for re-derivable scan data.
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 30000")
    except sqlite3.DatabaseError as exc:
        raise StorageError(f"cannot open database: {exc}") from exc
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


def stored_schema_version(conn: sqlite3.Connection) -> int | None:
    """Schema version recorded in the file; None for a new, empty database."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "meta" not in tables:
        if tables:
            raise StorageError("file is a SQLite database but not a Terminus database")
        return None
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    try:
        return int(row[0]) if row else None
    except ValueError:
        raise StorageError(f"unreadable schema version {row[0]!r}") from None


def _backup(db_path: Path, version: int) -> Path:
    target = db_path.with_name(f"{db_path.name}.v{version}.bak")
    if not target.exists():
        dest = sqlite3.connect(str(target))
        try:
            _thread_connection(db_path).backup(dest)
        finally:
            dest.close()
    return target


def init_db(db_path: Path) -> None:
    ensure_dir(db_path.parent)
    try:
        with transaction(db_path) as conn:
            current = stored_schema_version(conn)
    except sqlite3.DatabaseError as exc:
        raise StorageError(f"{db_path} is not a usable SQLite database: {exc}") from exc
    except StorageError as exc:
        raise StorageError(f"{db_path}: {exc}") from exc
    if current is not None and current > SCHEMA_VERSION:
        raise StorageError(
            f"{db_path} was written by a newer Terminus (schema {current}, this release "
            f"supports {SCHEMA_VERSION}); upgrade Terminus or use another --db"
        )
    if current is not None and current < SCHEMA_VERSION:
        _backup(db_path, current)
    with transaction(db_path) as conn:
        conn.executescript(SCHEMA)
        start = SCHEMA_VERSION if current is None else current
        for version in range(start + 1, SCHEMA_VERSION + 1):
            conn.executescript(MIGRATIONS[version])
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
