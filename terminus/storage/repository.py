"""Repository: the only module that talks SQL.

All queries are parameterized. Full Pydantic models are stored as JSON in a
``data`` column; a few columns are duplicated for indexing and filtering.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from terminus.models import (
    DEMO_SOURCE,
    CveRecord,
    EpssScore,
    Finding,
    InventoryItem,
    KevEntry,
    OsvAdvisory,
    ScanRecord,
    utcnow,
)
from terminus.storage.db import init_db, transaction

UpsertOutcome = Literal["inserted", "updated", "unchanged"]

_TIER_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "INFO": 5}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _content_hash(record: CveRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"retrieved_at", "source"})
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


class Repository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        init_db(self.db_path)

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------
    def replace_inventory(self, items: Sequence[InventoryItem], name: str, raw: bytes) -> str:
        """Replace the active inventory. Findings for removed items are deleted
        because they no longer describe anything in scope."""
        inventory_id = uuid.uuid4().hex[:12]
        new_ids = {i.item_id for i in items}
        with transaction(self.db_path) as conn:
            conn.execute(
                "INSERT INTO inventories(inventory_id, name, imported_at, item_count, sha256) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    inventory_id,
                    name[:200],
                    utcnow().isoformat(),
                    len(items),
                    hashlib.sha256(raw).hexdigest(),
                ),
            )
            existing = [r["item_id"] for r in conn.execute("SELECT item_id FROM inventory_items")]
            removed = [i for i in existing if i not in new_ids]
            conn.executemany("DELETE FROM findings WHERE item_id = ?", [(i,) for i in removed])
            conn.execute("DELETE FROM inventory_items")
            conn.executemany(
                "INSERT INTO inventory_items(item_id, inventory_id, asset_id, software_name, data) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (i.item_id, inventory_id, i.asset_id, i.software_name, i.model_dump_json())
                    for i in items
                ],
            )
        return inventory_id

    def list_items(self) -> list[InventoryItem]:
        with transaction(self.db_path) as conn:
            rows = conn.execute("SELECT data FROM inventory_items ORDER BY asset_id, software_name")
            return [InventoryItem.model_validate_json(r["data"]) for r in rows]

    def latest_inventory(self) -> dict[str, object] | None:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT inventory_id, name, imported_at, item_count FROM inventories "
                "ORDER BY imported_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # CVEs
    # ------------------------------------------------------------------
    def upsert_cve(self, record: CveRecord) -> UpsertOutcome:
        digest = _content_hash(record)
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT content_hash, revision FROM cves WHERE cve_id = ?", (record.cve_id,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO cves(cve_id, last_modified, content_hash, source, retrieved_at, "
                    "first_ingested_at, revision, data) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (
                        record.cve_id,
                        _iso(record.last_modified),
                        digest,
                        record.source,
                        record.retrieved_at.isoformat(),
                        utcnow().isoformat(),
                        record.model_dump_json(),
                    ),
                )
                return "inserted"
            if row["content_hash"] == digest:
                # Same content: only refresh the retrieval timestamp.
                conn.execute(
                    "UPDATE cves SET retrieved_at = ?, data = ? WHERE cve_id = ?",
                    (record.retrieved_at.isoformat(), record.model_dump_json(), record.cve_id),
                )
                return "unchanged"
            conn.execute(
                "UPDATE cves SET last_modified = ?, content_hash = ?, source = ?, retrieved_at = ?, "
                "revision = ?, data = ? WHERE cve_id = ?",
                (
                    _iso(record.last_modified),
                    digest,
                    record.source,
                    record.retrieved_at.isoformat(),
                    int(row["revision"]) + 1,
                    record.model_dump_json(),
                    record.cve_id,
                ),
            )
            return "updated"

    def get_cve(self, cve_id: str) -> CveRecord | None:
        with transaction(self.db_path) as conn:
            row = conn.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
            return CveRecord.model_validate_json(row["data"]) if row else None

    def cve_sources(self) -> set[str]:
        """Distinct sources of stored CVE records (e.g. ``nvd``, ``demo-fixture``)."""
        with transaction(self.db_path) as conn:
            return {r[0] for r in conn.execute("SELECT DISTINCT source FROM cves")}

    def remove_demo_data(self) -> tuple[int, int]:
        """Delete recorded demo CVEs, findings derived from them, and the KEV/EPSS
        caches (demo KEV is a 5-entry excerpt that must never stand in for the live
        catalog). Inventory, scan history and live CVE records are kept.
        Returns (findings removed, CVE records removed)."""
        with transaction(self.db_path) as conn:
            rows = conn.execute("SELECT finding_id, data FROM findings").fetchall()
            demo_findings = [
                (r["finding_id"],)
                for r in rows
                if Finding.model_validate_json(r["data"]).cve_source == DEMO_SOURCE
            ]
            conn.executemany("DELETE FROM findings WHERE finding_id = ?", demo_findings)
            cves = conn.execute("DELETE FROM cves WHERE source = ?", (DEMO_SOURCE,)).rowcount
            conn.execute("DELETE FROM kev_entries")
            conn.execute("DELETE FROM meta WHERE key = 'kev_retrieved_at'")
            conn.execute("DELETE FROM epss_scores")
        return len(demo_findings), cves

    def cve_revision(self, cve_id: str) -> int | None:
        with transaction(self.db_path) as conn:
            row = conn.execute("SELECT revision FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
            return int(row["revision"]) if row else None

    def list_cves(self) -> list[CveRecord]:
        with transaction(self.db_path) as conn:
            rows = conn.execute("SELECT data FROM cves ORDER BY cve_id")
            return [CveRecord.model_validate_json(r["data"]) for r in rows]

    def count_cves(self) -> int:
        with transaction(self.db_path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])

    # ------------------------------------------------------------------
    # KEV / EPSS / OSV
    # ------------------------------------------------------------------
    def replace_kev(self, entries: Iterable[KevEntry]) -> int:
        entries = list(entries)
        with transaction(self.db_path) as conn:
            conn.execute("DELETE FROM kev_entries")
            conn.executemany(
                "INSERT INTO kev_entries(cve_id, retrieved_at, data) VALUES (?, ?, ?)",
                [(e.cve_id, e.retrieved_at.isoformat(), e.model_dump_json()) for e in entries],
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                (
                    "kev_retrieved_at",
                    (entries[0].retrieved_at if entries else utcnow()).isoformat(),
                ),
            )
        return len(entries)

    def kev_retrieved_at(self) -> datetime | None:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = ?", ("kev_retrieved_at",)
            ).fetchone()
            return datetime.fromisoformat(row["value"]) if row else None

    def kev_cve_ids(self) -> set[str]:
        with transaction(self.db_path) as conn:
            return {r[0] for r in conn.execute("SELECT cve_id FROM kev_entries")}

    def get_kev(self, cve_id: str) -> KevEntry | None:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM kev_entries WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return KevEntry.model_validate_json(row["data"]) if row else None

    def upsert_epss(self, scores: Iterable[EpssScore]) -> None:
        with transaction(self.db_path) as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO epss_scores(cve_id, retrieved_at, data) VALUES (?, ?, ?)",
                [(s.cve_id, s.retrieved_at.isoformat(), s.model_dump_json()) for s in scores],
            )

    def get_epss(self, cve_id: str) -> EpssScore | None:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM epss_scores WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return EpssScore.model_validate_json(row["data"]) if row else None

    def upsert_osv(self, advisory: OsvAdvisory) -> None:
        with transaction(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO osv_advisories(osv_id, retrieved_at, data) VALUES (?, ?, ?)",
                (advisory.id, advisory.retrieved_at.isoformat(), advisory.model_dump_json()),
            )
            conn.execute("DELETE FROM osv_aliases WHERE osv_id = ?", (advisory.id,))
            conn.executemany(
                "INSERT OR IGNORE INTO osv_aliases(alias, osv_id) VALUES (?, ?)",
                [(a, advisory.id) for a in {advisory.id, *advisory.aliases}],
            )

    def osv_for_cve(self, cve_id: str) -> list[OsvAdvisory]:
        with transaction(self.db_path) as conn:
            rows = conn.execute(
                "SELECT a.data FROM osv_advisories a JOIN osv_aliases x ON x.osv_id = a.osv_id "
                "WHERE x.alias = ? ORDER BY a.osv_id",
                (cve_id,),
            )
            return [OsvAdvisory.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def upsert_finding(self, finding: Finding) -> UpsertOutcome:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT first_seen FROM findings WHERE finding_id = ?", (finding.finding_id,)
            ).fetchone()
            if row is not None:
                finding = finding.model_copy(
                    update={"first_seen": datetime.fromisoformat(row["first_seen"])}
                )
            conn.execute(
                "INSERT OR REPLACE INTO findings(finding_id, cve_id, item_id, asset_id, "
                "software_name, status, priority_tier, priority_score, first_seen, last_assessed, "
                "scan_id, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.finding_id,
                    finding.cve_id,
                    finding.match.item_id,
                    finding.item.asset_id,
                    finding.item.software_name,
                    finding.match.status.value,
                    finding.priority.tier,
                    finding.priority.score,
                    finding.first_seen.isoformat(),
                    finding.last_assessed.isoformat(),
                    finding.scan_id,
                    finding.model_dump_json(),
                ),
            )
            return "inserted" if row is None else "updated"

    def get_finding(self, finding_id: str) -> Finding | None:
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            return Finding.model_validate_json(row["data"]) if row else None

    def list_findings(
        self,
        *,
        statuses: Sequence[str] | None = None,
        tiers: Sequence[str] | None = None,
        asset_id: str | None = None,
        cve_id: str | None = None,
        product: str | None = None,
        limit: int = 5000,
        offset: int = 0,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[object] = []
        if statuses:
            clauses.append(f"status IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
        if tiers:
            clauses.append(f"priority_tier IN ({','.join('?' * len(tiers))})")
            params.extend(tiers)
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        if cve_id:
            clauses.append("cve_id LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(cve_id.upper())}%")
        if product:
            clauses.append("LOWER(software_name) LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(product.lower())}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT data FROM findings {where} "  # noqa: S608 - clauses are fixed strings
            "ORDER BY priority_score DESC, cve_id, asset_id LIMIT ? OFFSET ?"
        )
        params.extend([max(1, min(limit, 10_000)), max(0, offset)])
        with transaction(self.db_path) as conn:
            rows = conn.execute(sql, params)
            findings = [Finding.model_validate_json(r["data"]) for r in rows]
        return sorted(findings, key=ranking_key)

    def count_findings(self) -> int:
        with transaction(self.db_path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    def prune_findings(self, keep: set[str]) -> int:
        """Delete findings that no longer describe a current candidate (e.g. NVD
        corrected a CPE, or matching rules became stricter)."""
        with transaction(self.db_path) as conn:
            rows = conn.execute("SELECT finding_id FROM findings").fetchall()
            stale = [r["finding_id"] for r in rows if r["finding_id"] not in keep]
            conn.executemany("DELETE FROM findings WHERE finding_id = ?", [(f,) for f in stale])
        return len(stale)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    def save_scan(self, scan: ScanRecord) -> None:
        with transaction(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans(scan_id, mode, status, started_at, finished_at, data) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan.scan_id,
                    scan.mode,
                    scan.status,
                    scan.started_at.isoformat(),
                    _iso(scan.finished_at),
                    scan.model_dump_json(),
                ),
            )

    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        with transaction(self.db_path) as conn:
            rows = conn.execute(
                "SELECT data FROM scans ORDER BY started_at DESC LIMIT ?", (max(1, limit),)
            )
            return [ScanRecord.model_validate_json(r["data"]) for r in rows]

    def last_completed_scan(self, modes: Sequence[str]) -> ScanRecord | None:
        with transaction(self.db_path) as conn:
            placeholders = ",".join("?" * len(modes))
            # Only "?" placeholders are interpolated; values are bound parameters.
            sql = (
                "SELECT data FROM scans WHERE status IN ('completed', 'completed_with_errors') "  # noqa: S608
                f"AND mode IN ({placeholders}) ORDER BY started_at DESC LIMIT 1"
            )
            row = conn.execute(sql, list(modes)).fetchone()
            return ScanRecord.model_validate_json(row["data"]) if row else None

    # ------------------------------------------------------------------
    # HTTP cache
    # ------------------------------------------------------------------
    def cache_get(self, key: str, max_age: timedelta) -> tuple[bytes, datetime] | None:
        """Cached body and its fetch time, if younger than ``max_age``."""
        with transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT fetched_at, body FROM http_cache WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        fetched_at = datetime.fromisoformat(row["fetched_at"])
        if utcnow() - fetched_at > max_age:
            return None
        return bytes(row["body"]), fetched_at

    def cache_put(self, key: str, body: bytes) -> None:
        with transaction(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO http_cache(cache_key, fetched_at, body) VALUES (?, ?, ?)",
                (key, utcnow().isoformat(), body),
            )


def ranking_key(f: Finding) -> tuple[object, ...]:
    """Deterministic ranking: tier, then score, then stable tie-breakers."""
    return (
        _TIER_ORDER.get(f.priority.tier, 9),
        -f.priority.score,
        -(f.cvss.base_score if f.cvss else -1),
        f.cve_id,
        f.item.asset_id,
        f.item.software_name,
    )
