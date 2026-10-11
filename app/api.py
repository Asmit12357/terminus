"""FastAPI backend.

Security model
--------------
- Binds to 127.0.0.1 by default (``terminus serve-api``).
- Every ``/api`` route requires ``Authorization: Bearer <TERMINUS_API_TOKEN>``
  (constant-time comparison). Without a configured token the API refuses all
  ``/api`` requests rather than running open.
- State-changing routes are limited to: import an inventory, start a scan.
  There is no route that executes commands, applies patches or edits systems.
- Strict input validation (enums, regexes, size limits), no CORS, security
  headers on every response, errors never echo secrets or stack traces.
"""

from __future__ import annotations

import hmac
import logging
import re
import threading
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from starlette.middleware.base import RequestResponseEndpoint

from app import __version__
from app.config import Settings, get_settings
from app.diagnostics import research_problems
from app.inventory import MAX_INVENTORY_BYTES, InventoryFormatError
from app.models import MatchStatus
from app.reports.export import export_csv, export_json, finding_report
from app.scanner import SCAN_LOCK
from app.service import get_repo, import_inventory, run_scan, summarize
from app.storage.repository import Repository

log = logging.getLogger("terminus.api")

app = FastAPI(
    title="Terminus API",
    version=__version__,
    description="Vulnerability intelligence and remediation recommendations (read-only research).",
    docs_url="/docs",
    redoc_url=None,
)

_FINDING_ID = re.compile(r"^[0-9a-f]{20}$")
_SAFE_FILTER = re.compile(r"^[A-Za-z0-9._:\- ]{1,80}$")

Tier = Literal["P1", "P2", "P3", "P4", "INFO"]


@app.middleware("http")
async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if not request.url.path.startswith("/docs") and request.url.path != "/openapi.json":
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error on %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "internal error"})


def settings_dep() -> Settings:
    return get_settings()


def repo_dep(settings: Annotated[Settings, Depends(settings_dep)]) -> Repository:
    return get_repo(settings)


Repo = Annotated[Repository, Depends(repo_dep)]


def require_token(request: Request, settings: Annotated[Settings, Depends(settings_dep)]) -> None:
    expected = settings.api_token.get_secret_value() if settings.api_token else ""
    if not expected:
        raise HTTPException(503, "API disabled: set TERMINUS_API_TOKEN to enable /api routes")
    header = request.headers.get("Authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            401, "invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"}
        )


Auth = Depends(require_token)


@app.get("/health")
def health(settings: Annotated[Settings, Depends(settings_dep)]) -> dict[str, object]:
    return {
        "status": "ok",
        "version": __version__,
        "mode": settings.mode,
        "api_enabled": bool(settings.api_token),
    }


@app.get("/api/summary", dependencies=[Auth])
def api_summary(repo: Repo) -> dict[str, object]:
    findings = repo.list_findings()
    scans = repo.list_scans(limit=1)
    return {
        **summarize(findings),
        "inventory": repo.latest_inventory(),
        "last_scan": scans[0].model_dump(mode="json") if scans else None,
    }


@app.get("/api/findings", dependencies=[Auth])
def api_findings(
    repo: Repo,
    status: Annotated[list[MatchStatus] | None, Query()] = None,
    tier: Annotated[list[Tier] | None, Query()] = None,
    asset_id: Annotated[str | None, Query(pattern=_SAFE_FILTER.pattern)] = None,
    cve_id: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9\-]{1,20}$")] = None,
    product: Annotated[str | None, Query(pattern=_SAFE_FILTER.pattern)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    findings = repo.list_findings(
        statuses=[s.value for s in status] if status else None,
        tiers=tier,
        asset_id=asset_id,
        cve_id=cve_id,
        product=product,
        limit=limit,
        offset=offset,
    )
    return {"count": len(findings), "findings": [finding_report(f) for f in findings]}


@app.get("/api/findings/{finding_id}", dependencies=[Auth])
def api_finding(finding_id: str, repo: Repo) -> dict[str, object]:
    if not _FINDING_ID.match(finding_id):
        raise HTTPException(422, "invalid finding id")
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    return finding_report(finding)


@app.get("/api/scans", dependencies=[Auth])
def api_scans(
    repo: Repo, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[dict[str, object]]:
    return [s.model_dump(mode="json") for s in repo.list_scans(limit)]


@app.post("/api/inventory", dependencies=[Auth])
async def api_import_inventory(repo: Repo, file: Annotated[UploadFile, File()]) -> JSONResponse:
    name = file.filename or ""
    if not name.lower().endswith((".json", ".csv")):
        raise HTTPException(415, "inventory must be a .json or .csv file")
    content = await file.read(MAX_INVENTORY_BYTES + 1)
    if len(content) > MAX_INVENTORY_BYTES:
        raise HTTPException(413, "inventory too large")
    try:
        result, inventory_id = import_inventory(repo, content, name.rsplit("/", 1)[-1])
    except InventoryFormatError as exc:
        raise HTTPException(422, str(exc)) from exc
    body = {
        "imported": inventory_id is not None,
        "inventory_id": inventory_id,
        "items": len(result.items),
        "errors": [e.model_dump() for e in result.errors[:200]],
        "warnings": result.warnings[:200],
        "duplicates_removed": result.duplicates_removed,
    }
    return JSONResponse(status_code=200 if inventory_id else 422, content=body)


class ScanRequest(BaseModel):
    mode: Literal["incremental", "full"] = "incremental"
    demo: bool = False


@app.post("/api/scans", dependencies=[Auth], status_code=202)
def api_start_scan(
    req: ScanRequest, repo: Repo, settings: Annotated[Settings, Depends(settings_dep)]
) -> dict[str, str]:
    if SCAN_LOCK.locked():
        raise HTTPException(409, "a scan is already running")
    if not repo.list_items():
        raise HTTPException(409, "import an inventory before scanning")
    problems = research_problems(settings, demo=req.demo or settings.is_demo)
    if problems:
        raise HTTPException(400, {"configuration_problems": problems})

    def worker() -> None:
        try:
            run_scan(settings, repo, req.mode, demo=req.demo or None)
        except Exception as exc:  # recorded on the scan record; never crash the server
            log.error("background scan failed: %s", type(exc).__name__)

    threading.Thread(target=worker, name="terminus-scan", daemon=True).start()
    return {"status": "started", "mode": req.mode, "data": "demo" if req.demo else settings.mode}


@app.get("/api/reports/export", dependencies=[Auth])
def api_export(
    repo: Repo,
    format: Annotated[Literal["json", "csv"], Query()] = "json",
    tier: Annotated[list[Tier] | None, Query()] = None,
    status: Annotated[list[MatchStatus] | None, Query()] = None,
) -> Response:
    findings = repo.list_findings(
        tiers=tier, statuses=[s.value for s in status] if status else None
    )
    demo = any(f.cve_source == "demo-fixture" for f in findings)
    if format == "csv":
        return Response(
            export_csv(findings),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="terminus-findings.csv"'},
        )
    return Response(
        export_json(findings, demo=demo),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="terminus-findings.json"'},
    )
