from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import app, settings_dep
from app.config import Settings
from app.service import get_repo, import_inventory, run_scan
from tests.conftest import DATA_DIR

TOKEN = "test-token-0123456789"


@pytest.fixture
def api_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"api_token": SecretStr(TOKEN)})


@pytest.fixture
def client(api_settings: Settings):
    app.dependency_overrides[settings_dep] = lambda: api_settings
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def seeded(api_settings: Settings) -> Settings:
    repo = get_repo(api_settings)
    import_inventory(
        repo, (DATA_DIR / "sample_inventory.json").read_bytes(), "sample_inventory.json"
    )
    run_scan(api_settings, repo, "full", demo=True)
    return api_settings


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_health_is_public_and_has_security_headers(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert TOKEN not in r.text


@pytest.mark.parametrize(
    "path", ["/api/summary", "/api/findings", "/api/scans", "/api/reports/export"]
)
def test_api_requires_token(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(path, headers={"Authorization": TOKEN}).status_code == 401  # no scheme


def test_api_disabled_without_configured_token(settings: Settings) -> None:
    app.dependency_overrides[settings_dep] = lambda: settings  # api_token None
    try:
        r = TestClient(app).get("/api/findings", headers={"Authorization": "Bearer anything"})
        assert r.status_code == 503
        r = TestClient(app).post(
            "/api/scans", json={"mode": "full"}, headers={"Authorization": "Bearer "}
        )
        assert r.status_code == 503
    finally:
        app.dependency_overrides.clear()


def test_findings_and_filters(client: TestClient, seeded: Settings) -> None:
    r = client.get("/api/findings", headers=AUTH, params={"tier": ["P1"]})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] > 0 and all(f["priority"]["tier"] == "P1" for f in body["findings"])
    fid = body["findings"][0]["finding_id"]
    detail = client.get(f"/api/findings/{fid}", headers=AUTH).json()
    assert detail["recommendation"]["patch_applied"] is False
    assert client.get("/api/findings/../../etc/passwd", headers=AUTH).status_code in (404, 422)
    assert client.get("/api/findings/zzzz", headers=AUTH).status_code == 422
    assert client.get("/api/findings", headers=AUTH, params={"status": "pwned"}).status_code == 422
    assert (
        client.get("/api/findings", headers=AUTH, params={"product": "x' OR 1=1; --"}).status_code
        == 422
    )
    assert client.get("/api/findings", headers=AUTH, params={"limit": 100000}).status_code == 422


def test_export_endpoints(client: TestClient, seeded: Settings) -> None:
    r = client.get("/api/reports/export", headers=AUTH, params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    j = client.get("/api/reports/export", headers=AUTH).json()
    assert j["disclaimer"].startswith("Terminus generates recommendations only")


def test_inventory_upload_validation(client: TestClient) -> None:
    good = (DATA_DIR / "sample_inventory.csv").read_bytes()
    r = client.post("/api/inventory", headers=AUTH, files={"file": ("inv.csv", good, "text/csv")})
    assert r.status_code == 200 and r.json()["imported"] is True

    bad = json.dumps([{"asset_id": "bad id", "software_name": "x"}]).encode()
    r = client.post(
        "/api/inventory", headers=AUTH, files={"file": ("inv.json", bad, "application/json")}
    )
    assert r.status_code == 422 and r.json()["imported"] is False and r.json()["errors"]

    r = client.post(
        "/api/inventory", headers=AUTH, files={"file": ("evil.py", b"import os", "text/x-python")}
    )
    assert r.status_code == 415
    r = client.post(
        "/api/inventory",
        headers=AUTH,
        files={"file": ("../../etc/passwd.json", b"{bad", "application/json")},
    )
    assert r.status_code == 422
    assert not Path("../../etc/passwd.json").exists()


def test_scan_requires_inventory_and_valid_mode(client: TestClient, api_settings: Settings) -> None:
    assert client.post("/api/scans", headers=AUTH, json={"mode": "full"}).status_code == 409
    assert client.post("/api/scans", headers=AUTH, json={"mode": "rm -rf /"}).status_code == 422
    assert client.post(
        "/api/scans", headers=AUTH, json={"mode": "full", "cmd": "x"}
    ).status_code in (202, 409, 422)


def test_no_state_changing_routes_beyond_intended() -> None:
    mutating = sorted(
        (route.path, method)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if method in {"POST", "PUT", "PATCH", "DELETE"}
    )
    assert mutating == [("/api/inventory", "POST"), ("/api/scans", "POST")]
