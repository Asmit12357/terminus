"""CLI behaviour: installed entry point, data locations, configuration errors,
exit codes, persistence, and the guarantee that core commands need no web
framework, LLM package or network server."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
from contextlib import closing
from pathlib import Path

import pytest

from terminus import cli, diagnostics, paths
from terminus.config import Settings, load_settings
from terminus.storage import db as dbmod
from terminus.storage.db import StorageError
from terminus.storage.repository import Repository
from tests.conftest import DATA_DIR

REPO_ROOT = Path(__file__).resolve().parent.parent
OPTIONAL_MODULES = (
    "streamlit",
    "fastapi",
    "starlette",
    "uvicorn",
    "pandas",
    "altair",
    "llama_index",
)


def _clean_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TERMINUS_")}
    env["TERMINUS_HOME"] = str(home)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _console_script() -> str | None:
    return shutil.which("terminus", path=str(Path(sys.executable).parent))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated Terminus home for in-process CLI calls, with the CWD elsewhere."""
    for name in list(os.environ):
        if name.startswith("TERMINUS_"):
            monkeypatch.delenv(name)
    home = tmp_path / "home"
    monkeypatch.setenv("TERMINUS_HOME", str(home))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return home


def run_cli(*argv: str) -> int:
    return cli.main(list(argv))


# ---------------------------------------------------------------------------
# Installed console script, run from outside the repository
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_console_script() is None, reason="console script not installed")
def test_console_script_help_from_outside_repo(tmp_path: Path) -> None:
    home = tmp_path / "home"
    result = subprocess.run(
        [str(_console_script()), "--help"],
        cwd=tmp_path,
        env=_clean_env(home),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    for command in ("import-inventory", "scan", "findings", "export", "validate", "benchmark"):
        assert command in result.stdout
    assert not home.exists(), "--help must not create the data folder"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(_console_script() is None, reason="console script not installed")
def test_console_script_workflow_persists_between_runs(tmp_path: Path) -> None:
    home, work = tmp_path / "home", tmp_path / "work"
    work.mkdir()
    env = _clean_env(home)

    def term(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(_console_script()), *args],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    assert term("import-inventory", "--sample").returncode == 0
    scan = term("scan", "--demo", "--mode", "full", "--json", "-q")
    assert scan.returncode == 0, scan.stderr
    scan_record = json.loads(scan.stdout)
    assert scan_record["status"] == "completed"
    assert scan_record["mode"] == "demo-full"

    # A new process sees the same history and findings.
    scans = json.loads(term("scans", "--json").stdout)
    assert [s["scan_id"] for s in scans] == [scan_record["scan_id"]]
    listing = json.loads(term("findings", "--json", "--limit", "0").stdout)
    assert listing["data_mode"] == "demo"
    assert listing["summary"]["total"] == scan_record["findings_count"] > 0

    first = listing["findings"][0]
    shown = term("show", first["finding_id"][:10], "--json")
    assert shown.returncode == 0
    assert json.loads(shown.stdout)["cve_id"] == first["cve_id"]

    exported = term("export", "--format", "csv", "--out", "report.csv")
    assert exported.returncode == 0
    assert (work / "report.csv").read_text(encoding="utf-8").startswith("priority_tier,")

    # User data lives only in the home; the working directory holds just the export.
    assert (home / "terminus.db").is_file()
    assert sorted(p.name for p in work.iterdir()) == ["report.csv"]


# ---------------------------------------------------------------------------
# No web server, no optional packages for the core workflow
# ---------------------------------------------------------------------------


def test_core_workflow_runs_without_optional_packages_or_servers(tmp_path: Path) -> None:
    """Optional packages are made unimportable and sockets cannot listen; every
    core command must still succeed and none of the optional stacks may load."""
    script = textwrap.dedent(
        f"""
        import importlib.abc, json, socket, sys

        BLOCKED = {OPTIONAL_MODULES!r}

        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in BLOCKED:
                    raise ImportError(f"blocked optional module {{name}}")
                return None

        sys.meta_path.insert(0, Block())

        def no_server(*args, **kwargs):
            raise AssertionError("a core command tried to open a listening socket")

        socket.socket.listen = no_server
        socket.socket.bind = no_server

        from terminus.cli import main

        codes = {{}}
        for argv in (
            ["--help"],
            ["init"],
            ["info"],
            ["validate", sys.argv[1]],
            ["import-inventory", sys.argv[1]],
            ["scan", "--demo", "-q"],
            ["findings"],
            ["queue"],
            ["scans"],
            ["export", "--format", "json"],
            ["benchmark"],
        ):
            try:
                codes[argv[0]] = main(argv)
            except SystemExit as exc:
                codes[argv[0]] = exc.code
        loaded = sorted(m for m in sys.modules if m.split(".")[0] in BLOCKED)
        print("RESULT" + json.dumps({{"codes": codes, "loaded": loaded}}))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(DATA_DIR / "sample_inventory.csv")],
        cwd=tmp_path,
        env={**_clean_env(tmp_path / "home"), "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    payload = json.loads(result.stdout.split("RESULT", 1)[1])
    assert payload["loaded"] == []
    assert payload["codes"] == {
        "--help": 0,
        "init": 0,
        "info": 0,
        "validate": 0,
        "import-inventory": 0,
        "scan": 0,
        "findings": 0,
        "queue": 0,
        "scans": 0,
        "export": 0,
        "benchmark": 0,
    }


@pytest.mark.parametrize(
    ("command", "extra"), [(["dashboard"], "dashboard"), (["serve-api"], "api")]
)
def test_optional_commands_explain_missing_extra(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
    extra: str,
) -> None:
    monkeypatch.setattr(cli, "installed", lambda _dist: False)
    assert run_cli(*command) == cli.EXIT_ENV
    err = capsys.readouterr().err
    assert "not installed" in err
    assert f"terminus[{extra}] @ git+https://github.com/Asmit12357/terminus.git" in err


# ---------------------------------------------------------------------------
# Data locations and configuration
# ---------------------------------------------------------------------------


def test_default_home_per_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert paths.default_home() == tmp_path / "Local" / "Terminus"

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert paths.default_home() == tmp_path / "xdg" / "terminus"
    monkeypatch.setenv("XDG_DATA_HOME", "relative/ignored")
    assert paths.default_home() == Path.home() / ".local" / "share" / "terminus"


def test_terminus_home_override_and_relative_db_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TERMINUS_HOME", str(tmp_path / "custom"))
    monkeypatch.setenv("TERMINUS_DB_PATH", "nested/my.db")
    settings = load_settings()
    assert settings.home == (tmp_path / "custom").resolve()
    # Relative database paths are anchored to the home, never to the CWD.
    assert settings.db_path == settings.home / "nested" / "my.db"


def test_config_file_in_home_is_read_and_cwd_dotenv_is_ignored(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home.mkdir()
    (home / "config.env").write_text("TERMINUS_MODE=demo\n", encoding="utf-8")
    # A .env in the working directory (e.g. an untrusted checkout) must not be used.
    Path(".env").write_text("TERMINUS_DB_PATH=hijacked.db\nTERMINUS_MODE=live\n", encoding="utf-8")

    settings = load_settings()
    assert settings.mode == "demo"
    assert settings.db_path == home.resolve() / "terminus.db"

    assert run_cli("import-inventory", "--sample") == 0
    assert run_cli("scan", "-q") == 0  # demo mode comes from config.env
    assert "DEMO" in capsys.readouterr().err
    assert not Path("hijacked.db").exists()


def test_environment_variables_override_config_file(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home.mkdir()
    (home / "config.env").write_text("TERMINUS_MODE=demo\n", encoding="utf-8")
    monkeypatch.setenv("TERMINUS_MODE", "live")
    assert load_settings().mode == "live"


def test_info_creates_nothing_and_init_never_overwrites_config(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli("info") == 0
    assert not home.exists()

    assert run_cli("init") == 0
    config = home / "config.env"
    assert config.is_file() and (home / "terminus.db").is_file()
    config.write_text("TERMINUS_NVD_API_KEY=my-own-key\n", encoding="utf-8")
    assert run_cli("init") == 0
    assert config.read_text(encoding="utf-8") == "TERMINUS_NVD_API_KEY=my-own-key\n"

    capsys.readouterr()
    assert run_cli("info", "--json") == 0
    info = json.loads(capsys.readouterr().out)
    assert info["secrets_configured"] == ["TERMINUS_NVD_API_KEY"]
    assert "my-own-key" not in json.dumps(info)


def test_global_options_work_before_or_after_the_command(home: Path, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere.db"
    assert run_cli("--db", str(other), "import-inventory", "--sample") == 0
    assert run_cli("findings", "--db", str(other)) == 0
    assert other.is_file()
    assert not (home / "terminus.db").exists()


# ---------------------------------------------------------------------------
# Missing or broken configuration is reported, never silently degraded
# ---------------------------------------------------------------------------


def test_llm_provider_without_key_blocks_scan(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    monkeypatch.setenv("TERMINUS_LLM_PROVIDER", "openai")
    assert run_cli("scan", "--demo", "-q") == cli.EXIT_ENV
    err = capsys.readouterr().err
    assert "TERMINUS_OPENAI_API_KEY is not set" in err
    assert Repository(home / "terminus.db").list_scans() == []


def test_llm_provider_without_package_names_the_extra(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    monkeypatch.setenv("TERMINUS_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("TERMINUS_ANTHROPIC_API_KEY", "sk-test-not-real")
    monkeypatch.setattr(diagnostics, "installed", lambda dist: dist == "llama-index-core")
    assert run_cli("scan", "--demo", "-q") == cli.EXIT_ENV
    err = capsys.readouterr().err
    assert "llama-index-llms-anthropic is not installed" in err
    assert "terminus[agent-anthropic]" in err
    assert "sk-test-not-real" not in err


def test_search_provider_without_key_blocks_live_scan_only(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    monkeypatch.setenv("TERMINUS_SEARCH_PROVIDER", "tavily")
    # Live scan: refused before any network request.
    assert run_cli("scan", "-q") == cli.EXIT_ENV
    assert "TERMINUS_TAVILY_API_KEY is not set" in capsys.readouterr().err
    # Demo scans never use web search, so they still run (and say they are demo).
    assert run_cli("scan", "--demo", "-q") == 0


def test_build_llm_researcher_raises_instead_of_degrading(tmp_path: Path) -> None:
    from terminus.agent.llm import build_llm_researcher

    base = Settings(_env_file=None, db_path=tmp_path / "t.db")
    assert build_llm_researcher(base) is None
    broken = Settings(_env_file=None, db_path=tmp_path / "t.db", llm_provider="openai")
    with pytest.raises(diagnostics.ConfigurationError, match="OPENAI_API_KEY"):
        build_llm_researcher(broken)


def test_live_scan_never_falls_back_to_fixtures(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The README flow: demo scan first, then live. With every live source
    unreachable, the live scan reports the outage. It must neither serve recorded
    demo data nor keep earlier demo records around to be matched as live data."""
    import terminus.service

    assert run_cli("import-inventory", "--sample") == 0
    assert run_cli("scan", "--demo", "-q") == 0
    repo = Repository(home / "terminus.db")
    assert repo.cve_sources() == {"demo-fixture"}
    demo_findings = repo.count_findings()
    assert demo_findings > 0

    def unreachable(settings: Settings, repo: Repository, demo: bool | None = None):  # type: ignore[no-untyped-def]
        assert demo is False, "a live scan asked for demo sources"
        from terminus.sources import build_live_sources

        offline = settings.model_copy(
            update={
                "nvd_base_url": "https://127.0.0.1:9/nvd",
                "kev_url": "https://127.0.0.1:9/kev.json",
                "epss_base_url": "https://127.0.0.1:9/epss",
                "osv_base_url": "https://127.0.0.1:9/osv",
                "http_max_retries": 0,
                "http_timeout_seconds": 2.0,
                "fetch_vendor_pages": False,
            }
        )
        return build_live_sources(offline, repo)

    monkeypatch.setattr(terminus.service, "build_sources", unreachable)
    capsys.readouterr()
    run_cli("scan", "--json", "-q")
    scan = json.loads(capsys.readouterr().out)
    assert scan["mode"] == "incremental"
    assert scan["status"] in ("failed", "completed_with_errors")
    states = {s["source"]: s["state"] for s in scan["source_status"]}
    assert states.get("nvd") == "unavailable"
    assert "demo" not in states.values()
    assert any(f"{demo_findings} demo findings" in n for n in scan["notices"])

    assert repo.cve_sources() == set()
    assert repo.list_findings() == []
    # KEV was unreachable: no stale demo KEV excerpt may stand in for the catalog.
    assert repo.get_kev("CVE-2021-44228") is None
    assert repo.kev_retrieved_at() is None
    # Inventory and scan history survive the switch.
    assert len(repo.list_items()) == 16
    assert [s.mode for s in repo.list_scans()] == ["incremental", "demo-incremental"]


def test_demo_scan_refuses_to_mix_into_live_results(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.conftest import make_cve

    assert run_cli("import-inventory", "--sample") == 0
    repo = Repository(home / "terminus.db")
    repo.upsert_cve(make_cve("CVE-2099-0001"))  # a record from a live NVD scan
    assert run_cli("scan", "--demo", "-q") == cli.EXIT_FAILED
    err = capsys.readouterr().err
    assert "holds live scan results" in err and "--home" in err
    assert repo.cve_sources() == {"nvd"}
    assert repo.list_scans() == []


# ---------------------------------------------------------------------------
# Exit codes and input handling
# ---------------------------------------------------------------------------


def test_exit_codes(home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli("validate", "missing.json") == cli.EXIT_USAGE
    assert "file not found" in capsys.readouterr().err

    bad = tmp_path / "bad.csv"
    bad.write_text("asset_id,software_name\n,\n", encoding="utf-8")
    assert run_cli("validate", str(bad)) == cli.EXIT_FAILED

    assert run_cli("scan", "--demo") == cli.EXIT_FAILED
    assert "no inventory imported" in capsys.readouterr().err

    assert run_cli("import-inventory", "--sample") == 0
    assert run_cli("show", "not-hex!") == cli.EXIT_USAGE
    assert run_cli("show", "abcdef0123") == cli.EXIT_FAILED

    with pytest.raises(SystemExit) as exc:
        run_cli("findings", "--tier", "P9")
    assert exc.value.code == cli.EXIT_USAGE
    with pytest.raises(SystemExit) as exc:
        run_cli()
    assert exc.value.code == cli.EXIT_USAGE


def test_unwritable_home_is_an_environment_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("TERMINUS_HOME", str(blocker / "home"))
    monkeypatch.chdir(tmp_path)
    assert run_cli("import-inventory", "--sample") == cli.EXIT_ENV
    err = capsys.readouterr().err
    assert "--home" in err and "TERMINUS_HOME" in err


def test_failed_import_keeps_previous_inventory(home: Path, tmp_path: Path) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"asset_id": "", "software_name": "x"}]), encoding="utf-8")
    assert run_cli("import-inventory", str(bad)) == cli.EXIT_FAILED
    assert len(Repository(home / "terminus.db").list_items()) == 16


def test_sample_inventory_never_overwrites_without_force(home: Path) -> None:
    target = Path("inventory.json")
    target.write_text("my real inventory", encoding="utf-8")
    assert run_cli("sample-inventory", "--out", str(target)) == cli.EXIT_USAGE
    assert target.read_text(encoding="utf-8") == "my real inventory"
    assert run_cli("sample-inventory", "--out", str(target), "--force") == 0
    assert run_cli("validate", str(target)) == 0


def test_findings_filters_and_json(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    assert run_cli("scan", "--demo", "-q") == 0
    capsys.readouterr()

    assert run_cli("findings", "--json", "--asset", "app-prod-02", "--product", "log4j") == 0
    rows = json.loads(capsys.readouterr().out)["findings"]
    assert rows and all(r["asset_id"] == "app-prod-02" for r in rows)
    assert all("log4j" in r["software"].lower() for r in rows)

    assert run_cli("findings", "--json", "--cve", "CVE-2021-44228") == 0
    rows = json.loads(capsys.readouterr().out)["findings"]
    assert rows and {r["cve_id"] for r in rows} == {"CVE-2021-44228"}

    assert run_cli("queue", "--json", "--confirmed-only") == 0
    plan = json.loads(capsys.readouterr().out)["items"]
    log4j = next(r for r in plan if r["asset_id"] == "app-prod-02" and "log4j" in r["software"])
    # One target satisfies every open log4j CVE on that host.
    assert log4j["target_version"] and len(log4j["open_cves"]) > 1


def test_benchmark_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli("benchmark", "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["false_positives"] == 0 and report["false_negatives"] == 0
    assert len(report["rows"]) == report["cases"]


# ---------------------------------------------------------------------------
# Database safety across upgrades
# ---------------------------------------------------------------------------


def test_reopening_preserves_inventory_and_history(home: Path) -> None:
    assert run_cli("import-inventory", "--sample") == 0
    assert run_cli("scan", "--demo", "-q") == 0
    dbmod._local.conns = {}  # drop cached connections: behave like a new process
    repo = Repository(home / "terminus.db")
    assert len(repo.list_items()) == 16
    assert len(repo.list_scans()) == 1
    assert repo.count_findings() > 0


def test_schema_upgrade_backs_up_and_keeps_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "terminus.db"
    from terminus.service import import_inventory

    import_inventory(Repository(path), (DATA_DIR / "sample_inventory.json").read_bytes(), "s.json")
    monkeypatch.setattr(dbmod, "SCHEMA_VERSION", 2)
    monkeypatch.setattr(dbmod, "MIGRATIONS", {2: "CREATE TABLE IF NOT EXISTS added (x TEXT);"})

    repo = Repository(path)
    assert len(repo.list_items()) == 16
    backup = tmp_path / "terminus.db.v1.bak"
    assert backup.is_file()
    with closing(sqlite3.connect(backup)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM inventory_items").fetchone()[0] == 16
    with dbmod.transaction(path) as conn:
        assert dbmod.stored_schema_version(conn) == 2


def test_newer_foreign_or_corrupt_databases_are_refused_untouched(
    tmp_path: Path, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    newer = tmp_path / "newer.db"
    Repository(newer)
    with dbmod.transaction(newer) as conn:
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(StorageError, match="newer Terminus"):
        Repository(newer)
    assert run_cli("--db", str(newer), "findings") == cli.EXIT_ENV
    assert "newer Terminus" in capsys.readouterr().err

    foreign = tmp_path / "other-app.db"
    with closing(sqlite3.connect(foreign)) as conn:
        conn.execute("CREATE TABLE notes (body TEXT)")
        conn.commit()
    with pytest.raises(StorageError, match="not a Terminus database"):
        Repository(foreign)
    with closing(sqlite3.connect(foreign)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert tables == {"notes"}

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(StorageError):
        Repository(corrupt)
    assert corrupt.read_bytes() == b"this is not sqlite" * 100


# ---------------------------------------------------------------------------
# Optional: build the wheel and install it as a uv tool (slow; opt-in)
# ---------------------------------------------------------------------------


@pytest.mark.install
@pytest.mark.skipif(
    os.environ.get("TERMINUS_INSTALL_TESTS") != "1" or shutil.which("uv") is None,
    reason="set TERMINUS_INSTALL_TESTS=1 (needs uv and network access to PyPI)",
)
def test_wheel_installs_as_uv_tool(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    dist = tmp_path / "dist"
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(dist), str(REPO_ROOT)],
        check=True,
        capture_output=True,
        timeout=600,
    )
    wheel = next(dist.glob("terminus-*.whl"))
    env = _clean_env(tmp_path / "home")
    env.update(
        UV_TOOL_DIR=str(tmp_path / "tools"),
        UV_TOOL_BIN_DIR=str(tmp_path / "bin"),
        UV_LINK_MODE="copy",
    )
    subprocess.run(
        [uv, "tool", "install", str(wheel)], check=True, env=env, capture_output=True, timeout=900
    )
    exe = shutil.which("terminus", path=str(tmp_path / "bin"))
    assert exe is not None
    work = tmp_path / "work"
    work.mkdir()

    def term(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [exe, *args], cwd=work, env=env, capture_output=True, text=True, timeout=300
        )

    assert term("--version").stdout.strip().startswith("terminus ")
    assert term("import-inventory", "--sample").returncode == 0
    assert term("scan", "--demo", "-q").returncode == 0
    assert json.loads(term("findings", "--json").stdout)["summary"]["total"] > 0
    assert term("benchmark").returncode == 0
    # The core install does not include the optional dashboard.
    dashboard = term("dashboard")
    assert dashboard.returncode == cli.EXIT_ENV
    assert "terminus[dashboard]" in dashboard.stderr


# ---------------------------------------------------------------------------
# Importing an existing (e.g. 0.1) database
# ---------------------------------------------------------------------------


def _old_database(tmp_path: Path) -> Path:
    """A database with an inventory, a scan and findings, like 0.1 left in a clone."""
    from terminus.service import import_inventory, run_scan

    path = tmp_path / "old-clone" / "terminus.db"
    repo = Repository(path)
    import_inventory(repo, (DATA_DIR / "sample_inventory.json").read_bytes(), "s.json")
    run_scan(Settings(_env_file=None, db_path=path), repo, "full", demo=True)
    dbmod._local.conns = {}  # close the cached handle: the file is now "someone else's"
    return path


def test_init_from_db_imports_history_and_leaves_source_untouched(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import hashlib

    old = _old_database(tmp_path)
    before = hashlib.sha256(old.read_bytes()).hexdigest()
    assert run_cli("init", "--from-db", str(old)) == 0
    out = capsys.readouterr().out
    assert "inventory items: 16, scans: 1, findings:" in out
    assert hashlib.sha256(old.read_bytes()).hexdigest() == before

    repo = Repository(home / "terminus.db")
    assert len(repo.list_items()) == 16
    assert len(repo.list_scans()) == 1
    assert repo.count_findings() > 0
    assert run_cli("findings", "--limit", "1") == 0


def test_init_from_db_never_overwrites_existing_data(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old = _old_database(tmp_path)
    assert run_cli("import-inventory", "--sample") == 0
    target = home / "terminus.db"
    before = Repository(target).latest_inventory()
    capsys.readouterr()
    assert run_cli("init", "--from-db", str(old)) == cli.EXIT_FAILED
    err = capsys.readouterr().err
    assert "already holds" in err and "left unchanged" in err
    assert Repository(target).latest_inventory() == before
    assert Repository(target).list_scans() == []


@pytest.mark.parametrize("kind", ["missing", "foreign", "corrupt", "newer"])
def test_init_from_db_rejects_unusable_sources(home: Path, tmp_path: Path, kind: str) -> None:
    source = tmp_path / f"{kind}.db"
    if kind == "foreign":
        with closing(sqlite3.connect(source)) as conn:
            conn.execute("CREATE TABLE notes (body TEXT)")
            conn.commit()
    elif kind == "corrupt":
        source.write_bytes(b"not a database" * 50)
    elif kind == "newer":
        Repository(source)
        with dbmod.transaction(source) as conn:
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        dbmod._local.conns = {}
    assert run_cli("init", "--from-db", str(source)) == cli.EXIT_USAGE
    assert not (home / "terminus.db").exists() or not Repository(home / "terminus.db").list_items()


def test_legacy_database_hint_in_source_checkouts(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    checkout = tmp_path / "clone"
    (checkout / "terminus").mkdir(parents=True)
    (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(paths, "PACKAGE_DIR", checkout / "terminus")
    assert paths.legacy_database() is None
    (checkout / "terminus.db").write_bytes(b"")
    assert paths.legacy_database() == checkout / "terminus.db"

    assert run_cli("info") == 0
    assert f"terminus init --from-db {checkout / 'terminus.db'}" in capsys.readouterr().out
    # Once the active database holds data, the hint goes away.
    assert run_cli("import-inventory", "--sample") == 0
    capsys.readouterr()
    assert run_cli("info") == 0
    assert "--from-db" not in capsys.readouterr().out
