"""Terminus command-line interface (the primary way to use Terminus).

    terminus init                              create the data folder and config template
    terminus import-inventory --sample         or: terminus import-inventory my_inventory.csv
    terminus scan --demo                       recorded fixtures, no network
    terminus scan --mode full                  live NVD/KEV/EPSS/OSV
    terminus findings --tier P1 P2
    terminus show <finding-id>
    terminus queue                             one upgrade target per software install
    terminus export --format csv --out report.csv

Nothing here starts a web server or imports the optional dashboard/API stacks;
``dashboard`` and ``serve-api`` load them only when invoked.

Exit codes: 0 success; 1 the command ran but the result is negative (invalid
inventory rows, failed scan, finding not found, benchmark mismatch); 2 usage or
input-file error; 3 environment/configuration problem (data folder, database,
missing optional component); 130 interrupted.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app import __version__
from app.config import Settings, load_settings
from app.diagnostics import (
    Component,
    ConfigurationError,
    install_hint,
    installed,
    llm_component,
    nvd_component,
    optional_components,
    search_component,
)
from app.inventory import MAX_INVENTORY_BYTES, InventoryFormatError, parse_inventory
from app.models import DEMO_SOURCE, Finding, ScanRecord
from app.paths import (
    CONFIG_TEMPLATE,
    SAMPLE_INVENTORY_CSV,
    SAMPLE_INVENTORY_JSON,
    ensure_dir,
)
from app.storage.db import StorageError
from app.storage.repository import Repository

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_ENV = 3
EXIT_INTERRUPTED = 130

STATUSES = ["confirmed_affected", "potentially_affected", "confirmed_unaffected", "unverified"]
TIERS = ["P1", "P2", "P3", "P4", "INFO"]


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_USAGE, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.hint = hint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _err(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _emit_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")


def _settings(args: argparse.Namespace) -> Settings:
    home = Path(args.home).expanduser().resolve() if args.home else None
    settings = load_settings(home)
    if args.db:
        settings = settings.model_copy(update={"db_path": Path(args.db).expanduser().resolve()})
    return settings


def _repo(settings: Settings) -> Repository:
    try:
        return Repository(settings.db_path)
    except OSError as exc:
        raise CliError(
            f"cannot create or open the data folder for {settings.db_path}: {exc}",
            EXIT_ENV,
            "choose a writable location with --home DIR or the TERMINUS_HOME variable",
        ) from exc


def _read_input(path_arg: str) -> tuple[bytes, str]:
    path = Path(path_arg).expanduser()
    if not path.exists():
        raise CliError(f"file not found: {path}")
    if not path.is_file():
        raise CliError(f"not a file: {path}")
    size = path.stat().st_size
    if size > MAX_INVENTORY_BYTES:
        raise CliError(f"{path} is {size:,} bytes; the limit is {MAX_INVENTORY_BYTES:,}")
    try:
        return path.read_bytes(), path.name
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc}") from exc


def _write_output(path_arg: str, text: str, *, force: bool = True) -> Path:
    path = Path(path_arg).expanduser()
    if path.exists() and not force:
        raise CliError(f"{path} already exists", hint="use --force to overwrite it")
    if not path.parent.is_dir():
        raise CliError(f"folder does not exist: {path.parent}")
    try:
        path.write_text(text, encoding="utf-8", newline="")
    except OSError as exc:
        raise CliError(f"cannot write {path}: {exc}") from exc
    return path


def _wrap(text: str, indent: str = "  ") -> str:
    width = max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent + "  ")


def _clip(value: object, width: int) -> str:
    text = str(value)
    return text if len(text) <= width else text[: width - 1] + "~"


def _is_demo(findings: list[Finding]) -> bool:
    return any(f.cve_source == DEMO_SOURCE for f in findings)


def _demo_note(findings: list[Finding]) -> str | None:
    if not _is_demo(findings):
        return None
    captured = min((f.cve_retrieved_at for f in findings if f.cve_retrieved_at), default=None)
    when = f" captured {captured:%Y-%m-%d}" if captured else ""
    return (
        f"DEMO DATA: findings come from recorded API responses{when}, not live sources. "
        "Run `terminus scan` without --demo for current data."
    )


def _validation_dict(result: Any) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "items": len(result.items),
        "errors": [e.model_dump() for e in result.errors],
        "warnings": result.warnings,
        "duplicates_removed": result.duplicates_removed,
    }


def _print_validation(result: Any) -> None:
    print(
        f"items: {len(result.items)}  errors: {len(result.errors)}  "
        f"warnings: {len(result.warnings)}  duplicates removed: {result.duplicates_removed}"
    )
    for err in result.errors[:50]:
        print(f"  ERROR row {err.row} [{err.field or '-'}]: {err.message}")
    if len(result.errors) > 50:
        print(f"  ... {len(result.errors) - 50} more errors (use --json for all)")
    for warning in result.warnings[:50]:
        print(f"  warning: {warning}")


def _component_line(c: Component) -> str:
    line = f"  {c.name:14} {c.state:13} {c.detail}"
    return line + (f"\n  {'':14} {'':13} -> {c.hint}" if c.hint and c.state != "ok" else "")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    settings = _settings(args)
    try:
        ensure_dir(settings.home)
    except OSError as exc:
        raise CliError(f"cannot create {settings.home}: {exc}", EXIT_ENV) from exc
    config_created = False
    if not settings.config_file.exists():
        shutil.copyfile(CONFIG_TEMPLATE, settings.config_file)
        config_created = True
    repo = _repo(settings)
    data = {
        "home": str(settings.home),
        "config_file": str(settings.config_file),
        "config_created": config_created,
        "database": str(repo.db_path),
    }
    if args.json:
        _emit_json(data)
        return EXIT_OK
    print(f"Terminus home:  {settings.home}")
    verb = "created from template" if config_created else "already exists, left unchanged"
    print(f"Config file:    {settings.config_file} ({verb})")
    print(f"Database:       {repo.db_path}")
    print("\nNext: terminus import-inventory --sample   then   terminus scan --demo")
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    """Reports paths and configuration. Creates nothing that does not exist yet."""
    settings = _settings(args)
    db = settings.db_path
    components = [
        nvd_component(settings),
        search_component(settings),
        llm_component(settings),
        *optional_components(),
    ]
    data: dict[str, Any] = {
        "version": __version__,
        "python": sys.version.split()[0],
        "home": str(settings.home),
        "config_file": str(settings.config_file),
        "config_file_exists": settings.config_file.is_file(),
        "database": str(db),
        "database_exists": db.is_file(),
        "database_bytes": db.stat().st_size if db.is_file() else None,
        "data_mode": settings.mode,
        "secrets_configured": settings.configured_secret_names(),
        "components": [c.__dict__ for c in components],
    }
    if db.is_file():
        repo = _repo(settings)
        inv = repo.latest_inventory()
        scans = repo.list_scans(limit=1)
        data["inventory"] = inv
        data["findings"] = repo.count_findings()
        data["last_scan"] = scans[0].model_dump(mode="json") if scans else None
    if args.json:
        _emit_json(data)
        return EXIT_OK
    print(f"Terminus {__version__} (Python {data['python']})")
    print(f"  home           {settings.home}")
    exists = "" if data["config_file_exists"] else "  (not created; run `terminus init`)"
    print(f"  config file    {settings.config_file}{exists}")
    if db.is_file():
        print(f"  database       {db} ({data['database_bytes']:,} bytes)")
        inv = data["inventory"]
        print(
            "  inventory      "
            + (f"{inv['name']}: {inv['item_count']} items" if inv else "none imported")
        )
        print(f"  findings       {data['findings']}")
        last = data["last_scan"]
        print(
            "  last scan      "
            + (f"{last['started_at']} {last['mode']} {last['status']}" if last else "never")
        )
    else:
        print(f"  database       {db}  (not created yet)")
    print(f"  data mode      {settings.mode} (`scan --demo` always uses recorded fixtures)")
    secrets = ", ".join(data["secrets_configured"]) or "none"
    print(f"  secrets set    {secrets} (values are never shown)")
    print("\nComponents:")
    for c in components:
        print(_component_line(c))
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    content, name = _read_input(args.path)
    try:
        result = parse_inventory(content, name)
    except InventoryFormatError as exc:
        raise CliError(f"invalid inventory: {exc}") from exc
    if args.json:
        _emit_json(_validation_dict(result))
    else:
        _print_validation(result)
    return EXIT_OK if result.ok else EXIT_FAILED


def cmd_import(args: argparse.Namespace) -> int:
    from app.service import import_inventory

    if args.sample == bool(args.path):
        raise CliError("give an inventory file or --sample (not both)")
    if args.sample:
        content, name = SAMPLE_INVENTORY_JSON.read_bytes(), SAMPLE_INVENTORY_JSON.name
    else:
        content, name = _read_input(args.path)
    repo = _repo(_settings(args))
    try:
        result, inventory_id = import_inventory(repo, content, name)
    except InventoryFormatError as exc:
        raise CliError(f"invalid inventory: {exc}") from exc
    if args.json:
        _emit_json({**_validation_dict(result), "inventory_id": inventory_id})
    else:
        _print_validation(result)
        if inventory_id is None:
            _err("inventory NOT imported - fix the errors above (the previous inventory is kept)")
        else:
            print(f"imported inventory {inventory_id} ({len(result.items)} items) from {name}")
    return EXIT_OK if inventory_id else EXIT_FAILED


def cmd_sample(args: argparse.Namespace) -> int:
    source = SAMPLE_INVENTORY_CSV if args.format == "csv" else SAMPLE_INVENTORY_JSON
    text = source.read_text(encoding="utf-8")
    if args.out:
        path = _write_output(args.out, text, force=args.force)
        _err(f"wrote the synthetic sample inventory to {path}")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def _scan_dict(scan: ScanRecord) -> dict[str, Any]:
    return scan.model_dump(mode="json")


def cmd_scan(args: argparse.Namespace) -> int:
    from app.diagnostics import require_research_config
    from app.scanner import ScanAlreadyRunning
    from app.service import LiveDataPresent, check_data_mode, run_scan

    settings = _settings(args)
    repo = _repo(settings)
    if not repo.list_items():
        raise CliError(
            "no inventory imported",
            EXIT_FAILED,
            "run `terminus import-inventory <file>` or `terminus import-inventory --sample`",
        )
    demo = True if args.demo else None
    use_demo = settings.is_demo if demo is None else demo

    def progress(fraction: float, message: str) -> None:
        if not args.quiet:
            _err(f"[{fraction * 100:5.1f}%] {message}")

    try:
        # Cheap pre-checks first, so nothing claims a scan started when it cannot.
        require_research_config(settings, demo=use_demo)
        check_data_mode(repo, demo=use_demo)
        if not args.json:
            label = "DEMO (recorded fixtures, no network)" if use_demo else "LIVE public APIs"
            _err(f"Starting {args.mode} scan using {label}. Database: {repo.db_path}")
        scan = run_scan(settings, repo, args.mode, demo=demo, progress=progress)
    except ScanAlreadyRunning as exc:
        raise CliError("another scan is already running", EXIT_FAILED) from exc
    except LiveDataPresent as exc:
        raise CliError(
            str(exc),
            EXIT_FAILED,
            "try the demo in a separate data folder, e.g. "
            "`terminus --home terminus-demo import-inventory --sample` then "
            "`terminus --home terminus-demo scan --demo`",
        ) from exc
    if args.json:
        _emit_json(_scan_dict(scan))
    else:
        print(
            f"scan {scan.scan_id} {scan.status}: {scan.cves_processed} CVEs processed, "
            f"{scan.findings_count} findings"
        )
        for st in scan.source_status:
            print(f"  source {st.source}: {st.state.value} {st.detail or ''}")
        for err in scan.errors[:20]:
            print(f"  issue: {err}")
        for notice in scan.notices:
            _err(f"note: {notice}")
        if scan.status != "failed":
            print("Next: terminus findings")
    return EXIT_OK if scan.status != "failed" else EXIT_FAILED


def _filtered_findings(args: argparse.Namespace, repo: Repository) -> list[Finding]:
    return repo.list_findings(
        tiers=args.tier,
        statuses=args.status,
        asset_id=args.asset,
        cve_id=args.cve,
        product=args.product,
        limit=10_000,
    )


def _summary_row(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "tier": f.priority.tier,
        "score": f.priority.score,
        "cve_id": f.cve_id,
        "status": f.match.status.value,
        "confidence": f.match.confidence,
        "asset_id": f.item.asset_id,
        "software": f.item.software_name,
        "installed_version": f.item.software_version,
        "kev": f.kev.in_kev,
        "epss": f.epss.score,
        "fix_status": f.fix.status.value,
        "fixed_version": f.fix.fixed_version,
        "action": f.recommendation.action,
        "data_source": f.cve_source,
    }


def cmd_findings(args: argparse.Namespace) -> int:
    from app.service import summarize

    findings = _filtered_findings(args, _repo(_settings(args)))
    shown = findings if args.limit <= 0 else findings[: args.limit]
    if args.json:
        _emit_json(
            {
                "summary": summarize(findings),
                "data_mode": "demo" if _is_demo(findings) else "live",
                "shown": len(shown),
                "findings": [_summary_row(f) for f in shown],
            }
        )
        return EXIT_OK
    note = _demo_note(findings)
    if note:
        _err(note)
    if not findings:
        print("no findings match. Import an inventory and run `terminus scan` first.")
        return EXIT_OK
    s = summarize(findings)
    tiers = "  ".join(f"{t}:{s['by_tier'][t]}" for t in TIERS if t in s["by_tier"])
    print(f"{s['total']} findings  {tiers}  KEV-listed: {s['kev_listed']}")
    print(
        f"{'ID':8}  {'TIER':4} {'SCORE':>5}  {'CVE':16} {'STATUS':20} {'ASSET':14} "
        f"{'SOFTWARE':26} ACTION"
    )
    for f in shown:
        software = f"{f.item.software_name} {f.item.software_version or '?'}"
        action = f.recommendation.action
        target = f.fix.fixed_version or f.fix.conservative_target
        if action == "upgrade" and target:
            action = f"upgrade to >= {target}"
        print(
            f"{f.finding_id[:8]}  {f.priority.tier:4} {f.priority.score:5.1f}  {f.cve_id:16} "
            f"{_clip(f.match.status.value, 20):20} {_clip(f.item.asset_id, 14):14} "
            f"{_clip(software, 26):26} {action}"
        )
    if len(shown) < len(findings):
        print(f"... {len(findings) - len(shown)} more (use --limit 0 to show all)")
    print("Details: terminus show <ID>")
    return EXIT_OK


def _resolve_finding(repo: Repository, ident: str) -> Finding:
    ident = ident.strip().lower()
    if not ident or not all(c in "0123456789abcdef" for c in ident):
        raise CliError("a finding ID is hexadecimal, as printed by `terminus findings`")
    exact = repo.get_finding(ident)
    if exact:
        return exact
    matches = [f for f in repo.list_findings(limit=10_000) if f.finding_id.startswith(ident)]
    if not matches:
        raise CliError(f"no finding with ID {ident}", EXIT_FAILED)
    if len(matches) > 1:
        raise CliError(f"ID prefix {ident} matches {len(matches)} findings; use more characters")
    return matches[0]


def _print_finding(f: Finding) -> None:
    def section(title: str) -> None:
        print(f"\n{title}")

    def ts(value: Any) -> str:
        return f"{value:%Y-%m-%d %H:%M} UTC" if value else "unknown"

    item = f.item
    print(f"{f.cve_id}  [{f.priority.tier} {f.priority.score:.1f}]  finding {f.finding_id}")
    if f.cve_source == DEMO_SOURCE:
        print("DEMO DATA (recorded fixture)")
    print(_wrap(f.summary, ""))

    section("Asset")
    print(f"  {item.asset_id} ({item.hostname or 'no hostname'})")
    env = item.environment.value if item.environment else "unknown environment"
    exposed = "internet-exposed" if item.internet_exposed else "not internet-exposed"
    print(f"  criticality {item.criticality.value}, {env}, {exposed}")
    version = item.software_version or "version unknown"
    print(f"  software: {item.software_name} {version} ({item.ecosystem.value})")

    section("Assessment")
    m = f.match
    print(
        f"  {m.status.label} - confidence {m.confidence:.2f} "
        f"(identity: {m.identity_method.value}, versions: {m.version_scheme})"
    )
    for reason in m.reasons:
        print(_wrap(f"- {reason}"))
    for rng in m.vulnerable_ranges:
        print(f"  vulnerable range: {rng}")

    section("Verified facts")
    if f.cvss:
        print(f"  CVSS {f.cvss.version} {f.cvss.base_score} {f.cvss.vector or ''}")
    else:
        print("  CVSS: not available")
    kev = {True: "LISTED", False: "not listed", None: "unknown (source unavailable)"}[f.kev.in_kev]
    extra = f", added {f.kev.date_added}" if f.kev.date_added else ""
    print(f"  CISA KEV: {kev}{extra} (retrieved {ts(f.kev.retrieved_at)})")
    if f.epss.score is not None:
        pct = f", percentile {f.epss.percentile:.3f}" if f.epss.percentile is not None else ""
        print(f"  EPSS: {f.epss.score:.4f}{pct} (retrieved {ts(f.epss.retrieved_at)})")
    else:
        print("  EPSS: not available")
    fix = f.fix
    fixed = fix.fixed_version or (
        f"conflicting sources; conservative target {fix.conservative_target}"
        if fix.conservative_target
        else "not established"
    )
    print(f"  fixed version: {fixed} [{fix.status.value}]")
    for note in fix.notes:
        print(_wrap(f"- {note}"))
    for ev in m.evidence:
        print(_wrap(f"evidence ({ev.source}, {ev.trust_tier.value}): {ev.claim}"))

    section("Priority factors")
    name_width = max((len(x.name) for x in f.priority.factors), default=10)
    for factor in f.priority.factors:
        flag = "  MISSING" if factor.missing else ""
        print(
            f"  {factor.name:{name_width}} {factor.points:5.1f}/{factor.max_points:<5.1f} "
            f"{_clip(factor.raw_value, 40)}{flag}"
        )
    print(f"  confidence multiplier {f.priority.confidence_multiplier:.2f}")
    for override in f.priority.overrides:
        print(f"  override: {override}")

    section("Recommendation (requires human review; nothing was applied)")
    print(_wrap(f"{f.recommendation.action}: {f.recommendation.summary}"))
    for step in f.recommendation.steps:
        print(_wrap(f"- {step}"))
    if f.vendor_advisory_urls:
        section("Vendor advisories")
        for url in f.vendor_advisory_urls:
            print(f"  {url}")
    if f.supporting_urls:
        section("Other sources")
        for url in f.supporting_urls[:10]:
            print(f"  {url}")
    if f.missing_information or f.uncertainties:
        section("Missing information and uncertainty")
        for line in [*f.missing_information, *f.uncertainties]:
            print(_wrap(f"- {line}"))
    if f.next_verification_step:
        section("Next verification step")
        print(_wrap(f.next_verification_step))
    if f.ai_interpretation:
        section("AI-generated interpretation (not verified)")
        print(_wrap(f.ai_interpretation))
    print(f"\nlast assessed {ts(f.last_assessed)}; first seen {ts(f.first_seen)}")


def cmd_show(args: argparse.Namespace) -> int:
    from app.reports.export import finding_report

    finding = _resolve_finding(_repo(_settings(args)), args.finding_id)
    if args.json:
        _emit_json(finding_report(finding))
    else:
        _print_finding(finding)
    return EXIT_OK


def cmd_queue(args: argparse.Namespace) -> int:
    from app.reports.queue import remediation_plan

    findings = _repo(_settings(args)).list_findings(limit=10_000)
    plan = remediation_plan(
        findings,
        include_potential=not args.confirmed_only,
        include_unverified=not (args.confirmed_only or args.no_unverified),
    )
    if args.json:
        _emit_json(
            {
                "data_mode": "demo" if _is_demo(findings) else "live",
                "items": [row.as_dict() for row in plan],
            }
        )
        return EXIT_OK
    note = _demo_note(findings)
    if note:
        _err(note)
    if not plan:
        print("remediation queue is empty.")
        return EXIT_OK
    print(
        "One change per software installation: the highest fixed version across its open "
        "findings.\nRecommendations only; review before changing anything.\n"
    )
    print(f"{'TIER':4} {'SCORE':>5}  {'ASSET':14} {'SOFTWARE':26} {'CVES':>4} {'KEV':>3}  TARGET")
    for row in plan:
        software = f"{row.software} {row.installed_version or '?'}"
        target = f">= {row.target_version}" if row.target_version else "verify / see advisory"
        print(
            f"{row.highest_tier:4} {row.max_score:5.1f}  {_clip(row.asset_id, 14):14} "
            f"{_clip(software, 26):26} {len(row.open_cves):4} {row.kev_listed:3}  {target}"
        )
        if row.caveats:
            shown = "; ".join(row.caveats[:3])
            more = len(row.caveats) - 3
            if more > 0:
                shown += f"; +{more} more (terminus queue --json)"
            print(_wrap("caveats: " + shown, " " * 12))
    return EXIT_OK


def cmd_scans(args: argparse.Namespace) -> int:
    scans = _repo(_settings(args)).list_scans(limit=max(1, args.limit))
    if args.json:
        _emit_json([_scan_dict(s) for s in scans])
        return EXIT_OK
    if not scans:
        print("no scans yet. Run `terminus scan --demo` or `terminus scan`.")
        return EXIT_OK
    print(
        f"{'SCAN':12}  {'STARTED (UTC)':16}  {'MODE':16} {'STATUS':22} {'CVES':>6} {'FINDINGS':>8}"
    )
    for s in scans:
        print(
            f"{s.scan_id:12}  {s.started_at:%Y-%m-%d %H:%M}  {s.mode:16} {s.status:22} "
            f"{s.cves_processed:6} {s.findings_count:8}"
        )
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    from app.reports.export import DISCLAIMER, export_csv, export_json

    findings = _filtered_findings(args, _repo(_settings(args)))
    demo = _is_demo(findings)
    text = export_json(findings, demo=demo) if args.format == "json" else export_csv(findings)
    if args.out:
        path = _write_output(args.out, text)
        _err(f"wrote {len(findings)} findings to {path}. {DISCLAIMER}")
        note = _demo_note(findings)
        if note:
            _err(note)
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    from app.benchmark import format_report, run_benchmark

    report = run_benchmark()
    if args.json:
        rows = [
            {
                "cve_id": r["case"].cve_id,
                "software": r["case"].item["software_name"],
                "version": r["case"].item.get("software_version"),
                "expected": r["case"].expected,
                "predicted": r["predicted"],
                "status": r["status"],
                "basis": r["case"].basis,
            }
            for r in report["rows"]
        ]
        _emit_json({**{k: v for k, v in report.items() if k != "rows"}, "rows": rows})
    else:
        print(format_report(report))
    return EXIT_OK if report["false_positives"] == 0 and report["false_negatives"] == 0 else 1


def _require_extra(extra: str, distributions: tuple[str, ...]) -> None:
    missing = [d for d in distributions if not installed(d)]
    if missing:
        raise CliError(
            f"this optional command needs packages that are not installed: {', '.join(missing)}",
            EXIT_ENV,
            f"install the '{extra}' extra: {install_hint(extra)}",
        )


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Optional local web dashboard. Never needed for the CLI workflow."""
    _require_extra("dashboard", ("streamlit", "pandas"))
    from streamlit.web import cli as stcli

    settings = _settings(args)
    os.environ["TERMINUS_HOME"] = str(settings.home)
    os.environ["TERMINUS_DB_PATH"] = str(settings.db_path)
    script = Path(__file__).resolve().parent / "dashboard.py"
    sys.argv = [
        "streamlit",
        "run",
        str(script),
        "--server.address=127.0.0.1",
        f"--server.port={args.port}",
        "--server.maxUploadSize=5",
        "--browser.gatherUsageStats=false",
        # Headless: no first-run e-mail prompt and no browser auto-launch.
        "--server.headless=true",
    ]
    _err(f"Terminus dashboard: open http://127.0.0.1:{args.port} (Ctrl+C to stop)")
    return int(stcli.main() or 0)


def cmd_serve_api(args: argparse.Namespace) -> int:
    """Optional REST API. Never needed for the CLI workflow."""
    _require_extra("api", ("fastapi", "uvicorn", "python-multipart"))
    import uvicorn

    settings = _settings(args)
    os.environ["TERMINUS_HOME"] = str(settings.home)
    os.environ["TERMINUS_DB_PATH"] = str(settings.db_path)
    uvicorn.run("app.api:app", host=args.host, port=args.port, log_level="info")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _global_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    default: Any = argparse.SUPPRESS if suppress else None
    parser.add_argument(
        "--home",
        metavar="DIR",
        default=default,
        help="Terminus data folder (default: TERMINUS_HOME or the per-user data folder)",
    )
    parser.add_argument(
        "--db", metavar="FILE", default=default, help="database file (default: <home>/terminus.db)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="debug logging and full tracebacks",
    )


def _filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tier", nargs="+", choices=TIERS, help="priority tiers to include")
    p.add_argument("--status", nargs="+", choices=STATUSES, help="match statuses to include")
    p.add_argument("--asset", metavar="ASSET_ID", help="only this asset ID (exact)")
    p.add_argument("--cve", metavar="TEXT", help="CVE ID or part of one")
    p.add_argument("--product", metavar="TEXT", help="software name contains TEXT")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="terminus",
        description=(
            "Terminus: vulnerability intelligence and remediation recommendations. "
            "Matches CVEs (NVD, CISA KEV, FIRST EPSS, OSV) against your software inventory, "
            "ranks them, and explains what to patch. It never applies changes."
        ),
        epilog=(
            "quick start:  terminus import-inventory --sample  &&  terminus scan --demo  &&  "
            "terminus findings\n"
            "exit codes: 0 ok, 1 negative result, 2 usage/input error, 3 environment/config "
            "problem, 130 interrupted"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"terminus {__version__}")
    _global_options(parser, suppress=False)
    common = argparse.ArgumentParser(add_help=False)
    _global_options(common, suppress=True)
    as_json = argparse.ArgumentParser(add_help=False)
    as_json.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    def add(
        name: str, fn: Callable[[argparse.Namespace], int], help_: str, json_: bool = False
    ) -> argparse.ArgumentParser:
        parents = [common, as_json] if json_ else [common]
        p = sub.add_parser(name, parents=parents, help=help_, description=help_)
        p.set_defaults(fn=fn)
        if not json_:
            p.set_defaults(json=False)
        return p

    add("init", cmd_init, "create the data folder, config template and database", True)
    add("info", cmd_info, "show data locations, configuration and optional components", True)

    p = add("validate", cmd_validate, "validate an inventory file without importing it", True)
    p.add_argument("path", help="inventory file (.json or .csv)")

    p = add("import-inventory", cmd_import, "validate and import an inventory (JSON/CSV)", True)
    p.add_argument("path", nargs="?", help="inventory file (.json or .csv)")
    p.add_argument("--sample", action="store_true", help="import the bundled synthetic sample")

    p = add("sample-inventory", cmd_sample, "write the synthetic sample inventory (a template)")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--out", metavar="FILE", help="write to FILE instead of stdout")
    p.add_argument("--force", action="store_true", help="overwrite FILE if it exists")

    p = add("scan", cmd_scan, "match vulnerabilities against the imported inventory", True)
    p.add_argument("--mode", choices=["incremental", "full"], default="incremental")
    p.add_argument("--demo", action="store_true", help="use bundled recorded fixtures (no network)")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress lines")

    p = add("findings", cmd_findings, "list findings, highest priority first", True)
    _filters(p)
    p.add_argument("--limit", type=int, default=50, help="rows to show (0 = all; default 50)")

    p = add("show", cmd_show, "show full evidence and recommendation for one finding", True)
    p.add_argument("finding_id", metavar="FINDING_ID", help="ID or unique ID prefix")

    p = add("queue", cmd_queue, "consolidated upgrade plan: one target per software install", True)
    p.add_argument("--confirmed-only", action="store_true", help="only confirmed-affected findings")
    p.add_argument("--no-unverified", action="store_true", help="leave out unverified findings")

    p = add("scans", cmd_scans, "show scan history", True)
    p.add_argument("--limit", type=int, default=20)

    p = add("export", cmd_export, "export findings as a JSON or CSV report")
    _filters(p)
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--out", metavar="FILE", help="write to FILE instead of stdout")

    add("benchmark", cmd_benchmark, "run the matching benchmark on recorded data", True)

    p = add(
        "dashboard", cmd_dashboard, "optional: local web dashboard (needs the 'dashboard' extra)"
    )
    p.add_argument("--port", type=int, default=8501)

    p = add("serve-api", cmd_serve_api, "optional: REST API (needs the 'api' extra)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.fn(args))
    except CliError as exc:
        _err(f"terminus: error: {exc.message}")
        if exc.hint:
            _err(f"  hint: {exc.hint}")
        return exc.code
    except ConfigurationError as exc:
        _err("terminus: error: configuration problem")
        for problem in exc.problems:
            _err(f"  - {problem}")
        return EXIT_ENV
    except StorageError as exc:
        _err(f"terminus: error: {exc}")
        return EXIT_ENV
    except KeyboardInterrupt:
        _err("terminus: interrupted")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # Output piped to a command that exited early (e.g. `| head`): silence the
        # interpreter's final flush of the closed pipe.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_OK
    except Exception as exc:
        if args.verbose:
            raise
        _err(f"terminus: unexpected error: {type(exc).__name__}: {exc}")
        _err("  rerun with -v for a traceback")
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
