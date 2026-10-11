"""Command-line interface.

terminus validate data/sample_inventory.json
terminus import-inventory data/sample_inventory.json
terminus scan --demo                # recorded fixtures, no network
terminus scan --mode full           # live NVD/KEV/EPSS/OSV
terminus findings --tier P1 P2
terminus export --format csv --out report.csv
terminus benchmark
terminus serve-api
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from app.config import get_settings
from app.inventory import InventoryFormatError, parse_inventory
from app.reports.export import DISCLAIMER, export_csv, export_json
from app.service import get_repo, import_inventory, run_scan, summarize


def _print_validation(result: object) -> None:
    from app.inventory import InventoryValidationResult

    assert isinstance(result, InventoryValidationResult)
    print(
        f"items: {len(result.items)}  errors: {len(result.errors)}  "
        f"warnings: {len(result.warnings)}  duplicates removed: {result.duplicates_removed}"
    )
    for err in result.errors[:50]:
        print(f"  ERROR row {err.row} [{err.field or '-'}]: {err.message}")
    for warning in result.warnings[:50]:
        print(f"  warning: {warning}")


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        result = parse_inventory(path.read_bytes(), path.name)
    except InventoryFormatError as exc:
        print(f"invalid inventory: {exc}")
        return 2
    _print_validation(result)
    return 0 if result.ok else 1


def cmd_import(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        result, inventory_id = import_inventory(get_repo(), path.read_bytes(), path.name)
    except InventoryFormatError as exc:
        print(f"invalid inventory: {exc}")
        return 2
    _print_validation(result)
    if inventory_id is None:
        print("inventory NOT imported - fix the errors above")
        return 1
    print(f"imported inventory {inventory_id}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = get_settings()
    repo = get_repo(settings)

    def progress(fraction: float, message: str) -> None:
        print(f"[{fraction * 100:5.1f}%] {message}", flush=True)

    scan = run_scan(settings, repo, args.mode, demo=True if args.demo else None, progress=progress)
    print(
        f"scan {scan.scan_id} {scan.status}: {scan.cves_processed} CVEs processed, "
        f"{scan.findings_count} findings"
    )
    for st in scan.source_status:
        print(f"  source {st.source}: {st.state.value} {st.detail or ''}")
    for err in scan.errors[:20]:
        print(f"  issue: {err}")
    return 0 if scan.status != "failed" else 1


def cmd_findings(args: argparse.Namespace) -> int:
    findings = get_repo().list_findings(tiers=args.tier, statuses=args.status)
    print(summarize(findings))
    print(f"{'tier':4} {'score':>5}  {'cve':16} {'status':22} {'asset':16} software")
    for f in findings[: args.limit]:
        print(
            f"{f.priority.tier:4} {f.priority.score:5.1f}  {f.cve_id:16} {f.match.status.value:22} "
            f"{f.item.asset_id:16} {f.item.software_name} {f.item.software_version or '?'} "
            f"-> {f.recommendation.action}"
        )
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    settings = get_settings()
    findings = get_repo(settings).list_findings(tiers=args.tier, statuses=args.status)
    demo = any(f.cve_source == "demo-fixture" for f in findings)
    text = export_json(findings, demo=demo) if args.format == "json" else export_csv(findings)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="")
        print(f"wrote {len(findings)} findings to {args.out}. {DISCLAIMER}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from app.benchmark import format_report, run_benchmark

    report = run_benchmark()
    print(format_report(report))
    return 0 if report["false_positives"] == 0 and report["false_negatives"] == 0 else 1


def cmd_serve_api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("app.api:app", host=args.host, port=args.port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="terminus", description="Vulnerability intelligence agent"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate an inventory file without importing")
    p.add_argument("path")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("import-inventory", help="validate and import an inventory (JSON/CSV)")
    p.add_argument("path")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("scan", help="run a scan")
    p.add_argument("--mode", choices=["incremental", "full"], default="incremental")
    p.add_argument("--demo", action="store_true", help="use recorded fixtures (no network)")
    p.set_defaults(fn=cmd_scan)

    statuses = ["confirmed_affected", "potentially_affected", "confirmed_unaffected", "unverified"]
    for name, fn in (("findings", cmd_findings), ("export", cmd_export)):
        p = sub.add_parser(name)
        p.add_argument("--tier", nargs="*", choices=["P1", "P2", "P3", "P4", "INFO"])
        p.add_argument("--status", nargs="*", choices=statuses)
        if name == "findings":
            p.add_argument("--limit", type=int, default=50)
        else:
            p.add_argument("--format", choices=["json", "csv"], default="json")
            p.add_argument("--out")
        p.set_defaults(fn=fn)

    p = sub.add_parser("benchmark", help="run the matching benchmark")
    p.set_defaults(fn=cmd_benchmark)

    p = sub.add_parser("serve-api", help="run the FastAPI backend")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(fn=cmd_serve_api)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
