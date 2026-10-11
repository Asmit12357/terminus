"""Inventory import and validation (JSON and CSV).

Accepted shapes
---------------
JSON, nested (preferred)::

    {"assets": [{"asset_id": "web-01", "hostname": "...", "criticality": "high",
                 "internet_exposed": true, "environment": "production",
                 "software": [{"software_name": "nginx", "software_version": "1.24.0",
                               "vendor": "F5", "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"}]}]}

JSON, flat: a list of item objects, or ``{"items": [...]}``.

CSV: one row per software item, header names equal to ``InventoryItem`` fields.

Parsing never evaluates content: only ``json.loads`` and ``csv.DictReader``.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.models import InventoryItem

MAX_INVENTORY_BYTES = 5 * 1024 * 1024
MAX_INVENTORY_ITEMS = 20_000

_TRUE = {"true", "yes", "y", "1"}
_FALSE = {"false", "no", "n", "0"}


class RowError(BaseModel):
    row: int  # 1-based record number (CSV: data row number, excluding header)
    field: str | None
    message: str


class InventoryValidationResult(BaseModel):
    items: list[InventoryItem] = Field(default_factory=list)
    errors: list[RowError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    duplicates_removed: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.items)


class InventoryFormatError(ValueError):
    """Raised when the file cannot be parsed at all."""


def _parse_bool(value: Any) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "" or text in {"unknown", "null", "none"}:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"cannot interpret {str(value)[:20]!r} as true/false")


def _normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        k = key.strip().lower()
        if isinstance(value, str) and value.strip() == "":
            value = None
        record[k] = value
    if "internet_exposed" in record:
        record["internet_exposed"] = _parse_bool(record["internet_exposed"])
    for enum_field in ("ecosystem", "criticality", "environment"):
        if isinstance(record.get(enum_field), str):
            record[enum_field] = record[enum_field].strip().lower()
    return record


def _flatten_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        if not all(isinstance(r, dict) for r in data):
            _bad("every element of the top-level list must be an object")
        return list(data)
    if not isinstance(data, dict):
        _bad("top-level JSON must be an object or a list")
    if "items" in data:
        items = data["items"]
        if not isinstance(items, list):
            _bad("'items' must be a list")
        return _flatten_json(items)
    if "assets" not in data:
        _bad("expected an 'assets' or 'items' key")
    assets = data["assets"]
    if not isinstance(assets, list):
        _bad("'assets' must be a list")
    rows: list[dict[str, Any]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            _bad("every asset must be an object")
        software = asset.get("software", [])
        if not isinstance(software, list):
            _bad("'software' must be a list")
        # Unknown asset keys are kept so InventoryItem(extra="forbid") reports them.
        asset_part = {k: v for k, v in asset.items() if k != "software"}
        if not software:
            # An asset with no software is kept visible as a validation error.
            rows.append({**asset_part, "__no_software__": True})
        for sw in software:
            if not isinstance(sw, dict):
                _bad("every software entry must be an object")
            rows.append({**asset_part, **sw})
    return rows


def _bad(message: str) -> Any:
    raise InventoryFormatError(message)


def parse_inventory(content: bytes, filename: str) -> InventoryValidationResult:
    """Parse and validate an inventory file. Never raises for row-level errors."""
    if len(content) > MAX_INVENTORY_BYTES:
        raise InventoryFormatError(
            f"inventory exceeds {MAX_INVENTORY_BYTES // (1024 * 1024)} MB limit"
        )
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InventoryFormatError("inventory must be UTF-8 encoded") from exc

    lower = filename.lower()
    if lower.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InventoryFormatError(f"invalid JSON: {exc.msg} (line {exc.lineno})") from exc
        raw_rows = _flatten_json(data)
    elif lower.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise InventoryFormatError("CSV has no header row")
        raw_rows = [dict(r) for r in reader]
    else:
        raise InventoryFormatError("unsupported file type: use .json or .csv")

    if len(raw_rows) > MAX_INVENTORY_ITEMS:
        raise InventoryFormatError(f"inventory exceeds {MAX_INVENTORY_ITEMS} items")

    return validate_rows(raw_rows)


def validate_rows(raw_rows: list[dict[str, Any]]) -> InventoryValidationResult:
    result = InventoryValidationResult()
    seen: set[str] = set()
    for idx, raw in enumerate(raw_rows, start=1):
        if raw.get("__no_software__"):
            result.errors.append(
                RowError(row=idx, field="software", message="asset has no software entries")
            )
            continue
        if None in raw:  # csv.DictReader puts surplus columns under the None key
            result.errors.append(
                RowError(row=idx, field=None, message="row has more columns than the header")
            )
            continue
        try:
            record = _normalize_record(raw)
            item = InventoryItem.model_validate(record)
        except ValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(p) for p in err["loc"]) or None
                result.errors.append(RowError(row=idx, field=loc, message=err["msg"]))
            continue
        except ValueError as exc:
            result.errors.append(RowError(row=idx, field="internet_exposed", message=str(exc)))
            continue

        if item.item_id in seen:
            result.duplicates_removed += 1
            continue
        seen.add(item.item_id)
        result.items.append(item)

        label = f"{item.asset_id}/{item.software_name}"
        if not item.software_version:
            result.warnings.append(f"{label}: no version recorded - findings will be 'unverified'")
        if not (item.cpe or item.purl or item.vendor) and item.ecosystem.value == "generic":
            result.warnings.append(
                f"{label}: no vendor, CPE or package identifier - identity matches will be weak"
            )
        if item.internet_exposed is None:
            result.warnings.append(f"{label}: internet exposure unknown")
    if not raw_rows:
        result.errors.append(RowError(row=0, field=None, message="inventory contains no records"))
    return result
