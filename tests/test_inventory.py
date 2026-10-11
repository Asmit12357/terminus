from __future__ import annotations

import json

import pytest

from app.inventory import MAX_INVENTORY_BYTES, InventoryFormatError, parse_inventory
from app.models import Ecosystem
from tests.conftest import DATA_DIR

GOOD_CSV = (
    "asset_id,hostname,software_name,software_version,ecosystem,vendor,cpe,criticality,"
    "internet_exposed,environment\n"
    "web-01,web-01.corp.example,nginx,1.24.0,generic,F5,,high,yes,production\n"
    "web-01,web-01.corp.example,requests,2.31.0,pypi,,,high,yes,production\n"
)


def test_sample_json_inventory_is_valid() -> None:
    raw = (DATA_DIR / "sample_inventory.json").read_bytes()
    result = parse_inventory(raw, "sample_inventory.json")
    assert result.ok, result.errors
    assert len(result.items) == 16
    assets = {i.asset_id for i in result.items}
    assert {"web-prod-01", "app-prod-02", "dev-ws-07"} <= assets


def test_sample_csv_inventory_matches_json() -> None:
    json_items = parse_inventory((DATA_DIR / "sample_inventory.json").read_bytes(), "a.json").items
    csv_items = parse_inventory((DATA_DIR / "sample_inventory.csv").read_bytes(), "a.csv").items
    assert {i.item_id for i in json_items} == {i.item_id for i in csv_items}


def test_csv_parses_booleans_and_enums() -> None:
    result = parse_inventory(GOOD_CSV.encode(), "inv.csv")
    assert result.ok
    nginx, requests = result.items
    assert nginx.internet_exposed is True
    assert requests.ecosystem == Ecosystem.PYPI
    assert nginx.criticality.value == "high"


def test_flat_json_list_and_items_key() -> None:
    rows = [{"asset_id": "a1", "software_name": "curl", "software_version": "8.4.0"}]
    assert parse_inventory(json.dumps(rows).encode(), "x.json").ok
    assert parse_inventory(json.dumps({"items": rows}).encode(), "x.json").ok


def test_missing_version_and_unknown_exposure_produce_warnings() -> None:
    rows = [{"asset_id": "a1", "software_name": "curl"}]
    result = parse_inventory(json.dumps(rows).encode(), "x.json")
    assert result.ok
    assert any("no version" in w for w in result.warnings)
    assert any("exposure unknown" in w for w in result.warnings)
    assert any("no vendor, CPE or package identifier" in w for w in result.warnings)


@pytest.mark.parametrize(
    ("row", "field"),
    [
        ({"asset_id": "bad id!", "software_name": "x"}, "asset_id"),
        ({"asset_id": "a1", "software_name": ""}, "software_name"),
        ({"asset_id": "a1", "software_name": "x", "cpe": "cpe:/a:apache:http_server"}, "cpe"),
        ({"asset_id": "a1", "software_name": "x", "criticality": "extreme"}, "criticality"),
        ({"asset_id": "a1", "software_name": "x", "environment": "prod-ish"}, "environment"),
        ({"asset_id": "a1", "software_name": "x", "hostname": "bad host"}, "hostname"),
        ({"asset_id": "a1", "software_name": "x", "purl": "maven:foo"}, "purl"),
        ({"asset_id": "a1", "software_name": "x", "unexpected": "y"}, "unexpected"),
        ({"asset_id": "a1", "software_name": "x", "internet_exposed": "maybe"}, "internet_exposed"),
    ],
)
def test_invalid_rows_are_reported_with_field(row: dict, field: str) -> None:
    result = parse_inventory(json.dumps([row]).encode(), "x.json")
    assert not result.ok
    assert result.errors[0].row == 1
    assert result.errors[0].field == field


def test_invalid_rows_do_not_hide_valid_rows() -> None:
    rows = [
        {"asset_id": "a1", "software_name": "curl", "software_version": "8.4.0"},
        {"asset_id": "", "software_name": "x"},
    ]
    result = parse_inventory(json.dumps(rows).encode(), "x.json")
    assert len(result.items) == 1
    assert len(result.errors) >= 1 and result.errors[0].row == 2
    assert not result.ok  # an inventory with errors is not accepted as-is


def test_duplicates_are_removed() -> None:
    row = {"asset_id": "a1", "software_name": "curl", "software_version": "8.4.0"}
    result = parse_inventory(json.dumps([row, row]).encode(), "x.json")
    assert len(result.items) == 1
    assert result.duplicates_removed == 1


def test_csv_with_extra_columns_is_rejected_per_row() -> None:
    csv = "asset_id,software_name\na1,curl,unexpected-extra\n"
    result = parse_inventory(csv.encode(), "x.csv")
    assert result.errors and "more columns" in result.errors[0].message


def test_asset_without_software_is_an_error() -> None:
    data = {"assets": [{"asset_id": "a1", "software": []}]}
    result = parse_inventory(json.dumps(data).encode(), "x.json")
    assert result.errors[0].field == "software"


@pytest.mark.parametrize(
    ("content", "name", "message"),
    [
        (b"{not json", "x.json", "invalid JSON"),
        (b"\xff\xfe\x00bad", "x.csv", "UTF-8"),
        (b"[]", "x.yaml", "unsupported file type"),
        (b'{"something": []}', "x.json", "expected an 'assets' or 'items' key"),
        (b"[1, 2]", "x.json", "must be an object"),
        (b"", "x.csv", "no header"),
    ],
)
def test_unparseable_files_raise_format_error(content: bytes, name: str, message: str) -> None:
    with pytest.raises(InventoryFormatError, match=message):
        parse_inventory(content, name)


def test_oversized_inventory_is_rejected() -> None:
    with pytest.raises(InventoryFormatError, match="limit"):
        parse_inventory(b" " * (MAX_INVENTORY_BYTES + 1), "x.json")


def test_control_and_bidi_characters_are_stripped() -> None:
    rows = [{"asset_id": "a1", "software_name": "cu‮rl\x00", "software_version": "8.4.0"}]
    item = parse_inventory(json.dumps(rows).encode(), "x.json").items[0]
    assert item.software_name == "curl"


def test_csv_formula_text_is_kept_as_plain_data() -> None:
    csv = 'asset_id,software_name,business_context\na1,curl,"=HYPERLINK(""http://x"")"\n'
    result = parse_inventory(csv.encode(), "x.csv")
    assert result.ok
    assert result.items[0].business_context.startswith(
        "=HYPERLINK"
    )  # stored verbatim, never evaluated
