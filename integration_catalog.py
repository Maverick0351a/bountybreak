"""Read-only catalog of optional, separately installed security integrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CATALOG_PATH = ROOT / "integrations" / "projectdiscovery.json"
MAX_RECORDS = 50
ALLOWED_LICENSES = {"MIT"}


def _text(value: Any, field: str, maximum: int = 1_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"Invalid integration catalog field: {field}")
    return value.strip()


def _text_list(value: Any, field: str, maximum: int = 20) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValueError(f"Invalid integration catalog field: {field}")
    return [_text(item, field, 120) for item in value]


def load_catalog(path: Path = CATALOG_PATH) -> list[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Integration catalog is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("Unsupported integration catalog schema")
    records = value.get("integrations")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("Integration catalog has an invalid record list")

    checked: list[dict] = []
    seen: set[str] = set()
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("Integration catalog records must be objects")
        ident = _text(item.get("id"), "id", 64)
        if ident in seen:
            raise ValueError("Integration catalog ids must be unique")
        seen.add(ident)
        record = {
            "id": ident,
            "vendor": _text(item.get("vendor"), "vendor", 100),
            "display_name": _text(item.get("display_name"), "display_name", 100),
            "repository": _text(item.get("repository"), "repository", 500),
            "license": _text(item.get("license"), "license", 80),
            "license_source": _text(item.get("license_source"), "license_source", 500),
            "license_verified_at": _text(item.get("license_verified_at"), "license_verified_at", 20),
            "role": _text(item.get("role"), "role"),
            "phases": _text_list(item.get("phases"), "phases"),
            "capabilities": _text_list(item.get("capabilities"), "capabilities"),
            "operation_classes": _text_list(item.get("operation_classes"), "operation_classes"),
            "traffic_profile": _text(item.get("traffic_profile"), "traffic_profile"),
            "safe_defaults": _text_list(item.get("safe_defaults"), "safe_defaults"),
            "required_gates": _text_list(item.get("required_gates"), "required_gates"),
            "outputs": _text_list(item.get("outputs"), "outputs"),
            "excluded_components": _text_list(
                item.get("excluded_components", ["none"]), "excluded_components"
            ),
        }
        if record["license"] not in ALLOWED_LICENSES:
            raise ValueError(
                f"Integration {ident} is not permitted by the MIT-only license policy"
            )
        if not record["license_source"].startswith(
            f"{record['repository'].rstrip('/')}/blob/"
        ):
            raise ValueError(f"Integration {ident} lacks a repository license source")
        checked.append(record)
    return checked


def search_catalog(*, query: str = "", phase: str = "", operation_class: str = "",
                   limit: int = 10) -> dict:
    if not isinstance(query, str) or len(query) > 120:
        raise ValueError("query must be text up to 120 characters")
    if not isinstance(phase, str) or len(phase) > 80:
        raise ValueError("phase must be text up to 80 characters")
    if not isinstance(operation_class, str) or len(operation_class) > 80:
        raise ValueError("operation_class must be text up to 80 characters")
    if type(limit) is not int or not 1 <= limit <= 25:
        raise ValueError("limit must be an integer from 1 to 25")

    needle = query.strip().casefold()
    selected = []
    for record in load_catalog():
        if phase and phase not in record["phases"]:
            continue
        if operation_class and operation_class not in record["operation_classes"]:
            continue
        haystack = " ".join([
            record["id"], record["display_name"], record["role"],
            *record["capabilities"], *record["phases"],
        ]).casefold()
        if needle and needle not in haystack:
            continue
        selected.append(record)
        if len(selected) >= limit:
            break
    return {
        "integrations": selected,
        "catalog_source": str(CATALOG_PATH),
        "installation_state": "not_checked",
        "license_policy": "MIT-only; verified from each upstream repository before catalog admission",
        "boundary": (
            "Catalog records are product-maintained routing guidance. They do not mean a tool is installed, "
            "reviewed, authorized, or safe to execute. MIT still requires preservation of its copyright and "
            "license notice. Register an exact installed file separately before routing."
        ),
    }
