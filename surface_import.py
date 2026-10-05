"""Secret-reducing import of local HAR and OpenAPI JSON artifacts.

Only route shape is retained.  Headers, cookies, bodies, examples, defaults,
query values, response content, and off-origin requests are never saved.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid


MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 5_000
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
FORMAT_IDS = {"har", "openapi_json"}
TOKEN_SEGMENT = re.compile(
    r"^(?:[0-9]{4,}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _source_path(engagement_dir: Path, reference: Any) -> tuple[Path, str]:
    if not isinstance(reference, str) or not reference or len(reference) > 300 or "\\" in reference:
        raise ValueError("source_reference must be a short forward-slash relative path")
    relative = PurePosixPath(reference)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("source_reference must stay inside the engagement directory")
    root = engagement_dir.resolve()
    path = (root / Path(*relative.parts)).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("source_reference escapes the engagement directory") from exc
    if path.is_symlink() or not path.is_file():
        raise ValueError("source_reference must name a regular non-symlink file")
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError("Surface artifact exceeds the 20 MiB import ceiling")
    return path, reference


def _load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    try:
        return json.loads(raw), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Surface artifact must be valid UTF-8 JSON") from exc


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("asset must be an HTTP(S) URL without embedded credentials")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port


def _safe_path(value: str) -> str:
    try:
        decoded = unquote(value)
    except Exception:
        decoded = value
    parts = []
    for part in decoded.split("/"):
        if not part:
            continue
        if TOKEN_SEGMENT.fullmatch(part):
            parts.append("{value}")
        else:
            cleaned = "".join(character for character in part if character.isprintable())[:100]
            parts.append(cleaned or "{value}")
    result = "/" + "/".join(parts)
    return result[:500]


def _short(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value.strip() if character.isprintable())[:maximum]


def _deduplicate(routes: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for route in routes:
        canonical = json.dumps(route, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if canonical not in seen:
            seen.add(canonical)
            result.append(route)
    return sorted(result, key=lambda item: (item["path"], item["method"], str(item.get("status", ""))))


def _har(value: Any, asset_origin: tuple[str, str, int]) -> tuple[list[dict], dict]:
    if not isinstance(value, dict) or not isinstance(value.get("log"), dict):
        raise ValueError("HAR artifact must contain a log object")
    entries = value["log"].get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError("HAR entries must be a list of at most 5000 requests")
    routes = []
    excluded = 0
    invalid = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            invalid += 1
            continue
        request = entry["request"]
        method = _short(request.get("method"), 12).upper()
        url = request.get("url")
        if method not in HTTP_METHODS or not isinstance(url, str) or len(url) > 8_000:
            invalid += 1
            continue
        try:
            parsed = urlsplit(url)
            if parsed.username or parsed.password or _origin(url) != asset_origin:
                excluded += 1
                continue
        except (TypeError, ValueError):
            invalid += 1
            continue
        query_names = {name[:100] for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
                       if isinstance(name, str) and name}
        query = request.get("queryString")
        if isinstance(query, list):
            for parameter in query[:200]:
                if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
                    query_names.add(parameter["name"][:100])
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        status = response.get("status")
        if type(status) is not int or not 0 <= status <= 999:
            status = None
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        mime = _short(content.get("mimeType"), 100)
        routes.append({
            "method": method, "path": _safe_path(parsed.path or "/"),
            "query_parameters": sorted(query_names), "status": status,
            "mime_type": mime or None,
        })
    return _deduplicate(routes), {
        "input_entries": len(entries), "off_origin_or_credential_url_entries": excluded,
        "invalid_entries": invalid,
    }


def _parameter_shape(parameters: Any) -> list[dict]:
    if not isinstance(parameters, list):
        return []
    result = []
    for parameter in parameters[:200]:
        if not isinstance(parameter, dict) or "$ref" in parameter:
            continue
        name = _short(parameter.get("name"), 100)
        location = parameter.get("in")
        if not name or location not in ("path", "query", "header", "cookie"):
            continue
        result.append({"name": name, "in": location, "required": parameter.get("required") is True})
    unique = {json.dumps(item, sort_keys=True): item for item in result}
    return sorted(unique.values(), key=lambda item: (item["in"], item["name"]))


def _openapi(value: Any) -> tuple[list[dict], dict]:
    if not isinstance(value, dict) or not isinstance(value.get("paths"), dict):
        raise ValueError("OpenAPI JSON artifact must contain a paths object")
    paths = value["paths"]
    if len(paths) > MAX_ENTRIES:
        raise ValueError("OpenAPI paths exceed the 5000-route ceiling")
    routes = []
    invalid = 0
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or not isinstance(path_item, dict):
            invalid += 1
            continue
        common = _parameter_shape(path_item.get("parameters"))
        for raw_method, operation in path_item.items():
            method = raw_method.upper()
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = _parameter_shape(operation.get("parameters"))
            merged = {json.dumps(item, sort_keys=True): item for item in [*common, *parameters]}
            request_body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
            content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
            responses = operation.get("responses") if isinstance(operation.get("responses"), dict) else {}
            routes.append({
                "method": method, "path": _safe_path(raw_path),
                "parameters": sorted(merged.values(), key=lambda item: (item["in"], item["name"])),
                "request_content_types": sorted(_short(key, 100) for key in content if _short(key, 100)),
                "response_statuses": sorted(_short(str(key), 20) for key in responses)[:100],
                "operation_id": _short(operation.get("operationId"), 120) or None,
            })
    return _deduplicate(routes), {"input_paths": len(paths), "invalid_paths": invalid}


def import_surface(engagement: dict, engagement_dir: Path, *, source_reference: Any,
                   artifact_format: Any, asset: Any) -> dict:
    if artifact_format not in FORMAT_IDS:
        raise ValueError("format must be har or openapi_json")
    if not isinstance(asset, str) or asset not in {entry.get("value") for entry in engagement.get("assets", [])}:
        raise ValueError("asset must exactly match a recorded engagement asset")
    path, relative = _source_path(engagement_dir, source_reference)
    value, raw = _load_json(path)
    if artifact_format == "har":
        routes, statistics = _har(value, _origin(asset))
    else:
        routes, statistics = _openapi(value)
    source_hash = hashlib.sha256(raw).hexdigest()
    inventory_id = f"{artifact_format}-{source_hash[:16]}"
    record = {
        "schema_version": 1, "inventory_id": inventory_id, "created_at": _now(),
        "engagement_id": engagement["id"], "asset": asset, "format": artifact_format,
        "source_reference": relative, "source_sha256": source_hash, "source_bytes": len(raw),
        "statistics": statistics, "route_count": len(routes), "routes": routes,
        "privacy": (
            "Retains route shape only. Headers, cookies, bodies, examples, defaults, query values, response "
            "content, and off-origin HAR entries were not saved. Token-like path segments were replaced."
        ),
        "claim_boundary": "Imported routes are surface inventory, not vulnerability findings or authorization",
    }
    destination = engagement_dir / "surface-inventory" / f"{inventory_id}.json"
    _atomic_json(destination, record)
    return {
        "inventory_id": inventory_id, "route_count": len(routes), "source_sha256": source_hash,
        "statistics": statistics, "saved_to": str(destination), "privacy": record["privacy"],
        "claim_boundary": record["claim_boundary"],
    }


def get_inventory(engagement_dir: Path, inventory_id: Any, query: Any = "", limit: Any = 50) -> dict:
    if not isinstance(inventory_id, str) or not re.fullmatch(r"(?:har|openapi_json)-[0-9a-f]{16}", inventory_id):
        raise ValueError("Invalid inventory_id")
    if not isinstance(query, str) or len(query) > 120:
        raise ValueError("query must be text up to 120 characters")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    path = engagement_dir / "surface-inventory" / f"{inventory_id}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError("Surface inventory not found") from None
    needle = query.casefold().strip()
    routes = record.get("routes", [])
    if needle:
        routes = [route for route in routes if needle in json.dumps(route, ensure_ascii=False).casefold()]
    return {
        "inventory_id": inventory_id, "engagement_id": record.get("engagement_id"),
        "asset": record.get("asset"), "format": record.get("format"),
        "source_sha256": record.get("source_sha256"), "route_count": record.get("route_count"),
        "matched_count": len(routes), "routes": routes[:limit], "truncated": len(routes) > limit,
        "privacy": record.get("privacy"), "claim_boundary": record.get("claim_boundary"),
    }
