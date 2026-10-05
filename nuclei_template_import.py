"""Conservative, read-only intake of local Nuclei template metadata.

The importer never executes a template, invokes Nuclei, resolves includes, or
retains request bodies and payload values.  It extracts only a narrow metadata
profile from a regular UTF-8 YAML file already placed in an engagement folder.
This is intentionally a lexical reader rather than a general YAML loader.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
import uuid

import integration_catalog


MAX_TEMPLATE_BYTES = 512 * 1024
UPSTREAM_REPOSITORY = "https://github.com/projectdiscovery/nuclei-templates"
TEMPLATE_ID = re.compile(r"^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*$")
COMMIT_ID = re.compile(r"^[0-9a-fA-F]{40}$")
IMPORT_ID = re.compile(r"^nuclei-template-[0-9a-f]{16}$")
KEY_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):(?:\s*(.*))?$")
SEVERITIES = {"undefined", "info", "low", "medium", "high", "critical", "unknown"}
PROTOCOL_KEYS = {
    "requests", "http", "dns", "network", "ssl", "websocket", "whois",
    "headless", "code", "javascript", "file", "workflows",
}
BLOCKED_PROTOCOLS = {"headless", "code", "javascript", "file", "workflows"}
EXPANDING_TAGS = {"dos", "fuzz", "fuzzing", "bruteforce", "race", "intrusive"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", "PURGE", "DEBUG"}


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


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _relative_path(value: Any, field: str, *, extensions: set[str] | None = None) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value) > 500 or "\\" in value:
        raise ValueError(f"{field} must be a short forward-slash relative path")
    relative = PurePosixPath(value)
    if (relative.is_absolute() or any(part in ("", ".", "..") or ":" in part
                                     for part in relative.parts)):
        raise ValueError(f"{field} must stay within its declared root")
    if extensions and relative.suffix.casefold() not in extensions:
        raise ValueError(f"{field} must name a YAML template")
    return relative


def _source_path(engagement_dir: Path, reference: Any) -> tuple[Path, str]:
    relative = _relative_path(reference, "source_reference", extensions={".yaml", ".yml"})
    root = engagement_dir.resolve()
    candidate = root / Path(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() and _is_reparse(current):
            raise ValueError("source_reference must not traverse a symlink or reparse point")
    try:
        path = candidate.resolve(strict=True)
        path.relative_to(root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ValueError("source_reference must name a file inside the engagement directory") from exc
    if not path.is_file() or _is_reparse(path):
        raise ValueError("source_reference must name a regular non-symlink file")
    if path.stat().st_size > MAX_TEMPLATE_BYTES:
        raise ValueError("Nuclei template exceeds the 512 KiB import ceiling")
    return path, relative.as_posix()


def _strip_comment(value: str) -> str:
    quote = ""
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = ""
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 1
            elif character == "'":
                quote = ""
        elif character in ('"', "'"):
            quote = character
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    return value.rstrip()


def _scalar(value: str, maximum: int = 500) -> str:
    text = value.strip()
    if not text or text[0] in "|>":
        return ""
    if len(text) >= 2 and text[0] == text[-1] == "'":
        text = text[1:-1].replace("''", "'")
    elif len(text) >= 2 and text[0] == text[-1] == '"':
        try:
            decoded = json.loads(text)
            text = decoded if isinstance(decoded, str) else text[1:-1]
        except json.JSONDecodeError:
            text = text[1:-1]
    return "".join(character for character in text if character.isprintable())[:maximum].strip()


def _split_values(value: str) -> list[str]:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    result = []
    quote = ""
    escaped = False
    start = 0
    for index, character in enumerate(text):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = ""
        elif quote == "'":
            if character == "'":
                quote = ""
        elif character in ('"', "'"):
            quote = character
        elif character == ",":
            item = _scalar(text[start:index], 300)
            if item:
                result.append(item)
            start = index + 1
    item = _scalar(text[start:], 300)
    if item:
        result.append(item)
    return result


def _key_lines(lines: list[str]) -> list[dict]:
    result = []
    block_indent: int | None = None
    for line_number, raw_line in enumerate(lines, 1):
        prefix = raw_line[:len(raw_line) - len(raw_line.lstrip(" \t"))]
        if "\t" in prefix:
            raise ValueError(f"YAML indentation contains a tab at line {line_number}")
        indent = len(prefix)
        stripped = raw_line[len(prefix):]
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue
            block_indent = None
        content = _strip_comment(stripped).strip()
        if not content:
            continue
        if re.fullmatch(r"-\s*[|>][0-9+-]*", content):
            block_indent = indent
            continue
        if content.startswith("- "):
            content = content[2:].lstrip()
            indent += 2
        match = KEY_LINE.fullmatch(content)
        if not match:
            continue
        value = (match.group(2) or "").strip()
        result.append({
            "key": match.group(1), "value": value, "indent": indent,
            "line": line_number, "index": line_number - 1,
        })
        if re.fullmatch(r"[|>][0-9+-]*", value):
            block_indent = indent
    return result


def _direct_entries(entries: list[dict], start: int, end: int, parent_indent: int) -> dict[str, dict]:
    candidates = [entry for entry in entries
                  if start <= entry["index"] < end and entry["indent"] > parent_indent]
    if not candidates:
        return {}
    child_indent = min(entry["indent"] for entry in candidates)
    direct = [entry for entry in candidates if entry["indent"] == child_indent]
    result: dict[str, dict] = {}
    for position, entry in enumerate(direct):
        if entry["key"] in result:
            raise ValueError(f"Duplicate YAML key {entry['key']} at line {entry['line']}")
        copied = dict(entry)
        copied["end"] = direct[position + 1]["index"] if position + 1 < len(direct) else end
        result[entry["key"]] = copied
    return result


def _field_values(lines: list[str], field: dict | None, *, comma: bool = True,
                  maximum: int = 20) -> list[str]:
    if field is None:
        return []
    if field["value"]:
        values = _split_values(field["value"]) if comma else [_scalar(field["value"], 500)]
        return [value for value in values if value][:maximum]
    values = []
    for raw_line in lines[field["index"] + 1:field["end"]]:
        prefix = raw_line[:len(raw_line) - len(raw_line.lstrip(" \t"))]
        if len(prefix) <= field["indent"]:
            continue
        content = _strip_comment(raw_line[len(prefix):]).strip()
        if content.startswith("- "):
            value = _scalar(content[2:], 500)
            if value:
                values.append(value)
        if len(values) >= maximum:
            break
    return values


def _integer(value: str) -> int | None:
    scalar = _scalar(value, 40)
    if not re.fullmatch(r"[0-9]+", scalar):
        return None
    number = int(scalar)
    return number if 0 <= number <= 1_000_000 else None


def _boolean(value: str) -> bool | None:
    scalar = _scalar(value, 10).casefold()
    if scalar == "true":
        return True
    if scalar == "false":
        return False
    return None


def _float(value: str) -> float | None:
    scalar = _scalar(value, 40)
    try:
        number = float(scalar)
    except ValueError:
        return None
    return number if 0 <= number <= 10 else None


def _parse_template(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Nuclei template must be valid UTF-8 YAML") from exc
    if "\x00" in text:
        raise ValueError("Nuclei template contains a NUL byte")
    lines = text.splitlines()
    document_markers = [index for index, line in enumerate(lines)
                        if _strip_comment(line).strip() in {"---", "..."}]
    if len(document_markers) > 1 or (document_markers and any(
            _strip_comment(line).strip() for line in lines[:document_markers[0]])):
        raise ValueError("Only one YAML document is supported")

    entries = _key_lines(lines)
    top_candidates = [entry for entry in entries if entry["indent"] == 0]
    top: dict[str, dict] = {}
    for position, entry in enumerate(top_candidates):
        if entry["key"] in top:
            raise ValueError(f"Duplicate top-level YAML key {entry['key']}")
        copied = dict(entry)
        copied["end"] = (top_candidates[position + 1]["index"]
                         if position + 1 < len(top_candidates) else len(lines))
        top[entry["key"]] = copied

    template_id = _scalar(top.get("id", {}).get("value", ""), 128)
    if not TEMPLATE_ID.fullmatch(template_id):
        raise ValueError("Template id is missing or does not match the Nuclei id form")
    info = top.get("info")
    if not info or info["value"]:
        raise ValueError("Template info must be a YAML mapping")
    info_fields = _direct_entries(entries, info["index"] + 1, info["end"], info["indent"])
    name = _scalar(info_fields.get("name", {}).get("value", ""), 300)
    severity = _scalar(info_fields.get("severity", {}).get("value", ""), 20).casefold()
    if not name or severity not in SEVERITIES:
        raise ValueError("Template info requires a name and recognized severity")

    authors = _field_values(lines, info_fields.get("author"))
    tags = [value.casefold() for value in _field_values(lines, info_fields.get("tags"))]
    references = _field_values(lines, info_fields.get("reference"), comma=False)
    references = [value for value in references
                  if value.startswith(("https://", "http://"))][:20]

    classification_field = info_fields.get("classification")
    classification = (_direct_entries(
        entries, classification_field["index"] + 1, classification_field["end"],
        classification_field["indent"]
    ) if classification_field and not classification_field["value"] else {})
    cve_ids = [value.upper() for value in _field_values(lines, classification.get("cve-id"))
               if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value, re.I)]
    cwe_ids = [value.upper() for value in _field_values(lines, classification.get("cwe-id"))
               if re.fullmatch(r"CWE-[0-9]+", value, re.I)]
    cvss_score = _float(classification.get("cvss-score", {}).get("value", ""))

    metadata_field = info_fields.get("metadata")
    metadata = (_direct_entries(
        entries, metadata_field["index"] + 1, metadata_field["end"], metadata_field["indent"]
    ) if metadata_field and not metadata_field["value"] else {})
    max_requests = _integer((metadata.get("max-request") or metadata.get("max-requests") or {}).get("value", ""))
    verified = _boolean(metadata.get("verified", {}).get("value", ""))
    vendor = _scalar(metadata.get("vendor", {}).get("value", ""), 120)
    product = _scalar(metadata.get("product", {}).get("value", ""), 120)

    protocols = sorted(PROTOCOL_KEYS.intersection(top))
    if not protocols:
        raise ValueError("Template has no recognized protocol or workflow block")
    methods = sorted({
        _scalar(entry["value"], 20).upper() for entry in entries
        if entry["key"] == "method" and _scalar(entry["value"], 20)
    })
    lower_text = text.casefold()
    risk_flags: set[str] = set()
    blocked = sorted(BLOCKED_PROTOCOLS.intersection(protocols))
    risk_flags.update(f"protocol:{value}" for value in blocked)
    key_lookup: dict[str, list[dict]] = {}
    for entry in entries:
        key_lookup.setdefault(entry["key"].casefold(), []).append(entry)
    for key in ("unsafe", "race", "self-contained", "redirects", "host-redirects",
                "iterate-all", "skip-variables-check", "cookie-reuse"):
        if any(_boolean(entry["value"]) is True for entry in key_lookup.get(key, [])):
            risk_flags.add(key)
    for key in ("fuzzing", "payloads", "raw"):
        if key in key_lookup:
            risk_flags.add(key)
    if "{{interactsh-url}}" in lower_text or "{{interactsh_url}}" in lower_text:
        risk_flags.add("out-of-band")
    for entry in key_lookup.get("attack", []):
        attack = _scalar(entry["value"], 40).casefold()
        if attack in {"batteringram", "pitchfork", "clusterbomb"}:
            risk_flags.add(f"payload-attack:{attack}")
    state_methods = sorted(STATE_CHANGING_METHODS.intersection(methods))
    if state_methods:
        risk_flags.add("state-changing-method")
    for tag in EXPANDING_TAGS.intersection(tags):
        risk_flags.add(f"tag:{tag}")
    if "flow" in top:
        risk_flags.add("flow")

    hard_block = bool(blocked or EXPANDING_TAGS.intersection(tags))
    if hard_block:
        review_class = "blocked_feature"
    elif risk_flags:
        review_class = "high_review"
    else:
        review_class = "manual_review"
    digest_present = any(re.match(r"^\s*#\s*digest:\s*\S+", line, re.I) for line in lines)
    warnings = []
    if max_requests is None:
        warnings.append("No usable metadata max-request value was found")
    if not references:
        warnings.append("No HTTP(S) reference was retained")
    if not cve_ids and not vendor and not product:
        warnings.append("No CVE or vendor/product mapping was retained")

    return {
        "id": template_id,
        "name": name,
        "authors": authors,
        "severity": severity,
        "tags": sorted(set(tags)),
        "references": sorted(set(references)),
        "classification": {
            "cve_ids": sorted(set(cve_ids)), "cwe_ids": sorted(set(cwe_ids)),
            "cvss_score": cvss_score,
        },
        "technology": {"vendor": vendor or None, "product": product or None},
        "protocols": protocols,
        "http_methods": methods,
        "flow_present": "flow" in top,
        "digest": {
            "present": digest_present,
            "verification": "not performed; presence is not signature validation",
        },
        "upstream_verified_marker": verified,
        "request_bound": {
            "declared_max_requests": max_requests,
            "state": "metadata_only_unenforced" if max_requests is not None else "unknown",
            "enforced_by_scoperook": False,
        },
        "execution_risk": {
            "review_class": review_class,
            "flags": sorted(risk_flags),
            "blocked_protocols": blocked,
            "state_changing_methods": state_methods,
        },
        "warnings": warnings,
    }


def _nuclei_templates_license() -> dict:
    match = next((record for record in integration_catalog.load_catalog()
                  if record["id"] == "projectdiscovery-nuclei-templates"), None)
    if not match or match["repository"] != UPSTREAM_REPOSITORY or match["license"] != "MIT":
        raise ValueError("The Nuclei Templates MIT integration record is unavailable")
    return match


def import_template(engagement: dict, engagement_dir: Path, *, source_reference: Any,
                    asset: Any, upstream_commit: Any, upstream_path: Any) -> dict:
    if not isinstance(asset, str) or asset not in {
            entry.get("value") for entry in engagement.get("assets", [])}:
        raise ValueError("asset must exactly match a recorded engagement asset")
    if not isinstance(upstream_commit, str) or not COMMIT_ID.fullmatch(upstream_commit):
        raise ValueError("upstream_commit must be an exact 40-character Git commit id")
    upstream_relative = _relative_path(
        upstream_path, "upstream_path", extensions={".yaml", ".yml"}
    ).as_posix()
    path, local_reference = _source_path(engagement_dir, source_reference)
    raw = path.read_bytes()
    metadata = _parse_template(raw)
    source_hash = hashlib.sha256(raw).hexdigest()
    import_id = f"nuclei-template-{source_hash[:16]}"
    license_record = _nuclei_templates_license()
    upstream_commit = upstream_commit.casefold()
    source_url = f"{UPSTREAM_REPOSITORY}/blob/{upstream_commit}/{upstream_relative}"
    record = {
        "schema_version": 1,
        "import_id": import_id,
        "created_at": _now(),
        "engagement_id": engagement["id"],
        "asset": asset,
        "source": {
            "local_reference": local_reference,
            "sha256": source_hash,
            "bytes": len(raw),
            "repository": UPSTREAM_REPOSITORY,
            "upstream_commit": upstream_commit,
            "upstream_path": upstream_relative,
            "upstream_url": source_url,
            "provenance_state": "local_hash_recorded; upstream commit and path not network-verified",
            "license": license_record["license"],
            "license_source": license_record["license_source"],
            "license_verified_at": license_record["license_verified_at"],
        },
        "template": metadata,
        "candidate_seed": {
            "claim_state": "unverified_prior_art",
            "title": metadata["name"],
            "identifiers": metadata["classification"]["cve_ids"],
            "technology_terms": [value for value in (
                metadata["technology"]["vendor"], metadata["technology"]["product"]
            ) if value],
            "required_checks": [
                "Verify the current primary advisory and affected versions",
                "Establish target product, version, and configuration independently",
                "Confirm the exact program permits the proposed technique",
                "Review every request, payload expansion, redirect, and callback before execution",
                "Use a separately enforced request ceiling and candidate/control proof",
            ],
        },
        "execution": {
            "allowed": False,
            "reason": (
                "Metadata intake only. ScopeRook did not validate YAML semantics, template signatures, "
                "source provenance, target applicability, program authorization, or an engine-enforced "
                "request bound."
            ),
        },
        "privacy": (
            "Retains selected public metadata, source provenance, hashes, protocols, methods, and risk flags. "
            "Request paths, headers, bodies, payload values, matchers, extractors, and template source are not copied."
        ),
        "claim_boundary": (
            "A template is public prior art and a hypothesis lead. It is not proof that the recorded asset is affected."
        ),
    }
    destination = engagement_dir / "template-intelligence" / f"{import_id}.json"
    _atomic_json(destination, record)
    return {
        "import_id": import_id,
        "asset": asset,
        "source_sha256": source_hash,
        "template": metadata,
        "candidate_seed": record["candidate_seed"],
        "execution": record["execution"],
        "saved_to": str(destination),
        "privacy": record["privacy"],
        "claim_boundary": record["claim_boundary"],
    }


def get_template_intelligence(engagement_dir: Path, import_id: Any) -> dict:
    if not isinstance(import_id, str) or not IMPORT_ID.fullmatch(import_id):
        raise ValueError("Invalid Nuclei template import id")
    path = engagement_dir / "template-intelligence" / f"{import_id}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Nuclei template intelligence record not found") from None
    if not isinstance(value, dict) or value.get("import_id") != import_id:
        raise ValueError("Nuclei template intelligence record is invalid")
    return value
