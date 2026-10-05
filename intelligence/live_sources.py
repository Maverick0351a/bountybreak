"""Small read-only adapters for fixed public vulnerability-intelligence sources.

Only CISA's KEV JSON feed and the CVE List v5 API are contacted. User input is
used for local filtering or a validated CVE identifier, never as a URL. Remote
text is returned as untrusted reference data and is never executed.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import json
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_API_ROOT = "https://cveawg.mitre.org/api/cve/"
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.I)
MAX_RESPONSE = 8 * 1024 * 1024
CACHE_SECONDS = 15 * 60
_CACHE: dict[str, tuple[float, dict]] = {}


def _fetch_json(url: str) -> dict:
    cached = _CACHE.get(url)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "BountyBreak/0.3"})
    try:
        with urlopen(request, timeout=12) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in {"www.cisa.gov", "cveawg.mitre.org"}:
                raise ValueError("Vulnerability source redirected outside its fixed host")
            raw = response.read(MAX_RESPONSE + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise ValueError("Vulnerability record was not found at the official source") from None
        raise ValueError(f"Official vulnerability source returned HTTP {exc.code}") from None
    except (OSError, TimeoutError, URLError):
        raise ValueError("Official vulnerability source is unavailable") from None
    if len(raw) > MAX_RESPONSE:
        raise ValueError("Vulnerability source response exceeded 8 MiB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Vulnerability source returned invalid JSON") from None
    if not isinstance(value, dict):
        raise ValueError("Vulnerability source returned an invalid document")
    _CACHE[url] = (time.monotonic(), value)
    return value


def _text(value: Any, limit: int = 2_000) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _date(value: Any) -> str:
    text = _text(value, 10)
    if not text:
        return ""
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        return ""


def _kev_record(item: dict) -> dict:
    cwes = item.get("cwes") if isinstance(item.get("cwes"), list) else []
    return {
        "cve_id": _text(item.get("cveID"), 32),
        "vendor": _text(item.get("vendorProject"), 200),
        "product": _text(item.get("product"), 300),
        "name": _text(item.get("vulnerabilityName"), 500),
        "date_added": _date(item.get("dateAdded")),
        "due_date": _date(item.get("dueDate")),
        "known_ransomware_campaign_use": _text(item.get("knownRansomwareCampaignUse"), 50),
        "short_description": _text(item.get("shortDescription")),
        "required_action": _text(item.get("requiredAction"), 1_000),
        "cwes": [_text(value, 40) for value in cwes[:20] if _text(value, 40)],
        "notes": _text(item.get("notes"), 1_000),
        "source": CISA_KEV_URL,
    }


def search_kev(query: str = "", *, added_since: str = "", limit: int = 10,
               fetch: Callable[[str], dict] = _fetch_json) -> dict:
    if not isinstance(query, str) or len(query) > 120:
        raise ValueError("query must be at most 120 characters")
    query = " ".join(query.split()).casefold()
    if added_since:
        try:
            threshold = date.fromisoformat(added_since)
        except (TypeError, ValueError):
            raise ValueError("added_since must use YYYY-MM-DD") from None
    else:
        threshold = None
    if type(limit) is not int or not 1 <= limit <= 25:
        raise ValueError("limit must be an integer from 1 to 25")

    payload = fetch(CISA_KEV_URL)
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValueError("CISA KEV feed did not contain a vulnerability list")
    matches = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        record = _kev_record(item)
        if threshold and (not record["date_added"] or date.fromisoformat(record["date_added"]) < threshold):
            continue
        haystack = " ".join(str(value) for value in (
            record["cve_id"], record["vendor"], record["product"], record["name"],
            record["short_description"], " ".join(record["cwes"]),
        )).casefold()
        if query and query not in haystack:
            continue
        matches.append(record)
    matches.sort(key=lambda row: (row["date_added"], row["cve_id"]), reverse=True)
    return {
        "catalog_version": _text(payload.get("catalogVersion"), 100),
        "date_released": _text(payload.get("dateReleased"), 100),
        "catalog_count": payload.get("count") if type(payload.get("count")) is int else len(entries),
        "matches": matches[:limit],
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": CISA_KEV_URL,
        "interpretation": (
            "CISA KEV confirms known exploitation and remediation urgency. It does not establish that any "
            "bounty asset runs the affected product or version, and it does not authorize testing."
        ),
    }


def _english_description(cna: dict) -> str:
    descriptions = cna.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    english = next((item for item in descriptions
                    if isinstance(item, dict) and item.get("lang", "").lower().startswith("en")), None)
    return _text((english or {}).get("value"))


def _affected(cna: dict) -> list[dict]:
    result = []
    affected = cna.get("affected") if isinstance(cna.get("affected"), list) else []
    for item in affected[:10]:
        if not isinstance(item, dict):
            continue
        versions = []
        raw_versions = item.get("versions") if isinstance(item.get("versions"), list) else []
        for version in raw_versions[:20]:
            if not isinstance(version, dict):
                continue
            versions.append({key: _text(version.get(key), 200) for key in
                             ("version", "status", "lessThan", "lessThanOrEqual", "versionType")
                             if _text(version.get(key), 200)})
        result.append({
            "vendor": _text(item.get("vendor"), 200),
            "product": _text(item.get("product"), 300),
            "default_status": _text(item.get("defaultStatus"), 50),
            "versions": versions,
        })
    return result


def verify_cve(cve_id: str, *, fetch: Callable[[str], dict] = _fetch_json) -> dict:
    if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id.strip()):
        raise ValueError("cve_id must look like CVE-YYYY-NNNN")
    cve_id = cve_id.strip().upper()
    cve_url = CVE_API_ROOT + cve_id
    payload = fetch(cve_url)
    metadata = payload.get("cveMetadata")
    containers = payload.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise ValueError("CVE List API returned an invalid record")
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}

    problem_types = []
    raw_problem_types = cna.get("problemTypes") if isinstance(cna.get("problemTypes"), list) else []
    for group in raw_problem_types[:20]:
        if not isinstance(group, dict):
            continue
        descriptions = group.get("descriptions") if isinstance(group.get("descriptions"), list) else []
        for item in descriptions[:20]:
            if isinstance(item, dict):
                value = _text(item.get("description"), 200)
                if value and value not in problem_types:
                    problem_types.append(value)

    references = []
    raw_references = cna.get("references") if isinstance(cna.get("references"), list) else []
    for item in raw_references[:40]:
        if not isinstance(item, dict):
            continue
        url = _text(item.get("url"), 1_000)
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            continue
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        references.append({"url": url, "tags": [_text(tag, 80) for tag in tags[:10]]})

    kev = search_kev(cve_id, limit=1, fetch=fetch)
    kev_match = next((item for item in kev["matches"] if item["cve_id"] == cve_id), None)
    return {
        "cve_id": _text(metadata.get("cveId"), 32),
        "state": _text(metadata.get("state"), 50),
        "date_published": _text(metadata.get("datePublished"), 100),
        "date_updated": _text(metadata.get("dateUpdated"), 100),
        "title": _text(cna.get("title"), 500),
        "description": _english_description(cna),
        "affected": _affected(cna),
        "problem_types": problem_types,
        "references": references,
        "cisa_kev": kev_match,
        "sources": [cve_url, CISA_KEV_URL],
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "interpretation": (
            "CVE List establishes the published record; CISA KEV, when present, establishes known exploitation. "
            "Neither proves target applicability, scope, reachability, configuration, or bounty eligibility."
        ),
    }
