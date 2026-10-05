"""Read-only vulnerability references for agent research.

The module retrieves metadata from fixed public sources. It never downloads
exploit files, executes proofs of concept, accepts arbitrary URLs, or contacts
a bounty target. Remote text is untrusted data and is reduced before return.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import html
import io
import json
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from intelligence import live_sources


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
GITHUB_ADVISORIES = "https://api.github.com/advisories"
OSV_QUERY = "https://api.osv.dev/v1/query"
CIRCL_VULNERABILITY = "https://vulnerability.circl.lu/api/vulnerability/"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_COMMITS = (
    "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/commits?per_page=1"
)
ALLOWED_HOSTS = {
    "services.nvd.nist.gov", "api.first.org", "api.github.com", "api.osv.dev",
    "vulnerability.circl.lu", "gitlab.com",
}
MAX_JSON = 8 * 1024 * 1024
MAX_CSV = 16 * 1024 * 1024
CACHE_SECONDS = 30 * 60
_CACHE: dict[tuple[str, str, bytes], tuple[float, bytes]] = {}


def _clean_text(value: Any, limit: int = 2_000) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _clean_url(value: Any) -> str:
    url = _clean_text(value, 1_000)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return url


def _validated_cve(value: Any) -> str:
    if not isinstance(value, str) or not live_sources.CVE_ID.fullmatch(value.strip()):
        raise ValueError("cve_id must look like CVE-YYYY-NNNN")
    return value.strip().upper()


def _request_bytes(url: str, *, method: str = "GET", body: bytes = b"",
                   content_type: str = "", max_bytes: int = MAX_JSON) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Source URL is not an approved fixed vulnerability endpoint")
    key = (method, url, body)
    cached = _CACHE.get(key)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    headers = {"Accept": "application/json", "User-Agent": "BountyBreak/0.8"}
    if parsed.hostname == "api.github.com":
        headers.update({"X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github+json"})
    if content_type:
        headers["Content-Type"] = content_type
    request = Request(url, data=body or None, headers=headers, method=method)
    try:
        with urlopen(request, timeout=15) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
                raise ValueError("Vulnerability source redirected outside an approved host")
            raw = response.read(max_bytes + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise ValueError("Record was not found at the source") from None
        if exc.code == 403 and parsed.hostname == "api.github.com":
            raise ValueError("GitHub advisory rate limit or access policy rejected the request") from None
        raise ValueError(f"Vulnerability source returned HTTP {exc.code}") from None
    except (OSError, TimeoutError, URLError):
        raise ValueError("Vulnerability source is unavailable") from None
    if len(raw) > max_bytes:
        raise ValueError(f"Vulnerability source response exceeded {max_bytes // (1024 * 1024)} MiB")
    _CACHE[key] = (time.monotonic(), raw)
    return raw


def _request_json(url: str, *, method: str = "GET", body: dict | None = None) -> Any:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else b""
    raw = _request_bytes(url, method=method, body=encoded,
                         content_type="application/json" if body is not None else "")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Vulnerability source returned invalid JSON") from None


def _references(values: Any, limit: int = 30) -> list[dict]:
    if not isinstance(values, list):
        return []
    result = []
    for item in values[:limit]:
        if isinstance(item, str):
            url, tags = _clean_url(item), []
        elif isinstance(item, dict):
            url = _clean_url(item.get("url"))
            raw_tags = item.get("tags") if isinstance(item.get("tags"), list) else []
            tags = [_clean_text(tag, 80) for tag in raw_tags[:10] if _clean_text(tag, 80)]
        else:
            continue
        if url:
            result.append({"url": url, "tags": tags})
    return result


def nvd_details(cve_id: str, *, fetch: Callable[..., Any] = _request_json) -> dict:
    cve_id = _validated_cve(cve_id)
    url = NVD_API + "?" + urlencode({"cveId": cve_id})
    payload = fetch(url)
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return {"found": False, "source": url}
    record = vulnerabilities[0].get("cve") if isinstance(vulnerabilities[0], dict) else None
    if not isinstance(record, dict):
        raise ValueError("NVD returned an invalid CVE record")

    metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) if isinstance(metrics.get(key), list) else []
        if not candidates:
            continue
        metric = next((item for item in candidates if item.get("type") == "Primary"), candidates[0])
        data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        cvss = {
            "version": _clean_text(data.get("version"), 20),
            "vector": _clean_text(data.get("vectorString"), 300),
            "base_score": data.get("baseScore") if type(data.get("baseScore")) in (int, float) else None,
            "base_severity": _clean_text(data.get("baseSeverity"), 30),
            "attack_vector": _clean_text(data.get("attackVector"), 30),
            "attack_complexity": _clean_text(data.get("attackComplexity"), 30),
            "privileges_required": _clean_text(data.get("privilegesRequired"), 30),
            "user_interaction": _clean_text(data.get("userInteraction"), 30),
            "scope": _clean_text(data.get("scope"), 30),
            "exploitability_score": metric.get("exploitabilityScore"),
            "impact_score": metric.get("impactScore"),
            "source": _clean_text(metric.get("source"), 200),
        }
        break

    ssvc = []
    for metric in (metrics.get("ssvcV203") if isinstance(metrics.get("ssvcV203"), list) else [])[:5]:
        data = metric.get("ssvcData") if isinstance(metric, dict) and isinstance(metric.get("ssvcData"), dict) else {}
        options = {}
        for option in data.get("options", []) if isinstance(data.get("options"), list) else []:
            if isinstance(option, dict):
                options.update({_clean_text(key, 50): _clean_text(value, 100) for key, value in option.items()})
        ssvc.append({"timestamp": _clean_text(data.get("timestamp"), 100), "options": options})

    weaknesses = []
    raw_weaknesses = record.get("weaknesses") if isinstance(record.get("weaknesses"), list) else []
    for group in raw_weaknesses[:20]:
        descriptions = group.get("description") if isinstance(group, dict) else []
        for item in descriptions if isinstance(descriptions, list) else []:
            value = _clean_text(item.get("value") if isinstance(item, dict) else "", 100)
            if value and value not in weaknesses:
                weaknesses.append(value)

    cpes = []
    def visit_nodes(nodes: Any) -> None:
        if not isinstance(nodes, list) or len(cpes) >= 50:
            return
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch") if isinstance(node.get("cpeMatch"), list) else []
            for match in matches:
                if not isinstance(match, dict) or len(cpes) >= 50:
                    continue
                cpes.append({key: match.get(key) for key in (
                    "vulnerable", "criteria", "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding",
                ) if match.get(key) not in (None, "")})
            visit_nodes(node.get("children"))
    configurations = record.get("configurations") if isinstance(record.get("configurations"), list) else []
    for configuration in configurations:
        if isinstance(configuration, dict):
            visit_nodes(configuration.get("nodes"))

    return {
        "found": True,
        "cve_id": _clean_text(record.get("id"), 32),
        "published": _clean_text(record.get("published"), 100),
        "last_modified": _clean_text(record.get("lastModified"), 100),
        "vuln_status": _clean_text(record.get("vulnStatus"), 100),
        "cvss": cvss,
        "ssvc": ssvc,
        "weaknesses": weaknesses,
        "affected_cpes": cpes,
        "references": _references(record.get("references")),
        "source": url,
        "detail_url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
    }


def epss_details(cve_id: str, *, fetch: Callable[..., Any] = _request_json) -> dict:
    cve_id = _validated_cve(cve_id)
    url = EPSS_API + "?" + urlencode({"cve": cve_id})
    payload = fetch(url)
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list) or not data:
        return {"found": False, "source": url}
    item = data[0] if isinstance(data[0], dict) else {}
    try:
        score = float(item.get("epss"))
        percentile = float(item.get("percentile"))
    except (TypeError, ValueError):
        score = percentile = None
    return {
        "found": True, "cve_id": _clean_text(item.get("cve"), 32),
        "probability": score, "percentile": percentile,
        "score_date": _clean_text(item.get("date"), 20), "source": url,
        "interpretation": "EPSS estimates near-term exploitation probability; it is not proof of exploitation.",
    }


def github_advisories(cve_id: str, *, fetch: Callable[..., Any] = _request_json) -> dict:
    cve_id = _validated_cve(cve_id)
    url = GITHUB_ADVISORIES + "?" + urlencode({"cve_id": cve_id, "per_page": 5})
    payload = fetch(url)
    if not isinstance(payload, list):
        raise ValueError("GitHub returned an invalid advisory list")
    advisories = []
    for item in payload[:5]:
        if not isinstance(item, dict):
            continue
        cwes = item.get("cwes") if isinstance(item.get("cwes"), list) else []
        cvss = item.get("cvss") if isinstance(item.get("cvss"), dict) else {}
        advisories.append({
            "ghsa_id": _clean_text(item.get("ghsa_id"), 40),
            "cve_id": _clean_text(item.get("cve_id"), 32),
            "url": _clean_url(item.get("html_url")),
            "summary": _clean_text(item.get("summary"), 1_000),
            "severity": _clean_text(item.get("severity"), 30),
            "published_at": _clean_text(item.get("published_at"), 100),
            "updated_at": _clean_text(item.get("updated_at"), 100),
            "withdrawn_at": _clean_text(item.get("withdrawn_at"), 100),
            "cvss": {"score": cvss.get("score"), "vector": _clean_text(cvss.get("vector_string"), 300)},
            "cwes": [{"id": _clean_text(cwe.get("cwe_id"), 30),
                      "name": _clean_text(cwe.get("name"), 300)} for cwe in cwes[:20]
                     if isinstance(cwe, dict)],
            "references": _references(item.get("references")),
        })
    return {"advisories": advisories, "source": url,
            "interpretation": "GitHub advisories are useful for reviewed open-source context and references."}


def circl_sightings(cve_id: str, *, fetch: Callable[..., Any] = _request_json) -> dict:
    cve_id = _validated_cve(cve_id)
    url = CIRCL_VULNERABILITY + cve_id + "?with_sightings=true"
    payload = fetch(url)
    if not isinstance(payload, dict):
        raise ValueError("CIRCL returned an invalid vulnerability record")
    raw = payload.get("vulnerability-lookup:sightings")
    raw = raw if isinstance(raw, list) else []
    counts = Counter(_clean_text(item.get("type"), 80) for item in raw if isinstance(item, dict))
    leads = []
    useful = {"published-proof-of-concept", "exploited", "confirmed", "seen", "patched", "not-patched"}
    ordered = sorted((item for item in raw if isinstance(item, dict)),
                     key=lambda item: _clean_text(item.get("creation_timestamp"), 100), reverse=True)
    for item in ordered:
        sighting_type = _clean_text(item.get("type"), 80)
        if sighting_type not in useful or len(leads) >= 25:
            continue
        leads.append({
            "type": sighting_type,
            "source": _clean_text(item.get("source"), 1_000),
            "created_at": _clean_text(item.get("creation_timestamp"), 100),
        })
    return {
        "counts_by_type": dict(sorted((key, value) for key, value in counts.items() if key)),
        "recent_leads": leads,
        "source": url,
        "interpretation": (
            "CIRCL sightings are leads. Social, Gist, Nuclei, Exploit-DB, Metasploit, and Telegram sightings "
            "must be checked against a vendor advisory, CVE record, KEV entry, or reproducible public source."
        ),
    }


def search_exploitdb(*, query: str = "", cve_id: str = "", limit: int = 10,
                     fetch_bytes: Callable[..., bytes] = _request_bytes,
                     fetch_json: Callable[..., Any] = _request_json) -> dict:
    if not isinstance(query, str) or len(query) > 120:
        raise ValueError("query must be at most 120 characters")
    query = " ".join(query.split()).casefold()
    cve_id = _validated_cve(cve_id) if cve_id else ""
    if not query and not cve_id:
        raise ValueError("Provide a title/product query or an exact CVE ID")
    if type(limit) is not int or not 1 <= limit <= 25:
        raise ValueError("limit must be an integer from 1 to 25")

    raw = fetch_bytes(EXPLOITDB_CSV, max_bytes=MAX_CSV)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("Exploit-DB metadata was not valid UTF-8") from None
    matches = []
    for row in csv.DictReader(io.StringIO(text)):
        codes = [_clean_text(code, 80) for code in (row.get("codes") or "").split(";") if _clean_text(code, 80)]
        if cve_id and cve_id not in {code.upper() for code in codes}:
            continue
        haystack = " ".join(row.get(field) or "" for field in
                            ("description", "author", "type", "platform", "codes", "tags", "aliases")).casefold()
        if query and query not in haystack:
            continue
        ident = _clean_text(row.get("id"), 20)
        if not ident.isdigit():
            continue
        matches.append({
            "exploitdb_id": ident,
            "title": _clean_text(html.unescape(row.get("description") or ""), 1_000),
            "published": _clean_text(row.get("date_published"), 20),
            "updated": _clean_text(row.get("date_updated"), 20),
            "author": _clean_text(row.get("author"), 200),
            "type": _clean_text(row.get("type"), 80),
            "platform": _clean_text(row.get("platform"), 100),
            "port": _clean_text(row.get("port"), 20),
            "verified": row.get("verified") == "1",
            "codes": codes,
            "tags": [_clean_text(tag, 100) for tag in (row.get("tags") or "").split(";") if _clean_text(tag, 100)],
            "source_url": _clean_url(row.get("source_url")),
            "record_url": "https://www.exploit-db.com/exploits/" + ident,
        })
    matches.sort(key=lambda item: (item["published"], item["exploitdb_id"]), reverse=True)

    commit = {}
    try:
        commits = fetch_json(EXPLOITDB_COMMITS)
        if isinstance(commits, list) and commits and isinstance(commits[0], dict):
            commit = {"id": _clean_text(commits[0].get("short_id"), 20),
                      "committed_at": _clean_text(commits[0].get("committed_date"), 100),
                      "title": _clean_text(commits[0].get("title"), 300)}
    except ValueError:
        commit = {"status": "unavailable"}
    return {
        "matches": matches[:limit], "catalog_commit": commit,
        "catalog_source": EXPLOITDB_CSV,
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "interpretation": (
            "Exploit-DB results are metadata leads only. Verified means Exploit-DB reviewed the entry; it does "
            "not prove target applicability, bounty eligibility, safety, or successful exploitation. "
            "BountyBreak does not fetch the exploit file."
        ),
    }


def query_osv_package(ecosystem: str, package: str, *, version: str = "", limit: int = 25,
                      fetch: Callable[..., Any] = _request_json) -> dict:
    ecosystem = _clean_text(ecosystem, 100)
    package = _clean_text(package, 300)
    version = _clean_text(version, 200)
    if not ecosystem or not package:
        raise ValueError("ecosystem and package are required")
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("limit must be an integer from 1 to 50")
    body = {"package": {"ecosystem": ecosystem, "name": package}}
    if version:
        body["version"] = version
    payload = fetch(OSV_QUERY, method="POST", body=body)
    raw_vulns = payload.get("vulns") if isinstance(payload, dict) else None
    raw_vulns = raw_vulns if isinstance(raw_vulns, list) else []
    advisories = []
    for item in raw_vulns[:limit]:
        if not isinstance(item, dict):
            continue
        affected = []
        raw_affected = item.get("affected") if isinstance(item.get("affected"), list) else []
        for entry in raw_affected[:10]:
            if not isinstance(entry, dict):
                continue
            pkg = entry.get("package") if isinstance(entry.get("package"), dict) else {}
            ranges = []
            for range_item in entry.get("ranges", []) if isinstance(entry.get("ranges"), list) else []:
                if not isinstance(range_item, dict):
                    continue
                events = range_item.get("events") if isinstance(range_item.get("events"), list) else []
                ranges.append({"type": _clean_text(range_item.get("type"), 50),
                               "events": [{_clean_text(key, 50): _clean_text(value, 200)
                                           for key, value in event.items()} for event in events[:30]
                                          if isinstance(event, dict)]})
            affected.append({"package": {"ecosystem": _clean_text(pkg.get("ecosystem"), 100),
                                          "name": _clean_text(pkg.get("name"), 300),
                                          "purl": _clean_text(pkg.get("purl"), 500)},
                             "ranges": ranges})
        severity = item.get("severity") if isinstance(item.get("severity"), list) else []
        advisories.append({
            "id": _clean_text(item.get("id"), 100),
            "aliases": [_clean_text(value, 100) for value in item.get("aliases", [])[:30]
                        if _clean_text(value, 100)] if isinstance(item.get("aliases"), list) else [],
            "summary": _clean_text(item.get("summary"), 1_000),
            "published": _clean_text(item.get("published"), 100),
            "modified": _clean_text(item.get("modified"), 100),
            "withdrawn": _clean_text(item.get("withdrawn"), 100),
            "affected": affected,
            "severity": [{"type": _clean_text(value.get("type"), 50),
                          "score": _clean_text(value.get("score"), 500)} for value in severity[:10]
                         if isinstance(value, dict)],
            "references": _references(item.get("references")),
            "record_url": "https://osv.dev/vulnerability/" + _clean_text(item.get("id"), 100),
        })
    return {
        "query": {"ecosystem": ecosystem, "package": package, "version": version or None},
        "advisories": advisories,
        "source": OSV_QUERY,
        "interpretation": (
            "OSV uses ecosystem-native package names and version ranges. A result supports dependency "
            "applicability only after the exact package and deployed version are independently verified."
        ),
    }


def research_cve(cve_id: str, *, providers: dict[str, Callable[[str], dict]] | None = None) -> dict:
    cve_id = _validated_cve(cve_id)
    providers = providers or {
        "cve_list_and_cisa_kev": live_sources.verify_cve,
        "nvd": nvd_details,
        "epss": epss_details,
        "github_advisories": github_advisories,
        "circl_sightings": circl_sightings,
        "exploitdb_metadata": lambda ident: search_exploitdb(cve_id=ident, limit=10),
    }
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="bountybreak-intel") as pool:
        pending = {pool.submit(function, cve_id): name for name, function in providers.items()}
        for future in as_completed(pending):
            name = pending[future]
            try:
                results[name] = {"ok": True, "data": future.result()}
            except Exception as exc:
                message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
                results[name] = {"ok": False, "error": _clean_text(message, 300)}
    ordered = {name: results[name] for name in providers}
    return {
        "cve_id": cve_id,
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": ordered,
        "interpretation": (
            "Use these records to form and prioritize hypotheses. They do not prove that a bounty asset uses "
            "the product, falls in an affected version/configuration, exposes the vulnerable path, or permits "
            "the test. Public exploit and sighting records are leads until corroborated."
        ),
    }
