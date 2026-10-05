"""Local, dependency-free research desk. No live bounty traffic is implemented."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from ai_local import draft as local_ai_draft
from intelligence import exploit_db, logic_sandbox


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_BODY = 16_384
MAX_RECORDS = 200
MAX_RESPONSE = 65_536
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TOOLS = [
    {"name": "OWASP ZAP", "role": "Proxy and application testing", "mode": "manual", "link": "https://www.zaproxy.org/"},
    {"name": "Nuclei", "role": "Template checks", "mode": "gated external tool", "link": "https://github.com/projectdiscovery/nuclei"},
    {"name": "ffuf", "role": "Content discovery", "mode": "gated external tool", "link": "https://github.com/ffuf/ffuf"},
    {"name": "Shannon", "role": "Autonomous application testing", "mode": "lab only here", "link": "https://github.com/KeygraphHQ/shannon"},
]
INTAKE_FIELDS = (
    "program_url", "exclusions", "reward_status", "technique_restrictions", "rate_limits",
    "account_requirements", "test_identity_rules", "safe_harbor", "evidence_requirements",
    "prior_art_sources", "open_questions",
)
PLAN_DETAIL_FIELDS = (
    "title", "asset", "minimum_access", "negative_control", "evidence_needed", "stop_conditions",
    "affected_version", "prior_art_result", "remediation",
)
UNRESOLVED = re.compile(r"^(unknown|tbd|pending|not checked|not reviewed|unavailable)(\b|$)", re.I)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected text")
    value = value.strip()
    if not value or len(value) > limit or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"Text must be 1–{limit} printable characters")
    return value


def clean_optional_text(value: object, limit: int) -> str:
    if value in (None, ""):
        return ""
    return clean_text(value, limit)


def clean_asset(value: object) -> str:
    """Keep an exact planning label; never treat it as an execution target."""
    asset = clean_text(value, 300)
    if "?" in asset or "#" in asset:
        raise ValueError("Asset must not contain a query or fragment")
    if "://" in asset:
        parsed = urlsplit(asset)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Use an HTTP(S) URL without credentials")
    return asset


def clean_program_url(value: object) -> str:
    url = clean_text(value, 500)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Program URL must be an HTTPS URL without credentials or a fragment")
    return url


def intake_gate(item: dict) -> dict:
    intake = item.get("intake") if isinstance(item.get("intake"), dict) else {}
    missing = [field for field in INTAKE_FIELDS if not isinstance(intake.get(field), str) or not intake[field].strip()]
    if not item.get("assets"):
        missing.append("exact_assets")
    unresolved = [field for field in INTAKE_FIELDS
                  if isinstance(intake.get(field), str) and UNRESOLVED.match(intake[field].strip())]
    return {
        "complete": not missing and not unresolved,
        "missing": missing,
        "unresolved": unresolved,
        "reviewed_at": intake.get("reviewed_at"),
        "interpretation": (
            "Completeness check only. Re-check current program terms before target traffic; "
            "a complete record does not grant authorization."
        ),
    }


def local_origin(value: object, app_port: int) -> tuple[str, int, str]:
    """Allow only an exact loopback IP origin with a nonprivileged explicit port."""
    asset = clean_asset(value)
    parsed = urlsplit(asset)
    if parsed.scheme not in ("http", "https") or parsed.hostname != "127.0.0.1":
        raise ValueError("Local checks require http(s)://127.0.0.1:<port>")
    port = parsed.port
    if port is None or not 1024 <= port <= 65535 or port == app_port:
        raise ValueError("Choose an explicit lab port from 1024 to 65535, outside this app")
    if parsed.netloc != f"127.0.0.1:{port}" or parsed.path not in ("", "/"):
        raise ValueError("Use an exact loopback origin without a path or credentials")
    return parsed.scheme, port, f"{parsed.scheme}://127.0.0.1:{port}"


def clean_probe_path(value: object) -> str:
    path = clean_text(value, 256)
    if (not path.startswith("/") or path.startswith("//")
            or any(char in path for char in ("?", "#", "\\", "%"))
            or any(not 33 <= ord(char) <= 126 for char in path)):
        raise ValueError("Use a relative path beginning with /, without query or fragment")
    return path


def slug_for(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:42].strip("-")
    return f"{base or 'engagement'}-{uuid.uuid4().hex[:8]}"


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


class Store:
    def __init__(self, data_dir: Path):
        self.directory = data_dir.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def _path(self, ident: str) -> Path:
        if not SLUG.fullmatch(ident):
            raise ValueError("Invalid engagement ID")
        return self.directory / ident / "engagement.json"

    def snapshot(self) -> tuple[list[dict], list[dict]]:
        """Return readable engagements and explicit warnings for preserved bad records."""
        with self.lock:
            result = []
            warnings = []
            for path in sorted(self.directory.glob("*/engagement.json")):
                if SLUG.fullmatch(path.parent.name):
                    try:
                        item = json.loads(path.read_text(encoding="utf-8"))
                        if not isinstance(item, dict) or item.get("id") != path.parent.name:
                            raise ValueError("invalid engagement record")
                        result.append(item)
                    except (OSError, UnicodeError, ValueError):
                        warnings.append({
                            "engagement_id": path.parent.name,
                            "message": "Record was preserved on disk but could not be loaded",
                        })
            return (sorted(result, key=lambda item: item.get("created_at", ""), reverse=True),
                    warnings)

    def list(self) -> list[dict]:
        return self.snapshot()[0]

    def get(self, ident: str) -> dict:
        with self.lock:
            try:
                return json.loads(self._path(ident).read_text(encoding="utf-8"))
            except FileNotFoundError:
                raise ValueError("Engagement not found") from None

    def create(self, name: str, kind: str, authority: str, asset: str = "") -> dict:
        if kind not in ("bounty", "internal", "owned_lab"):
            raise ValueError("Invalid engagement kind")
        with self.lock:
            if len(self.list()) >= MAX_RECORDS:
                raise ValueError("Engagement limit reached")
            item = {"id": slug_for(name), "name": name, "kind": kind,
                    "authority": authority, "created_at": now(), "assets": [], "plans": [], "runs": []}
            if asset:
                item["assets"].append({"value": clean_asset(asset), "added_at": now()})
            save_json(self._path(item["id"]), item)
            return item

    def add_asset(self, ident: str, value: str) -> dict:
        with self.lock:
            item = self.get(ident)
            assets = item.setdefault("assets", [])
            if len(assets) >= MAX_RECORDS:
                raise ValueError("Asset limit reached")
            value = clean_asset(value)
            if any(existing["value"].casefold() == value.casefold() for existing in assets):
                raise ValueError("Asset already recorded")
            asset = {"value": value, "added_at": now()}
            assets.append(asset)
            save_json(self._path(ident), item)
            return asset

    def add_plan(self, ident: str, hypothesis: str, impact: str) -> dict:
        with self.lock:
            item = self.get(ident)
            if len(item["plans"]) >= MAX_RECORDS:
                raise ValueError("Plan limit reached")
            plan = {"id": uuid.uuid4().hex[:12], "hypothesis": hypothesis,
                    "impact": impact, "created_at": now(), "status": "planning"}
            item["plans"].append(plan)
            save_json(self._path(ident), item)
            return plan

    def set_intake(self, ident: str, values: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            intake = {field: clean_text(values.get(field), 1_000) for field in INTAKE_FIELDS}
            intake["program_url"] = clean_program_url(values.get("program_url"))
            intake["reviewed_at"] = now()
            item["intake"] = intake
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return intake_gate(item)

    def add_candidate(self, ident: str, hypothesis: str, impact: str, details: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            if len(item["plans"]) >= MAX_RECORDS:
                raise ValueError("Plan limit reached")
            plan = {
                "id": uuid.uuid4().hex[:12],
                "hypothesis": clean_text(hypothesis, 500),
                "impact": clean_text(impact, 300),
                "created_at": now(),
                "status": "candidate",
            }
            for field in PLAN_DETAIL_FIELDS:
                plan[field] = clean_text(details.get(field), 1_000)
            if plan["asset"] not in {entry["value"] for entry in item.get("assets", [])}:
                raise ValueError("Candidate asset must be recorded on the engagement")
            item["plans"].append(plan)
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return plan

    def add_observation(self, ident: str, plan_id: str, values: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            if not any(plan["id"] == plan_id for plan in item["plans"]):
                raise ValueError("Plan not found")
            observations = item.setdefault("observations", [])
            if len(observations) >= MAX_RECORDS:
                raise ValueError("Observation limit reached")
            classification = values.get("classification")
            if classification not in ("observed", "derived", "unverified"):
                raise ValueError("Classification must be observed, derived, or unverified")
            references = values.get("evidence_refs", [])
            if (not isinstance(references, list) or len(references) > 20
                    or not all(isinstance(ref, str) and 0 < len(ref.strip()) <= 300 for ref in references)):
                raise ValueError("Evidence refs must be a list of up to 20 short local references")
            observation = {
                "id": uuid.uuid4().hex[:12], "plan_id": plan_id, "classification": classification,
                "summary": clean_text(values.get("summary"), 1_000),
                "reproduction": clean_text(values.get("reproduction"), 2_000),
                "negative_control_result": clean_text(values.get("negative_control_result"), 1_000),
                "independent_impact_check": clean_text(values.get("independent_impact_check"), 1_000),
                "evidence_refs": [ref.strip() for ref in references], "created_at": now(),
            }
            observations.append(observation)
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return observation

    def add_outcome(self, ident: str, plan_id: str, values: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            if not any(plan["id"] == plan_id for plan in item["plans"]):
                raise ValueError("Plan not found")
            outcomes = item.setdefault("outcomes", [])
            if len(outcomes) >= MAX_RECORDS:
                raise ValueError("Outcome limit reached")
            status = values.get("status")
            allowed = {"draft", "submitted", "needs_more_info", "triaged", "accepted", "rejected",
                       "duplicate", "withdrawn", "paid"}
            if status not in allowed:
                raise ValueError("Unsupported outcome status")
            event = {"id": uuid.uuid4().hex[:12], "plan_id": plan_id,
                     "status": status, "recorded_at": now()}
            submission_reference = clean_optional_text(values.get("submission_reference"), 300)
            if submission_reference:
                event["submission_reference"] = submission_reference
            for field in ("pending_award_usd", "received_cash_usd", "paid_costs_usd"):
                value = values.get(field)
                if value is not None:
                    if type(value) not in (int, float) or value < 0 or value > 10_000_000:
                        raise ValueError(f"{field} must be a non-negative number")
                    event[field] = round(float(value), 2)
            human_minutes = values.get("human_minutes")
            if human_minutes is not None:
                if type(human_minutes) is not int or not 0 <= human_minutes <= 1_000_000:
                    raise ValueError("human_minutes must be a non-negative integer")
                event["human_minutes"] = human_minutes
            note = clean_optional_text(values.get("note"), 1_000)
            if note:
                event["note"] = note
            outcomes.append(event)
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return event

    def add_run(self, ident: str, plan_id: str, evidence: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            if not any(p["id"] == plan_id for p in item["plans"]):
                raise ValueError("Plan not found")
            if len(item["runs"]) >= MAX_RECORDS:
                raise ValueError("Run limit reached")
            record = {"id": uuid.uuid4().hex[:12], "plan_id": plan_id,
                      "created_at": now(), **evidence}
            item["runs"].append(record)
            save_json(self._path(ident), item)
            return record


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/api/me":
            status, body = 200, b'{"user":"researcher","role":"member"}'
        elif self.path == "/api/admin":
            status, body = 403, b'{"error":"forbidden"}'
        else:
            status, body = 404, b'{"error":"not_found"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def bounded_check(scheme: str, port: int, primary_path: str, control_path: str,
                  expected_control_status: int) -> dict:
    """Make at most two same-origin requests, without DNS or redirect following."""
    observations = []
    sent = 0
    stopped_reason = None
    started = time.monotonic()
    for index, path in enumerate((primary_path, control_path)):
        connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        connection = connection_type("127.0.0.1", port, timeout=3)
        try:
            connection.request("GET", path, headers={"Host": f"127.0.0.1:{port}", "Accept": "*/*"})
            sent += 1
            response = connection.getresponse()
            observation = {"path": path, "status": response.status}
            observations.append(observation)
            if response.status == 429 or response.status >= 500:
                stopped_reason = "Lab throttled or returned a server error"
                break
            if 300 <= response.status < 400:
                stopped_reason = "Lab redirected; redirect was not followed"
                break
            body = response.read(MAX_RESPONSE + 1)
            observation["body_bytes"] = len(body)
            if len(body) > MAX_RESPONSE:
                observation["truncated"] = True
                stopped_reason = "Response exceeded the 64 KiB ceiling"
                break
            observation["body_sha256"] = hashlib.sha256(body).hexdigest()
            if index == 0 and not 200 <= response.status < 300:
                stopped_reason = "Primary request did not return 2xx"
                break
        except (OSError, http.client.HTTPException):
            if observations and observations[-1]["path"] == path:
                observations[-1]["error"] = "Connection failed after response"
            else:
                observations.append({"path": path, "error": "Connection failed"})
            stopped_reason = "Connection failed; no more requests were sent"
            break
        finally:
            connection.close()
        if index == 0:
            time.sleep(0.5)
    completed = stopped_reason is None and len(observations) == 2
    control_passed = observations[1]["status"] == expected_control_status if completed else None
    primary_passed = 200 <= observations[0]["status"] < 300 if completed else None
    return {"target_origin": f"{scheme}://127.0.0.1:{port}", "method": "GET",
            "request_budget": 2, "requests_sent": sent, "per_request_timeout_seconds": 3,
            "max_response_bytes": MAX_RESPONSE, "minimum_interval_seconds": 0.5,
            "duration_seconds": round(time.monotonic() - started, 3),
            "expected_control_status": expected_control_status, "observations": observations,
            "primary_passed": primary_passed, "negative_control_passed": control_passed,
            "status": "completed" if completed else "stopped", "stopped_reason": stopped_reason,
            "finding": "Expected behavior observed" if completed and primary_passed and control_passed
                       else "Check needs review; no vulnerability claimed", "classification": "observed"}


def demo_check(port: int) -> dict:
    """Two fixed requests to the bundled loopback lab."""
    return {"environment": "bundled researcher-owned loopback lab",
            **bounded_check("http", port, "/api/me", "/api/admin", 403)}


class AppHandler(BaseHTTPRequestHandler):
    server: "AppServer"

    def log_message(self, *_args):
        pass

    def _headers(self, status: int, mime: str, size: int):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def _json(self, status: int, value: object):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def _route(self) -> list[str]:
        path = urlsplit(self.path)
        if path.query or path.fragment or "%" in path.path or "//" in path.path:
            raise ValueError("Invalid route")
        return [part for part in path.path.split("/") if part]

    def do_GET(self):
        if not self._host_ok():
            self._json(403, {"error": "Host not allowed"})
            return
        try:
            route = self._route()
            if route == ["api", "state"]:
                engagements, data_warnings = self.server.store.snapshot()
                self._json(200, {"engagements": engagements, "data_warnings": data_warnings, "tools": TOOLS,
                                 "demo_ready": True, "csrf": self.server.csrf,
                                 "ai_port": self.server.model_port})
            elif route == ["api", "sandbox", "example"]:
                example = ROOT / "intelligence" / "examples"
                self._json(200, {"world": json.loads((example / "synthetic_role_chain_world.json").read_text(encoding="utf-8")),
                                 "plan": json.loads((example / "synthetic_role_chain_plan.json").read_text(encoding="utf-8"))})
            elif len(route) == 3 and route[:2] == ["api", "engagements"]:
                self._json(200, self.server.store.get(route[2]))
            elif route in ([], ["index.html"], ["app.js"], ["style.css"], ["brand.svg"]):
                filename = "index.html" if not route else route[0]
                mime = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
                        "style.css": "text/css; charset=utf-8", "brand.svg": "image/svg+xml"}[filename]
                body = (STATIC / filename).read_bytes()
                self._headers(200, mime, len(body))
                self.wfile.write(body)
            else:
                self._json(404, {"error": "Not found"})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})

    def do_POST(self):
        if not self._host_ok() or self.headers.get("Origin") != f"http://127.0.0.1:{self.server.server_port}":
            self._json(403, {"error": "Origin not allowed"})
            return
        if self.headers.get("X-CSRF-Token") != self.server.csrf:
            self._json(403, {"error": "Invalid CSRF token"})
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= size <= MAX_BODY or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("Invalid request body")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Expected JSON object")
            route = self._route()
            if route == ["api", "intelligence", "search"]:
                query = clean_text(payload.get("query"), 120)
                self._json(200, {"records": exploit_db.search(query, limit=8),
                                 "interpretation": "Prior art only. Re-check current primary sources and scope."})
            elif route == ["api", "sandbox", "simulate"]:
                world, plan = payload.get("world"), payload.get("plan")
                if not isinstance(world, dict) or not isinstance(plan, dict):
                    raise ValueError("World and plan must be JSON objects")
                result = logic_sandbox.simulate(world, plan)
                if payload.get("explore") is True:
                    result["exploration"] = logic_sandbox.explore(world)
                self._json(200, result)
            elif route == ["api", "ai", "draft"]:
                if self.server.model_port is None:
                    raise ValueError("AI drafting is off. Restart ScopeRook with --model-port PORT to use a chosen local model.")
                question = clean_text(payload.get("question"), 800)
                raw_query = payload.get("prior_art_query", "")
                if not isinstance(raw_query, str):
                    raise ValueError("Prior-art query must be text")
                query = raw_query.strip()
                records = exploit_db.search(clean_text(query, 120), limit=2) if query else []
                context = exploit_db.model_context(records)[:5500]
                sandbox_result = None
                if "world" in payload or "plan" in payload:
                    world, plan = payload.get("world"), payload.get("plan")
                    if not isinstance(world, dict) or not isinstance(plan, dict):
                        raise ValueError("AI sandbox context requires world and plan JSON objects")
                    sandbox_result = logic_sandbox.simulate(world, plan)
                    concise = {"result": sandbox_result["result"], "interpretation": sandbox_result["interpretation"],
                               "cases": [{"case": case["case"], "kind": case["kind"], "goal": case["goal"],
                                          "matches_expectation": case["matches_expectation"],
                                          "blocked": [step for step in case["trace"] if step["result"] != "applied"]}
                                         for case in sandbox_result["cases"]]}
                    context += "\nSymbolic sandbox result (model only; no observed target behavior):\n"
                    context += json.dumps(concise, ensure_ascii=False)[:1800]
                ident = payload.get("engagement_id")
                if ident:
                    item = self.server.store.get(clean_text(ident, 64))
                    assets = ", ".join(entry["value"] for entry in item.get("assets", [])[:3])
                    context += f"\nEngagement planning record: {item['name']} ({item['kind']}); assets: {assets}. "
                    context += "This record does not grant target access.\n"
                result = local_ai_draft(self.server.model_port, question, context[:8000])
                if sandbox_result:
                    result["sandbox_result"] = sandbox_result["result"]
                result["prior_art"] = [{"cve_id": record["cve_id"], "sources": record["sources"]}
                                       for record in records]
                self._json(200, result)
            elif route == ["api", "engagements"]:
                item = self.server.store.create(clean_text(payload.get("name"), 100),
                    payload.get("kind"), clean_text(payload.get("authority"), 500), payload.get("asset", ""))
                self._json(201, item)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "assets":
                asset = self.server.store.add_asset(route[2], payload.get("value"))
                self._json(201, asset)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "plans":
                plan = self.server.store.add_plan(route[2], clean_text(payload.get("hypothesis"), 500),
                                                  clean_text(payload.get("impact"), 300))
                self._json(201, plan)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "demo-run":
                ident = route[2]
                item = self.server.store.get(ident)
                if item["kind"] != "owned_lab":
                    raise ValueError("Demo runs require an owned-lab engagement")
                plan_id = clean_text(payload.get("plan_id"), 12)
                if not any(plan["id"] == plan_id for plan in item["plans"]):
                    raise ValueError("Plan not found")
                if not self.server.run_lock.acquire(blocking=False):
                    self._json(409, {"error": "Another demo run is active"})
                    return
                try:
                    evidence = demo_check(self.server.demo_port)
                    run = self.server.store.add_run(ident, plan_id, evidence)
                finally:
                    self.server.run_lock.release()
                self._json(201, run)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "local-run":
                ident = route[2]
                item = self.server.store.get(ident)
                if item["kind"] != "owned_lab" or payload.get("owned_lab_attested") is not True:
                    raise ValueError("Confirm this is a researcher-owned local lab")
                plan_id = clean_text(payload.get("plan_id"), 12)
                if not any(plan["id"] == plan_id for plan in item["plans"]):
                    raise ValueError("Plan not found")
                asset = clean_text(payload.get("asset"), 300)
                if not any(entry["value"] == asset for entry in item.get("assets", [])):
                    raise ValueError("Choose a recorded asset")
                scheme, port, origin = local_origin(asset, self.server.server_port)
                primary = clean_probe_path(payload.get("primary_path"))
                control = clean_probe_path(payload.get("control_path"))
                if primary == control:
                    raise ValueError("Primary and control paths must differ")
                expected = payload.get("expected_control_status")
                if type(expected) is not int or expected not in (401, 403, 404):
                    raise ValueError("Control status must be 401, 403, or 404")
                if len(item["runs"]) >= MAX_RECORDS:
                    raise ValueError("Run limit reached")
                if not self.server.run_lock.acquire(blocking=False):
                    self._json(409, {"error": "Another local run is active"})
                    return
                try:
                    evidence = {"environment": "attested researcher-owned loopback lab",
                                "owner_attested": True, **bounded_check(scheme, port, primary, control, expected)}
                    run = self.server.store.add_run(ident, plan_id, evidence)
                finally:
                    self.server.run_lock.release()
                self._json(201, run)
            else:
                self._json(404, {"error": "Not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except (OSError, RuntimeError, http.client.HTTPException):
            self._json(503, {"error": "Local check failed before evidence could be saved"})


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store: Store, demo_port: int, model_port: int | None = None):
        super().__init__(address, AppHandler)
        self.store = store
        self.demo_port = demo_port
        self.model_port = model_port
        self.csrf = secrets.token_urlsafe(32)
        self.run_lock = threading.Lock()


def main():
    parser = argparse.ArgumentParser(description="ScopeRook local security research desk")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--open", action="store_true", help="open the app in the default browser")
    parser.add_argument("--model-port", type=int,
                        help="explicitly enable AI drafting with an OpenAI-compatible local model on 127.0.0.1")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024–65535")
    if args.model_port is not None and (not 1024 <= args.model_port <= 65535 or args.model_port == args.port):
        parser.error("model port must be 1024–65535 and differ from the app port")
    demo = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    demo.daemon_threads = True
    threading.Thread(target=demo.serve_forever, daemon=True).start()
    app = AppServer(("127.0.0.1", args.port), Store(args.data_dir), demo.server_port, args.model_port)
    print(f"ScopeRook: http://127.0.0.1:{app.server_port}/", flush=True)
    if args.open:
        threading.Timer(0.4, webbrowser.open, args=(f"http://127.0.0.1:{app.server_port}/",)).start()
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.server_close()
        demo.shutdown()
        demo.server_close()


if __name__ == "__main__":
    main()
