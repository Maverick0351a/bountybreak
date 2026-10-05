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
VALIDATION_ENVIRONMENTS = {"offline_source", "synthetic_lab", "researcher_owned_runtime", "authorized_target"}
TARGET_PLATFORMS = {"bugcrowd", "hackerone", "intigriti", "yeswehack", "direct", "other"}
TARGET_STATUSES = {"active", "paused", "closed"}
TARGET_PRIORITIES = {"high", "normal", "low", "hold"}
ACCOUNT_STATES = {"not_required", "ready", "pending", "blocked", "unavailable"}
ACCOUNT_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$")
ASSET_TYPES = {"web", "api", "mobile", "repository", "hardware", "cloud", "other"}
ASSET_SCOPE_STATES = {"in_scope", "out_of_scope", "conditional", "unknown"}
ASSET_REWARD_STATES = {"rewarded", "no_reward", "unknown"}
ASSET_TEST_STATES = {"untested", "active", "paused", "closed"}
COVERAGE_LANES = {
    "identity_access", "business_logic", "api", "integrations_webhooks", "file_processing",
    "ai_agents", "client_mobile", "supply_chain", "infrastructure_configuration",
}
HUNT_SESSION_STATES = {"no_candidate", "lead", "candidate", "blocked", "paused"}
REQUEST_COUNT_STATES = {"measured", "not_applicable", "unknown"}


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


def clean_text_list(value: object, field: str, *, maximum_items: int = 30,
                    maximum_length: int = 120, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items or (not value and not allow_empty):
        requirement = "up to" if allow_empty else "1 to"
        raise ValueError(f"{field} must contain {requirement} {maximum_items} text values")
    cleaned = [clean_text(item, maximum_length) for item in value]
    if len({item.casefold() for item in cleaned}) != len(cleaned):
        raise ValueError(f"{field} values must be unique")
    return cleaned


def clean_date(value: object, field: str, *, optional: bool = False) -> str:
    if optional and value in (None, ""):
        return ""
    text = clean_text(value, 10)
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"{field} must use YYYY-MM-DD") from exc
    return text


def clean_account_label(value: object) -> str:
    """Accept only a non-secret local alias, never an address or credential-shaped value."""
    if value in (None, ""):
        return ""
    text = clean_text(value, 80)
    if not ACCOUNT_LABEL.fullmatch(text):
        raise ValueError("account_reference must be a short local alias without @, URL, or secret symbols")
    return text


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

    def set_target_profile(self, ident: str, values: dict) -> dict:
        """Save the durable, non-secret context needed to resume a target later."""
        with self.lock:
            item = self.get(ident)
            enum_fields = {
                "platform": TARGET_PLATFORMS,
                "program_status": TARGET_STATUSES,
                "priority": TARGET_PRIORITIES,
                "account_state": ACCOUNT_STATES,
            }
            profile = {}
            for field, choices in enum_fields.items():
                value = values.get(field)
                if value not in choices:
                    raise ValueError(f"Unsupported {field}")
                profile[field] = value
            profile.update({
                "attacker_payoffs": clean_text_list(
                    values.get("attacker_payoffs"), "attacker_payoffs", maximum_items=8,
                    maximum_length=200),
                "technologies": clean_text_list(
                    values.get("technologies"), "technologies", maximum_items=30,
                    maximum_length=120, allow_empty=True),
                "account_reference": clean_account_label(values.get("account_reference")),
                "research_strategy": clean_text(values.get("research_strategy"), 1_000),
                "next_action": clean_text(values.get("next_action"), 500),
                "revisit_after": clean_date(values.get("revisit_after"), "revisit_after", optional=True),
                "tags": clean_text_list(values.get("tags"), "tags", maximum_items=20,
                                        maximum_length=80, allow_empty=True),
                "updated_at": now(),
            })
            content = {key: profile[key] for key in profile if key != "updated_at"}
            canonical = json.dumps(content, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
            profile["content_sha256"] = hashlib.sha256(canonical).hexdigest()
            history = item.setdefault("target_profile_history", [])
            if not isinstance(history, list):
                raise ValueError("Existing target profile history is invalid")
            if not history or history[-1].get("content_sha256") != profile["content_sha256"]:
                if len(history) >= MAX_RECORDS:
                    raise ValueError("Target profile history limit reached")
                history.append({
                    "recorded_at": profile["updated_at"],
                    "content_sha256": profile["content_sha256"],
                    "snapshot": content,
                })
            item["target_profile"] = profile
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return profile

    def set_asset_context(self, ident: str, values: dict) -> dict:
        """Document per-asset scope and constraints without implying authorization."""
        with self.lock:
            item = self.get(ident)
            asset_value = clean_asset(values.get("asset"))
            asset = next((entry for entry in item.get("assets", [])
                          if entry.get("value") == asset_value), None)
            if asset is None:
                raise ValueError("Asset is not recorded on this engagement")
            enum_fields = {
                "asset_type": ASSET_TYPES,
                "scope_status": ASSET_SCOPE_STATES,
                "reward_status": ASSET_REWARD_STATES,
                "test_status": ASSET_TEST_STATES,
            }
            context = {}
            for field, choices in enum_fields.items():
                value = values.get(field)
                if value not in choices:
                    raise ValueError(f"Unsupported {field}")
                context[field] = value
            if context["scope_status"] == "out_of_scope" and context["test_status"] != "closed":
                raise ValueError("An out-of-scope asset must have test_status closed")
            context.update({
                "constraints": clean_text(values.get("constraints"), 1_000),
                "notes": clean_optional_text(values.get("notes"), 1_000),
                "reviewed_at": now(),
            })
            content = {key: context[key] for key in context if key != "reviewed_at"}
            canonical = json.dumps(content, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
            context["content_sha256"] = hashlib.sha256(canonical).hexdigest()
            history = asset.setdefault("context_history", [])
            if not isinstance(history, list):
                raise ValueError("Existing asset context history is invalid")
            if not history or history[-1].get("content_sha256") != context["content_sha256"]:
                if len(history) >= MAX_RECORDS:
                    raise ValueError("Asset context history limit reached")
                history.append({
                    "reviewed_at": context["reviewed_at"],
                    "content_sha256": context["content_sha256"],
                    "snapshot": content,
                })
            asset["context"] = context
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return {"asset": asset_value, **context}

    def add_hunt_session(self, ident: str, values: dict) -> dict:
        """Append one bounded hunting pass so future agents can resume from recorded facts."""
        with self.lock:
            item = self.get(ident)
            lane = values.get("lane")
            status_value = values.get("status")
            environment = values.get("environment")
            count_state = values.get("request_count_state")
            if lane not in COVERAGE_LANES:
                raise ValueError("Unsupported coverage lane")
            if status_value not in HUNT_SESSION_STATES:
                raise ValueError("Unsupported hunt session status")
            if environment not in VALIDATION_ENVIRONMENTS:
                raise ValueError("Unsupported hunt session environment")
            if count_state not in REQUEST_COUNT_STATES:
                raise ValueError("Unsupported request_count_state")
            request_count = values.get("target_requests")
            if type(request_count) is not int or not 0 <= request_count <= 100_000:
                raise ValueError("target_requests must be an integer from 0 to 100000")
            if count_state in {"not_applicable", "unknown"} and request_count != 0:
                raise ValueError("Use zero target_requests when the count is not applicable or unknown")
            if environment in {"offline_source", "synthetic_lab", "researcher_owned_runtime"}:
                if count_state != "not_applicable" or request_count != 0:
                    raise ValueError("Non-target sessions must record zero, not-applicable target requests")
            if environment == "authorized_target" and count_state == "not_applicable":
                raise ValueError("Authorized-target sessions require measured or explicitly unknown requests")
            human_minutes = values.get("human_minutes")
            if type(human_minutes) is not int or not 0 <= human_minutes <= 100_000:
                raise ValueError("human_minutes must be an integer from 0 to 100000")
            paid_cost_usd = values.get("paid_cost_usd")
            if type(paid_cost_usd) not in (int, float) or not 0 <= paid_cost_usd <= 1_000_000:
                raise ValueError("paid_cost_usd must be a non-negative number")
            candidate_ids = clean_text_list(
                values.get("candidate_ids"), "candidate_ids", maximum_items=20,
                maximum_length=12, allow_empty=True)
            known_plans = {plan.get("id") for plan in item.get("plans", [])}
            if any(plan_id not in known_plans for plan_id in candidate_ids):
                raise ValueError("Every candidate id must belong to this engagement")
            source_refs = clean_text_list(
                values.get("source_refs"), "source_refs", maximum_items=20,
                maximum_length=300, allow_empty=True)
            sessions = item.setdefault("hunt_sessions", [])
            if not isinstance(sessions, list):
                raise ValueError("Existing hunt session history is invalid")
            if len(sessions) >= MAX_RECORDS:
                raise ValueError("Hunt session limit reached")
            session = {
                "id": uuid.uuid4().hex[:12],
                "recorded_at": now(),
                "lane": lane,
                "status": status_value,
                "environment": environment,
                "summary": clean_text(values.get("summary"), 1_500),
                "candidate_ids": candidate_ids,
                "source_refs": source_refs,
                "request_count_state": count_state,
                "target_requests": request_count if count_state == "measured" else None,
                "human_minutes": human_minutes,
                "paid_cost_usd": round(float(paid_cost_usd), 2),
                "next_action": clean_text(values.get("next_action"), 500),
                "revisit_after": clean_date(
                    values.get("revisit_after"), "revisit_after", optional=True),
            }
            sessions.append(session)
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return session

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
            content = {field: intake[field] for field in INTAKE_FIELDS}
            canonical = json.dumps(content, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
            intake_hash = hashlib.sha256(canonical).hexdigest()
            intake["content_sha256"] = intake_hash
            history = item.setdefault("intake_history", [])
            if not isinstance(history, list):
                raise ValueError("Existing intake history is invalid")
            previous = item.get("intake")
            if previous and not history:
                previous_content = {field: previous.get(field) for field in INTAKE_FIELDS}
                previous_canonical = json.dumps(previous_content, ensure_ascii=False, sort_keys=True,
                                                separators=(",", ":")).encode("utf-8")
                history.append({
                    "reviewed_at": previous.get("reviewed_at"),
                    "content_sha256": previous.get("content_sha256")
                    or hashlib.sha256(previous_canonical).hexdigest(),
                    "snapshot": previous_content,
                })
            if not history or history[-1].get("content_sha256") != intake_hash:
                if len(history) >= MAX_RECORDS:
                    raise ValueError("Intake history limit reached")
                history.append({"reviewed_at": intake["reviewed_at"],
                                "content_sha256": intake_hash, "snapshot": content})
            item["intake"] = intake
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return intake_gate(item)

    def compare_intake(self, ident: str) -> dict:
        """Return a value-minimizing diff between the two latest policy snapshots."""
        with self.lock:
            item = self.get(ident)
            history = item.get("intake_history", [])
            if not isinstance(history, list):
                raise ValueError("Existing intake history is invalid")
            if not history:
                return {"engagement_id": ident, "snapshot_count": 0, "changed": False,
                        "changed_fields": [], "message": "No intake snapshot is recorded"}
            current = history[-1]
            if len(history) == 1:
                return {
                    "engagement_id": ident, "snapshot_count": 1, "changed": False,
                    "changed_fields": [], "current_reviewed_at": current.get("reviewed_at"),
                    "current_sha256": current.get("content_sha256"),
                    "scope_gate": intake_gate(item),
                    "message": "Baseline intake snapshot recorded; no earlier snapshot exists",
                }
            previous = history[-2]
            before = previous.get("snapshot") if isinstance(previous.get("snapshot"), dict) else {}
            after = current.get("snapshot") if isinstance(current.get("snapshot"), dict) else {}
            changed = [field for field in INTAKE_FIELDS if before.get(field) != after.get(field)]
            return {
                "engagement_id": ident, "snapshot_count": len(history), "changed": bool(changed),
                "changed_fields": changed,
                "previous_reviewed_at": previous.get("reviewed_at"),
                "current_reviewed_at": current.get("reviewed_at"),
                "previous_sha256": previous.get("content_sha256"),
                "current_sha256": current.get("content_sha256"),
                "scope_gate": intake_gate(item),
                "message": "Changed field names only; read the engagement explicitly to inspect current values",
            }

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

    def set_candidate_assessment(self, ident: str, plan_id: str, values: dict) -> dict:
        """Record transparent selection factors without pretending to predict acceptance."""
        with self.lock:
            item = self.get(ident)
            plan = next((entry for entry in item.get("plans", []) if entry.get("id") == plan_id), None)
            if plan is None:
                raise ValueError("Plan not found")
            allowed = {
                "duplicate_risk": {"low", "medium", "high", "unknown"},
                "setup_cost": {"none", "low", "medium", "high"},
                "proof_strength": {"clear_end_to_end", "partial", "source_only"},
                "decision": {"pursue", "hold", "stop"},
            }
            assessment = {
                "attacker_motive": clean_text(values.get("attacker_motive"), 1_000),
                "plausible_payoff": clean_text(values.get("plausible_payoff"), 1_000),
                "duplicate_risk_reason": clean_text(values.get("duplicate_risk_reason"), 1_000),
                "proof_path": clean_text(values.get("proof_path"), 1_000),
            }
            for field, choices in allowed.items():
                value = values.get(field)
                if value not in choices:
                    raise ValueError(f"Unsupported {field}")
                assessment[field] = value
            expected_requests = values.get("expected_requests")
            if type(expected_requests) is not int or not 0 <= expected_requests <= 1_000:
                raise ValueError("expected_requests must be an integer from 0 to 1000")
            assessment["expected_requests"] = expected_requests
            assessment["assessed_at"] = now()
            plan["assessment"] = assessment
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return assessment

    def set_validation_contract(self, ident: str, plan_id: str, values: dict) -> dict:
        """Bind a hypothesis to explicit identity, state, sequence, control, and proof limits."""
        with self.lock:
            item = self.get(ident)
            plan = next((entry for entry in item.get("plans", []) if entry.get("id") == plan_id), None)
            if plan is None:
                raise ValueError("Plan not found")
            environment = values.get("environment")
            if environment not in VALIDATION_ENVIRONMENTS:
                raise ValueError("Unsupported validation environment")
            steps = values.get("sequence_steps")
            if (not isinstance(steps, list) or not 1 <= len(steps) <= 12
                    or not all(isinstance(step, str) for step in steps)):
                raise ValueError("sequence_steps must contain 1 to 12 text steps")
            cleaned_steps = [clean_text(step, 300) for step in steps]
            if len(set(cleaned_steps)) != len(cleaned_steps):
                raise ValueError("sequence_steps must be unique")
            max_requests = values.get("max_requests")
            if type(max_requests) is not int or not 0 <= max_requests <= 100:
                raise ValueError("max_requests must be an integer from 0 to 100")
            if environment == "offline_source" and max_requests != 0:
                raise ValueError("offline_source validation must use a zero request budget")
            if environment in {"researcher_owned_runtime", "authorized_target"} and max_requests == 0:
                raise ValueError("runtime validation requires a positive request budget")
            contract = {
                "environment": environment,
                "asset": plan.get("asset"),
                "candidate_actor": clean_text(values.get("candidate_actor"), 300),
                "control_actor": clean_text(values.get("control_actor"), 300),
                "starting_state": clean_text(values.get("starting_state"), 500),
                "sequence_steps": cleaned_steps,
                "expected_secure_behavior": clean_text(values.get("expected_secure_behavior"), 500),
                "suspected_behavior": clean_text(values.get("suspected_behavior"), 500),
                "negative_control": clean_text(values.get("negative_control"), 500),
                "independent_impact_check": clean_text(values.get("independent_impact_check"), 500),
                "cleanup": clean_text(values.get("cleanup"), 500),
                "max_requests": max_requests,
                "recorded_at": now(),
                "execution_ready": False,
                "execution_requirements": (
                    "Use a separately approved executor bound to this exact contract"
                    if environment == "authorized_target"
                    else "Run only in the recorded researcher-controlled environment"
                ),
            }
            plan["validation_contract"] = contract
            item["updated_at"] = now()
            save_json(self._path(ident), item)
            return contract

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
