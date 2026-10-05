"""Compact cross-target portfolio and chronological engagement history."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from workbench import COVERAGE_LANES, INTAKE_FIELDS, intake_gate


PRIORITY_ORDER = {"high": 0, "normal": 1, "low": 2, "hold": 3}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _latest(values: list[Any]) -> str | None:
    valid = [(parsed, value) for value in values if (parsed := _time(value)) is not None]
    return max(valid)[1] if valid else None


def _changed_fields(before: dict, after: dict, fields: tuple[str, ...] | None = None) -> list[str]:
    keys = fields or tuple(sorted(set(before).union(after)))
    return [key for key in keys if before.get(key) != after.get(key)]


def _policy_age(item: dict, now_utc: datetime) -> int | None:
    intake = item.get("intake") if isinstance(item.get("intake"), dict) else {}
    reviewed = _time(intake.get("reviewed_at"))
    return (now_utc - reviewed).days if reviewed else None


def _lane_state(sessions: list[dict]) -> dict[str, dict]:
    result = {lane: {"status": "untested", "last_session_at": None}
              for lane in sorted(COVERAGE_LANES)}
    for session in sorted(sessions, key=lambda value: value.get("recorded_at", "")):
        lane = session.get("lane")
        if lane in result:
            result[lane] = {
                "status": session.get("status", "unknown"),
                "last_session_at": session.get("recorded_at"),
                "next_action": session.get("next_action"),
                "revisit_after": session.get("revisit_after") or None,
            }
    return result


def _candidate_counts(item: dict) -> dict:
    decisions = Counter()
    plans = [plan for plan in item.get("plans", []) if isinstance(plan, dict)] \
        if isinstance(item.get("plans"), list) else []
    for plan in plans:
        assessment = plan.get("assessment") if isinstance(plan.get("assessment"), dict) else {}
        decision = assessment.get("decision", "unassessed")
        decisions[decision] += 1
    return {"total": len(plans), **dict(sorted(decisions.items()))}


def _recorded_total(events: list[dict], field: str) -> float | int | None:
    values = [event[field] for event in events
              if isinstance(event, dict) and type(event.get(field)) in (int, float)]
    if not values:
        return None
    total = sum(values)
    return round(total, 2) if any(type(value) is float for value in values) else total


def build_portfolio(records: list[dict], *, stale_after_days: Any = 14) -> dict:
    if type(stale_after_days) is not int or not 1 <= stale_after_days <= 90:
        raise ValueError("stale_after_days must be an integer from 1 to 90")
    now_utc = datetime.now(timezone.utc)
    today = now_utc.date()
    targets = []
    for item in records:
        if not isinstance(item, dict):
            continue
        record_warnings = [
            f"{field} is not a list"
            for field in ("assets", "hunt_sessions", "plans", "outcomes")
            if field in item and not isinstance(item.get(field), list)
        ]
        profile = item.get("target_profile") if isinstance(item.get("target_profile"), dict) else {}
        gate = intake_gate(item)
        assets = [asset for asset in item.get("assets", []) if isinstance(asset, dict)] \
            if isinstance(item.get("assets"), list) else []
        documented_assets = sum(isinstance(asset.get("context"), dict) for asset in assets
                                if isinstance(asset, dict))
        asset_context_complete = bool(assets) and documented_assets == len(assets)
        sessions = [session for session in item.get("hunt_sessions", []) if isinstance(session, dict)] \
            if isinstance(item.get("hunt_sessions"), list) else []
        lanes = _lane_state(sessions)
        untested_lanes = [lane for lane, state in lanes.items() if state["status"] == "untested"]
        policy_age = _policy_age(item, now_utc)
        policy_refresh_due = policy_age is None or policy_age > stale_after_days
        revisit_text = ((sessions[-1].get("revisit_after") if sessions else "")
                        or profile.get("revisit_after") or "")
        revisit = _date(revisit_text)
        revisit_due = revisit is None or revisit <= today
        program_status = profile.get("program_status", "unconfigured")
        priority = profile.get("priority", "normal")
        outcomes = [outcome for outcome in item.get("outcomes", []) if isinstance(outcome, dict)] \
            if isinstance(item.get("outcomes"), list) else []
        latest_outcome = (outcomes or [{}])[-1].get("status")
        latest_activity = _latest([
            item.get("created_at"), item.get("updated_at"),
            *[session.get("recorded_at") for session in sessions],
        ])

        if record_warnings:
            next_action = "Repair the malformed local engagement record before selecting work"
            action_kind = "repair_record"
        elif not profile:
            next_action = "Complete the target profile before selecting a hunting lane"
            action_kind = "document_target"
        elif not asset_context_complete:
            next_action = "Document the current per-asset scope, reward state, and constraints"
            action_kind = "document_assets"
        elif not gate["complete"]:
            next_action = "Resolve the material program-intake gaps before target traffic"
            action_kind = "resolve_scope"
        elif policy_refresh_due:
            next_action = "Refresh the public program policy and review changes before testing"
            action_kind = "refresh_policy"
        elif program_status != "active":
            next_action = f"Target is {program_status}; preserve history and do not start a new pass"
            action_kind = "wait"
        elif not revisit_due:
            next_action = f"Wait until the recorded revisit date {revisit_text}"
            action_kind = "wait"
        else:
            recorded_next = (sessions[-1].get("next_action") if sessions else "") or profile.get("next_action")
            next_action = recorded_next or (
                f"Review the untested {untested_lanes[0]} lane" if untested_lanes
                else "Review target history and choose a materially new hypothesis"
            )
            action_kind = "hunt"

        measured_requests = [session.get("target_requests") for session in sessions
                             if session.get("request_count_state") == "measured"
                             and type(session.get("target_requests")) is int]
        unknown_request_sessions = sum(session.get("request_count_state") == "unknown"
                                       for session in sessions)
        human_minutes = sum(session.get("human_minutes", 0) for session in sessions
                            if type(session.get("human_minutes")) is int)
        paid_costs = round(sum(session.get("paid_cost_usd", 0.0) for session in sessions
                               if type(session.get("paid_cost_usd")) in (int, float)), 2)
        documentation_complete = bool(profile) and asset_context_complete and gate["complete"]
        target = {
            "engagement_id": item.get("id"),
            "name": item.get("name"),
            "kind": item.get("kind"),
            "platform": profile.get("platform"),
            "program_status": program_status,
            "priority": priority,
            "documentation_complete": documentation_complete,
            "record_warnings": record_warnings,
            "scope_complete": gate["complete"],
            "policy_reviewed_at": gate.get("reviewed_at"),
            "policy_age_days": policy_age,
            "policy_refresh_due": policy_refresh_due,
            "asset_count": len(assets),
            "documented_asset_count": documented_assets,
            "session_count": len(sessions),
            "candidate_counts": _candidate_counts(item),
            "lane_status": lanes,
            "untested_lanes": untested_lanes,
            "latest_outcome": latest_outcome,
            "outcome_financials": {
                "recorded_pending_awards_usd": _recorded_total(outcomes, "pending_award_usd"),
                "received_cash_usd": _recorded_total(outcomes, "received_cash_usd"),
                "paid_costs_usd": _recorded_total(outcomes, "paid_costs_usd"),
                "human_minutes": _recorded_total(outcomes, "human_minutes"),
                "interpretation": "Null means unrecorded; pending awards are not received cash",
            },
            "last_activity_at": latest_activity,
            "revisit_after": revisit_text or None,
            "revisit_due": revisit_due,
            "next_action_kind": action_kind,
            "next_action": next_action,
            "metrics": {
                "measured_target_requests": sum(measured_requests) if measured_requests else None,
                "unknown_request_count_sessions": unknown_request_sessions,
                "human_minutes": human_minutes if sessions else None,
                "paid_costs_usd": paid_costs if sessions else None,
            },
            "hunt_ready": (
                not record_warnings and documentation_complete and program_status == "active" and revisit_due
                and not policy_refresh_due
            ),
        }
        targets.append(target)

    def ranking(target: dict) -> tuple:
        status_rank = 0 if target["program_status"] == "active" else (
            1 if target["program_status"] in {"unconfigured", "paused"} else 2)
        priority_rank = PRIORITY_ORDER.get(target["priority"], 1)
        action_rank = {"repair_record": 0, "hunt": 1, "refresh_policy": 2, "resolve_scope": 3,
                       "document_assets": 4, "document_target": 5, "wait": 6}.get(
                           target["next_action_kind"], 6)
        return (status_rank, priority_rank, action_rank,
                target["last_activity_at"] or "", target["name"] or "")

    targets.sort(key=ranking)
    actionable = [target for target in targets
                  if target["program_status"] != "closed" and target["next_action_kind"] != "wait"]
    return {
        "generated_at": now_utc.isoformat(),
        "stale_after_days": stale_after_days,
        "target_count": len(targets),
        "active_target_count": sum(target["program_status"] == "active" for target in targets),
        "documented_target_count": sum(target["documentation_complete"] for target in targets),
        "hunt_ready_count": sum(target["hunt_ready"] for target in targets),
        "targets": targets,
        "next_target": actionable[0] if actionable else None,
        "privacy": "Portfolio omits assets, scope text, hypotheses, evidence, credentials, and account values",
        "boundary": (
            "This is an administrative resume queue. A hunt-ready target still requires current policy review "
            "and a separate exact authorization gate before traffic."
        ),
    }


def _artifact_events(engagement_dir: Path) -> list[dict]:
    events = []
    patterns = [
        ("surface-inventory", "*.json", "surface_import"),
        ("template-intelligence", "*.json", "template_intelligence"),
    ]
    for folder, pattern, event_type in patterns:
        for path in sorted((engagement_dir / folder).glob(pattern))[:200]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict):
                continue
            events.append({
                "timestamp": value.get("created_at"),
                "type": event_type,
                "title": (
                    (value.get("template") or {}).get("name")
                    if event_type == "template_intelligence"
                    else f"{value.get('format', 'surface')} route inventory"
                ),
                "reference": value.get("import_id") or value.get("inventory_id"),
                "details": {
                    "asset": value.get("asset"),
                    "source_sha256": (value.get("source") or {}).get("sha256")
                    or value.get("source_sha256"),
                    "route_count": value.get("route_count"),
                    "claim_boundary": value.get("claim_boundary"),
                },
            })
    for path, event_type, title in [
        *[(value, "evidence_manifest", "Evidence manifest saved")
          for value in sorted(engagement_dir.glob("evidence-manifest-*.json"))[:200]],
        *[(value, "report_draft", "Report draft saved")
          for value in sorted(engagement_dir.glob("report-draft-*.md"))[:200]],
    ]:
        try:
            stat_result = path.stat()
            if path.is_symlink() or not path.is_file() or stat_result.st_size > 1_048_576:
                continue
            modified = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc).isoformat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        reference = path.stem.removeprefix("evidence-manifest-").removeprefix("report-draft-")
        events.append({
            "timestamp": modified,
            "type": event_type,
            "title": title,
            "reference": reference,
            "details": {"file": path.name, "sha256": digest},
        })
    return events


def target_history(item: dict, engagement_dir: Path, *, include_details: Any = False,
                   offset: Any = 0, limit: Any = 50) -> dict:
    if type(include_details) is not bool:
        raise ValueError("include_details must be true or false")
    if type(offset) is not int or not 0 <= offset <= 100_000:
        raise ValueError("offset must be an integer from 0 to 100000")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("limit must be an integer from 1 to 200")
    events = [{
        "timestamp": item.get("created_at"), "type": "engagement_created",
        "title": item.get("name"), "reference": item.get("id"),
        "details": {"kind": item.get("kind")},
    }]

    previous_profile: dict = {}
    for revision in item.get("target_profile_history", []):
        snapshot = revision.get("snapshot") if isinstance(revision.get("snapshot"), dict) else {}
        events.append({
            "timestamp": revision.get("recorded_at"), "type": "target_profile_revision",
            "title": "Target profile updated", "reference": revision.get("content_sha256"),
            "details": {
                "changed_fields": _changed_fields(previous_profile, snapshot),
                **({"snapshot": snapshot} if include_details else {}),
            },
        })
        previous_profile = snapshot

    previous_intake: dict = {}
    for revision in item.get("intake_history", []):
        snapshot = revision.get("snapshot") if isinstance(revision.get("snapshot"), dict) else {}
        events.append({
            "timestamp": revision.get("reviewed_at"), "type": "scope_revision",
            "title": "Program intake reviewed", "reference": revision.get("content_sha256"),
            "details": {
                "changed_fields": _changed_fields(previous_intake, snapshot, INTAKE_FIELDS),
                **({"snapshot": snapshot} if include_details else {}),
            },
        })
        previous_intake = snapshot

    for asset in item.get("assets", []):
        events.append({
            "timestamp": asset.get("added_at"), "type": "asset_added",
            "title": asset.get("value"), "reference": None, "details": {},
        })
        previous_context: dict = {}
        for revision in asset.get("context_history", []):
            snapshot = revision.get("snapshot") if isinstance(revision.get("snapshot"), dict) else {}
            events.append({
                "timestamp": revision.get("reviewed_at"), "type": "asset_scope_revision",
                "title": asset.get("value"), "reference": revision.get("content_sha256"),
                "details": {
                    "changed_fields": _changed_fields(previous_context, snapshot),
                    **({"snapshot": snapshot} if include_details else {}),
                },
            })
            previous_context = snapshot

    for plan in item.get("plans", []):
        events.append({
            "timestamp": plan.get("created_at"), "type": "candidate_created",
            "title": plan.get("title") or plan.get("hypothesis"), "reference": plan.get("id"),
            "details": ({"plan": plan} if include_details else {"status": plan.get("status")}),
        })
        assessment = plan.get("assessment") if isinstance(plan.get("assessment"), dict) else None
        if assessment:
            events.append({
                "timestamp": assessment.get("assessed_at"), "type": "candidate_assessed",
                "title": f"Candidate decision: {assessment.get('decision')}",
                "reference": plan.get("id"),
                "details": assessment if include_details else {
                    "decision": assessment.get("decision"),
                    "duplicate_risk": assessment.get("duplicate_risk"),
                    "proof_strength": assessment.get("proof_strength"),
                },
            })
        contract = plan.get("validation_contract") if isinstance(plan.get("validation_contract"), dict) else None
        if contract:
            events.append({
                "timestamp": contract.get("recorded_at"), "type": "validation_contract",
                "title": "Candidate validation contract recorded", "reference": plan.get("id"),
                "details": contract if include_details else {
                    "environment": contract.get("environment"),
                    "max_requests": contract.get("max_requests"),
                },
            })

    for session in item.get("hunt_sessions", []):
        events.append({
            "timestamp": session.get("recorded_at"), "type": "hunt_session",
            "title": f"{session.get('lane')}: {session.get('status')}",
            "reference": session.get("id"),
            "details": session if include_details else {
                "environment": session.get("environment"),
                "summary": session.get("summary"),
                "candidate_ids": session.get("candidate_ids"),
                "next_action": session.get("next_action"),
                "human_minutes": session.get("human_minutes"),
                "request_count_state": session.get("request_count_state"),
                "target_requests": session.get("target_requests"),
            },
        })

    for observation in item.get("observations", []):
        events.append({
            "timestamp": observation.get("created_at"), "type": "observation",
            "title": observation.get("summary"), "reference": observation.get("plan_id"),
            "details": observation if include_details else {
                "classification": observation.get("classification"),
                "evidence_ref_count": len(observation.get("evidence_refs", [])),
            },
        })
    for outcome in item.get("outcomes", []):
        details = {"status": outcome.get("status")}
        for field in ("pending_award_usd", "received_cash_usd", "paid_costs_usd", "human_minutes"):
            if field in outcome:
                details[field] = outcome[field]
        if include_details:
            details = outcome
        events.append({
            "timestamp": outcome.get("recorded_at"), "type": "outcome",
            "title": f"Submission state: {outcome.get('status')}",
            "reference": outcome.get("plan_id"), "details": details,
        })
    for run in item.get("runs", []):
        events.append({
            "timestamp": run.get("created_at"), "type": "local_run",
            "title": run.get("status") or run.get("classification") or "Local run",
            "reference": run.get("plan_id"),
            "details": run if include_details else {
                "environment": run.get("environment"), "requests_sent": run.get("requests_sent")},
        })
    events.extend(_artifact_events(engagement_dir))
    events = [event for event in events if _time(event.get("timestamp")) is not None]
    events.sort(key=lambda event: (_time(event["timestamp"]), event["type"]), reverse=True)
    page = events[offset:offset + limit]
    return {
        "engagement_id": item.get("id"),
        "name": item.get("name"),
        "event_count": len(events),
        "offset": offset,
        "returned": len(page),
        "has_more": offset + len(page) < len(events),
        "events": page,
        "privacy": (
            "History contains durable planning facts and sanitized summaries. Credentials, cookies, tokens, "
            "raw response bodies, and customer data must never be recorded."
        ),
    }
