"""Deterministic agent workflow, triage review, and evidence integrity helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import hunt_portfolio
from workbench import PLAN_DETAIL_FIELDS, UNRESOLVED, intake_gate, save_json


MAX_EVIDENCE_BYTES = 50 * 1024 * 1024
ASSESSMENT_ENUMS = {
    "duplicate_risk": {"low", "medium", "high", "unknown"},
    "setup_cost": {"none", "low", "medium", "high"},
    "proof_strength": {"clear_end_to_end", "partial", "source_only"},
    "decision": {"pursue", "hold", "stop"},
}
ASSESSMENT_TEXT = ("attacker_motive", "plausible_payoff", "duplicate_risk_reason", "proof_path")


def _find_plan(item: dict, plan_id: str) -> dict:
    plan = next((entry for entry in item.get("plans", []) if entry.get("id") == plan_id), None)
    if not plan:
        raise ValueError("Plan not found")
    return plan


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_evidence(engagement_dir: Path, references: list[str]) -> list[dict]:
    result = []
    base = engagement_dir.resolve()
    for reference in references:
        record: dict[str, Any] = {"reference": reference}
        if not isinstance(reference, str) or not reference or "\\" in reference:
            record.update(state="invalid", reason="Use a non-empty forward-slash relative path")
            result.append(record)
            continue
        relative = PurePosixPath(reference)
        if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
            record.update(state="invalid", reason="Evidence reference must stay inside the engagement directory")
            result.append(record)
            continue
        path = (base / Path(*relative.parts)).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            record.update(state="invalid", reason="Evidence reference escapes the engagement directory")
            result.append(record)
            continue
        if path.is_symlink():
            record.update(state="invalid", reason="Symbolic-link evidence is not accepted")
        elif not path.exists():
            record.update(state="missing")
        elif not path.is_file():
            record.update(state="invalid", reason="Evidence reference is not a regular file")
        else:
            size = path.stat().st_size
            if size > MAX_EVIDENCE_BYTES:
                record.update(state="invalid", reason="Evidence file exceeds the 50 MiB verification ceiling",
                              bytes=size)
            else:
                record.update(state="verified", bytes=size, sha256=_sha256(path))
        result.append(record)
    return result


def review_candidate(item: dict, plan_id: str, engagement_dir: Path) -> dict:
    plan = _find_plan(item, plan_id)
    gate = intake_gate(item)
    observations = [entry for entry in item.get("observations", []) if entry.get("plan_id") == plan_id]
    observed = [entry for entry in observations if entry.get("classification") == "observed"]
    latest = observed[-1] if observed else None
    outcomes = [entry for entry in item.get("outcomes", []) if entry.get("plan_id") == plan_id]
    assessment = plan.get("assessment") if isinstance(plan.get("assessment"), dict) else None

    gaps = []
    risks = []
    if not gate["complete"]:
        gaps.append("complete_scope_intake")
        risks.append({"level": "high", "reason": "Current material scope fields are incomplete or unresolved"})
    if assessment is None:
        gaps.append("candidate_assessment")
        risks.append({"level": "medium", "reason": "Attacker motive, payoff, duplicate risk, cost, and proof path are unassessed"})
    else:
        if assessment["duplicate_risk"] in ("high", "unknown"):
            risks.append({"level": "medium", "reason":
                          f"Duplicate risk is {assessment['duplicate_risk']}: {assessment['duplicate_risk_reason']}"})
        if assessment["proof_strength"] == "source_only":
            risks.append({"level": "high", "reason": "The proposed proof is source-only"})
        if assessment["decision"] != "pursue":
            risks.append({"level": "medium", "reason": f"Candidate decision is {assessment['decision']}"})
    for field in ("title", "hypothesis", "impact", *PLAN_DETAIL_FIELDS):
        value = plan.get(field)
        if not isinstance(value, str) or not value.strip():
            gaps.append(field)
    for field in ("affected_version", "prior_art_result"):
        value = plan.get(field)
        if isinstance(value, str) and UNRESOLVED.match(value.strip()):
            gaps.append(f"resolved_{field}")
            risks.append({"level": "medium", "reason": f"{field.replace('_', ' ')} remains unresolved"})
    evidence = []
    if latest is None:
        gaps.append("observed_evidence")
        if observations:
            risks.append({"level": "high", "reason": "Only derived or unverified observations are recorded"})
        else:
            risks.append({"level": "high", "reason": "No observed result is recorded"})
    else:
        for field in ("summary", "reproduction", "negative_control_result", "independent_impact_check"):
            if not isinstance(latest.get(field), str) or not latest[field].strip():
                gaps.append(field)
        references = latest.get("evidence_refs") if isinstance(latest.get("evidence_refs"), list) else []
        if not references:
            gaps.append("evidence_refs")
        evidence = inspect_evidence(engagement_dir, references)
        bad = [record for record in evidence if record["state"] != "verified"]
        if bad:
            gaps.append("verified_evidence_files")
            risks.append({"level": "high", "reason": "One or more evidence references are missing or invalid"})

    latest_outcome = outcomes[-1] if outcomes else None
    report_ready = not gaps
    if latest_outcome and latest_outcome["status"] in {"rejected", "duplicate", "withdrawn", "paid"}:
        action = "No testing action; the recorded outcome is terminal"
    elif latest_outcome and latest_outcome["status"] in {"submitted", "triaged"}:
        action = "Wait for a material triage update and keep the submission state unchanged"
    elif latest_outcome and latest_outcome["status"] == "needs_more_info":
        action = "Address only the triager's recorded request with concise reproducible evidence"
    elif assessment and assessment["decision"] == "stop":
        action = "Stop this candidate and preserve the reason"
    elif assessment and assessment["decision"] == "hold":
        action = "Keep this candidate on hold until its recorded blocker changes"
    elif gaps:
        action = f"Resolve the first reportability gap: {gaps[0]}"
    else:
        action = "Build the concise report and obtain user review before submission"
    return {
        "engagement_id": item["id"], "plan_id": plan_id, "title": plan.get("title"),
        "scope_gate": gate, "assessment": assessment, "observation_count": len(observations),
        "latest_observed_id": latest.get("id") if latest else None,
        "evidence": evidence, "latest_outcome": latest_outcome,
        "report_ready": report_ready, "gaps": list(dict.fromkeys(gaps)),
        "triage_risks": risks, "recommended_action": action,
        "interpretation": "Deterministic completeness review, not an acceptance or severity prediction",
    }


def rank_candidates(records: list[dict], data_dir: Path, engagement_id: str = "") -> dict:
    ranked = []
    for item in records:
        if engagement_id and item.get("id") != engagement_id:
            continue
        for plan in item.get("plans", []):
            assessment = plan.get("assessment") if isinstance(plan.get("assessment"), dict) else None
            review = review_candidate(item, plan["id"], data_dir / item["id"])
            score = 0
            factors = []
            if review["scope_gate"]["complete"]:
                score += 25
                factors.append("+25 complete scope intake")
            else:
                factors.append("+0 incomplete scope intake")
            if assessment:
                duplicate = {"low": 20, "medium": 10, "high": -10, "unknown": 0}[assessment["duplicate_risk"]]
                setup = {"none": 15, "low": 10, "medium": 5, "high": -5}[assessment["setup_cost"]]
                proof = {"clear_end_to_end": 25, "partial": 10, "source_only": -20}[assessment["proof_strength"]]
                decision = {"pursue": 5, "hold": -20, "stop": -100}[assessment["decision"]]
                requests = 10 if assessment["expected_requests"] <= 5 else (
                    5 if assessment["expected_requests"] <= 20 else 0)
                for label, points in (("duplicate risk", duplicate), ("setup cost", setup),
                                      ("proof strength", proof), ("decision", decision),
                                      ("expected request count", requests)):
                    score += points
                    factors.append(f"{points:+d} {label}")
            else:
                factors.append("+0 candidate assessment missing")
            if review["latest_observed_id"]:
                score += 10
                factors.append("+10 observed result recorded")
            ranked.append({
                "engagement_id": item["id"], "engagement_name": item.get("name"),
                "plan_id": plan["id"], "title": plan.get("title"), "score": score,
                "factors": factors, "report_ready": review["report_ready"],
                "recommended_action": review["recommended_action"],
            })
    ranked.sort(key=lambda entry: (-entry["score"], entry["engagement_id"], entry["plan_id"]))
    return {
        "candidates": ranked,
        "interpretation": (
            "Transparent workflow priority only. Score is not vulnerability severity, acceptance probability, "
            "or authorization to test."
        ),
    }


def work_queue(records: list[dict], data_dir: Path, engagement_id: str = "") -> dict:
    actions = []
    waiting = []
    portfolio = hunt_portfolio.build_portfolio(records)
    portfolio_targets = {entry["engagement_id"]: entry for entry in portfolio["targets"]}
    for item in records:
        if engagement_id and item.get("id") != engagement_id:
            continue
        target = portfolio_targets.get(item.get("id"), {})
        action_kind = target.get("next_action_kind")
        if action_kind == "wait":
            waiting.append({"engagement_id": item["id"], "plan_id": None,
                            "status": target.get("program_status", "paused"),
                            "reason": target.get("next_action")})
            continue
        if action_kind in {"repair_record", "document_target", "document_assets",
                           "resolve_scope", "refresh_policy"}:
            actions.append({"priority": 1, "engagement_id": item["id"], "plan_id": None,
                            "action": target.get("next_action"), "reason": action_kind})
            continue
        if not item.get("plans"):
            actions.append({"priority": 2, "engagement_id": item["id"], "plan_id": None,
                            "action": "Research and record one bounded impact-bearing candidate",
                            "reason": "No candidate is recorded"})
            continue
        for plan in item["plans"]:
            review = review_candidate(item, plan["id"], data_dir / item["id"])
            outcome = review["latest_outcome"]
            if outcome and outcome["status"] in {"submitted", "triaged"}:
                waiting.append({"engagement_id": item["id"], "plan_id": plan["id"],
                                "status": outcome["status"], "reason": review["recommended_action"]})
                continue
            if outcome and outcome["status"] in {"rejected", "duplicate", "withdrawn", "paid"}:
                continue
            assessment = review["assessment"]
            if assessment and assessment["decision"] in {"hold", "stop"}:
                waiting.append({"engagement_id": item["id"], "plan_id": plan["id"],
                                "status": assessment["decision"], "reason": review["recommended_action"]})
                continue
            priority = 1 if outcome and outcome["status"] == "needs_more_info" else (
                3 if review["report_ready"] else 2)
            actions.append({"priority": priority, "engagement_id": item["id"], "plan_id": plan["id"],
                            "action": review["recommended_action"], "reason": review["gaps"]})
    actions.sort(key=lambda entry: (entry["priority"], entry["engagement_id"], entry["plan_id"] or ""))
    return {
        "actions": actions, "waiting": waiting,
        "next_action": actions[0] if actions else None,
        "interpretation": "One deterministic queue from recorded facts; unknown states remain unknown",
    }


def build_evidence_manifest(item: dict, plan_id: str, engagement_dir: Path, save: bool = False) -> dict:
    plan = _find_plan(item, plan_id)
    review = review_candidate(item, plan_id, engagement_dir)
    observations = [entry for entry in item.get("observations", [])
                    if entry.get("plan_id") == plan_id and entry.get("classification") == "observed"]
    latest = observations[-1] if observations else None
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engagement_id": item["id"],
        "plan": {key: plan.get(key) for key in ("id", "title", "hypothesis", "impact", "asset",
                                                        "minimum_access", "negative_control", "affected_version",
                                                        "prior_art_result", "remediation",
                                                        "validation_contract")},
        "assessment": review["assessment"],
        "scope_gate": review["scope_gate"],
        "observation": latest,
        "evidence": review["evidence"],
        "complete": review["report_ready"],
        "gaps": review["gaps"],
        "claim_boundary": "Manifest verifies local files and recorded fields; it does not prove target impact",
    }
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    result = {"manifest": manifest, "saved_to": None}
    if save:
        if not manifest["complete"]:
            raise ValueError("Evidence manifest is incomplete: " + ", ".join(manifest["gaps"]))
        path = engagement_dir / f"evidence-manifest-{plan_id}.json"
        save_json(path, manifest)
        result["saved_to"] = str(path)
    return result


def agent_brief(records: list[dict], data_dir: Path, engagement_id: str = "", plan_id: str = "") -> dict:
    if plan_id and not engagement_id:
        raise ValueError("plan_id requires engagement_id")
    selected = None
    if engagement_id:
        selected = next((item for item in records if item.get("id") == engagement_id), None)
        if selected is None:
            raise ValueError("Engagement not found")
    queue = work_queue(records, data_dir, engagement_id)
    ranking = rank_candidates(records, data_dir, engagement_id)
    context = None
    review = None
    if selected:
        profile = selected.get("target_profile") if isinstance(selected.get("target_profile"), dict) else None
        sessions = selected.get("hunt_sessions") if isinstance(selected.get("hunt_sessions"), list) else []
        assets = selected.get("assets") if isinstance(selected.get("assets"), list) else []
        context = {
            "id": selected["id"], "name": selected.get("name"), "kind": selected.get("kind"),
            "assets": [entry.get("value") for entry in assets],
            "documented_asset_count": sum(isinstance(entry.get("context"), dict) for entry in assets),
            "scope_gate": intake_gate(selected),
            "target_profile": profile,
            "hunt_session_count": len(sessions),
            "latest_hunt_session": sessions[-1] if sessions else None,
            "candidate_count": len(selected.get("plans", [])),
            "observation_count": len(selected.get("observations", [])),
            "latest_outcome": (selected.get("outcomes") or [{}])[-1].get("status"),
        }
        if plan_id:
            review = review_candidate(selected, plan_id, data_dir / selected["id"])
    return {
        "profile": "Daybreak Blue defensive bug-bounty workflow",
        "engagement_count": len(records),
        "selected_engagement": context,
        "selected_candidate_review": review,
        "next_action": queue["next_action"],
        "waiting": queue["waiting"],
        "top_candidates": ranking["candidates"][:5],
        "phase_tools": [
            {"phase": "scope", "tools": ["bountybreak_get_engagement", "bountybreak_set_intake"]},
            {"phase": "research", "tools": ["bountybreak_research_cve", "bountybreak_search_exploitdb",
                                               "bountybreak_query_osv_package"]},
            {"phase": "selection", "tools": ["bountybreak_add_plan", "bountybreak_set_candidate_assessment",
                                                "bountybreak_rank_candidates"]},
            {"phase": "local validation", "tools": ["bountybreak_simulate_hypothesis",
                                                       "bountybreak_run_synthetic_lab"]},
            {"phase": "evidence", "tools": ["bountybreak_record_observation",
                                               "bountybreak_review_candidate",
                                               "bountybreak_build_evidence_manifest"]},
            {"phase": "report and outcome", "tools": ["bountybreak_build_report",
                                                         "bountybreak_record_outcome"]},
        ],
        "execution_boundary": (
            "Daybreak Blue is used for defensive discovery, triage, source review, synthetic validation, "
            "evidence, and remediation. Live target traffic requires a separate current authorization gate "
            "and executor; BountyBreak does not infer permission or expose a generic shell."
        ),
    }
