"""ScopeRook MCP profile optimized for OpenAI Daybreak Blue.

This stable entry point extends the core ScopeRook planning server with a
deterministic agent queue, evidence verification, reviewed synthetic labs, and
a registry that points an agent to separately installed security tools.  It
never launches those tools or sends target traffic.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import agent_workflow
import hunt_portfolio
import integration_catalog
import nuclei_template_import
import scoperook_mcp as core
from sandbox_runner import LabRunner
import surface_import
from tool_router import INTERFACES, OPERATION_CLASSES, OUTPUT_FORMATS, PHASES, ToolRegistry
from workbench import (
    ACCOUNT_STATES, ASSET_REWARD_STATES, ASSET_SCOPE_STATES, ASSET_TEST_STATES,
    ASSET_TYPES, COVERAGE_LANES, HUNT_SESSION_STATES, REQUEST_COUNT_STATES,
    TARGET_PLATFORMS, TARGET_PRIORITIES, TARGET_STATUSES, VALIDATION_ENVIRONMENTS,
)


ROOT = Path(__file__).resolve().parent
PROTOCOL = core.PROTOCOL
SERVER_VERSION = "0.8.1"
SERVER_NAME = "scoperook-daybreak"


def _tool(name: str, description: str, properties: dict, required: list[str], *, read_only: bool) -> dict:
    annotations = {"readOnlyHint": read_only, "destructiveHint": False, "openWorldHint": False}
    if not read_only:
        annotations["idempotentHint"] = False
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object", "properties": properties, "required": required,
            "additionalProperties": False,
        },
        "annotations": annotations,
    }


ASSESSMENT_PROPERTIES = {
    "engagement_id": {"type": "string", "maxLength": 64},
    "plan_id": {"type": "string", "maxLength": 12},
    "attacker_motive": {"type": "string", "minLength": 1, "maxLength": 1000},
    "plausible_payoff": {"type": "string", "minLength": 1, "maxLength": 1000},
    "duplicate_risk": {"type": "string", "enum": ["low", "medium", "high", "unknown"]},
    "duplicate_risk_reason": {"type": "string", "minLength": 1, "maxLength": 1000},
    "setup_cost": {"type": "string", "enum": ["none", "low", "medium", "high"]},
    "proof_strength": {"type": "string", "enum": ["clear_end_to_end", "partial", "source_only"]},
    "proof_path": {"type": "string", "minLength": 1, "maxLength": 1000},
    "expected_requests": {"type": "integer", "minimum": 0, "maximum": 1000},
    "decision": {"type": "string", "enum": ["pursue", "hold", "stop"]},
}

VALIDATION_PROPERTIES = {
    "engagement_id": {"type": "string", "maxLength": 64},
    "plan_id": {"type": "string", "maxLength": 12},
    "environment": {"type": "string", "enum": sorted(VALIDATION_ENVIRONMENTS)},
    "candidate_actor": {"type": "string", "minLength": 1, "maxLength": 300},
    "control_actor": {"type": "string", "minLength": 1, "maxLength": 300},
    "starting_state": {"type": "string", "minLength": 1, "maxLength": 500},
    "sequence_steps": {"type": "array", "minItems": 1, "maxItems": 12,
                       "items": {"type": "string", "minLength": 1, "maxLength": 300}},
    "expected_secure_behavior": {"type": "string", "minLength": 1, "maxLength": 500},
    "suspected_behavior": {"type": "string", "minLength": 1, "maxLength": 500},
    "negative_control": {"type": "string", "minLength": 1, "maxLength": 500},
    "independent_impact_check": {"type": "string", "minLength": 1, "maxLength": 500},
    "cleanup": {"type": "string", "minLength": 1, "maxLength": 500},
    "max_requests": {"type": "integer", "minimum": 0, "maximum": 100},
}

TARGET_PROFILE_PROPERTIES = {
    "engagement_id": {"type": "string", "maxLength": 64},
    "platform": {"type": "string", "enum": sorted(TARGET_PLATFORMS)},
    "program_status": {"type": "string", "enum": sorted(TARGET_STATUSES)},
    "priority": {"type": "string", "enum": sorted(TARGET_PRIORITIES)},
    "attacker_payoffs": {"type": "array", "minItems": 1, "maxItems": 8,
                         "items": {"type": "string", "minLength": 1, "maxLength": 200}},
    "technologies": {"type": "array", "maxItems": 30,
                     "items": {"type": "string", "minLength": 1, "maxLength": 120}},
    "account_state": {"type": "string", "enum": sorted(ACCOUNT_STATES)},
    "account_reference": {"type": "string", "maxLength": 80,
                          "pattern": "^(?:|[A-Za-z0-9][A-Za-z0-9._ -]{0,79})$"},
    "research_strategy": {"type": "string", "minLength": 1, "maxLength": 1000},
    "next_action": {"type": "string", "minLength": 1, "maxLength": 500},
    "revisit_after": {"type": "string", "pattern": "^(?:|[0-9]{4}-[0-9]{2}-[0-9]{2})$"},
    "tags": {"type": "array", "maxItems": 20,
             "items": {"type": "string", "minLength": 1, "maxLength": 80}},
}

ASSET_CONTEXT_PROPERTIES = {
    "engagement_id": {"type": "string", "maxLength": 64},
    "asset": {"type": "string", "minLength": 1, "maxLength": 300},
    "asset_type": {"type": "string", "enum": sorted(ASSET_TYPES)},
    "scope_status": {"type": "string", "enum": sorted(ASSET_SCOPE_STATES)},
    "reward_status": {"type": "string", "enum": sorted(ASSET_REWARD_STATES)},
    "test_status": {"type": "string", "enum": sorted(ASSET_TEST_STATES)},
    "constraints": {"type": "string", "minLength": 1, "maxLength": 1000},
    "notes": {"type": "string", "maxLength": 1000},
}

HUNT_SESSION_PROPERTIES = {
    "engagement_id": {"type": "string", "maxLength": 64},
    "lane": {"type": "string", "enum": sorted(COVERAGE_LANES)},
    "status": {"type": "string", "enum": sorted(HUNT_SESSION_STATES)},
    "environment": {"type": "string", "enum": sorted(VALIDATION_ENVIRONMENTS)},
    "summary": {"type": "string", "minLength": 1, "maxLength": 1500},
    "candidate_ids": {"type": "array", "maxItems": 20,
                      "items": {"type": "string", "minLength": 1, "maxLength": 12}},
    "source_refs": {"type": "array", "maxItems": 20,
                    "items": {"type": "string", "minLength": 1, "maxLength": 300}},
    "request_count_state": {"type": "string", "enum": sorted(REQUEST_COUNT_STATES)},
    "target_requests": {"type": "integer", "minimum": 0, "maximum": 100000},
    "human_minutes": {"type": "integer", "minimum": 0, "maximum": 100000},
    "paid_cost_usd": {"type": "number", "minimum": 0, "maximum": 1000000},
    "next_action": {"type": "string", "minLength": 1, "maxLength": 500},
    "revisit_after": {"type": "string", "pattern": "^(?:|[0-9]{4}-[0-9]{2}-[0-9]{2})$"},
}

REGISTRY_PROPERTIES = {
    "tool_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"},
    "display_name": {"type": "string", "minLength": 1, "maxLength": 100},
    "version": {"type": "string", "maxLength": 80},
    "interface": {"type": "string", "enum": sorted(INTERFACES)},
    "phases": {"type": "array", "minItems": 1, "maxItems": 20,
               "items": {"type": "string", "enum": sorted(PHASES)}},
    "capabilities": {"type": "array", "minItems": 1, "maxItems": 20,
                     "items": {"type": "string", "minLength": 1, "maxLength": 80}},
    "operation_classes": {"type": "array", "minItems": 1, "maxItems": 4,
                          "items": {"type": "string", "enum": sorted(OPERATION_CLASSES)}},
    "output_formats": {"type": "array", "minItems": 1, "maxItems": 7,
                       "items": {"type": "string", "enum": sorted(OUTPUT_FORMATS)}},
    "local_path": {"type": "string", "maxLength": 500},
    "mcp_server": {"type": "string", "maxLength": 100},
    "mcp_tools": {"type": "array", "maxItems": 30,
                  "items": {"type": "string", "minLength": 1, "maxLength": 120}},
    "declared_available": {"type": "boolean"},
    "constraints": {"type": "string", "minLength": 1, "maxLength": 1000},
    "notes": {"type": "string", "maxLength": 1000},
}

EXTRA_TOOLS = [
    _tool(
        "scoperook_compare_intake",
        "Compare the two latest dated program-intake snapshots by content hash and changed field names. It never widens scope automatically.",
        {"engagement_id": {"type": "string", "maxLength": 64}},
        ["engagement_id"], read_only=True,
    ),
    _tool(
        "scoperook_set_candidate_assessment",
        "Record attacker motive, concrete payoff, duplicate risk, setup cost, proof path, request estimate, and a pursue/hold/stop decision. This is a transparent planning assessment, not an acceptance prediction.",
        ASSESSMENT_PROPERTIES, list(ASSESSMENT_PROPERTIES), read_only=False,
    ),
    _tool(
        "scoperook_set_validation_contract",
        "Record an identity, state, sequence, control, cleanup, and request-bounded proof contract for one candidate. This plans verification but never runs it or grants authorization.",
        VALIDATION_PROPERTIES, list(VALIDATION_PROPERTIES), read_only=False,
    ),
    _tool(
        "scoperook_set_target_profile",
        "Create or update the durable non-secret target profile used to resume continuous bounty work: platform, status, priority, attacker payoffs, technologies, account state, strategy, next action, and revisit date.",
        TARGET_PROFILE_PROPERTIES, list(TARGET_PROFILE_PROPERTIES), read_only=False,
    ),
    _tool(
        "scoperook_set_asset_context",
        "Document the current scope, reward state, test state, type, and constraints for one exact recorded asset. History is preserved and the record never grants authorization.",
        ASSET_CONTEXT_PROPERTIES, list(ASSET_CONTEXT_PROPERTIES), read_only=False,
    ),
    _tool(
        "scoperook_record_hunt_session",
        "Append one sanitized hunting pass with coverage lane, environment, result state, candidate links, request accounting, time, cost, next action, and revisit date.",
        HUNT_SESSION_PROPERTIES, list(HUNT_SESSION_PROPERTIES), read_only=False,
    ),
    _tool(
        "scoperook_hunt_portfolio",
        "Return the compact cross-target resume queue with documentation, policy freshness, lane coverage, candidate states, measured effort, and one deterministic next target. Assets and scope text are omitted.",
        {"stale_after_days": {"type": "integer", "minimum": 1, "maximum": 90}},
        [], read_only=True,
    ),
    _tool(
        "scoperook_get_target_history",
        "Return a paginated newest-first timeline for one target across profile and scope revisions, assets, hunting passes, candidates, controls, evidence, artifacts, and outcomes.",
        {
            "engagement_id": {"type": "string", "maxLength": 64},
            "include_details": {"type": "boolean"},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        ["engagement_id"], read_only=True,
    ),
    _tool(
        "scoperook_agent_brief",
        "Return a compact Daybreak Blue brief with one next action, waiting work, candidate ranking, evidence state, and phase tools.",
        {"engagement_id": {"type": "string", "maxLength": 64},
         "plan_id": {"type": "string", "maxLength": 12}}, [], read_only=True,
    ),
    _tool(
        "scoperook_work_queue",
        "Return the deterministic next-action queue from recorded scope, candidates, evidence, and outcomes.",
        {"engagement_id": {"type": "string", "maxLength": 64}}, [], read_only=True,
    ),
    _tool(
        "scoperook_rank_candidates",
        "Rank candidates using explicit scope, duplicate-risk, setup-cost, proof-strength, request-count, and evidence factors. The score is not severity or acceptance probability.",
        {"engagement_id": {"type": "string", "maxLength": 64}}, [], read_only=True,
    ),
    _tool(
        "scoperook_review_candidate",
        "Review one candidate for scope, proof, negative control, impact check, prior art, local evidence integrity, and reportability gaps.",
        {"engagement_id": {"type": "string", "maxLength": 64},
         "plan_id": {"type": "string", "maxLength": 12}},
        ["engagement_id", "plan_id"], read_only=True,
    ),
    _tool(
        "scoperook_build_evidence_manifest",
        "Hash and summarize the latest observed evidence for one candidate. Saving fails closed unless the full reportability review passes.",
        {"engagement_id": {"type": "string", "maxLength": 64},
         "plan_id": {"type": "string", "maxLength": 12}, "save": {"type": "boolean"}},
        ["engagement_id", "plan_id"], read_only=False,
    ),
    _tool(
        "scoperook_list_synthetic_labs",
        "List reviewed bundled lab manifests and the explicitly configured WSL isolation backend. No lab is run.",
        {}, [], read_only=True,
    ),
    _tool(
        "scoperook_run_synthetic_lab",
        "Run every candidate and negative-control case from one reviewed bundled synthetic lab. Accepts no code, command, path, package, image, credential, or network destination.",
        {"lab_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"}},
        ["lab_id"], read_only=False,
    ),
    _tool(
        "scoperook_register_tool_capability",
        "Register or update a local handoff reference for an already installed security tool. ScopeRook records capabilities and constraints but never launches it.",
        REGISTRY_PROPERTIES,
        ["tool_id", "display_name", "interface", "phases", "capabilities", "operation_classes",
         "output_formats", "constraints"], read_only=False,
    ),
    _tool(
        "scoperook_list_tool_capabilities",
        "List registered existing tools, their interfaces, verified local-path availability, output contracts, and constraints. No tool is launched.",
        {}, [], read_only=True,
    ),
    _tool(
        "scoperook_route_existing_tools",
        "Choose an installed tool for a Daybreak workflow phase and return a bounded handoff. Target-facing choices remain blocked on a separate exact executor preflight.",
        {
            "phase": {"type": "string", "enum": sorted(PHASES)},
            "required_capabilities": {"type": "array", "minItems": 1, "maxItems": 10,
                                      "items": {"type": "string", "minLength": 1, "maxLength": 80}},
            "operation_class": {"type": "string", "enum": sorted(OPERATION_CLASSES)},
            "engagement_id": {"type": "string", "maxLength": 64},
            "plan_id": {"type": "string", "maxLength": 12},
        },
        ["phase", "required_capabilities", "operation_class"], read_only=True,
    ),
    _tool(
        "scoperook_search_integration_catalog",
        "Search product-maintained routing guidance for optional security tools. Results never claim installation or authorization and never download or launch software.",
        {
            "query": {"type": "string", "maxLength": 120},
            "phase": {"type": "string", "maxLength": 80},
            "operation_class": {"type": "string", "maxLength": 80},
            "limit": {"type": "integer", "minimum": 1, "maximum": 25},
        },
        [], read_only=True,
    ),
    _tool(
        "scoperook_import_nuclei_template",
        "Import a local reviewed ProjectDiscovery Nuclei YAML template as sanitized prior-art metadata. Records a hash, immutable upstream declaration, protocols, request-risk flags, and candidate research gates; never executes or validates the template.",
        {
            "engagement_id": {"type": "string", "maxLength": 64},
            "source_reference": {"type": "string", "minLength": 1, "maxLength": 300},
            "asset": {"type": "string", "minLength": 1, "maxLength": 300},
            "upstream_commit": {"type": "string", "pattern": "^[0-9a-fA-F]{40}$"},
            "upstream_path": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        ["engagement_id", "source_reference", "asset", "upstream_commit", "upstream_path"],
        read_only=False,
    ),
    _tool(
        "scoperook_get_nuclei_template_intelligence",
        "Read one sanitized Nuclei template-intelligence record by exact local id. The record contains metadata and risk gates, never request bodies or payload values.",
        {
            "engagement_id": {"type": "string", "maxLength": 64},
            "import_id": {"type": "string", "pattern": "^nuclei-template-[0-9a-f]{16}$"},
        },
        ["engagement_id", "import_id"], read_only=True,
    ),
    _tool(
        "scoperook_import_surface_artifact",
        "Import a local HAR or OpenAPI JSON file from the engagement directory. Keep route shape while dropping headers, cookies, bodies, examples, defaults, query values, response content, and off-origin HAR requests.",
        {
            "engagement_id": {"type": "string", "maxLength": 64},
            "source_reference": {"type": "string", "minLength": 1, "maxLength": 300},
            "format": {"type": "string", "enum": ["har", "openapi_json"]},
            "asset": {"type": "string", "minLength": 1, "maxLength": 300},
        },
        ["engagement_id", "source_reference", "format", "asset"], read_only=False,
    ),
    _tool(
        "scoperook_get_surface_inventory",
        "Read a bounded, sanitized route-shape inventory produced from a local HAR or OpenAPI artifact. This is surface metadata, not a vulnerability finding.",
        {
            "engagement_id": {"type": "string", "maxLength": 64},
            "inventory_id": {"type": "string", "maxLength": 40},
            "query": {"type": "string", "maxLength": 120},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        ["engagement_id", "inventory_id"], read_only=True,
    ),
]


def _merge_tools() -> list[dict]:
    merged: dict[str, dict] = {tool["name"]: tool for tool in core.TOOLS}
    for tool in EXTRA_TOOLS:
        merged[tool["name"]] = tool
    return list(merged.values())


TOOLS = _merge_tools()

RESOURCES = [
    {
        "uri": "scoperook://methodology/daybreak-blue",
        "name": "ScopeRook Daybreak Blue operating method",
        "description": "Compact phase order, model boundary, and existing-tool handoff rules.",
        "mimeType": "text/markdown",
    },
    {
        "uri": "scoperook://methodology/evidence-standard",
        "name": "ScopeRook evidence standard",
        "description": "Observed/derived/unverified labels, negative controls, hashes, and report gates.",
        "mimeType": "text/markdown",
    },
    {
        "uri": "scoperook://methodology/continuous-hunt",
        "name": "ScopeRook continuous target-hunting method",
        "description": "Portfolio selection, target resume, coverage history, and session closeout rules.",
        "mimeType": "text/markdown",
    },
]

RESOURCE_TEXT = {
    RESOURCES[0]["uri"]: """# Daybreak Blue operating method

1. Read the compact agent brief and the selected engagement only.
2. Refresh current program policy; unresolved material limits fail closed.
3. Research public advisories and record one bounded, impact-bearing candidate.
4. Prefer offline source review or a reviewed synthetic fixture.
5. Route to an existing tool only for a named capability and phase.
6. Before target traffic, use a separate executor preflight bound to exact assets, activity, identity, request limits, deadline, redirects, and stop conditions.
7. Record observed results, a negative control, an independent impact check, and sanitized evidence hashes.
8. Keep the report concise and record triage, award, cash, costs, and time separately.

Daybreak model access is supplied by the customer's approved OpenAI account. ScopeRook does not bundle, proxy, or resell it.
""",
    RESOURCES[1]["uri"]: """# Evidence standard

- `observed`: directly reproduced and recorded.
- `derived`: inferred from observed data; identify the inference.
- `unverified`: a lead that still lacks direct proof.
- Use only researcher-controlled identities, services, devices, and data.
- Include the smallest reproduction, negative control, independent impact check, affected version, prior-art result, and remediation.
- Evidence references must remain within the engagement directory; ScopeRook verifies size and SHA-256 before saving a complete manifest.
- A source match, scanner result, synthetic pass, or version string alone does not prove a target vulnerability.
""",
    RESOURCES[2]["uri"]: """# Continuous target-hunting method

1. Call `scoperook_hunt_portfolio` and use its one deterministic next target or documentation action.
2. Read that target with `scoperook_get_engagement`, then load its paginated history and compact agent brief.
3. Refresh current program policy before target traffic; the portfolio freshness cue is administrative only.
4. Work one bounded coverage lane and preserve every lead, stop reason, candidate, control, and outcome.
5. Close the pass with `scoperook_record_hunt_session`, including measured time, cost, target-request state, next action, and revisit date.
6. Keep passwords, tokens, cookies, MFA material, raw customer data, and private response bodies outside ScopeRook.

The portfolio records decision-relevant history so another approved agent can resume work. It never turns prior authorization into standing permission.
""",
}

PROMPTS = [
    {
        "name": "scoperook-next-action",
        "description": "Guide Daybreak Blue to the smallest useful next action from durable ScopeRook state.",
        "arguments": [{"name": "engagement_id", "description": "Optional local engagement id", "required": False}],
    },
    {
        "name": "scoperook-candidate-review",
        "description": "Review one candidate's evidence and triage gaps without expanding the claim.",
        "arguments": [
            {"name": "engagement_id", "description": "Local engagement id", "required": True},
            {"name": "plan_id", "description": "Candidate plan id", "required": True},
        ],
    },
    {
        "name": "scoperook-continuous-hunt",
        "description": "Resume the highest-priority documented target without losing scope or history.",
        "arguments": [],
    },
]


class ScopeRookTools(core.ScopeRookTools):
    def __init__(self, data_dir: Path, sandbox_distro: str = ""):
        super().__init__(data_dir)
        self.labs = LabRunner(ROOT / "labs", self.store.directory, sandbox_distro)
        self.registry = ToolRegistry(self.store.directory)

    def _records(self) -> list[dict]:
        return self.store.snapshot()[0]

    def call(self, name: str, raw_args: Any) -> dict:
        args = core._arguments(raw_args)
        if name == "scoperook_status":
            result = super().call(name, args)
            result["server_version"] = SERVER_VERSION
            result["profile"] = "Daybreak Blue"
            result["capabilities"].extend([
                "deterministic agent workflow", "candidate economics", "local evidence hashing",
                "reviewed synthetic labs", "existing-tool capability routing",
                "optional integration catalog",
                "sanitized Nuclei template intelligence",
                "role state and sequence validation contracts",
                "continuous target portfolio and history",
                "secret-reducing HAR and OpenAPI route import",
            ])
            result["excluded_capabilities"] = sorted(set(result["excluded_capabilities"] + [
                "generic shell", "automatic external-tool launch", "model access resale",
            ]))
            return result
        if name == "scoperook_set_candidate_assessment":
            core._only(args, set(ASSESSMENT_PROPERTIES))
            ident = core.clean_text(args.get("engagement_id"), 64)
            plan_id = core.clean_text(args.get("plan_id"), 12)
            assessment = self.store.set_candidate_assessment(ident, plan_id, args)
            return {"engagement_id": ident, "plan_id": plan_id, "assessment": assessment}
        if name == "scoperook_set_validation_contract":
            core._only(args, set(VALIDATION_PROPERTIES))
            ident = core.clean_text(args.get("engagement_id"), 64)
            plan_id = core.clean_text(args.get("plan_id"), 12)
            contract = self.store.set_validation_contract(ident, plan_id, args)
            return {"engagement_id": ident, "plan_id": plan_id, "validation_contract": contract}
        if name == "scoperook_set_target_profile":
            core._only(args, set(TARGET_PROFILE_PROPERTIES))
            ident = core.clean_text(args.get("engagement_id"), 64)
            profile = self.store.set_target_profile(ident, args)
            return {"engagement_id": ident, "target_profile": profile,
                    "message": "Target profile and revision history saved locally"}
        if name == "scoperook_set_asset_context":
            core._only(args, set(ASSET_CONTEXT_PROPERTIES))
            ident = core.clean_text(args.get("engagement_id"), 64)
            context = self.store.set_asset_context(ident, args)
            return {"engagement_id": ident, "asset_context": context,
                    "message": "Asset context saved; re-check current program terms before testing"}
        if name == "scoperook_record_hunt_session":
            core._only(args, set(HUNT_SESSION_PROPERTIES))
            ident = core.clean_text(args.get("engagement_id"), 64)
            session = self.store.add_hunt_session(ident, args)
            return {"engagement_id": ident, "hunt_session": session,
                    "message": "Sanitized hunting pass appended to target history"}
        if name == "scoperook_hunt_portfolio":
            core._only(args, {"stale_after_days"})
            records, warnings = self.store.snapshot()
            portfolio = hunt_portfolio.build_portfolio(
                records, stale_after_days=args.get("stale_after_days", 14))
            portfolio["unreadable_records"] = warnings
            return portfolio
        if name == "scoperook_get_target_history":
            core._only(args, {"engagement_id", "include_details", "offset", "limit"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            return hunt_portfolio.target_history(
                self.store.get(ident), self.store.directory / ident,
                include_details=args.get("include_details", False),
                offset=args.get("offset", 0), limit=args.get("limit", 50),
            )
        if name == "scoperook_compare_intake":
            core._only(args, {"engagement_id"})
            return self.store.compare_intake(core.clean_text(args.get("engagement_id"), 64))
        if name == "scoperook_agent_brief":
            core._only(args, {"engagement_id", "plan_id"})
            brief = agent_workflow.agent_brief(
                self._records(), self.store.directory,
                core.clean_text(args.get("engagement_id"), 64) if args.get("engagement_id") else "",
                core.clean_text(args.get("plan_id"), 12) if args.get("plan_id") else "",
            )
            brief["phase_tools"].insert(4, {
                "phase": "existing tool handoff",
                "tools": ["scoperook_list_tool_capabilities", "scoperook_route_existing_tools",
                          "scoperook_import_surface_artifact", "scoperook_get_surface_inventory"],
            })
            brief["phase_tools"].insert(3, {
                "phase": "runtime proof design",
                "tools": ["scoperook_set_validation_contract"],
            })
            brief["phase_tools"].insert(0, {
                "phase": "target portfolio and resume",
                "tools": ["scoperook_hunt_portfolio", "scoperook_get_target_history",
                          "scoperook_set_target_profile", "scoperook_set_asset_context",
                          "scoperook_record_hunt_session"],
            })
            for phase in brief["phase_tools"]:
                if phase["phase"] == "research":
                    phase["tools"].extend([
                        "scoperook_import_nuclei_template",
                        "scoperook_get_nuclei_template_intelligence",
                    ])
            return brief
        if name == "scoperook_work_queue":
            core._only(args, {"engagement_id"})
            ident = core.clean_text(args.get("engagement_id"), 64) if args.get("engagement_id") else ""
            return agent_workflow.work_queue(self._records(), self.store.directory, ident)
        if name == "scoperook_rank_candidates":
            core._only(args, {"engagement_id"})
            ident = core.clean_text(args.get("engagement_id"), 64) if args.get("engagement_id") else ""
            return agent_workflow.rank_candidates(self._records(), self.store.directory, ident)
        if name == "scoperook_review_candidate":
            core._only(args, {"engagement_id", "plan_id"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            plan_id = core.clean_text(args.get("plan_id"), 12)
            return agent_workflow.review_candidate(
                self.store.get(ident), plan_id, self.store.directory / ident)
        if name == "scoperook_build_evidence_manifest":
            core._only(args, {"engagement_id", "plan_id", "save"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            plan_id = core.clean_text(args.get("plan_id"), 12)
            save = args.get("save", False)
            if type(save) is not bool:
                raise ValueError("save must be true or false")
            return agent_workflow.build_evidence_manifest(
                self.store.get(ident), plan_id, self.store.directory / ident, save)
        if name == "scoperook_list_synthetic_labs":
            core._only(args, set())
            return self.labs.list_labs()
        if name == "scoperook_run_synthetic_lab":
            core._only(args, {"lab_id"})
            return self.labs.run_lab(args.get("lab_id"))
        if name == "scoperook_register_tool_capability":
            core._only(args, set(REGISTRY_PROPERTIES))
            return {"tool": self.registry.register(args),
                    "message": "Local handoff recorded; no tool was launched"}
        if name == "scoperook_list_tool_capabilities":
            core._only(args, set())
            return self.registry.list()
        if name == "scoperook_route_existing_tools":
            core._only(args, {"phase", "required_capabilities", "operation_class",
                              "engagement_id", "plan_id"})
            ident = core.clean_text(args.get("engagement_id"), 64) if args.get("engagement_id") else ""
            plan_id = core.clean_text(args.get("plan_id"), 12) if args.get("plan_id") else ""
            engagement = self.store.get(ident) if ident else None
            return self.registry.route(
                phase=args.get("phase"), required_capabilities=args.get("required_capabilities"),
                operation_class=args.get("operation_class"), engagement=engagement, plan_id=plan_id)
        if name == "scoperook_search_integration_catalog":
            core._only(args, {"query", "phase", "operation_class", "limit"})
            return integration_catalog.search_catalog(
                query=args.get("query", ""), phase=args.get("phase", ""),
                operation_class=args.get("operation_class", ""), limit=args.get("limit", 10),
            )
        if name == "scoperook_import_nuclei_template":
            core._only(args, {"engagement_id", "source_reference", "asset",
                              "upstream_commit", "upstream_path"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            return nuclei_template_import.import_template(
                self.store.get(ident), self.store.directory / ident,
                source_reference=args.get("source_reference"), asset=args.get("asset"),
                upstream_commit=args.get("upstream_commit"),
                upstream_path=args.get("upstream_path"),
            )
        if name == "scoperook_get_nuclei_template_intelligence":
            core._only(args, {"engagement_id", "import_id"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            self.store.get(ident)
            return nuclei_template_import.get_template_intelligence(
                self.store.directory / ident, args.get("import_id"),
            )
        if name == "scoperook_import_surface_artifact":
            core._only(args, {"engagement_id", "source_reference", "format", "asset"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            return surface_import.import_surface(
                self.store.get(ident), self.store.directory / ident,
                source_reference=args.get("source_reference"), artifact_format=args.get("format"),
                asset=args.get("asset"),
            )
        if name == "scoperook_get_surface_inventory":
            core._only(args, {"engagement_id", "inventory_id", "query", "limit"})
            ident = core.clean_text(args.get("engagement_id"), 64)
            self.store.get(ident)
            return surface_import.get_inventory(
                self.store.directory / ident, args.get("inventory_id"),
                query=args.get("query", ""), limit=args.get("limit", 50),
            )
        return super().call(name, args)


def _prompt(name: str, arguments: Any) -> dict:
    args = arguments if isinstance(arguments, dict) else {}
    if name == "scoperook-next-action":
        extra = ""
        if args.get("engagement_id"):
            extra = f" for engagement `{core.clean_text(args['engagement_id'], 64)}`"
        text = (
            "Use ScopeRook as the durable source of truth. Call `scoperook_agent_brief`"
            f"{extra}, perform only its smallest supported next action, and keep observations separate from "
            "inference. If an existing tool is needed, call `scoperook_route_existing_tools`; treat its result "
            "as a handoff recommendation, not permission to send traffic."
        )
        return {"description": PROMPTS[0]["description"],
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}
    if name == "scoperook-candidate-review":
        ident = core.clean_text(args.get("engagement_id"), 64)
        plan_id = core.clean_text(args.get("plan_id"), 12)
        text = (
            f"Call `scoperook_review_candidate` for engagement `{ident}` and plan `{plan_id}`. Explain only "
            "the recorded evidence, negative control, independent impact check, prior-art state, and remaining "
            "gaps. Do not expand severity or impact beyond what is directly demonstrated."
        )
        return {"description": PROMPTS[1]["description"],
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}
    if name == "scoperook-continuous-hunt":
        text = (
            "Use ScopeRook as the durable source of truth for a continuous bounty pass. Call "
            "`scoperook_hunt_portfolio`, follow its smallest documentation or selection action, and if a "
            "target is selected call `scoperook_get_target_history`, `scoperook_get_engagement`, and "
            "`scoperook_agent_brief` before proposing work. Refresh current policy before target traffic. "
            "Work one bounded coverage lane, keep source leads separate from observations, and finish by "
            "calling `scoperook_record_hunt_session` with measured effort and the next resume point."
        )
        return {"description": PROMPTS[2]["description"],
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}
    raise ValueError("Prompt not found")


def handle(message: dict, tools: ScopeRookTools) -> dict | None:
    method = message.get("method")
    message_id = message.get("id")
    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion")
        return {
            "protocolVersion": requested if isinstance(requested, str) else PROTOCOL,
            "capabilities": {
                "tools": {"listChanged": False}, "resources": {"listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise ValueError("tools/call requires a tool name")
        try:
            output = tools.call(params["name"], params.get("arguments"))
            return {
                "content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}],
                "structuredContent": output,
            }
        except (KeyError, TypeError, ValueError) as exc:
            return {"content": [{"type": "text", "text": f"ScopeRook error: {exc}"}], "isError": True}
        except Exception as exc:
            return {"content": [{"type": "text", "text":
                                  f"ScopeRook internal error: {type(exc).__name__}"}], "isError": True}
    if method == "resources/list":
        return {"resources": RESOURCES}
    if method == "resources/read":
        params = message.get("params")
        uri = params.get("uri") if isinstance(params, dict) else None
        if uri not in RESOURCE_TEXT:
            raise ValueError("Resource not found")
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": RESOURCE_TEXT[uri]}]}
    if method == "prompts/list":
        return {"prompts": PROMPTS}
    if method == "prompts/get":
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise ValueError("prompts/get requires a prompt name")
        return _prompt(params["name"], params.get("arguments"))
    if method == "ping":
        return {}
    if message_id is not None:
        raise LookupError(method)
    return None


def serve(data_dir: Path, sandbox_distro: str = "") -> None:
    tools = ScopeRookTools(data_dir, sandbox_distro)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("Request must be a JSON object")
            if message.get("id") is None:
                continue
            try:
                result = handle(message, tools)
                reply = {"jsonrpc": "2.0", "id": message["id"], "result": result}
            except LookupError:
                reply = {"jsonrpc": "2.0", "id": message["id"],
                         "error": {"code": -32601, "message": "Method not found"}}
            except (KeyError, TypeError, ValueError) as exc:
                reply = {"jsonrpc": "2.0", "id": message.get("id"),
                         "error": {"code": -32602, "message": str(exc)}}
        except (json.JSONDecodeError, ValueError) as exc:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": f"Invalid request: {exc}"}}
        sys.stdout.write(json.dumps(reply, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="ScopeRook Daybreak Blue MCP server")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--sandbox-distro", default="",
                        help="Explicit WSL distribution for reviewed bundled synthetic labs")
    args = parser.parse_args()
    serve(args.data_dir, args.sandbox_distro)


if __name__ == "__main__":
    main()
