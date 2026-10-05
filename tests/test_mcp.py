import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import integration_catalog
from scoperook_daybreak_server import ScopeRookTools, TOOLS, handle
from workbench import INTAKE_FIELDS


class ScopeRookMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.tools = ScopeRookTools(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def create_candidate(self):
        created = self.tools.call("scoperook_create_engagement", {
            "name": "Private program", "kind": "bounty",
            "authority": "https://bugcrowd.example/program", "asset": "https://app.example.invalid",
        })
        intake = {field: "Verified in current brief" for field in (
            "exclusions", "reward_status", "technique_restrictions", "rate_limits",
            "account_requirements", "test_identity_rules", "safe_harbor", "evidence_requirements",
            "prior_art_sources", "open_questions",
        )}
        intake.update({"engagement_id": created["id"], "program_url": "https://bugcrowd.example/program"})
        gate = self.tools.call("scoperook_set_intake", intake)
        plan = self.tools.call("scoperook_add_plan", {
            "engagement_id": created["id"], "title": "Role boundary permits restricted read",
            "hypothesis": "A researcher-controlled member can read the controlled admin fixture",
            "impact": "Unauthorized access to researcher-controlled administrative data",
            "asset": "https://app.example.invalid", "minimum_access": "Researcher-controlled member account",
            "negative_control": "The member receives 403 for the same controlled object",
            "evidence_needed": "Sanitized request and response status with hashes",
            "stop_conditions": "Stop on any other-user data, 429, redirect, or server error",
            "affected_version": "Current hosted build observed during the test",
            "prior_art_result": "No matching known issue found in reviewed sources",
            "remediation": "Enforce the administrator role on the server before reading the object",
        })
        return created, gate, plan

    def test_initialize_and_tool_catalog(self):
        initialized = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": "2025-06-18"}}, self.tools)
        self.assertEqual(initialized["serverInfo"]["name"], "scoperook-daybreak")
        self.assertIn("resources", initialized["capabilities"])
        self.assertIn("prompts", initialized["capabilities"])
        listed = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, self.tools)
        names = {item["name"] for item in listed["tools"]}
        self.assertEqual(len(names), len(TOOLS))
        self.assertIn("scoperook_search_prior_art", names)
        self.assertIn("scoperook_search_current_kev", names)
        self.assertIn("scoperook_verify_cve", names)
        self.assertIn("scoperook_research_cve", names)
        self.assertIn("scoperook_search_exploitdb", names)
        self.assertIn("scoperook_query_osv_package", names)
        self.assertIn("scoperook_agent_brief", names)
        self.assertIn("scoperook_set_validation_contract", names)
        self.assertIn("scoperook_set_target_profile", names)
        self.assertIn("scoperook_set_asset_context", names)
        self.assertIn("scoperook_record_hunt_session", names)
        self.assertIn("scoperook_hunt_portfolio", names)
        self.assertIn("scoperook_get_target_history", names)
        self.assertIn("scoperook_work_queue", names)
        self.assertIn("scoperook_rank_candidates", names)
        self.assertIn("scoperook_review_candidate", names)
        self.assertIn("scoperook_build_evidence_manifest", names)
        self.assertIn("scoperook_list_synthetic_labs", names)
        self.assertIn("scoperook_run_synthetic_lab", names)
        self.assertIn("scoperook_register_tool_capability", names)
        self.assertIn("scoperook_route_existing_tools", names)
        self.assertIn("scoperook_search_integration_catalog", names)
        self.assertIn("scoperook_import_nuclei_template", names)
        self.assertIn("scoperook_get_nuclei_template_intelligence", names)
        self.assertIn("scoperook_import_surface_artifact", names)
        self.assertIn("scoperook_get_surface_inventory", names)
        self.assertIn("scoperook_compare_intake", names)
        self.assertNotIn("scoperook_local_run", names)

    def test_resources_prompts_and_existing_tool_router(self):
        resources = handle({"jsonrpc": "2.0", "id": 1, "method": "resources/list"}, self.tools)
        self.assertEqual(len(resources["resources"]), 3)
        resource = handle({"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                           "params": {"uri": "scoperook://methodology/daybreak-blue"}}, self.tools)
        self.assertIn("separate executor preflight", resource["contents"][0]["text"])
        prompts = handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/list"}, self.tools)
        self.assertEqual({item["name"] for item in prompts["prompts"]},
                         {"scoperook-next-action", "scoperook-candidate-review",
                          "scoperook-continuous-hunt"})
        prompt = handle({"jsonrpc": "2.0", "id": 4, "method": "prompts/get",
                         "params": {"name": "scoperook-next-action", "arguments": {}}}, self.tools)
        self.assertIn("scoperook_agent_brief", prompt["messages"][0]["content"]["text"])

        executable = Path(self.temp.name) / "review-tool.exe"
        executable.write_bytes(b"reviewed fixture")
        registered = self.tools.call("scoperook_register_tool_capability", {
            "tool_id": "review-tool", "display_name": "Review Tool", "version": "1.0",
            "interface": "local_cli", "phases": ["source_review", "candidate_validation"],
            "capabilities": ["static analysis", "route inventory"],
            "operation_classes": ["offline"], "output_formats": ["sarif", "json"],
            "local_path": str(executable), "declared_available": True,
            "constraints": "Use only local researcher-controlled source artifacts", "notes": "Fixture",
        })
        self.assertTrue(registered["tool"]["available"])
        routed = self.tools.call("scoperook_route_existing_tools", {
            "phase": "source_review", "required_capabilities": ["static analysis"],
            "operation_class": "offline",
        })
        self.assertEqual(routed["selected"]["tool_id"], "review-tool")
        self.assertTrue(routed["execution_ready"])
        self.assertIn("not a tool invocation", routed["boundary"])

        target_tool = self.tools.call("scoperook_register_tool_capability", {
            "tool_id": "proxy-tool", "display_name": "Proxy Tool", "interface": "human_ui",
            "phases": ["traffic_capture"], "capabilities": ["http capture"],
            "operation_classes": ["passive_capture"], "output_formats": ["har"],
            "declared_available": True,
            "constraints": "Current exact scope and numeric request limits are mandatory",
        })
        self.assertTrue(target_tool["tool"]["available"])
        target_route = self.tools.call("scoperook_route_existing_tools", {
            "phase": "traffic_capture", "required_capabilities": ["http capture"],
            "operation_class": "passive_capture",
        })
        self.assertFalse(target_route["execution_ready"])
        self.assertIn("Select an engagement", target_route["blockers"][0])

        directory = Path(self.temp.name) / "package-directory"
        directory.mkdir()
        unavailable = self.tools.call("scoperook_register_tool_capability", {
            "tool_id": "directory-cli", "display_name": "Directory CLI", "version": "1.0",
            "interface": "local_cli", "phases": ["source_review"],
            "capabilities": ["directory-only analysis"], "operation_classes": ["offline"],
            "output_formats": ["json"], "local_path": str(directory),
            "declared_available": True, "constraints": "Fixture",
        })
        self.assertFalse(unavailable["tool"]["available"])
        self.assertIn("exact file", unavailable["tool"]["verification"])
        unavailable_route = self.tools.call("scoperook_route_existing_tools", {
            "phase": "source_review", "required_capabilities": ["directory-only analysis"],
            "operation_class": "offline",
        })
        self.assertIsNone(unavailable_route["selected"])
        self.assertFalse(unavailable_route["execution_ready"])
        self.assertIn("No registered available tool", unavailable_route["blockers"][0])

    def test_projectdiscovery_integration_catalog_is_guidance_only(self):
        result = self.tools.call("scoperook_search_integration_catalog", {
            "query": "template", "phase": "candidate_validation", "limit": 10,
        })
        ids = {item["id"] for item in result["integrations"]}
        self.assertIn("projectdiscovery-nuclei", ids)
        self.assertEqual(result["installation_state"], "not_checked")
        self.assertIn("MIT-only", result["license_policy"])
        self.assertIn("do not mean a tool is installed", result["boundary"])
        self.assertTrue(all(item["license"] == "MIT" for item in result["integrations"]))
        self.assertTrue(all("/blob/" in item["license_source"] for item in result["integrations"]))
        nuclei = next(item for item in result["integrations"]
                      if item["id"] == "projectdiscovery-nuclei")
        self.assertIn("separate executor receipt", nuclei["required_gates"])

        rejected_path = Path(self.temp.name) / "non-mit.json"
        rejected = json.loads((Path(__file__).parents[1] / "integrations" /
                               "projectdiscovery.json").read_text(encoding="utf-8"))
        rejected["integrations"] = [dict(rejected["integrations"][0], license="GPL-3.0")]
        rejected_path.write_text(json.dumps(rejected), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "MIT-only"):
            integration_catalog.load_catalog(rejected_path)

    def test_runtime_validation_contract_binds_identity_state_sequence_and_budget(self):
        created, _gate, plan_result = self.create_candidate()
        plan = plan_result["plan"]
        result = self.tools.call("scoperook_set_validation_contract", {
            "engagement_id": created["id"], "plan_id": plan["id"],
            "environment": "researcher_owned_runtime",
            "candidate_actor": "Researcher-controlled member",
            "control_actor": "Researcher-controlled administrator",
            "starting_state": "Both controlled accounts exist and the marker object belongs to the administrator",
            "sequence_steps": ["Authenticate as the member", "Request the exact controlled marker object"],
            "expected_secure_behavior": "The member receives a denial and no marker content",
            "suspected_behavior": "The member receives the administrator marker",
            "negative_control": "The administrator can read the same marker through the ordinary path",
            "independent_impact_check": "Compare the returned marker hash without retaining response content",
            "cleanup": "Delete the controlled marker and sign out both controlled sessions",
            "max_requests": 3,
        })["validation_contract"]
        self.assertEqual(result["asset"], "https://app.example.invalid")
        self.assertEqual(result["max_requests"], 3)
        self.assertFalse(result["execution_ready"])
        record = self.tools.call("scoperook_get_engagement", {
            "engagement_id": created["id"],
        })["engagement"]
        self.assertEqual(record["plans"][0]["validation_contract"]["sequence_steps"],
                         ["Authenticate as the member", "Request the exact controlled marker object"])
        manifest = self.tools.call("scoperook_build_evidence_manifest", {
            "engagement_id": created["id"], "plan_id": plan["id"], "save": False,
        })["manifest"]
        self.assertEqual(manifest["plan"]["validation_contract"]["max_requests"], 3)
        with self.assertRaisesRegex(ValueError, "zero request budget"):
            self.tools.call("scoperook_set_validation_contract", {
                "engagement_id": created["id"], "plan_id": plan["id"],
                "environment": "offline_source", "candidate_actor": "Static reviewer",
                "control_actor": "Second reviewer", "starting_state": "Pinned local source",
                "sequence_steps": ["Inspect the pinned file"],
                "expected_secure_behavior": "Authorization is enforced", "suspected_behavior": "It is not",
                "negative_control": "Inspect the guarded path", "independent_impact_check": "Trace the sink",
                "cleanup": "No runtime state", "max_requests": 1,
            })

    def test_continuous_target_profile_history_and_nuclei_intake(self):
        created, _gate, plan_result = self.create_candidate()
        plan = plan_result["plan"]
        self.tools.call("scoperook_set_target_profile", {
            "engagement_id": created["id"], "platform": "bugcrowd",
            "program_status": "active", "priority": "high",
            "attacker_payoffs": ["Unauthorized access to controlled account data"],
            "technologies": ["Example Framework"], "account_state": "ready",
            "account_reference": "Researcher-controlled account A",
            "research_strategy": "Work one bounded lane and preserve the negative control",
            "next_action": "Review the identity boundary", "revisit_after": "",
            "tags": ["authenticated", "web"],
        })
        self.tools.call("scoperook_set_asset_context", {
            "engagement_id": created["id"], "asset": "https://app.example.invalid",
            "asset_type": "web", "scope_status": "in_scope",
            "reward_status": "rewarded", "test_status": "active",
            "constraints": "Manual low-volume tests with researcher-controlled data only",
            "notes": "No secret values stored",
        })
        session = self.tools.call("scoperook_record_hunt_session", {
            "engagement_id": created["id"], "lane": "identity_access", "status": "lead",
            "environment": "offline_source", "summary": "One bounded source lead remains",
            "candidate_ids": [plan["id"]], "source_refs": ["evidence/source-note.md"],
            "request_count_state": "not_applicable", "target_requests": 0,
            "human_minutes": 20, "paid_cost_usd": 0,
            "next_action": "Build the role and state table", "revisit_after": "",
        })
        self.assertEqual(session["hunt_session"]["human_minutes"], 20)

        engagement_dir = Path(self.temp.name) / created["id"]
        template_path = engagement_dir / "evidence" / "fixture.yaml"
        template_path.parent.mkdir(parents=True, exist_ok=True)
        template_path.write_text("""id: CVE-2026-12345
info:
  name: Example Authorization Check
  author: researcher
  severity: high
  reference:
    - https://vendor.example/advisory
  classification:
    cve-id: CVE-2026-12345
  metadata:
    max-request: 1
    vendor: Example
    product: Widget
  tags: cve,authorization
http:
  - method: GET
    path:
      - \"{{BaseURL}}/private-marker\"
""", encoding="utf-8")
        imported = self.tools.call("scoperook_import_nuclei_template", {
            "engagement_id": created["id"], "source_reference": "evidence/fixture.yaml",
            "asset": "https://app.example.invalid", "upstream_commit": "d" * 40,
            "upstream_path": "http/cves/2026/CVE-2026-12345.yaml",
        })
        self.assertFalse(imported["execution"]["allowed"])
        restored = self.tools.call("scoperook_get_nuclei_template_intelligence", {
            "engagement_id": created["id"], "import_id": imported["import_id"],
        })
        self.assertEqual(restored["template"]["id"], "CVE-2026-12345")
        portfolio = self.tools.call("scoperook_hunt_portfolio", {})
        self.assertEqual(portfolio["next_target"]["engagement_id"], created["id"])
        self.assertTrue(portfolio["targets"][0]["documentation_complete"])
        history = self.tools.call("scoperook_get_target_history", {
            "engagement_id": created["id"], "limit": 100,
        })
        types = {event["type"] for event in history["events"]}
        self.assertIn("hunt_session", types)
        self.assertIn("template_intelligence", types)

    def test_synthetic_lab_catalog_is_bundled_and_fail_closed(self):
        result = self.tools.call("scoperook_list_synthetic_labs", {})
        self.assertEqual(result["labs"][0]["id"], "python-access-control")
        self.assertTrue(result["labs"][0]["valid"])
        self.assertFalse(result["backend"]["configured"])
        with self.assertRaisesRegex(ValueError, "explicitly configured"):
            self.tools.call("scoperook_run_synthetic_lab", {"lab_id": "python-access-control"})

    def test_planning_records_are_metadata_only(self):
        created, gate, _plan = self.create_candidate()
        self.assertTrue(gate["scope_gate"]["complete"])
        listed = self.tools.call("scoperook_list_engagements", {})
        encoded = json.dumps(listed)
        self.assertIn(created["id"], encoded)
        self.assertNotIn("bugcrowd.example", encoded)
        self.assertNotIn("researcher-controlled member", encoded.lower())
        self.assertEqual(listed["engagements"][0]["plan_count"], 1)
        self.assertTrue(listed["engagements"][0]["scope_complete"])

    def test_scope_gate_report_and_financial_states(self):
        created, _gate, plan_result = self.create_candidate()
        plan = plan_result["plan"]
        incomplete = self.tools.call("scoperook_build_report", {
            "engagement_id": created["id"], "plan_id": plan["id"]})
        self.assertFalse(incomplete["ready"])
        self.assertIn("observed_evidence", incomplete["missing"])
        self.tools.call("scoperook_record_observation", {
            "engagement_id": created["id"], "plan_id": plan["id"], "classification": "observed",
            "summary": "The controlled member received the controlled fixture with HTTP 200",
            "reproduction": "Sign in as the controlled member; request the exact fixture; record HTTP 200",
            "negative_control_result": "The comparison route returned HTTP 403",
            "independent_impact_check": "The returned fixture contained the unique researcher marker",
            "evidence_refs": ["evidence/request-response-hashes.json"],
        })
        report = self.tools.call("scoperook_build_report", {
            "engagement_id": created["id"], "plan_id": plan["id"], "save": True})
        self.assertTrue(report["ready"])
        self.assertIn("## Negative control", report["markdown"])
        self.assertTrue(Path(report["saved_to"]).is_file())
        self.tools.call("scoperook_record_outcome", {
            "engagement_id": created["id"], "plan_id": plan["id"], "status": "accepted",
            "submission_reference": "BC-12345", "pending_award_usd": 500, "human_minutes": 45,
        })
        status = self.tools.call("scoperook_status", {})
        self.assertEqual(status["financials"]["recorded_pending_awards_usd"], 500.0)
        self.assertIsNone(status["financials"]["received_cash_usd"])
        self.assertEqual(status["financials"]["human_minutes"], 45)

    def test_agent_workflow_assessment_and_evidence_manifest(self):
        created, _gate, plan_result = self.create_candidate()
        plan = plan_result["plan"]
        self.tools.call("scoperook_set_candidate_assessment", {
            "engagement_id": created["id"], "plan_id": plan["id"],
            "attacker_motive": "A member would seek access to controlled administrator records",
            "plausible_payoff": "Unauthorized access to researcher-controlled administrative data",
            "duplicate_risk": "low", "duplicate_risk_reason": "No matching primary-source issue found",
            "setup_cost": "none", "proof_strength": "clear_end_to_end",
            "proof_path": "Compare the same controlled object as member and owner",
            "expected_requests": 2, "decision": "pursue",
        })
        evidence_dir = Path(self.temp.name) / created["id"] / "evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "proof.json").write_text('{"status":200}\n', encoding="utf-8")
        self.tools.call("scoperook_record_observation", {
            "engagement_id": created["id"], "plan_id": plan["id"], "classification": "observed",
            "summary": "The member received the controlled administrator fixture",
            "reproduction": "Request the exact controlled fixture as the controlled member",
            "negative_control_result": "The guarded comparison returned HTTP 403",
            "independent_impact_check": "The unique controlled marker was present",
            "evidence_refs": ["evidence/proof.json"],
        })
        review = self.tools.call("scoperook_review_candidate", {
            "engagement_id": created["id"], "plan_id": plan["id"],
        })
        self.assertTrue(review["report_ready"])
        self.assertEqual(review["evidence"][0]["state"], "verified")
        manifest = self.tools.call("scoperook_build_evidence_manifest", {
            "engagement_id": created["id"], "plan_id": plan["id"], "save": True,
        })
        self.assertTrue(Path(manifest["saved_to"]).is_file())
        self.assertEqual(len(manifest["manifest"]["manifest_sha256"]), 64)
        ranked = self.tools.call("scoperook_rank_candidates", {"engagement_id": created["id"]})
        self.assertGreater(ranked["candidates"][0]["score"], 50)
        brief = self.tools.call("scoperook_agent_brief", {
            "engagement_id": created["id"], "plan_id": plan["id"],
        })
        self.assertIn("Daybreak Blue", brief["profile"])
        self.assertTrue(brief["selected_candidate_review"]["report_ready"])

    def test_unknown_material_intake_keeps_scope_gate_closed(self):
        created = self.tools.call("scoperook_create_engagement", {
            "name": "Unresolved program", "kind": "bounty",
            "authority": "https://bugcrowd.example/program", "asset": "https://app.example.invalid",
        })
        intake = {field: "Verified in current brief" for field in (
            "exclusions", "reward_status", "technique_restrictions", "rate_limits",
            "account_requirements", "test_identity_rules", "safe_harbor", "evidence_requirements",
            "prior_art_sources", "open_questions",
        )}
        intake.update({"engagement_id": created["id"],
                       "program_url": "https://bugcrowd.example/program", "rate_limits": "Unknown"})
        gate = self.tools.call("scoperook_set_intake", intake)["scope_gate"]
        self.assertFalse(gate["complete"])
        self.assertEqual(gate["unresolved"], ["rate_limits"])

    def test_intake_snapshots_report_changed_fields_without_widening_scope(self):
        created, _gate, _plan = self.create_candidate()
        baseline = self.tools.call("scoperook_compare_intake", {"engagement_id": created["id"]})
        self.assertEqual(baseline["snapshot_count"], 1)
        self.assertFalse(baseline["changed"])
        current = self.tools.call("scoperook_get_engagement", {
            "engagement_id": created["id"]})["engagement"]["intake"]
        update = {field: current[field] for field in INTAKE_FIELDS}
        update.update({"engagement_id": created["id"], "rate_limits": "Ten requests per minute"})
        self.tools.call("scoperook_set_intake", update)
        changed = self.tools.call("scoperook_compare_intake", {"engagement_id": created["id"]})
        self.assertEqual(changed["snapshot_count"], 2)
        self.assertEqual(changed["changed_fields"], ["rate_limits"])
        self.assertNotEqual(changed["previous_sha256"], changed["current_sha256"])

    def test_prior_art_and_simulation_remain_offline(self):
        records = self.tools.call("scoperook_search_prior_art", {"query": "NetScaler", "limit": 2})
        self.assertEqual({"CVE-2026-88771", "CVE-2026-88772"},
                         {record["cve_id"] for record in records["records"]})
        example = Path(__file__).parents[1] / "intelligence" / "examples"
        world = json.loads((example / "synthetic_role_chain_world.json").read_text(encoding="utf-8"))
        plan = json.loads((example / "synthetic_role_chain_plan.json").read_text(encoding="utf-8"))
        result = self.tools.call("scoperook_simulate_hypothesis", {
            "world": world, "plan": plan, "explore": True,
        })
        self.assertEqual(result["result"], "supported_in_model")
        self.assertEqual(result["exploration"]["result"], "hypothesis_path_found")

    def test_stdio_transport_ignores_tool_call_notifications(self):
        server = Path(__file__).parents[1] / "scoperook_daybreak_server.py"
        data_dir = Path(self.temp.name) / "stdio"
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {
                "name": "scoperook_create_engagement", "arguments": {
                    "name": "Must not be created", "kind": "owned_lab", "authority": "notification"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "scoperook_status", "arguments": {}}},
        ]
        process = subprocess.run(
            [sys.executable, str(server), "--data-dir", str(data_dir)],
            input="".join(json.dumps(item) + "\n" for item in messages),
            text=True, capture_output=True, timeout=10, check=True,
        )
        replies = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([reply["id"] for reply in replies], [1, 2])
        status = json.loads(replies[1]["result"]["content"][0]["text"])
        self.assertEqual(status["engagement_count"], 0)
        self.assertEqual(replies[1]["result"]["structuredContent"]["engagement_count"], 0)


if __name__ == "__main__":
    unittest.main()
