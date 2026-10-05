import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scoperook_mcp import ScopeRookTools, TOOLS, handle


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
        self.assertEqual(initialized["serverInfo"]["name"], "scoperook")
        listed = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, self.tools)
        names = {item["name"] for item in listed["tools"]}
        self.assertEqual(len(names), len(TOOLS))
        self.assertIn("scoperook_search_prior_art", names)
        self.assertNotIn("scoperook_local_run", names)

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
        server = Path(__file__).parents[1] / "scoperook_mcp.py"
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


if __name__ == "__main__":
    unittest.main()
