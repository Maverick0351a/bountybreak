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
        created = self.tools.call("scoperook_create_engagement", {
            "name": "Private program", "kind": "bounty",
            "authority": "Private scope text that must not be listed",
            "asset": "https://example.invalid",
        })
        self.tools.call("scoperook_add_plan", {
            "engagement_id": created["id"], "hypothesis": "Sensitive hypothesis",
            "impact": "Sensitive impact",
        })
        listed = self.tools.call("scoperook_list_engagements", {})
        encoded = json.dumps(listed)
        self.assertIn(created["id"], encoded)
        self.assertNotIn("Private scope text", encoded)
        self.assertNotIn("Sensitive hypothesis", encoded)
        self.assertEqual(listed["engagements"][0]["plan_count"], 1)

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
