from pathlib import Path
import json
import tempfile
import unittest

import hunt_portfolio
from workbench import INTAKE_FIELDS, PLAN_DETAIL_FIELDS, Store


class HuntPortfolioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root)
        self.item = self.store.create(
            "Documented target", "bounty", "https://bugcrowd.example/program",
            "https://app.example.invalid",
        )
        intake = {field: "Reviewed current program rule" for field in INTAKE_FIELDS}
        intake["program_url"] = "https://bugcrowd.example/program"
        self.store.set_intake(self.item["id"], intake)
        self.profile = {
            "platform": "bugcrowd", "program_status": "active", "priority": "high",
            "attacker_payoffs": ["Unauthorized access to controlled account data"],
            "technologies": ["Example Framework"], "account_state": "ready",
            "account_reference": "Researcher-controlled account A",
            "research_strategy": "Start with one untested high-impact lane and preserve controls",
            "next_action": "Review identity and access boundaries",
            "revisit_after": "", "tags": ["web", "authenticated"],
        }
        self.store.set_target_profile(self.item["id"], self.profile)
        self.store.set_asset_context(self.item["id"], {
            "asset": "https://app.example.invalid", "asset_type": "web",
            "scope_status": "in_scope", "reward_status": "rewarded",
            "test_status": "active", "constraints": "Manual low-volume checks only",
            "notes": "Researcher-controlled data only",
        })
        details = {field: "Recorded detail" for field in PLAN_DETAIL_FIELDS}
        details["asset"] = "https://app.example.invalid"
        self.plan = self.store.add_candidate(
            self.item["id"], "Controlled member may read controlled administrator object",
            "Unauthorized access to researcher-controlled data", details,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_portfolio_and_history_resume_one_target(self):
        session = self.store.add_hunt_session(self.item["id"], {
            "lane": "identity_access", "status": "lead", "environment": "offline_source",
            "summary": "Source review produced one bounded authorization lead",
            "candidate_ids": [self.plan["id"]], "source_refs": ["evidence/source-note.md"],
            "request_count_state": "not_applicable", "target_requests": 0,
            "human_minutes": 25, "paid_cost_usd": 0,
            "next_action": "Build the candidate and negative-control state table",
            "revisit_after": "",
        })
        portfolio = hunt_portfolio.build_portfolio(self.store.list(), stale_after_days=14)
        self.assertEqual(portfolio["next_target"]["engagement_id"], self.item["id"])
        self.assertTrue(portfolio["targets"][0]["documentation_complete"])
        self.assertTrue(portfolio["targets"][0]["hunt_ready"])
        self.assertEqual(portfolio["targets"][0]["lane_status"]["identity_access"]["status"], "lead")
        self.assertEqual(portfolio["targets"][0]["metrics"]["human_minutes"], 25)
        self.assertIsNone(portfolio["targets"][0]["metrics"]["measured_target_requests"])
        history = hunt_portfolio.target_history(
            self.store.get(self.item["id"]), self.root / self.item["id"], limit=100)
        types = {event["type"] for event in history["events"]}
        self.assertTrue({"engagement_created", "target_profile_revision", "scope_revision",
                         "asset_added", "asset_scope_revision", "candidate_created",
                         "hunt_session"}.issubset(types))
        hunt_event = next(event for event in history["events"] if event["type"] == "hunt_session")
        self.assertEqual(hunt_event["reference"], session["id"])

    def test_profile_and_asset_revisions_are_preserved(self):
        changed = dict(self.profile, next_action="Review business logic state transitions")
        self.store.set_target_profile(self.item["id"], changed)
        self.store.set_asset_context(self.item["id"], {
            "asset": "https://app.example.invalid", "asset_type": "web",
            "scope_status": "conditional", "reward_status": "rewarded",
            "test_status": "paused", "constraints": "Wait for refreshed rate limit",
            "notes": "No target traffic while paused",
        })
        record = self.store.get(self.item["id"])
        self.assertEqual(len(record["target_profile_history"]), 2)
        self.assertEqual(len(record["assets"][0]["context_history"]), 2)
        history = hunt_portfolio.target_history(
            record, self.root / self.item["id"], include_details=True, limit=100)
        profile_events = [event for event in history["events"]
                          if event["type"] == "target_profile_revision"]
        self.assertEqual(len(profile_events), 2)
        self.assertIn("next_action", profile_events[0]["details"]["changed_fields"])

    def test_history_indexes_saved_report_and_manifest_without_reading_contents(self):
        engagement_dir = self.root / self.item["id"]
        (engagement_dir / f"report-draft-{self.plan['id']}.md").write_text(
            "# Concise local draft\n", encoding="utf-8")
        (engagement_dir / f"evidence-manifest-{self.plan['id']}.json").write_text(
            '{"complete": true}\n', encoding="utf-8")
        history = hunt_portfolio.target_history(
            self.store.get(self.item["id"]), engagement_dir, limit=100)
        types = {event["type"] for event in history["events"]}
        self.assertIn("report_draft", types)
        self.assertIn("evidence_manifest", types)
        report_event = next(event for event in history["events"]
                            if event["type"] == "report_draft")
        self.assertEqual(report_event["details"]["file"], f"report-draft-{self.plan['id']}.md")
        self.assertEqual(len(report_event["details"]["sha256"]), 64)

    def test_account_reference_accepts_only_a_non_secret_local_alias(self):
        for unsafe in ("researcher@example.com", "https://vault.example/account", "synthetic-secret!"):
            with self.subTest(unsafe=unsafe), self.assertRaisesRegex(ValueError, "local alias"):
                self.store.set_target_profile(
                    self.item["id"], dict(self.profile, account_reference=unsafe))

    def test_malformed_legacy_collections_are_visible_and_never_hunt_ready(self):
        malformed = self.store.get(self.item["id"])
        malformed["hunt_sessions"] = {"unexpected": "object"}
        portfolio = hunt_portfolio.build_portfolio([malformed])
        target = portfolio["targets"][0]
        self.assertFalse(target["hunt_ready"])
        self.assertEqual(target["next_action_kind"], "repair_record")
        self.assertIn("hunt_sessions is not a list", target["record_warnings"])

    def test_session_accounting_and_scope_context_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "Non-target sessions"):
            self.store.add_hunt_session(self.item["id"], {
                "lane": "api", "status": "no_candidate", "environment": "offline_source",
                "summary": "Offline review", "candidate_ids": [], "source_refs": [],
                "request_count_state": "measured", "target_requests": 1,
                "human_minutes": 5, "paid_cost_usd": 0,
                "next_action": "Stop", "revisit_after": "",
            })
        with self.assertRaisesRegex(ValueError, "out-of-scope"):
            self.store.set_asset_context(self.item["id"], {
                "asset": "https://app.example.invalid", "asset_type": "web",
                "scope_status": "out_of_scope", "reward_status": "no_reward",
                "test_status": "active", "constraints": "Excluded", "notes": "",
            })

    def test_unmeasured_time_and_cost_remain_unknown(self):
        session = self.store.add_hunt_session(self.item["id"], {
            "lane": "supply_chain", "status": "no_candidate",
            "environment": "offline_source", "summary": "Historical offline review",
            "candidate_ids": [], "source_refs": ["sanitized historical record"],
            "request_count_state": "not_applicable", "target_requests": 0,
            "next_action": "Preserve for regression comparison", "revisit_after": "",
        })
        self.assertIsNone(session["human_minutes"])
        self.assertIsNone(session["paid_cost_usd"])
        metrics = hunt_portfolio.build_portfolio(self.store.list())["targets"][0]["metrics"]
        self.assertIsNone(metrics["human_minutes"])
        self.assertIsNone(metrics["paid_costs_usd"])
        self.assertEqual(metrics["effort_interpretation"],
                         "Null means unrecorded; zero is a measured zero")

    def test_historical_intake_keeps_its_source_review_time(self):
        historical = {field: "Reviewed historical program rule" for field in INTAKE_FIELDS}
        historical["program_url"] = "https://bugcrowd.example/program"
        historical["reviewed_at"] = "2026-09-30T21:20:27Z"
        historical["policy_max_age_hours"] = 24
        gate = self.store.set_intake(self.item["id"], historical)
        self.assertEqual(gate["reviewed_at"], "2026-09-30T21:20:27+00:00")
        portfolio = hunt_portfolio.build_portfolio(self.store.list(), stale_after_days=90)
        target = portfolio["targets"][0]
        self.assertTrue(target["policy_refresh_due"])
        self.assertEqual(target["policy_max_age_hours"], 24)
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.store.set_intake(self.item["id"], dict(historical, reviewed_at="2026-09-30T21:20:27"))

    def test_closed_and_paused_targets_do_not_generate_hunting_work(self):
        for state in ("closed", "paused"):
            self.store.set_target_profile(
                self.item["id"], dict(self.profile, program_status=state,
                                      next_action=f"Recorded {state} resume condition"))
            portfolio = hunt_portfolio.build_portfolio(self.store.list())
            target = portfolio["targets"][0]
            self.assertEqual(target["next_action_kind"], "wait")
            self.assertEqual(target["next_action"], f"Recorded {state} resume condition")
            self.assertIsNone(portfolio["next_target"])

    def test_engagement_schema_is_versioned_and_future_versions_fail_closed(self):
        path = self.root / self.item["id"] / "engagement.json"
        current = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(current["schema_version"], 1)

        current.pop("schema_version")
        path.write_text(json.dumps(current), encoding="utf-8")
        self.store.set_target_profile(self.item["id"], self.profile)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema_version"], 1)

        future = json.loads(path.read_text(encoding="utf-8"))
        future["schema_version"] = 99
        path.write_text(json.dumps(future), encoding="utf-8")
        records, warnings = self.store.snapshot()
        self.assertEqual(records, [])
        self.assertEqual(warnings[0]["engagement_id"], self.item["id"])
        self.assertTrue(path.exists())
        with self.assertRaisesRegex(ValueError, "Unsupported engagement schema"):
            self.store.get(self.item["id"])


if __name__ == "__main__":
    unittest.main()
