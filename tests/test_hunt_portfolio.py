from pathlib import Path
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
        for unsafe in ("researcher@example.com", "https://vault.example/account", "***REMOVED***"):
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


if __name__ == "__main__":
    unittest.main()
