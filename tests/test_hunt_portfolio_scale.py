from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

import hunt_portfolio
from workbench import COVERAGE_LANES, INTAKE_FIELDS


class HuntPortfolioScaleTests(unittest.TestCase):
    def _target(self, index: int) -> dict:
        timestamp = datetime(2026, 10, 4, 12, index % 60, tzinfo=timezone.utc).isoformat()
        intake = {field: "Current rule recorded" for field in INTAKE_FIELDS}
        intake.update({
            "program_url": f"https://program.example/{index}",
            "reviewed_at": timestamp,
        })
        sessions = []
        lanes = sorted(COVERAGE_LANES)
        for session_index in range(50):
            sessions.append({
                "id": f"session-{index:03d}-{session_index:03d}",
                "recorded_at": timestamp,
                "lane": lanes[session_index % len(lanes)],
                "status": "no_candidate",
                "environment": "source_only",
                "summary": "Reviewed one bounded source-only hypothesis",
                "candidate_ids": [],
                "source_refs": ["https://vendor.example/advisory"],
                "request_count_state": "not_applicable",
                "target_requests": 0,
                "human_minutes": 1,
                "paid_cost_usd": 0.0,
                "next_action": "Review a materially different lane",
                "revisit_after": "2026-10-04",
            })
        profile = {
            "platform": "other",
            "program_status": "active",
            "priority": "normal",
            "attacker_payoffs": ["Unauthorized access"],
            "technologies": ["Synthetic service"],
            "account_state": "not_required",
            "strategy": "Bounded source review",
            "next_action": "Review a materially different lane",
            "revisit_after": "2026-10-04",
            "tags": ["synthetic"],
        }
        asset_context = {
            "asset_type": "web",
            "scope_state": "in_scope",
            "reward_state": "eligible",
            "test_state": "available",
            "constraints": ["Synthetic only"],
            "notes": "Scale fixture",
        }
        return {
            "id": f"target-{index:03d}",
            "name": f"Target {index:03d}",
            "kind": "bounty",
            "created_at": timestamp,
            "updated_at": timestamp,
            "target_profile": profile,
            "target_profile_history": [{
                "recorded_at": timestamp,
                "content_sha256": f"{index:064x}"[-64:],
                "snapshot": profile,
            }],
            "intake": intake,
            "intake_history": [{
                "reviewed_at": timestamp,
                "content_sha256": f"{index + 1:064x}"[-64:],
                "snapshot": intake,
            }],
            "assets": [{
                "value": f"https://target-{index}.example.invalid",
                "added_at": timestamp,
                "context": asset_context,
                "context_history": [{
                    "reviewed_at": timestamp,
                    "content_sha256": f"{index + 2:064x}"[-64:],
                    "snapshot": asset_context,
                }],
            }],
            "hunt_sessions": sessions,
            "plans": [],
            "observations": [],
            "outcomes": [],
            "runs": [],
        }

    def test_one_hundred_targets_and_five_thousand_sessions_are_resumable(self):
        records = [self._target(index) for index in range(100)]
        portfolio = hunt_portfolio.build_portfolio(records, stale_after_days=90)

        self.assertEqual(portfolio["target_count"], 100)
        self.assertEqual(sum(target["session_count"] for target in portfolio["targets"]), 5000)
        self.assertEqual(portfolio["next_target"]["name"], "Target 000")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            total_history_events = 0
            for record in records:
                history = hunt_portfolio.target_history(record, root, limit=1)
                total_history_events += history["event_count"]
                self.assertEqual(history["returned"], 1)
                self.assertTrue(history["has_more"])

        self.assertGreaterEqual(total_history_events, 5000)


if __name__ == "__main__":
    unittest.main()
