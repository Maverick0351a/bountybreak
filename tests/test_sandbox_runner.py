import json
from pathlib import Path
import shutil
import tempfile
import unittest

from sandbox_runner import LabRunner, SandboxError


ROOT = Path(__file__).parents[1]


class FakeLabRunner(LabRunner):
    def backend_status(self):
        return {
            "backend": "wsl", "configured": True, "ready": True, "distro": "test",
            "isolation": ["test boundary"],
            "boundary": "Synthetic fixtures only",
        }

    def _invoke(self, directory, manifest, case, token):
        stdout = "candidate marker" if case["role"] == "candidate" else "control marker"
        return {
            "id": case["id"], "role": case["role"], "passed": True,
            "exit_code": 0, "expected_exit_code": 0,
            "stdout": stdout, "stderr": "", "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "checks": {"stdout_contains": {}, "stdout_not_contains": {}},
        }


class SandboxRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name) / "data"

    def tearDown(self):
        self.temp.cleanup()

    def test_bundled_manifest_is_valid_and_backend_is_explicit(self):
        runner = LabRunner(ROOT / "labs", self.data)
        result = runner.list_labs()
        self.assertEqual(result["labs"][0]["id"], "python-access-control")
        self.assertTrue(result["labs"][0]["valid"])
        self.assertFalse(result["backend"]["configured"])
        with self.assertRaisesRegex(SandboxError, "explicitly configured"):
            runner.run_lab("python-access-control")

    def test_run_always_records_candidate_and_control(self):
        runner = FakeLabRunner(ROOT / "labs", self.data, "test")
        result = runner.run_lab("python-access-control")
        self.assertTrue(result["overall_passed"])
        self.assertEqual({"candidate", "negative_control"}, {case["role"] for case in result["cases"]})
        evidence = Path(result["evidence_path"])
        self.assertTrue(evidence.is_file())
        saved = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertNotIn("evidence_path", saved)
        self.assertIn("no target traffic", saved["scope"])

    def test_hash_change_and_path_like_id_fail_closed(self):
        labs = Path(self.temp.name) / "labs"
        shutil.copytree(ROOT / "labs" / "python-access-control", labs / "python-access-control")
        entrypoint = labs / "python-access-control" / "runner.py"
        entrypoint.write_text(entrypoint.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
        runner = LabRunner(labs, self.data)
        listed = runner.list_labs()
        self.assertFalse(listed["labs"][0]["valid"])
        self.assertIn("hash", listed["labs"][0]["error"])
        with self.assertRaisesRegex(SandboxError, "lowercase"):
            runner.run_lab("../python-access-control")


if __name__ == "__main__":
    unittest.main()
