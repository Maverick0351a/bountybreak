import http.client
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from workbench import AppServer, DemoHandler, Store


class WorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.demo = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        cls.demo.daemon_threads = True
        threading.Thread(target=cls.demo.serve_forever, daemon=True).start()
        cls.app = AppServer(("127.0.0.1", 0), Store(Path(cls.temp.name)), cls.demo.server_port)
        threading.Thread(target=cls.app.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.app.server_close()
        cls.demo.shutdown()
        cls.demo.server_close()
        cls.temp.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=4)
        default = {"Host": f"127.0.0.1:{self.app.server_port}"}
        if body is not None:
            default.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.app.server_port}",
                            "X-CSRF-Token": self.app.csrf})
        default.update(headers or {})
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=default)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_owned_lab_end_to_end(self):
        status, engagement = self.request("/api/engagements", "POST", {
            "name": "Synthetic demo", "kind": "owned_lab", "authority": "Researcher-owned bundled lab"})
        self.assertEqual(status, 201)
        status, plan = self.request(f"/api/engagements/{engagement['id']}/plans", "POST", {
            "hypothesis": "Member is denied admin access", "impact": "Unauthorized data access"})
        self.assertEqual(status, 201)
        status, run = self.request(f"/api/engagements/{engagement['id']}/demo-run", "POST", {"plan_id": plan["id"]})
        self.assertEqual(status, 201)
        self.assertEqual([item["status"] for item in run["observations"]], [200, 403])
        self.assertTrue(run["negative_control_passed"])
        self.assertEqual(run["requests_sent"], 2)
        self.assertNotIn('"role": "member"', json.dumps(run))
        saved = json.loads((Path(self.temp.name) / engagement["id"] / "engagement.json").read_text())
        self.assertEqual(len(saved["runs"]), 1)

    def test_live_engagement_and_cross_site_requests_fail_closed(self):
        status, engagement = self.request("/api/engagements", "POST", {
            "name": "Public program", "kind": "bounty", "authority": "https://example.invalid/program"})
        self.assertEqual(status, 201)
        status, _ = self.request(f"/api/engagements/{engagement['id']}/demo-run", "POST", {"plan_id": "abcdef123456"})
        self.assertEqual(status, 400)
        status, _ = self.request("/api/engagements", "POST", {
            "name": "Wrong host", "kind": "owned_lab", "authority": "mine"}, {"Host": "evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/engagements", "POST", {
            "name": "Wrong origin", "kind": "owned_lab", "authority": "mine"}, {"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/engagements", "POST", {
            "name": "Wrong token", "kind": "owned_lab", "authority": "mine"}, {"X-CSRF-Token": "no"})
        self.assertEqual(status, 403)

    def test_assets_are_saved_for_planning_without_target_traffic(self):
        status, engagement = self.request("/api/engagements", "POST", {
            "name": "Asset planning", "kind": "bounty", "authority": "Current public program brief",
            "asset": "https://app.example.invalid/login"})
        self.assertEqual(status, 201)
        self.assertEqual(engagement["assets"][0]["value"], "https://app.example.invalid/login")
        status, second = self.request(f"/api/engagements/{engagement['id']}/assets", "POST", {
            "value": "*.example.invalid"})
        self.assertEqual(status, 201)
        self.assertEqual(second["value"], "*.example.invalid")
        status, item = self.request(f"/api/engagements/{engagement['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(len(item["assets"]), 2)
        self.assertEqual(item["runs"], [])
        status, _ = self.request(f"/api/engagements/{engagement['id']}/assets", "POST", {
            "value": "https://user:secret@app.example.invalid/?token=abc"})
        self.assertEqual(status, 400)

    def test_corrupt_engagement_is_preserved_and_reported(self):
        ident = "corrupt-fixture"
        directory = Path(self.temp.name) / ident
        path = directory / "engagement.json"
        directory.mkdir(exist_ok=True)
        path.write_text("{not valid json", encoding="utf-8")
        try:
            status, state = self.request("/api/state")
            self.assertEqual(status, 200)
            self.assertIn({
                "engagement_id": ident,
                "message": "Record was preserved on disk but could not be loaded",
            }, state["data_warnings"])
            self.assertTrue(path.exists())
        finally:
            path.unlink(missing_ok=True)
            directory.rmdir()

    def test_recorded_owned_loopback_asset_can_run_bounded_check(self):
        origin = f"http://127.0.0.1:{self.demo.server_port}"
        status, engagement = self.request("/api/engagements", "POST", {
            "name": "Custom local lab", "kind": "owned_lab", "authority": "My local synthetic server", "asset": origin})
        self.assertEqual(status, 201)
        _, plan = self.request(f"/api/engagements/{engagement['id']}/plans", "POST", {
            "hypothesis": "Admin route denies a member", "impact": "Unauthorized admin access"})
        path = f"/api/engagements/{engagement['id']}/local-run"
        manifest = {"plan_id": plan["id"], "asset": origin, "primary_path": "/api/me",
                    "control_path": "/api/admin", "expected_control_status": 403,
                    "owned_lab_attested": True}
        status, _ = self.request(path, "POST", {**manifest, "owned_lab_attested": False})
        self.assertEqual(status, 400)
        status, run = self.request(path, "POST", manifest)
        self.assertEqual(status, 201)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["target_origin"], origin)
        self.assertEqual(run["requests_sent"], 2)
        self.assertTrue(run["negative_control_passed"])
        self.assertNotIn('"role": "member"', json.dumps(run))
        status, _ = self.request(path, "POST", {**manifest, "primary_path": "/api/me?token=secret"})
        self.assertEqual(status, 400)
        status, _ = self.request(path, "POST", {**manifest, "asset": f"http://127.0.0.1:{self.app.server_port}"})
        self.assertEqual(status, 400)
        self.request(f"/api/engagements/{engagement['id']}/assets", "POST", {"value": "https://example.invalid"})
        status, _ = self.request(path, "POST", {**manifest, "asset": "https://example.invalid"})
        self.assertEqual(status, 400)

    def test_redirect_stops_before_control_request(self):
        class RedirectLab(BaseHTTPRequestHandler):
            calls = []

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.calls.append(self.path)
                self.send_response(302)
                self.send_header("Location", "https://example.invalid/elsewhere")
                self.end_headers()

        lab = ThreadingHTTPServer(("127.0.0.1", 0), RedirectLab)
        lab.daemon_threads = True
        threading.Thread(target=lab.serve_forever, daemon=True).start()
        try:
            origin = f"http://127.0.0.1:{lab.server_port}"
            _, engagement = self.request("/api/engagements", "POST", {
                "name": "Redirect lab", "kind": "owned_lab", "authority": "Researcher-owned redirect fixture", "asset": origin})
            _, plan = self.request(f"/api/engagements/{engagement['id']}/plans", "POST", {
                "hypothesis": "A redirect stops the check", "impact": "Scope boundary"})
            status, run = self.request(f"/api/engagements/{engagement['id']}/local-run", "POST", {
                "plan_id": plan["id"], "asset": origin, "primary_path": "/redirect",
                "control_path": "/control", "expected_control_status": 404, "owned_lab_attested": True})
            self.assertEqual(status, 201)
            self.assertEqual(run["status"], "stopped")
            self.assertEqual(run["requests_sent"], 1)
            self.assertIsNone(run["negative_control_passed"])
            self.assertEqual(RedirectLab.calls, ["/redirect"])
        finally:
            lab.shutdown()
            lab.server_close()

    def test_intelligence_and_symbolic_sandbox_are_local(self):
        status, found = self.request("/api/intelligence/search", "POST", {"query": "NetScaler"})
        self.assertEqual(status, 200)
        self.assertEqual({"CVE-2026-88771", "CVE-2026-88772"},
                         {record["cve_id"] for record in found["records"]})
        self.assertTrue(all(record["sources"] for record in found["records"]))
        status, example = self.request("/api/sandbox/example")
        self.assertEqual(status, 200)
        status, result = self.request("/api/sandbox/simulate", "POST", {**example, "explore": True})
        self.assertEqual(status, 200)
        self.assertEqual(result["result"], "supported_in_model")
        self.assertEqual([case["goal"] for case in result["cases"]], [True, False])
        self.assertEqual(result["exploration"]["result"], "hypothesis_path_found")
        example["world"]["actions"][0]["command"] = "unreviewed executable text"
        status, _ = self.request("/api/sandbox/simulate", "POST", example)
        self.assertEqual(status, 400)

    def test_ai_draft_uses_only_configured_loopback_model_and_prior_art(self):
        class FakeModel(BaseHTTPRequestHandler):
            requests = []

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.requests.append(("GET", self.path))
                payload = {"data": [{"id": "fixture-model"}]}
                encoded = json.dumps(payload).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(encoded))); self.end_headers()
                self.wfile.write(encoded)

            def do_POST(self):
                self.requests.append(("POST", self.path,
                                      json.loads(self.rfile.read(int(self.headers["Content-Length"])).decode())))
                payload = {"choices": [{"message": {"content": "Hypothesis: verify version and negative control."}}]}
                encoded = json.dumps(payload).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(encoded))); self.end_headers()
                self.wfile.write(encoded)

        model = ThreadingHTTPServer(("127.0.0.1", 0), FakeModel)
        model.daemon_threads = True
        threading.Thread(target=model.serve_forever, daemon=True).start()
        previous_port = self.app.model_port
        self.app.model_port = model.server_port
        try:
            _, example = self.request("/api/sandbox/example")
            status, response = self.request("/api/ai/draft", "POST", {
                "question": "What is the bounded research question?", "prior_art_query": "NetScaler",
                **example})
            self.assertEqual(status, 200)
            self.assertEqual(response["classification"], "unverified")
            self.assertFalse(response["target_traffic"])
            self.assertEqual(response["model"], "fixture-model")
            self.assertEqual(response["sandbox_result"], "supported_in_model")
            self.assertEqual([call[1] for call in FakeModel.requests], ["/v1/models", "/v1/chat/completions"])
            prompt = FakeModel.requests[1][2]["messages"][1]["content"]
            self.assertIn("CVE-2026-88771", prompt)
            self.assertIn("support.citrix.com", prompt)
            self.assertIn("negative_control", prompt)
            self.assertEqual(FakeModel.requests[1][2]["max_tokens"], 1800)
            status, response = self.request("/api/ai/draft", "POST", {
                "question": "What can I test in a synthetic access-control lab?", "prior_art_query": ""})
            self.assertEqual(status, 200)
            self.assertEqual(response["prior_art"], [])
            self.assertNotIn("CVE-", FakeModel.requests[3][2]["messages"][1]["content"])
        finally:
            self.app.model_port = previous_port
            model.shutdown()
            model.server_close()

    def test_ai_draft_is_off_without_explicit_model_port(self):
        self.assertIsNone(self.app.model_port)
        status, state = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertIsNone(state["ai_port"])
        status, response = self.request("/api/ai/draft", "POST", {
            "question": "What could I test in my own lab?"})
        self.assertEqual(status, 400)
        self.assertIn("AI drafting is off", response["error"])


if __name__ == "__main__":
    unittest.main()
