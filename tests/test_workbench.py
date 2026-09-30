import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
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


if __name__ == "__main__":
    unittest.main()
