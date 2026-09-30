"""Local, dependency-free research desk. No live bounty traffic is implemented."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_BODY = 16_384
MAX_RECORDS = 200
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TOOLS = [
    {"name": "OWASP ZAP", "role": "Proxy and application testing", "mode": "manual", "link": "https://www.zaproxy.org/"},
    {"name": "Nuclei", "role": "Template checks", "mode": "gated external tool", "link": "https://github.com/projectdiscovery/nuclei"},
    {"name": "ffuf", "role": "Content discovery", "mode": "gated external tool", "link": "https://github.com/ffuf/ffuf"},
    {"name": "Shannon", "role": "Autonomous application testing", "mode": "lab only here", "link": "https://github.com/KeygraphHQ/shannon"},
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected text")
    value = value.strip()
    if not value or len(value) > limit or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"Text must be 1–{limit} printable characters")
    return value


def slug_for(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:42].strip("-")
    return f"{base or 'engagement'}-{uuid.uuid4().hex[:8]}"


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


class Store:
    def __init__(self, data_dir: Path):
        self.directory = data_dir.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def _path(self, ident: str) -> Path:
        if not SLUG.fullmatch(ident):
            raise ValueError("Invalid engagement ID")
        return self.directory / ident / "engagement.json"

    def list(self) -> list[dict]:
        with self.lock:
            result = []
            for path in sorted(self.directory.glob("*/engagement.json")):
                if SLUG.fullmatch(path.parent.name):
                    try:
                        result.append(json.loads(path.read_text(encoding="utf-8")))
                    except (OSError, json.JSONDecodeError):
                        continue
            return sorted(result, key=lambda item: item.get("created_at", ""), reverse=True)

    def get(self, ident: str) -> dict:
        with self.lock:
            try:
                return json.loads(self._path(ident).read_text(encoding="utf-8"))
            except FileNotFoundError:
                raise ValueError("Engagement not found") from None

    def create(self, name: str, kind: str, authority: str) -> dict:
        if kind not in ("bounty", "internal", "owned_lab"):
            raise ValueError("Invalid engagement kind")
        with self.lock:
            if len(self.list()) >= MAX_RECORDS:
                raise ValueError("Engagement limit reached")
            item = {"id": slug_for(name), "name": name, "kind": kind,
                    "authority": authority, "created_at": now(), "plans": [], "runs": []}
            save_json(self._path(item["id"]), item)
            return item

    def add_plan(self, ident: str, hypothesis: str, impact: str) -> dict:
        with self.lock:
            item = self.get(ident)
            if len(item["plans"]) >= MAX_RECORDS:
                raise ValueError("Plan limit reached")
            plan = {"id": uuid.uuid4().hex[:12], "hypothesis": hypothesis,
                    "impact": impact, "created_at": now(), "status": "planning"}
            item["plans"].append(plan)
            save_json(self._path(ident), item)
            return plan

    def add_run(self, ident: str, plan_id: str, evidence: dict) -> dict:
        with self.lock:
            item = self.get(ident)
            if not any(p["id"] == plan_id for p in item["plans"]):
                raise ValueError("Plan not found")
            if len(item["runs"]) >= MAX_RECORDS:
                raise ValueError("Run limit reached")
            record = {"id": uuid.uuid4().hex[:12], "plan_id": plan_id,
                      "created_at": now(), **evidence}
            item["runs"].append(record)
            save_json(self._path(ident), item)
            return record


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/api/me":
            status, body = 200, b'{"user":"researcher","role":"member"}'
        elif self.path == "/api/admin":
            status, body = 403, b'{"error":"forbidden"}'
        else:
            status, body = 404, b'{"error":"not_found"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def demo_check(port: int) -> dict:
    """Two fixed requests to the bundled loopback lab. No user URL or redirect is used."""
    results = []
    for path in ("/api/me", "/api/admin"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
            response = connection.getresponse()
            body = response.read(4097)
            if len(body) > 4096 or response.status in (429,) or response.status >= 500:
                raise RuntimeError("Lab returned an error or oversized response; run stopped")
            if 300 <= response.status < 400:
                raise RuntimeError("Lab redirected; run stopped")
            results.append({"path": path, "status": response.status,
                            "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()})
        finally:
            connection.close()
        if path == "/api/me":
            time.sleep(0.5)
    return {"environment": "bundled researcher-owned loopback lab", "request_budget": 2,
            "requests_sent": len(results), "observations": results,
            "negative_control_passed": results[1]["status"] == 403,
            "finding": "No vulnerability demonstrated", "classification": "observed"}


class AppHandler(BaseHTTPRequestHandler):
    server: "AppServer"

    def log_message(self, *_args):
        pass

    def _headers(self, status: int, mime: str, size: int):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def _json(self, status: int, value: object):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def _route(self) -> list[str]:
        path = urlsplit(self.path)
        if path.query or path.fragment or "%" in path.path or "//" in path.path:
            raise ValueError("Invalid route")
        return [part for part in path.path.split("/") if part]

    def do_GET(self):
        if not self._host_ok():
            self._json(403, {"error": "Host not allowed"})
            return
        try:
            route = self._route()
            if route == ["api", "state"]:
                self._json(200, {"engagements": self.server.store.list(), "tools": TOOLS,
                                 "demo_ready": True, "csrf": self.server.csrf})
            elif len(route) == 3 and route[:2] == ["api", "engagements"]:
                self._json(200, self.server.store.get(route[2]))
            elif route in ([], ["index.html"], ["app.js"], ["style.css"]):
                filename = "index.html" if not route else route[0]
                mime = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
                        "style.css": "text/css; charset=utf-8"}[filename]
                body = (STATIC / filename).read_bytes()
                self._headers(200, mime, len(body))
                self.wfile.write(body)
            else:
                self._json(404, {"error": "Not found"})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})

    def do_POST(self):
        if not self._host_ok() or self.headers.get("Origin") != f"http://127.0.0.1:{self.server.server_port}":
            self._json(403, {"error": "Origin not allowed"})
            return
        if self.headers.get("X-CSRF-Token") != self.server.csrf:
            self._json(403, {"error": "Invalid CSRF token"})
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= size <= MAX_BODY or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("Invalid request body")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Expected JSON object")
            route = self._route()
            if route == ["api", "engagements"]:
                item = self.server.store.create(clean_text(payload.get("name"), 100),
                    payload.get("kind"), clean_text(payload.get("authority"), 500))
                self._json(201, item)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "plans":
                plan = self.server.store.add_plan(route[2], clean_text(payload.get("hypothesis"), 500),
                                                  clean_text(payload.get("impact"), 300))
                self._json(201, plan)
            elif len(route) == 4 and route[:2] == ["api", "engagements"] and route[3] == "demo-run":
                ident = route[2]
                item = self.server.store.get(ident)
                if item["kind"] != "owned_lab":
                    raise ValueError("Demo runs require an owned-lab engagement")
                plan_id = clean_text(payload.get("plan_id"), 12)
                if not any(plan["id"] == plan_id for plan in item["plans"]):
                    raise ValueError("Plan not found")
                if not self.server.run_lock.acquire(blocking=False):
                    self._json(409, {"error": "Another demo run is active"})
                    return
                try:
                    evidence = demo_check(self.server.demo_port)
                    run = self.server.store.add_run(ident, plan_id, evidence)
                finally:
                    self.server.run_lock.release()
                self._json(201, run)
            else:
                self._json(404, {"error": "Not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except (OSError, RuntimeError, http.client.HTTPException):
            self._json(503, {"error": "Demo lab failed or stopped. No result was saved."})


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store: Store, demo_port: int):
        super().__init__(address, AppHandler)
        self.store = store
        self.demo_port = demo_port
        self.csrf = secrets.token_urlsafe(32)
        self.run_lock = threading.Lock()


def main():
    parser = argparse.ArgumentParser(description="Local bounty research desk")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024–65535")
    demo = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    demo.daemon_threads = True
    threading.Thread(target=demo.serve_forever, daemon=True).start()
    app = AppServer(("127.0.0.1", args.port), Store(args.data_dir), demo.server_port)
    print(f"Bounty Workbench: http://127.0.0.1:{app.server_port}/", flush=True)
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.server_close()
        demo.shutdown()
        demo.server_close()


if __name__ == "__main__":
    main()
