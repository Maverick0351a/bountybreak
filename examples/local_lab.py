"""Small researcher-owned target for trying the recorded-URL check."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/api/me":
            status, body = 200, b'{"role":"member"}'
        elif self.path == "/api/admin":
            status, body = 403, b'{"error":"forbidden"}'
        else:
            status, body = 404, b'{"error":"not_found"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Synthetic loopback target")
    parser.add_argument("--port", type=int, default=8866)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024–65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Synthetic lab: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
