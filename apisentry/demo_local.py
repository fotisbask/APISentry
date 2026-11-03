"""Run a reproducible assessment against a temporary loopback-only lab.

All records and credentials are synthetic. The server stops after the scan.
No external network access or additional dependencies are needed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit


class DemoHandler(BaseHTTPRequestHandler):
    """Serve deliberately weak configuration and two fictional user records."""

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        status = 200
        if path == "/":
            content_type = "text/html; charset=utf-8"
            body = b'<!doctype html><html><title>APISentry local lab</title><h1>Synthetic test data only</h1><script src="/app.js"></script></html>'
        elif path == "/app.js":
            content_type = "application/javascript"
            body = b'const api_key = "DEMO_ONLY_NOT_A_REAL_SECRET_12345"; const endpoint = "/api/users/1";'
        elif path in {"/api/users/1", "/api/users/2"}:
            content_type = "application/json"
            identifier = int(path.rsplit("/", 1)[1])
            body = json.dumps({"id": identifier, "name": f"Fictional User {identifier}",
                               "demo": True}).encode("utf-8")
        else:
            status, content_type, body = 404, "application/json", b'{"error":"Not found"}'
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Deliberately reflect Origin and omit security headers for the lab.
        if origin := self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[local lab] {format % args}", flush=True)


def main() -> int:
    root = Path(__file__).resolve().parent
    # Port 0 lets the OS choose an available port; never listen on all interfaces.
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    target = f"http://127.0.0.1:{server.server_port}"
    print(f"Temporary local lab: {target}", flush=True)
    try:
        completed = subprocess.run(
            [sys.executable, str(root / "main.py"), "--target", target,
             "--bola", "--max-bola-checks", "1", "--concurrency", "1",
             "--delay", "0.1", "--max-requests", "10",
             "--output", str(root / "reports" / "local-demo.html")],
            cwd=root, check=False,
        )
        print("Expected: High 1, Medium 5, Low 1; requests 5; coverage errors 0.")
        print("These are intentional lab findings, not vulnerabilities in your computer.")
        # APISentry's code 1 means findings, which is expected in this lab.
        return 0 if completed.returncode == 1 else 2
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
        print("Local lab stopped.")


if __name__ == "__main__":
    raise SystemExit(main())
