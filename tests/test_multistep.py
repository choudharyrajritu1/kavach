from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.exploit.llm_generator import LlmExploitGenerator, LlmExploitPlan  # noqa: E402


def _make_server():
    """A 2-step lab: /token issues a one-time token; /run needs it to reveal flag."""
    state = {"token": "tok-abc123"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): return

        def do_GET(self):
            if self.path == "/token":
                body = f'{{"token": "{state["token"]}"}}'.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path.startswith("/run"):
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                if q.get("t", [""])[0] == state["token"]:
                    body = b"KAVACHCAP[KAVACH_FLAG{multi-step-win}]KAVACHEND"
                else:
                    body = b"forbidden"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404); self.end_headers(); self.wfile.write(b"x")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class MultiStepExploitTest(unittest.TestCase):
    def test_token_extraction_chain(self) -> None:
        httpd = _make_server()
        port = httpd.server_address[1]
        base = f"http://127.0.0.1:{port}"
        try:
            gen = LlmExploitGenerator(object(), {"llm_mode": "live"})
            plan = LlmExploitPlan(
                reasoning="grab token then use it",
                steps=[
                    {"method": "GET", "url": f"{base}/token", "body": "", "headers": {},
                     "extract": [{"name": "t", "from": "json", "json_path": "token"}]},
                    {"method": "GET", "url": f"{base}/run?t={{{{t}}}}", "body": "", "headers": {},
                     "extract": []},
                ],
            )
            result = gen.execute(plan, flag="KAVACH_FLAG{multi-step-win}")
            self.assertTrue(result.success)
            self.assertEqual(result.flag_captured, "KAVACH_FLAG{multi-step-win}")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
