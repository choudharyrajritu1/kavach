"""A deliberately-vulnerable HTTP service used as the local exploit "twin".

WARNING: This code is intentionally insecure. It is a security test fixture.
Do NOT deploy it, expose it to a network, or copy its patterns into real code.

It supports two variants so the Judge can run a twin comparison:
  - VULNERABLE: a command-injection sink that lets a PoC read the planted flag.
  - PATCHED:    the same endpoint with input validation that blocks the PoC.

The server binds to 127.0.0.1 only.
"""
from __future__ import annotations

import errno
import subprocess
import threading
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class VulnClass(str, Enum):
    COMMAND_INJECTION = "command_injection"


class LabServer:
    """Runs the vulnerable app on a loopback port in a background thread."""

    def __init__(
        self,
        flag: str,
        *,
        patched: bool = False,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.flag = flag
        self.patched = patched
        self.host = host
        self._port = port  # 0 = OS picks a free port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        assert self._httpd is not None, "server not started"
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "LabServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> None:
        handler = _make_handler(flag=self.flag, patched=self.patched)
        try:
            self._httpd = ThreadingHTTPServer((self.host, self._port), handler)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE and self._port != 0:
                # Requested port busy — fall back to an ephemeral port.
                self._httpd = ThreadingHTTPServer((self.host, 0), handler)
            else:
                raise
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _make_handler(*, flag: str, patched: bool):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # silence access logs
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                return self._send(200, "ok")
            if parsed.path != "/api/ping":
                return self._send(404, "not found")

            params = parse_qs(parsed.query)
            host = (params.get("host") or [""])[0]

            if patched:
                # FIX: strict allowlist for the host parameter.
                if not host or not all(c.isalnum() or c in ".-" for c in host):
                    return self._send(400, "invalid host")
                return self._send(200, f"PING {host}: ok")

            # VULNERABLE: user input is concatenated into a shell command.
            # The planted flag lives in an env var the command can reach.
            cmd = f"echo pinging {host}"
            try:
                out = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env={"KAVACH_FLAG": flag, "PATH": "/usr/bin:/bin"},
                )
                body = out.stdout + out.stderr
            except subprocess.SubprocessError as exc:  # pragma: no cover
                body = f"error: {exc}"
            return self._send(200, body)

        def _send(self, code: int, body: str) -> None:
            data = body.encode("utf-8", "replace")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler
