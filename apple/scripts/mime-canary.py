# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Literal-loopback request canary for the hostile HTML feasibility gate."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock


class RequestCounter:
    """Thread-safe request counter with explicit control endpoints."""

    def __init__(self) -> None:
        self._count = 0
        self._lock = Lock()

    def increment(self) -> int:
        with self._lock:
            self._count += 1
            return self._count

    def reset(self) -> None:
        with self._lock:
            self._count = 0

    def read(self) -> int:
        with self._lock:
            return self._count


def handler_for(counter: RequestCounter) -> type[BaseHTTPRequestHandler]:
    """Builds a handler whose control endpoints never count as probe hits."""

    class CanaryHandler(BaseHTTPRequestHandler):
        server_version = "TersaMimeCanary/1"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/control/count":
                self._reply({"count": counter.read()})
                return
            if self.path == "/control/reset":
                counter.reset()
                self._reply({"count": 0})
                return
            counter.increment()
            self._reply({"accepted": True})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            counter.increment()
            self._reply({"accepted": True})

        def log_message(self, format: str, *args: object) -> None:
            return

        def _reply(self, payload: dict[str, object]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return CanaryHandler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True, type=Path)
    arguments = parser.parse_args()
    counter = RequestCounter()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(counter))
    arguments.port_file.write_text(str(server.server_port), encoding="ascii")
    server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
