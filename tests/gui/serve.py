#!/usr/bin/env python3
"""serve.py — the GUI as the real server serves it, with recorded API answers.

    python3 tests/gui/serve.py [--port 8431]

For the visual check (visual.js) on a machine with no Agenti on it, such as
a CI runner: the pages, scripts and styles come straight from shared/gui/,
with the real server's security headers, and every API call is answered from
fixtures/<signed-in|signed-out>.json (recorded from a live box by record.js).
A request carrying the cookie gui-test=signed-in gets the signed-in answers.

Nothing here is the API: an unknown call is a 404 that is also listed at
GET /__misses (the visual check fails on any), so a page that starts calling
something new shows up as "record the fixtures again", not as a blank page.
"""
import json
import mimetypes
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
# AGENTI_GUI_DIR: another copy of the pages (the check's own self-test breaks one on purpose).
GUI = Path(os.environ.get("AGENTI_GUI_DIR") or HERE.parent.parent / "shared" / "gui").resolve()
FIXTURES = {who: json.loads((HERE / "fixtures" / f"{who}.json").read_text())["answers"]
            for who in ("signed-in", "signed-out")}
# The real server's headers (shared/api/main.py, _security_headers), so a
# page that would break under them breaks here too.
HEADERS = {"Content-Security-Policy": "frame-ancestors 'self'", "X-Frame-Options": "SAMEORIGIN",
           "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"}
MISSES: list = []
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, status, body, ctype):
        self.send_response(status)
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _who(self):
        return "signed-in" if "gui-test=signed-in" in (self.headers.get("Cookie") or "") else "signed-out"

    def _answer(self):
        url = urlsplit(self.path)
        path = unquote(url.path)
        if path == "/__misses":
            with _lock:
                return self._send(200, json.dumps(MISSES).encode(), "application/json")
        if self.command in ("GET", "HEAD"):
            rel = "index.html" if path == "/" else path.lstrip("/")
            f = (GUI / rel).resolve()
            if f.is_file() and GUI in f.parents:
                return self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        answers = FIXTURES[self._who()]
        key = f"{self.command} {path}" + (f"?{url.query}" if url.query else "")
        hit = answers.get(key) or answers.get(f"{self.command} {path}")
        if hit is None:
            with _lock:
                MISSES.append({"as": self._who(), "request": key})
            return self._send(404, b'{"detail":"not recorded (tests/gui/record.js)"}', "application/json")
        return self._send(hit["status"], json.dumps(hit["body"]).encode(), "application/json")

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _answer


def main(argv):
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 8431
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serving shared/gui with recorded answers on http://127.0.0.1:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
