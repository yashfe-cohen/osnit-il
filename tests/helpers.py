import http.server
import os
import tempfile
import threading

from osnit.config import Config
from osnit.engine import Engine
from osnit.search import SearchService
from osnit.store import Store

PAGES = {}


class H(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        H.hits.append(self.path)
        if self.path == "/robots.txt":
            body, ct = b"User-agent: *\nDisallow: /private\n", "text/plain"
        elif self.path in PAGES:
            body, ct = PAGES[self.path]
            body = body if isinstance(body, bytes) else body.encode("utf-8")
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeProvider:
    name = "fake"
    plain = False

    def __init__(self, urls):
        self.urls, self.calls = urls, []

    def search(self, query, limit):
        self.calls.append(query)
        return self.urls


def make(provider_urls=()):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    db = os.path.join(tempfile.mkdtemp(), "t.db")    # file db: shared-cache :memory: has table-level locks
    cfg = Config(db_path=db, request_delay=0, allow_private_hosts=True, workers=2)
    store = Store(db)
    prov = FakeProvider([base + p for p in provider_urls])
    eng = Engine(store, cfg, providers={"fake": prov})
    return srv, base, store, eng, SearchService(eng), prov
