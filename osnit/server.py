"""Local HTTP API + single-page Hebrew UI (live-updating). Binds to loopback by default."""
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .search import SearchService

INDEX = open(os.path.join(os.path.dirname(__file__), "ui.html"), encoding="utf-8").read()


def make_server(svc: SearchService, host="127.0.0.1", port=8080, token=None):
    store = svc.store

    class Handler(BaseHTTPRequestHandler):
        server_version = "osnit"

        def log_message(self, *a):
            pass

        def _send(self, code, obj, ctype="application/json; charset=utf-8"):
            body = (obj if isinstance(obj, (bytes, str)) else json.dumps(obj, ensure_ascii=False)).encode() \
                if not isinstance(obj, bytes) else obj
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _authed(self, q):
            if not token:
                return True
            got = self.headers.get("Authorization", "").removeprefix("Bearer ") or (q.get("token") or [""])[0]
            return got == token

        def _same_origin(self):
            o = self.headers.get("Origin")
            return not o or urlsplit(o).netloc == self.headers.get("Host")

        def do_GET(self):
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            if u.path == "/":
                return self._send(200, INDEX, "text/html; charset=utf-8")
            if not self._authed(q):
                return self._send(401, {"error": "unauthorized"})
            m = re.fullmatch(r"/api/subjects/(\d+)(?:/(events))?", u.path)
            if u.path == "/api/stats":
                return self._send(200, store.stats())
            if u.path == "/api/subjects":
                return self._send(200, [dict(r) for r in store.q(
                    "SELECT id,query,kind,status,created,rounds FROM subjects ORDER BY id DESC LIMIT 100")])
            if u.path == "/api/entities":
                like = f"%{(q.get('q') or [''])[0]}%"
                rows = store.q("SELECT id,type,display,first_seen,last_seen FROM entities WHERE display LIKE ? OR key LIKE ? "
                               "ORDER BY last_seen DESC LIMIT 50", (like, like))
                return self._send(200, [dict(r) for r in rows])
            if m:
                sid = int(m.group(1))
                if m.group(2):
                    return self._send(200, svc.events(sid, int((q.get("after") or ["0"])[0])))
                since = (q.get("since") or [None])[0]
                prof = svc.profile(sid, float(since) if since else None)
                return self._send(200 if prof else 404, prof or {"error": "not found"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            u = urlsplit(self.path)
            if not self._authed(parse_qs(u.query)):
                return self._send(401, {"error": "unauthorized"})
            if not self._same_origin() or "application/json" not in self.headers.get("Content-Type", ""):
                return self._send(403, {"error": "forbidden"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            if u.path == "/api/search":
                qy = str(data.get("query", "")).strip()
                if not qy or len(qy) > 200:
                    return self._send(400, {"error": "query required (<=200 chars)"})
                hrs = data.get("hours")
                return self._send(200, svc.search(qy, data.get("kind"), float(hrs) if hrs else None))
            m = re.fullmatch(r"/api/subjects/(\d+)/stop", u.path)
            if m:
                svc.stop(int(m.group(1)))
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def serve_in_thread(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
