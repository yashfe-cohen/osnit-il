"""Local HTTP API + single-page Hebrew UI (live-updating). Binds to loopback by default."""
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .search import SearchService

INDEX = open(os.path.join(os.path.dirname(__file__), "ui.html"), encoding="utf-8").read()


def entity_detail(store, eid):
    """Everything the DB holds about one entity: where it was seen and what it is linked to."""
    e = store.q1("SELECT * FROM entities WHERE id=?", (eid,))
    if not e:
        return None
    seen = [dict(r) for r in store.q(
        "SELECT s.url, s.title, v.snippet, v.confidence, v.first_seen, v.last_seen FROM evidence v "
        "JOIN sources s ON s.id=v.source_id WHERE v.entity_id=? ORDER BY v.last_seen DESC LIMIT 30", (eid,))]
    links = [dict(r) for r in store.q(
        "SELECT o.id, o.type, o.display, r.kind, MAX(re.confidence) confidence, COUNT(DISTINCT re.source_id) sources, "
        "MIN(re.first_seen) first_seen, MAX(re.last_seen) last_seen, "
        "(SELECT s.url FROM sources s WHERE s.id=re.source_id) url "
        "FROM relations r JOIN rel_evidence re ON re.relation_id=r.id "
        "JOIN entities o ON o.id = CASE WHEN r.a_id=? THEN r.b_id ELSE r.a_id END "
        "WHERE r.a_id=? OR r.b_id=? GROUP BY o.id, r.kind ORDER BY confidence DESC LIMIT 100", (eid, eid, eid))]
    aliases = [r["alias"] for r in store.q("SELECT alias FROM aliases WHERE entity_id=?", (eid,))]
    from .linking import attributes_of, connections, origins_of
    return dict(entity=dict(e), aliases=aliases, seen=seen, links=links, attributes=attributes_of(store, [eid]),
                origins=origins_of(store, eid), connections=connections(store, eid))


def types_catalog(store):
    from .semantic import TYPES
    return dict(builtin=[dict(key=t.key, label=t.label, group=t.group, entity=t.entity) for t in TYPES.values()],
                custom=store.custom_type_rows())


def fields_catalog(store):
    """Everything the system knows about column names: learned/taught headers, and the fields kept so far."""
    from .semantic import Registry, header_label
    reg = Registry(store.custom_types())
    mem = [dict(r, label="🚫 לא לשמור" if r["type"] == "skip" else reg.label(r["type"])) for r in store.q("SELECT * FROM field_memory ORDER BY source DESC, hits DESC")]
    kept = [dict(r, label=reg.label(r["kind"]) if r["kind"] and r["kind"] != "unknown" else (header_label(r["name"]) or "לא מזוהה"))
            for r in store.q("SELECT name, kind, COUNT(*) n, COUNT(DISTINCT entity_id) entities, "
                             "(SELECT value FROM attributes a2 WHERE a2.name=a.name LIMIT 1) example "
                             "FROM attributes a GROUP BY name, kind ORDER BY entities DESC LIMIT 300")]
    return dict(memory=mem, kept=kept)


def _safe_name(s):
    s = re.sub(r"[\x00-\x1f/\\]+", "_", str(s)).strip()[:120]
    return s


def make_server(svc: SearchService, host="127.0.0.1", port=8080, token=None, queue=None):
    store = svc.store

    class Handler(BaseHTTPRequestHandler):
        server_version = "osnit"

        def log_message(self, *a):
            pass

        def handle_one_request(self):
            # the browser closing a tab / navigating away aborts an open request (common on the live SSE
            # stream and the dashboard poll). That is normal, not an error — swallow the socket exception.
            try:
                super().handle_one_request()
            except (ConnectionError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError):
                self.close_connection = True

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
            m = re.fullmatch(r"/api/subjects/(\d+)(?:/(events|stream|export))?", u.path)
            if u.path == "/api/stats":
                provs = sorted(svc.engine.providers)
                return self._send(200, {**store.stats(), "paused": svc.engine.is_paused, "providers": provs,
                                        "web_search": any(p != "archive" for p in provs)})
            if u.path == "/api/dashboard":
                from .analytics import dashboard
                return self._send(200, dashboard(store))
            if u.path == "/api/imports":
                return self._send(200, queue.list() if queue else [])
            mi = re.fullmatch(r"/api/imports/(\d+)", u.path)
            if mi:
                d = queue.detail(int(mi.group(1))) if queue else None
                return self._send(200 if d else 404, d or {"error": "not found"})
            if u.path == "/api/types":
                return self._send(200, types_catalog(store))
            if u.path == "/api/dossier":
                from .identity import dossier
                eid, name = (q.get("eid") or [""])[0], (q.get("name") or [""])[0].strip()[:120]
                return self._send(200, dossier(store, int(eid) if eid.isdigit() else None, name or None))
            if u.path == "/api/fields":
                return self._send(200, fields_catalog(store))
            if u.path == "/api/contacts":
                from .contacts import contacts
                return self._send(200, contacts(store, (q.get("q") or [""])[0],
                                   (q.get("contactable") or [""])[0] in ("1", "true"),
                                   min(int((q.get("limit") or ["500"])[0]), 2000),
                                   int((q.get("offset") or ["0"])[0])))
            if u.path == "/api/contacts/export":
                from .contacts import contacts_csv
                body = contacts_csv(store, (q.get("q") or [""])[0],
                                    (q.get("contactable") or [""])[0] in ("1", "true")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="osnit-contacts.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if u.path == "/api/subjects":
                return self._send(200, [dict(r) for r in store.q(
                    "SELECT s.id,s.query,s.kind,s.status,s.created,s.rounds,"
                    "(SELECT COUNT(*) FROM events e WHERE e.subject_id=s.id AND e.kind='finding') findings,"
                    "(SELECT MAX(at) FROM events e WHERE e.subject_id=s.id) last_event "
                    "FROM subjects s ORDER BY id DESC LIMIT 200")])
            if u.path == "/api/overview":
                return self._send(200, dict(
                    stats=store.stats(),
                    sources=[dict(r) for r in store.q(
                        "SELECT id,url,title,kind,page_type,hit,last_scanned,state FROM sources "
                        "WHERE state IN ('scanned','imported') ORDER BY last_scanned DESC LIMIT 25")],
                    entities=[dict(r) for r in store.q(
                        "SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                        "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources "
                        "FROM entities e WHERE e.type IN ('person','org') ORDER BY e.last_seen DESC LIMIT 25")]))
            if u.path == "/api/entities":
                like = f"%{(q.get('q') or [''])[0]}%"
                typ = (q.get("type") or [""])[0]
                rows = store.q("SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                               "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources "
                               "FROM entities e WHERE (e.display LIKE ? OR e.key LIKE ? OR (length(?)>3 AND e.id IN "
                               "(SELECT entity_id FROM attributes WHERE value LIKE ?))) AND (?='' OR e.type=?) "
                               "ORDER BY sources DESC, e.last_seen DESC LIMIT 100", (like, like.lower(), like, like, typ, typ))
                return self._send(200, [dict(r) for r in rows])
            me = re.fullmatch(r"/api/entities/(\d+)", u.path)
            if me:
                return self._send(200, entity_detail(store, int(me.group(1))) or {"error": "not found"})
            if m:
                sid = int(m.group(1))
                if m.group(2) == "events":
                    return self._send(200, svc.events(sid, int((q.get("after") or ["0"])[0])))
                if m.group(2) == "stream":
                    return self._stream(sid, int((q.get("after") or ["0"])[0]))
                if m.group(2) == "export":
                    return self._export(sid, (q.get("format") or ["json"])[0])
                since = (q.get("since") or [None])[0]
                prof = svc.profile(sid, float(since) if since else None)
                return self._send(200 if prof else 404, prof or {"error": "not found"})
            self._send(404, {"error": "not found"})

        def _stream(self, sid, after):
            """Server-Sent Events: pushes each new subject event as it is written; the page re-reads the profile."""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            last_beat, end = time.time(), time.time() + 1800   # the browser reconnects after this
            try:
                self.wfile.write(b"retry: 3000\n\n")
                while time.time() < end:
                    evs = svc.events(sid, after)
                    if evs:
                        after = evs[-1]["id"]
                        body = json.dumps(evs, ensure_ascii=False)
                        self.wfile.write(f"id: {after}\nevent: update\ndata: {body}\n\n".encode())
                        self.wfile.flush()
                    elif time.time() - last_beat > 15:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                        last_beat = time.time()
                    time.sleep(1.0)
            except (ConnectionError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError, OSError):
                pass

        def _export(self, sid, fmt):
            from .export import profile_csv
            prof = svc.profile(sid)
            if not prof:
                return self._send(404, {"error": "not found"})
            name = f"osnit-subject-{sid}"
            if fmt == "csv":
                body, ctype, ext = profile_csv(prof).encode("utf-8"), "text/csv; charset=utf-8", "csv"
            else:
                body, ctype, ext = json.dumps(prof, ensure_ascii=False, indent=1).encode(), "application/json; charset=utf-8", "json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{name}.{ext}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            u = urlsplit(self.path)
            if not self._authed(parse_qs(u.query)):
                return self._send(401, {"error": "unauthorized"})
            if not self._same_origin():
                return self._send(403, {"error": "forbidden"})
            if u.path == "/api/upload":
                return self._upload(parse_qs(u.query))
            if "application/json" not in self.headers.get("Content-Type", ""):
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
            r = self._post_data(u.path, data)
            if r is not None:
                return self._send(*r)
            if u.path == "/api/pause":
                svc.engine.pause()
                return self._send(200, {"paused": True})
            if u.path == "/api/resume":
                svc.engine.resume()
                return self._send(200, {"paused": False})
            self._send(404, {"error": "not found"})

        def _post_data(self, path, data):
            """Imports, reset, information types and field names. Returns (code, body) or None."""
            m = re.fullmatch(r"/api/imports/(\d+)/(approve|reanalyze|preview|purge)", path)
            if m:
                if not queue:
                    return 503, {"error": "import queue not running"}
                jid, act = int(m.group(1)), m.group(2)
                ov = data.get("overrides")
                if ov is not None and not (isinstance(ov, dict) and all(isinstance(v, dict) for v in ov.values())):
                    return 400, {"error": "overrides must be {table: {column: type}}"}
                if act == "approve":
                    return (200, {"ok": True}) if queue.approve(jid, ov, bool(data.get("teach"))) else (409, {"error": "not waiting"})
                if act == "preview":       # live re-catalogue from the stored sample rows (no file read)
                    a = queue.repreview(jid, ov)
                    return (200, a) if a else (404, {"error": "no analysis to update"})
                if act == "reanalyze":
                    a = queue.reanalyze(jid, ov)
                    return (200, a) if a else (404, {"error": "file not available"})
                try:
                    res = queue.purge(jid, delete_file=data.get("delete_file", True))
                except RuntimeError as e:
                    return 409, {"error": str(e)}
                return (200, res) if res is not None else (404, {"error": "not found"})
            if path == "/api/reset":
                scope = data.get("scope")
                if scope not in ("files", "web", "all"):
                    return 400, {"error": "scope must be files, web or all"}
                if str(data.get("confirm", "")).strip() != str(svc.engine.cfg.reset_code):
                    return 403, {"error": "קוד איפוס שגוי"}
                return 200, store.reset(scope)
            if path == "/api/types":
                from .semantic import custom_key, pattern_from_examples, CustomType
                label = str(data.get("label", "")).strip()[:60]
                if not label:
                    return 400, {"error": "label required"}
                headers = [str(h).strip()[:60] for h in (data.get("headers") or []) if str(h).strip()][:30]
                examples = [str(x).strip()[:120] for x in (data.get("examples") or []) if str(x).strip()][:30]
                pattern = str(data.get("pattern") or "").strip()[:300] or pattern_from_examples(examples)
                if not pattern and not headers:
                    return 400, {"error": "give header names, examples or a pattern"}
                try:
                    re.compile(pattern)
                except re.error as e:
                    return 400, {"error": f"bad pattern: {e}"}
                key = str(data.get("key") or custom_key(label))
                if not key.startswith("u_"):
                    return 400, {"error": "bad key"}
                ct = CustomType(key, label, tuple(headers), pattern)
                store.save_custom_type(key, label, headers, pattern, examples, data.get("identifier", True),
                                       data.get("sensitive", False))
                return 200, dict(key=key, pattern=pattern, examples=[dict(value=x, matches=ct.matches(x)) for x in examples])
            mt = re.fullmatch(r"/api/types/(u_\w+)/delete", path)
            if mt:
                store.delete_custom_type(mt.group(1))
                return 200, {"ok": True}
            if path == "/api/fields":
                from .semantic import header_key
                h, t = str(data.get("header", "")).strip(), str(data.get("type", "")).strip()
                if not h or not t:
                    return 400, {"error": "header and type required"}
                store.learn_fields([(header_key(h), h, t)], source="user")
                return 200, {"ok": True}
            if path == "/api/fields/delete":
                store.forget_field(str(data.get("header_key", "")))
                return 200, {"ok": True}
            return None

        def _upload(self, q):
            """Stream one raw file body to the inbox (filename in X-Filename) and queue it for import."""
            if not queue:
                return self._send(503, {"error": "import queue not running"})
            import os as _os
            import re as _re
            import time as _time
            from urllib.parse import unquote
            shown = _safe_name(unquote(self.headers.get("X-Filename", "upload.bin"))) or "upload.bin"
            name = shown
            name = _re.sub(r"[^\w.\-]+", "_", _os.path.basename(name))[:120] or "upload.bin"
            total = int(self.headers.get("Content-Length", 0))
            if total > 2 * 1024 ** 3:
                return self._send(413, {"error": "file too large (max 2GB per upload)"})
            dest = _os.path.join(queue.inbox, f"{int(_time.time()*1000)}_{name}")
            got = 0
            try:
                with open(dest, "wb") as f:
                    while got < total:
                        chunk = self.rfile.read(min(1 << 20, total - got))
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
            except OSError as e:
                return self._send(500, {"error": f"write failed: {e}"})
            delete = (q.get("delete_raw") or ["1"])[0] not in ("0", "false", "")
            review = (q.get("review") or ["0"])[0] in ("1", "true")
            res = queue.add_file(dest, name=shown, delete_raw=delete, move=True, review=review)
            return self._send(200, res)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            # backstop: a dropped client connection is not a server error worth a traceback
            import sys
            if not isinstance(sys.exc_info()[1], (ConnectionError, ConnectionResetError, ConnectionAbortedError,
                                                  BrokenPipeError, TimeoutError)):
                super().handle_error(request, client_address)

    return Server((host, port), Handler)


def serve_in_thread(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
