"""Local HTTP API + single-page Hebrew UI (live-updating). Binds to loopback by default."""
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .search import SearchService
from .contacts import cap_lists, linked_exists

with open(os.path.join(os.path.dirname(__file__), "ui.html"), encoding="utf-8") as _ui_f:
    INDEX = _ui_f.read()


def page_view(prof):
    """An investigation profile as the page draws it: without the per-source identity packs (the CSV/JSON
    exports and API callers still get them), which on a common name were most of a multi-MB response."""
    out = dict(prof)
    out["identities"] = []
    out["unattributed"] = None
    return out


def entity_detail(store, eid):
    """Everything the DB holds about one entity: where it was seen and what it is linked to."""
    e = store.q1("SELECT * FROM entities WHERE id=?", (eid,))
    if not e:
        return None
    from .linking import attributes_of, connections, origins_of
    kinship = []
    c_eids = [eid]
    if e["type"] == "person":
        try:
            from .identity import dossier
            dos = dossier(store, eid=eid)
            kinship = dos.get("kinship", [])
            for cl in dos.get("clusters", []):
                c_rec_ids = [r["id"] for r in cl.get("records", []) if r.get("id")]
                if eid in c_rec_ids or len(dos.get("clusters", [])) == 1:
                    for rid in c_rec_ids:
                        if rid not in c_eids:
                            c_eids.append(rid)
        except Exception:
            kinship = []
    ph = ",".join("?" * len(c_eids))
    seen = [dict(r) for r in store.q(
        f"SELECT s.url, s.title, COALESCE(v.snippet, (SELECT substr(text, 1, 300) FROM records WHERE id=v.record_id)) snippet, v.confidence, v.first_seen, v.last_seen FROM evidence v "
        f"JOIN sources s ON s.id=v.source_id WHERE v.entity_id IN ({ph}) ORDER BY v.last_seen DESC LIMIT 40", tuple(c_eids))]
    links = [dict(r) for r in store.q(
        f"SELECT o.id, o.type, o.display, r.kind, MAX(re.confidence) confidence, COUNT(DISTINCT re.source_id) sources, "
        f"MIN(re.first_seen) first_seen, MAX(re.last_seen) last_seen, "
        f"(SELECT s.url FROM sources s WHERE s.id=re.source_id) url "
        f"FROM ("
        f"  SELECT * FROM (SELECT id, a_id, b_id, kind, b_id AS other_id FROM relations WHERE a_id IN ({ph}) AND b_id NOT IN ({ph}) LIMIT 800) "
        f"  UNION ALL "
        f"  SELECT * FROM (SELECT id, a_id, b_id, kind, a_id AS other_id FROM relations WHERE b_id IN ({ph}) AND a_id NOT IN ({ph}) LIMIT 800)"
        f") r CROSS JOIN rel_evidence re ON re.relation_id=r.id "
        f"CROSS JOIN entities o ON o.id = r.other_id "
        f"GROUP BY o.id, r.kind ORDER BY confidence DESC LIMIT 120", tuple(c_eids * 4))]
    aliases = []
    for r in store.q(f"SELECT DISTINCT alias FROM aliases WHERE entity_id IN ({ph})", tuple(c_eids)):
        if r["alias"] and r["alias"] not in aliases:
            aliases.append(r["alias"])
    return dict(entity=dict(e), aliases=aliases, seen=seen, links=links, attributes=attributes_of(store, c_eids),
                origins=origins_of(store, eid), connections=connections(store, eid), kinship=kinship,
                osint_findings=store.osint_findings_for(c_eids),
                images=store.entity_images_for(c_eids),
                primary_avatar=store.primary_avatar_for(c_eids))




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


def _idjoin_rows(path, table, a, b, sample, want=60, scan_cap=20000):
    """Up to `want` DISTINCT (a, b) pairs where BOTH fields are present — rows missing a part (e.g. no family tz)
    are skipped, so the id-join check runs on real, complete, different people rather than coincidental rows. Read
    straight from the file (scanning up to `scan_cap` rows to gather enough complete ones even when the field is
    sparse); falls back to the stored preview sample when the file is gone."""
    has = lambda x: any(ch.isdigit() for ch in str(x if x is not None else ""))

    def collect(rows):
        seen, out = set(), []
        for r in rows:
            av, bv = r.get(a), r.get(b)
            if not (has(av) and has(bv)):
                continue
            key = (str(av), str(bv))
            if key in seen:                      # distinct people only — don't count the same pair ten times
                continue
            seen.add(key)
            out.append((av, bv))
            if len(out) >= want:
                break
        return out

    try:
        if path and os.path.exists(path):
            import itertools
            from .importdb import raw_tables
            for tbl, _cols, rows in raw_tables(path):
                if str(tbl) != table:
                    continue
                out = collect(itertools.islice(rows, scan_cap))
                if out:
                    return out
    except Exception:
        pass
    return collect(iter(sample))


def _safe_name(s):
    s = re.sub(r"[\x00-\x1f/\\]+", "_", str(s)).strip()[:120]
    return s


def make_server(svc: SearchService, host="127.0.0.1", port=8080, token=None, queue=None):
    store = svc.store
    from .web_osint import ReconJobManager
    recon_mgr = ReconJobManager(store)

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
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data: blob: https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: blob: https: http:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self' 'unsafe-inline'; connect-src 'self'")
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
                try:
                    with open(os.path.join(os.path.dirname(__file__), "ui.html"), encoding="utf-8") as _f:
                        content = _f.read()
                except Exception:
                    content = INDEX
                return self._send(200, content, "text/html; charset=utf-8")
            m_av = re.fullmatch(r"/api/avatars/([\w\.\-]+)", u.path)
            if m_av:
                fname = os.path.basename(m_av.group(1))
                cand_dirs = ["data/avatars"]
                if store.path and store.path != ":memory:":
                    cand_dirs.insert(0, os.path.join(os.path.dirname(store.path), "avatars"))
                for d_av in cand_dirs:
                    fpath = os.path.join(d_av, fname)
                    if os.path.isfile(fpath):
                        try:
                            with open(fpath, "rb") as f_img:
                                raw_img = f_img.read()
                            ext = os.path.splitext(fname)[1].lower()
                            mime = "image/png" if ext == ".png" else ("image/webp" if ext == ".webp" else "image/jpeg")
                            return self._send(200, raw_img, mime)
                        except Exception:
                            break
                return self._send(404, {"error": "avatar not found"})
            if not self._authed(q):
                return self._send(401, {"error": "unauthorized"})
            m = re.fullmatch(r"/api/subjects/(\d+)(?:/(events|stream|export))?", u.path)
            mr = re.fullmatch(r"/api/recon/status/([\w\-]+)", u.path)
            if mr:
                job = recon_mgr.get_job(mr.group(1))
                return self._send(200 if job else 404, job or {"error": "job not found"})
            if u.path == "/api/recon/findings":
                eid_s = (q.get("eid") or q.get("entity_id") or [""])[0]
                if not eid_s.isdigit():
                    return self._send(400, {"error": "eid required"})
                eid_val = int(eid_s)
                return self._send(200, {
                    "findings": store.osint_findings_for([eid_val]),
                    "images": store.entity_images_for([eid_val]),
                    "primary_avatar": store.primary_avatar_for([eid_val]),
                    "latest_job": recon_mgr.get_latest_for_entity(eid_val),
                })
            if u.path == "/api/stats":
                provs = sorted(svc.engine.providers)
                from . import ai as _ai
                return self._send(200, {**store.stats(blocking=False), "paused": svc.engine.is_paused, "providers": provs,
                                        "web_search": any(p != "archive" for p in provs),
                                        "ai": _ai.enabled(svc.engine.cfg)})
            if u.path == "/api/dashboard":
                from .analytics import dashboard
                return self._send(200, dashboard(store))
            if u.path == "/api/imports":
                return self._send(200, queue.list() if queue else [])
            if u.path == "/api/archive/view":
                from .archive import view_archive_content
                sid = (q.get("source_id") or [""])[0]
                loc = (q.get("loc") or [""])[0]
                res = view_archive_content(store, int(sid) if sid.isdigit() else None, location_ref=loc or None)
                return self._send(200 if "error" not in res else 404, res)
            mi = re.fullmatch(r"/api/imports/(\d+)", u.path)
            if mi:
                d = queue.detail(int(mi.group(1))) if queue else None
                return self._send(200 if d else 404, d or {"error": "not found"})
            if u.path in ("/api/search", "/api/search/fts"):
                term = (q.get("q") or q.get("query") or [""])[0].strip()
                lim = min(int((q.get("limit") or ["50"])[0]), 200)
                return self._send(200, store.search_fts(term, limit=lim))
            if u.path == "/api/types":
                return self._send(200, types_catalog(store))
            if u.path == "/api/dossier":
                from .identity import dossier
                eid = (q.get("eid") or [""])[0]
                name = (q.get("name") or q.get("q") or [""])[0].strip()[:120]
                return self._send(200, dossier(store, int(eid) if eid.isdigit() else None, name or None))
            if u.path == "/api/dossier/export":
                from .identity import export_dossier_html, export_dossier_markdown, export_dossier_json
                eid_s = (q.get("eid") or q.get("entity_id") or [""])[0]
                name = (q.get("name") or q.get("q") or [""])[0].strip()[:120]
                fmt = (q.get("format") or ["html"])[0].strip().lower()
                eid_val = int(eid_s) if eid_s.isdigit() else None
                if fmt in ("md", "markdown"):
                    content = export_dossier_markdown(store, eid=eid_val, name=name or None)
                    mime, ext = "text/markdown; charset=utf-8", "md"
                elif fmt == "json":
                    content = export_dossier_json(store, eid=eid_val, name=name or None)
                    mime, ext = "application/json; charset=utf-8", "json"
                else:
                    content = export_dossier_html(store, eid=eid_val, name=name or None)
                    mime, ext = "text/html; charset=utf-8", "html"
                body = content.encode("utf-8")
                slug = re.sub(r"[^a-zA-Z0-9_\-]+", "_", str(eid_val or name or "target"))[:40] or "target"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Disposition", f'attachment; filename="osnit-dossier-{slug}.{ext}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if u.path == "/api/graph":
                from .identity import dossier
                eid = (q.get("eid") or [""])[0]
                name = (q.get("name") or q.get("q") or [""])[0].strip()[:120]
                d = dossier(store, int(eid) if eid.isdigit() else None, name or None)
                return self._send(200, {"title": d.get("title", ""), "graph": d.get("graph", {"nodes": [], "edges": []}),
                                        "kinship": d.get("kinship", [])})

            if u.path == "/api/fields":
                return self._send(200, fields_catalog(store))
            if u.path == "/api/contacts":
                from .contacts import contacts
                return self._send(200, contacts(store, (q.get("q") or [""])[0],
                                   (q.get("contactable") or [""])[0] in ("1", "true"),
                                   min(int((q.get("limit") or ["500"])[0]), 2000),
                                   int((q.get("offset") or ["0"])[0]), cap=8))
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
                subj_rows = [dict(r) for r in store.q(
                    "SELECT s.id,s.query,s.canonical,s.kind,s.entity_type,s.entity_key,s.status,s.created,s.rounds,"
                    "(SELECT COUNT(*) FROM events e WHERE e.subject_id=s.id AND e.kind='finding') findings,"
                    "(SELECT MAX(at) FROM events e WHERE e.subject_id=s.id) last_event "
                    "FROM subjects s ORDER BY id DESC LIMIT 200")]
                for sr in subj_rows:
                    se = store.q1("SELECT entity_id FROM subject_entities WHERE subject_id=? ORDER BY score DESC LIMIT 1", (sr["id"],))
                    if se:
                        eid_val = se["entity_id"]
                    else:
                        erow = store.q1("SELECT id FROM entities WHERE type=? AND key=?",
                                        (sr.get("entity_type") or sr["kind"], sr.get("entity_key") or sr["canonical"]))
                        eid_val = erow["id"] if erow else None
                    sr["entity_id"] = eid_val
                    if eid_val:
                        la = store.q1("SELECT COUNT(*) c FROM (SELECT 1 FROM relations WHERE a_id=? LIMIT 500)", (eid_val,))["c"]
                        lb = store.q1("SELECT COUNT(*) c FROM (SELECT 1 FROM relations WHERE b_id=? LIMIT 500)", (eid_val,))["c"]
                        # web findings are stored on the person: for a phone / email / ID search count its owners too
                        o_ids = [eid_val]
                        if (sr.get("kind") or "person") != "person":
                            for orow in store.q(
                                "SELECT o.id FROM (SELECT b_id AS oid FROM relations WHERE a_id=? "
                                "UNION SELECT a_id FROM relations WHERE b_id=?) r CROSS JOIN entities o ON o.id=r.oid "
                                "WHERE o.type='person' LIMIT 5", (eid_val, eid_val)):
                                o_ids.append(orow["id"])
                        o_cnt = store.q1(f"SELECT COUNT(*) c FROM osint_findings WHERE entity_id IN ({','.join('?' * len(o_ids))})",
                                         tuple(o_ids))["c"]
                        sr["osint_count"] = o_cnt
                        sr["findings"] = max(int(sr.get("findings") or 0), la + lb + o_cnt)
                    else:
                        sr["osint_count"] = 0
                return self._send(200, subj_rows)
            if u.path == "/api/overview":
                max_id_row = store.q1("SELECT COALESCE(MAX(id), 0) m FROM entities")
                is_large = bool(max_id_row and (max_id_row["m"] or 0) > 50000)
                osint_eids = [r["entity_id"] for r in store.q("SELECT DISTINCT entity_id FROM osint_findings LIMIT 25")]
                cand_ids = list(osint_eids)
                for et in ("person", "org"):
                    for r in store.q("SELECT id FROM entities WHERE type=? ORDER BY last_seen DESC LIMIT 25", (et,)):
                        if r["id"] not in cand_ids:
                            cand_ids.append(r["id"])
                ov_rows = []
                if cand_ids:
                    ph = ",".join(str(int(x)) for x in cand_ids[:60])
                    ov_rows = [dict(r) for r in store.q(
                        "SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                        "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources,"
                        "(SELECT COUNT(*) FROM osint_findings o WHERE o.entity_id=e.id) osint_count "
                        f"FROM entities e WHERE e.id IN ({ph}) AND e.type IN ('person','org')"
                    )]
                    ov_rows.sort(key=lambda r: (0 if r.get("osint_count", 0) > 0 else 1, -(r.get("last_seen") or 0), -r["id"]))
                    ov_rows = ov_rows[:25]
                try:
                    from .contacts import _aggregate, _dedupe
                    p_ids = [r["id"] for r in ov_rows if r["type"] == "person"]
                    det = _aggregate(store, p_ids) if p_ids else {}
                    for r in ov_rows:
                        d = det.get(r["id"], {})
                        r["emails"] = _dedupe(d.get("emails", []))
                        r["phones"] = _dedupe(d.get("phones", []))
                        r["orgs"] = _dedupe(d.get("orgs", []))
                        r["avatar"] = d.get("avatar", "")
                        if r["id"] in corrected:
                            r["corrected"], r["corrected_why"] = corrected[r["id"]]
                        cap_lists(r, 8)
                except Exception:
                    pass
                return self._send(200, dict(
                    stats=store.stats(blocking=not is_large),
                    sources=[dict(r) for r in store.q(
                        "SELECT id,url,title,kind,page_type,hit,last_scanned,state FROM sources "
                        "WHERE state IN ('scanned','imported') ORDER BY last_scanned DESC LIMIT 25")],
                    entities=ov_rows))
            if u.path == "/api/entities":
                term = (q.get("q") or [""])[0].strip()
                typ = (q.get("type") or [""])[0]
                corrected = {}                      # entity id -> the spelling a fuzzy reading searched for
                max_id_row = store.q1("SELECT COALESCE(MAX(id), 0) m FROM entities")
                is_large = bool(max_id_row and (max_id_row["m"] or 0) > 50000)
                osint_set = {r["entity_id"] for r in store.q("SELECT DISTINCT entity_id FROM osint_findings LIMIT 200")}

                if is_large and term:
                    from .textnorm import name_key, fold
                    from .contacts import _fast_match_person_ids
                    cand_ids = []
                    seen_c = set()

                    def _add_c(eid):
                        if eid and eid not in seen_c:
                            seen_c.add(int(eid))
                            cand_ids.append(int(eid))

                    if not typ or typ == "person":
                        for pid in _fast_match_person_ids(store, term, limit=100):
                            _add_c(pid)
                    tl = fold(term).strip()
                    nk = name_key(term)
                    search_types = (typ,) if typ else ("person", "org", "phone", "email", "national_id", "id_number", "username", "domain", "address")
                    for pfx in {tl, nk}:
                        if not pfx:
                            continue
                        for st in search_types:
                            for r in store.q(
                                "SELECT id FROM entities WHERE type=? AND (key=? OR (key >= ? AND key < ?)) LIMIT 50",
                                (st, pfx, pfx, pfx + "\uffff")
                            ):
                                _add_c(r["id"])
                    if not cand_ids:
                        return self._send(200, [])
                    ph = ",".join(str(int(x)) for x in cand_ids[:200])
                    t_cond = " AND e.type=?" if typ else ""
                    t_args = (typ,) if typ else ()
                    rows = [dict(r) for r in store.q(
                        "SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                        "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources,"
                        "(SELECT COUNT(*) FROM osint_findings o WHERE o.entity_id=e.id) osint_count "
                        f"FROM entities e WHERE e.id IN ({ph}){t_cond}",
                        t_args
                    )]
                    rank_c = {cid: idx for idx, cid in enumerate(cand_ids)}
                    rows.sort(key=lambda r: (0 if r.get("osint_count", 0) > 0 else 1, rank_c.get(r["id"], 999999), -(r.get("last_seen") or 0)))
                    rows = rows[:100]
                elif is_large and not term:
                    cand_ids = []
                    if osint_set:
                        ph_o = ",".join(str(int(x)) for x in list(osint_set)[:100])
                        t_cond = " AND type=?" if typ else ""
                        t_args = (typ,) if typ else ()
                        for r in store.q(f"SELECT id FROM entities WHERE id IN ({ph_o}){t_cond} ORDER BY last_seen DESC LIMIT 100", t_args):
                            cand_ids.append(r["id"])
                    if len(cand_ids) < 100:
                        if typ:
                            q_recent = store.q("SELECT id FROM entities WHERE type=? ORDER BY last_seen DESC LIMIT 100", (typ,))
                        else:
                            q_recent = store.q("SELECT id FROM entities ORDER BY id DESC LIMIT 100")
                        for r in q_recent:
                            if r["id"] not in cand_ids:
                                cand_ids.append(r["id"])
                                if len(cand_ids) >= 100:
                                    break
                    if not cand_ids:
                        return self._send(200, [])
                    ph = ",".join(str(int(x)) for x in cand_ids[:100])
                    rows = [dict(r) for r in store.q(
                        "SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                        "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources,"
                        "(SELECT COUNT(*) FROM osint_findings o WHERE o.entity_id=e.id) osint_count "
                        f"FROM entities e WHERE e.id IN ({ph})"
                    )]
                    rows.sort(key=lambda r: (0 if r.get("osint_count", 0) > 0 else 1, -(r.get("last_seen") or 0), -r["id"]))
                else:
                    conds, args = [], []
                    if typ:
                        conds.append("e.type=?"); args.append(typ)
                    if term:
                        like = f"%{term}%"
                        sub = ("e.display LIKE ? OR e.key LIKE ? OR e.id IN (SELECT entity_id FROM aliases WHERE alias LIKE ?)")
                        subargs = [like, like.lower(), like]
                        if len(term) > 2:
                            sub += " OR e.id IN (SELECT entity_id FROM attributes WHERE value LIKE ?)"
                            sub += " OR e.id IN (SELECT entity_id FROM osint_findings WHERE source_tool LIKE ? OR title LIKE ? OR summary LIKE ? OR url LIKE ?)"
                            sub += " OR " + linked_exists("e.id", "(o.display LIKE ? OR o.key LIKE ?)")
                            subargs += [like, like, like, like, like, like, like.lower(), like, like.lower()]
                        try:
                            from .extract import norm_phone_il
                            np = norm_phone_il(term)
                            if np:
                                sub += " OR e.key=? OR " + linked_exists("e.id", "o.key=?")
                                subargs += [np, np, np]
                        except Exception:
                            pass
                        try:
                            from .identity import find_people
                            matched_pids = [m["id"] for m in find_people(store, term)[:50]]
                            if not matched_pids and any(ch.isalpha() for ch in term):
                                # not found as typed: the name as it was probably meant (fuzzyname.py)
                                from .fuzzyname import ai_readings, fuzzy_find
                                for fm in fuzzy_find(store, term, limit=30) or ai_readings(svc.engine.cfg, store, term, 30):
                                    matched_pids.append(fm["id"])
                                    corrected[fm["id"]] = (fm["corrected"], fm.get("why", ""))
                            if matched_pids:
                                sub += f" OR e.id IN ({','.join(str(int(x)) for x in matched_pids)})"
                        except Exception:
                            pass
                        conds.append("(" + sub + ")"); args += subargs
                    where = " AND ".join(conds) or "1"
                    rows = [dict(r) for r in store.q(
                        "SELECT e.id,e.type,e.display,e.first_seen,e.last_seen,"
                        "(SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=e.id) sources,"
                        "(SELECT COUNT(*) FROM osint_findings o WHERE o.entity_id=e.id) osint_count "
                        f"FROM entities e WHERE {where} "
                        "ORDER BY e.last_seen DESC, e.id DESC LIMIT 100",
                        tuple(args))]
                    rows.sort(key=lambda r: (0 if r.get("osint_count", 0) > 0 else 1, -(r.get("last_seen") or 0), -r["id"]))
                try:
                    from .contacts import _aggregate, _dedupe
                    p_ids = [r["id"] for r in rows if r["type"] == "person"]
                    det = _aggregate(store, p_ids) if p_ids else {}
                    for r in rows:
                        d = det.get(r["id"], {})
                        r["emails"] = _dedupe(d.get("emails", []))
                        r["phones"] = _dedupe(d.get("phones", []))
                        r["orgs"] = _dedupe(d.get("orgs", []))
                        r["avatar"] = d.get("avatar", "")
                        if r["id"] in corrected:
                            r["corrected"], r["corrected_why"] = corrected[r["id"]]
                        cap_lists(r, 8)
                except Exception:
                    pass
                return self._send(200, rows)
            if u.path == "/api/network":              # the network around one person (network.py)
                from .connect import resolve_person
                from .network import ego_network
                who = (q.get("id") or q.get("name") or [""])[0]
                pid, read = resolve_person(store, who, cfg=svc.engine.cfg)
                if not pid or not store.q1("SELECT 1 x FROM entities WHERE id=? AND type='person'", (pid,)):
                    return self._send(404, {"error": "לא נמצא אדם: " + str(who)})
                try:
                    depth = max(1, min(2, int((q.get("depth") or ["1"])[0])))
                except ValueError:
                    depth = 1
                at = (q.get("at") or [""])[0].strip()
                res = ego_network(store, pid, depth=depth, at=int(at) if at.isdigit() and len(at) == 4 else None)
                res["read"] = read
                return self._send(200, res)
            if u.path == "/api/connect":              # how are two people connected (connect.py)
                from .connect import MAX_HOPS, how_connected, resolve_person
                a, a_read = resolve_person(store, (q.get("a") or [""])[0], cfg=svc.engine.cfg)
                b, b_read = resolve_person(store, (q.get("b") or [""])[0], cfg=svc.engine.cfg)
                if not a or not b:
                    return self._send(404, {"error": "לא נמצא אדם בשם " + ((q.get("a") or [""])[0] if not a
                                                                         else (q.get("b") or [""])[0])})
                res = how_connected(store, a, b)
                res.update(a_read=a_read, b_read=b_read, max_hops=MAX_HOPS)
                return self._send(200, res)
            if u.path == "/api/links/decisions":       # the operator's related / unrelated decisions (audit trail)
                from .linkdecide import log as link_log
                return self._send(200, link_log(store, limit=min(int((q.get("limit") or ["100"])[0]), 1000)))
            if u.path == "/api/identity/decisions":    # the operator's same / not-the-same decisions (audit trail)
                from .possible import decision_log
                return self._send(200, decision_log(store, limit=min(int((q.get("limit") or ["100"])[0]), 1000)))
            mp = re.fullmatch(r"/api/entities/(\d+)/possible", u.path)
            if mp:                                    # "possible same person": ranked candidates with reasons
                from .possible import possible_matches
                res = possible_matches(store, int(mp.group(1)), limit=min(int((q.get("limit") or ["30"])[0]), 100))
                return self._send(200 if res else 404, res or {"error": "not a person"})
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
                if (q.get("view") or [""])[0] == "page" and not since:
                    # the page: the saved copy at once, or "building" (202) while a first build runs
                    prof = svc.profile_cached(sid, wait=3.0)
                    if prof is None:
                        return self._send(404, {"error": "not found"})
                    if prof.get("building"):
                        return self._send(202, prof)
                    return self._send(200, page_view(prof))
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
            if u.path == "/api/sensitive":        # ad-hoc context-aware scan of pasted text
                from dataclasses import asdict
                from .sensitive import analyze_text
                txt = str(data.get("text", ""))[:200000]
                rep = analyze_text(txt, min_score=float(data.get("min", 0.4)))
                return self._send(200, {"people": list(rep.people),
                                        "findings": [asdict(f) for f in rep.findings]})
            if u.path == "/api/find":              # multi-field lookup: name + phone + address + ... at once
                from .multisearch import multi_find
                return self._send(200, multi_find(store, data if isinstance(data, dict) else {}, cfg=svc.engine.cfg))
            if u.path == "/api/recon/start":
                eid_raw = data.get("entity_id") or data.get("eid")
                eid_val = int(eid_raw) if str(eid_raw or "").isdigit() else None
                qy = str(data.get("query") or "").strip()[:200] or None
                if not eid_val and not qy:
                    return self._send(400, {"error": "entity_id or query required"})
                job = recon_mgr.start_job(entity_id=eid_val, query=qy, max_depth=int(data.get("max_depth") or 2))
                return self._send(200, job)
            if u.path == "/api/search":
                qy = str(data.get("query", "")).strip()
                if not qy or len(qy) > 200:
                    return self._send(400, {"error": "query required (<=200 chars)"})
                hrs = data.get("hours")
                page = data.get("view") == "page"
                res = svc.search(qy, data.get("kind"), float(hrs) if hrs else None, wait=3.0 if page else None)
                if page and res.get("profile") and not res["profile"].get("building"):
                    res["profile"] = page_view(res["profile"])
                if not page:          # the page never shows these; on millions of rows ranking them is the slow part
                    res["fts_matches"] = store.search_fts(qy, limit=20)
                return self._send(200, res)
            m = re.fullmatch(r"/api/subjects/(\d+)/stop", u.path)
            if m:
                svc.stop(int(m.group(1)))
                return self._send(200, {"ok": True})
            m = re.fullmatch(r"/api/subjects/(\d+)/delete", u.path)
            if m:
                sid = int(m.group(1))
                with store.tx() as c:
                    c.execute("DELETE FROM events WHERE subject_id=?", (sid,))
                    c.execute("DELETE FROM subject_entities WHERE subject_id=?", (sid,))
                    c.execute("DELETE FROM subjects WHERE id=?", (sid,))
                    c.execute("DELETE FROM subject_cache WHERE subject_id=?", (sid,))
                return self._send(200, {"ok": True, "subject_id": sid})
            m = re.fullmatch(r"/api/entities/(\d+)/delete", u.path)
            if m:
                eid = int(m.group(1))
                return self._send(200, store.delete_entity(eid))
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
            if path == "/api/imports/clear":         # empty the file list (finished files, or everything idle)
                if not queue:
                    return 503, {"error": "import queue not running"}
                try:
                    return 200, queue.clear(data.get("which", "finished"), bool(data.get("purge")))
                except RuntimeError as e:
                    return 409, {"error": str(e)}
            m = re.fullmatch(r"/api/imports/(\d+)/spans(/suggest)?", path)
            if m:                                    # teach by marking pieces (***…***) in a sample row
                if not queue:
                    return 503, {"error": "import queue not running"}
                if m.group(2):
                    pieces = [str(p)[:300] for p in (data.get("pieces") or [])][:50]
                    return 200, queue.suggest_types(pieces)
                items = data.get("items") or []
                if not isinstance(items, list) or not all(isinstance(i, dict) and {"col", "text", "start", "end", "type"} <= i.keys()
                                                          for i in items):
                    return 400, {"error": "items: [{col, text, start, end, type, label}]"}
                for i in items:
                    i.setdefault("label", i["type"])
                rem = [tuple(x) for x in (data.get("remove") or []) if isinstance(x, (list, tuple)) and len(x) == 2]
                a = queue.teach_spans(int(m.group(1)), str(data.get("table", "")), items, bool(data.get("teach", True)), rem)
                return (200, a) if a else (404, {"error": "no analysis to update"})
            m = re.fullmatch(r"/api/imports/(\d+)/remove", path)
            if m:                                    # take one file off the list (optionally with its data)
                if not queue:
                    return 503, {"error": "import queue not running"}
                try:
                    return 200, queue.remove([int(m.group(1))], bool(data.get("purge")))
                except RuntimeError as e:
                    return 409, {"error": str(e)}
            m = re.fullmatch(r"/api/imports/(\d+)/idjoin", path)
            if m:                                  # the operator marks TWO columns (either order); try every way of
                jid = int(m.group(1))              # combining them, across many rows, and keep what builds valid IDs
                table, a, b = str(data.get("table", "")), str(data.get("tz", "")), str(data.get("family", ""))
                prow = store.q1("SELECT path, preview FROM imports WHERE id=?", (jid,))
                if not prow or not prow["preview"]:
                    return 404, {"error": "no preview"}
                prev = json.loads(prow["preview"])
                t = next((x for x in prev.get("tables", []) if str(x.get("table")) == table), None)
                if not t:
                    return 404, {"error": "table not found"}
                colset = set(str(c) for c in (t.get("cols") or []))
                if a not in colset or b not in colset or a == b:
                    return 400, {"error": "choose two different columns"}
                pairs = _idjoin_rows(prow["path"], table, a, b, t.get("raw") or [])
                from .idrecon import detect_id_join
                best, assign = None, (a, b)
                for tz, fam, ps in ((a, b, pairs), (b, a, [(y, x) for x, y in pairs])):   # order-agnostic: either
                    d = detect_id_join(ps, min_rows=10, min_rate=0.9)                       # column may be the 7-digit id
                    if d and (best is None or (d["valid_rate"], d["tested"]) > (best["valid_rate"], best["tested"])):
                        best, assign = d, (tz, fam)
                return 200, dict(ok=bool(best), tz=assign[0], family=assign[1], rows_tested=len(pairs), **(best or {}))
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
            if path == "/api/links/decide":          # the operator: these two people are / are not related
                from .linkdecide import decide as link_decide
                try:
                    return 200, link_decide(store, int(data.get("a")), int(data.get("b")),
                                            str(data.get("decision", "")), data.get("note", ""))
                except (TypeError, ValueError) as e:
                    return 400, {"error": str(e)}
            if path == "/api/identity/decide":       # the operator: these two identities are / are not one person
                from .possible import decide
                try:
                    return 200, decide(store, int(data.get("a")), int(data.get("b")), str(data.get("decision", "")),
                                       data.get("reasons"), data.get("score"))
                except (TypeError, ValueError) as e:
                    return 400, {"error": str(e)}
            if path == "/api/reset":
                scope = data.get("scope")
                if scope not in ("files", "web", "all"):
                    return 400, {"error": "scope must be files, web or all"}
                if str(data.get("confirm", "")).strip() != str(svc.engine.cfg.reset_code):
                    return 403, {"error": "קוד איפוס שגוי"}
                res = store.reset(scope)
                if scope == "all" and queue:         # a full reset also empties the file list and its stored files
                    try:
                        res["files_removed"] = queue.clear("all")["removed"]
                    except RuntimeError:
                        res["files_removed"] = 0
                try:
                    store.vacuum()                   # give the space back: the .db file actually shrinks
                except Exception:
                    pass
                return 200, res
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
            limit = float(_os.environ.get("OSNIT_MAX_UPLOAD_GB", "100")) * 1024 ** 3
            if total > limit:
                return self._send(413, {"error": f"file too large (limit {limit / 1024 ** 3:.0f} GB, OSNIT_MAX_UPLOAD_GB)"})
            import shutil as _sh
            free = _sh.disk_usage(queue.inbox).free
            if total + 512 * 1024 ** 2 > free:
                return self._send(507, {"error": f"not enough disk space: need {total / 1024 ** 3:.1f} GB, "
                                                 f"free {free / 1024 ** 3:.1f} GB"})
            # ".part" is not an importable extension, so the inbox scanner never picks up a half-written upload
            dest = _os.path.join(queue.inbox, f"{int(_time.time()*1000)}_{name}.part")
            got = 0
            try:
                with open(dest, "wb") as f:     # streamed to disk in 4 MB chunks: any size, flat memory
                    while got < total:
                        chunk = self.rfile.read(min(4 << 20, total - got))
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
            except OSError as e:
                if _os.path.exists(dest):
                    _os.remove(dest)
                return self._send(500, {"error": f"write failed: {e}"})
            if got < total:                     # the browser stopped mid-way: never import half a file
                _os.remove(dest)
                return self._send(400, {"error": f"upload interrupted ({got}/{total} bytes)"})
            delete = (q.get("delete_raw") or ["1"])[0] not in ("0", "false", "")
            review = (q.get("review") or ["0"])[0] in ("1", "true")
            ai = (q.get("ai") or ["0"])[0] in ("1", "true")
            res = queue.add_file(dest, name=shown, delete_raw=delete, move=True, review=review, ai=ai)
            return self._send(200, res)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            # backstop: a dropped client connection is not a server error worth a traceback
            import sys
            if not isinstance(sys.exc_info()[1], (ConnectionError, ConnectionResetError, ConnectionAbortedError,
                                                  BrokenPipeError, TimeoutError)):
                super().handle_error(request, client_address)

        def shutdown(self):
            try:
                super().shutdown()
            finally:
                try:
                    self.server_close()
                except Exception:
                    pass

    return Server((host, port), Handler)


def serve_in_thread(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
