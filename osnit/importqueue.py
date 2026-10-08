"""Background import queue: files dropped in the inbox (or uploaded via the UI) go through two stages:

  1. analyse   read-only: record tables, column types, sample records, links to what the DB already knows
               (saved as the job's preview the moment it is ready, so the UI shows it before importing)
  2. import    records -> entities/attributes (with the user's corrections), documents -> text extraction

A job uploaded with review=1 stops after stage 1 (state 'review') until it is approved. Raw files are deleted
after a successful import when asked; crawled web content is never written to disk at all.
"""
import json
import os
import re
import shutil
import threading
import time

from .analyze import analyze_file, import_summary, repreview
from .detect import detect
from .ingest import SUPPORTED, import_path
from .importdb import DOC_EXT, count_sql_tuples, import_db

TABULAR = (".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".mde", ".accde", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".sql", ".dump",
           ".xlsx", ".xlsm", ".xls")


def estimate_total(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in (".db", ".sqlite", ".sqlite3"):
            import sqlite3
            with open(path, "rb") as f:
                if f.read(16) != b"SQLite format 3\x00":
                    return 0
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            n = 0
            for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                try:
                    n += con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except sqlite3.Error:
                    pass
            con.close()
            return n
        if ext in (".mdb", ".accdb", ".mde", ".accde"):
            from .mdb import count_access
            return sum(n for n, _ in count_access(path).values())
        if ext in (".csv", ".tsv", ".jsonl", ".ndjson"):
            with open(path, "rb") as f:
                return max(0, sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b"")) - 1)
        if ext in (".sql", ".dump"):
            return count_sql_tuples(path)
    except Exception:
        pass
    return 0



def _keep_spans(stored_json, incoming):
    """The UI may send column choices only; keep the piece rules (__spans__) and the row layout (__merge__) the
    user already set for the file unless the payload sets them itself."""
    if incoming is None:
        return None
    stored = json.loads(stored_json) if stored_json else {}
    out = {t: dict(v) for t, v in incoming.items()}
    for table, tv in stored.items():
        for key in ("__spans__", "__merge__"):
            if isinstance(tv, dict) and tv.get(key) and key not in out.get(table, {}):
                out.setdefault(table, {})[key] = tv[key]
    return out


class ImportQueue:
    def __init__(self, engine, inbox="data/inbox", trust=0.8):
        self.engine, self.store, self.trust = engine, engine.store, trust
        self.inbox = inbox
        os.makedirs(inbox, exist_ok=True)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None

    # ------------------------------------------------------------ enqueue
    def add_file(self, src_path, name=None, delete_raw=None, move=False, review=False):
        name = name or os.path.basename(src_path)
        dest = self._stash(src_path, name, move)
        return self._enqueue(dest, name, delete_raw, review)

    def add_bytes(self, body: bytes, name: str, delete_raw=True, review=False):
        safe = re.sub(r"[^\w.\-]+", "_", name) or "upload"
        dest = os.path.join(self.inbox, f"{int(time.time()*1000)}_{safe}")
        with open(dest, "wb") as f:
            f.write(body)
        return self._enqueue(dest, name, delete_raw, review)

    def _stash(self, src, name, move):
        safe = re.sub(r"[^\w.\-]+", "_", name)
        dest = os.path.join(self.inbox, f"{int(time.time()*1000)}_{safe}")
        (shutil.move if move else shutil.copy2)(src, dest)
        return dest

    def _enqueue(self, path, name, delete_raw, review=False):
        if delete_raw is None:
            delete_raw = getattr(self.engine.cfg, "delete_imported", False)
        with open(path, "rb") as f:
            head = f.read(16384)
        det = detect(head + (b"" if len(head) < 16384 else b""), name)
        now = time.time()
        with self.store.tx() as c:
            cur = c.execute(
                "INSERT INTO imports(name,path,bytes,detected,state,total,delete_raw,created,updated,review) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (name, path, os.path.getsize(path), det["kind"], "queued", estimate_total(path),
                 1 if delete_raw else 0, now, now, 1 if review else 0))
        self._wake.set()
        return dict(id=cur.lastrowid, detected=det)

    def scan_inbox(self, settle=10.0):
        """Queue files dropped into the inbox folder. A file modified in the last `settle` seconds is still being
        copied in (a multi-GB copy takes minutes) and is left for a later scan."""
        known = {r["path"] for r in self.store.q("SELECT path FROM imports")}
        now = time.time()
        for fn in sorted(os.listdir(self.inbox)):
            p = os.path.join(self.inbox, fn)
            if os.path.isfile(p) and p not in known and os.path.splitext(fn)[1].lower() in (SUPPORTED | set(TABULAR)):
                try:
                    if now - os.path.getmtime(p) < settle:
                        continue
                except OSError:
                    continue
                self._enqueue(p, fn, None)

    # ------------------------------------------------------------ worker
    def _run_one(self, job):
        jid, path = job["id"], job["path"]
        ext = os.path.splitext(path)[1].lower()
        overrides = json.loads(job["overrides"]) if job.get("overrides") else None
        try:
            if not os.path.exists(path):
                raise FileNotFoundError("the file is no longer on disk")
            # ---- stage 1: analyse (read-only)
            self._set(jid, state="analyzing", updated=time.time())
            analysis = analyze_file(self.store, path, job["name"], overrides)
            total = analysis["records"] or job["total"]
            self._set(jid, preview=json.dumps(analysis, ensure_ascii=False, default=str), total=total, updated=time.time())
            if job.get("review"):
                self._set(jid, state="review", updated=time.time())
                return
            # ---- stage 2: import
            self._set(jid, state="running", updated=time.time())

            def progress(stats):
                done = stats.get("records", 0) + stats.get("documents", 0)
                self._set(jid, done=done, records=stats.get("records", 0), documents=stats.get("documents", 0),
                          failed=stats.get("failed", 0), updated=time.time())

            def live(preview):
                analysis["live"] = preview
                self._set(jid, preview=json.dumps(analysis, ensure_ascii=False, default=str), updated=time.time())

            res = {"records": 0, "documents": 0, "failed": 0}
            if ext in TABULAR or any(t["usable"] for t in analysis["tables"]):
                r = import_db(self.engine, path, label=job["name"], trust=self.trust, delete_raw=False,
                              progress=progress, import_id=jid, on_preview=live, overrides=overrides)
                res.update(records=r["records"], documents=r["documents"])
            if ext in DOC_EXT or ext not in TABULAR:
                r = import_path(self.engine, path, delete_raw=False, import_id=jid)
                res["documents"] += r.get("imported", 0)
                res["failed"] += r.get("failed", 0)
            done = res["records"] + res["documents"]
            summary = import_summary(self.store, jid)
            self._set(jid, state="done", done=done, total=max(done, total or 0), records=res["records"],
                      documents=res["documents"], failed=res["failed"], updated=time.time(),
                      summary=json.dumps(summary, ensure_ascii=False))
            if bool(job["delete_raw"]) and os.path.exists(path):
                os.remove(path)
        except Exception as e:
            self._set(jid, state="error", error=f"{type(e).__name__}: {e}"[:300], updated=time.time())

    # ------------------------------------------------------------ user actions
    def approve(self, jid, overrides=None, teach=False):
        """Import a job that waits in review, with the user's column corrections ({table: {column: type}})."""
        job = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not job or job["state"] not in ("review", "done", "error"):
            return False
        if overrides is not None:
            overrides = _keep_spans(job["overrides"], overrides)
            self._set(jid, overrides=json.dumps(overrides, ensure_ascii=False))
            if teach:
                from .semantic import header_key
                self.store.learn_fields([(header_key(c), c, t) for cols in overrides.values() for c, t in cols.items()
                                         if not c.startswith("__") and " ▸ " not in c and isinstance(t, str)],
                                        source="user")
        if job["state"] != "review":            # re-import with corrections: drop what the first run added
            self.store.purge_sources("import_id=?", (jid,))
        self._set(jid, state="queued", review=0, error=None, done=0, updated=time.time())
        self._wake.set()
        return True

    def reanalyze(self, jid, overrides=None):
        job = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not job or not os.path.exists(job["path"]):
            return None
        analysis = analyze_file(self.store, job["path"], job["name"], overrides)
        self._set(jid, preview=json.dumps(analysis, ensure_ascii=False, default=str),
                  overrides=json.dumps(overrides, ensure_ascii=False) if overrides else job["overrides"])
        return analysis

    def repreview(self, jid, overrides=None):
        """Live update: re-catalogue the stored sample rows with the user's corrections, no file read. Saves the
        overrides so an eventual approve/import uses them, and returns the refreshed analysis for the UI."""
        job = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not job or not job["preview"]:
            return None
        preview = json.loads(job["preview"])
        overrides = _keep_spans(job["overrides"], overrides)
        updated = repreview(self.store, preview, overrides)
        self._set(jid, preview=json.dumps(updated, ensure_ascii=False, default=str),
                  overrides=json.dumps(overrides, ensure_ascii=False) if overrides else job["overrides"])
        return updated

    def teach_spans(self, jid, table, items, teach=True, remove=None):
        """Learn piece rules from the user's marked examples and re-preview.
        items: [{col, text, start, end, type, label}] — text is the column value with markers removed, start/end
        the marked piece. Examples for the same (column, label) accumulate, so every extra example (from this file
        or from earlier files with the same header) makes the rule more general. remove: [(col, label)] to drop."""
        from .semantic import header_key
        from .spans import learn
        job = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not job or not job["preview"]:
            return None
        overrides = json.loads(job["overrides"]) if job["overrides"] else {}
        tov = overrides.setdefault(table, {})
        rules = {(r["col"], r["label"]): r for r in tov.get("__spans__", [])}
        for col, label in remove or []:            # kept as "disabled" so a rule learned from other files stays off here
            rules[(col, label)] = dict(col=col, label=label, disabled=True)
        learned = self.store.span_rules()
        groups = {}
        for it in items or []:
            groups.setdefault((it["col"], it["label"].strip() or it["type"]), []).append(it)
        for (col, label), its in groups.items():
            prev = rules.get((col, label), {}).get("examples", [])
            prev += [e for r in learned.get(header_key(col), []) if r["label"] == label for e in r["examples"]]
            exs = prev + [dict(text=i["text"], start=int(i["start"]), end=int(i["end"])) for i in its]
            uniq = list({(e["text"], e["start"], e["end"]): e for e in exs}.values())
            rule = learn(uniq)
            if not rule:
                continue
            typ = its[-1]["type"]
            rules[(col, label)] = dict(col=col, label=label, type=typ, rule=rule, examples=uniq[-30:])
            if teach:
                self.store.save_span_rule(header_key(col), label, typ, rule, uniq)
        tov["__spans__"] = list(rules.values())
        return self.repreview(jid, overrides)

    def suggest_types(self, pieces):
        """What each marked piece most likely is — the system's guess, which the user can change."""
        from .semantic import KIND_TO_TYPES, Registry
        reg = Registry(self.store.custom_types())
        out = []
        for p in pieces:
            k = reg.kind(p)
            t = (reg.kind_types(k) or ["unknown"])[0]
            if k == "name?":
                t = "name"
            elif k == "number" and re.fullmatch(r"\d{8,9}", p.strip()):
                t = "national_id"                    # a bare 8–9 digit number is an ID, never a phone
            out.append(dict(piece=p, kind=k, type=t, label=reg.label(t)))
        return out

    def remove(self, ids, purge_data=False):
        """Take files off the list. With purge_data their extracted data is deleted too; otherwise it stays in the
        database. The stored raw file is always deleted, so the inbox scanner never picks it up again."""
        ids = [int(i) for i in ids]
        busy = [r["id"] for r in self.store.q(
            f"SELECT id FROM imports WHERE id IN ({','.join('?' * len(ids)) or 'NULL'}) "
            f"AND state IN ('running','analyzing')", ids)]
        if busy:
            raise RuntimeError("a file is being processed right now — wait for it to finish")
        purged = {"sources": 0, "entities": 0}
        if purge_data:
            for jid in ids:
                r = self.store.purge_sources("import_id=?", (jid,))
                purged["sources"] += r["sources"]
                purged["entities"] += r["entities"]
        removed_files = 0
        for p in self.store.delete_import_rows(ids):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                    removed_files += 1
                except OSError:
                    pass
        return dict(removed=len(ids), files_deleted=removed_files, **purged)

    def clear(self, which="finished", purge_data=False):
        """which: finished (done / error / purged) | all (everything not currently being processed)."""
        states = ("done", "error", "purged") if which == "finished" else ("done", "error", "purged", "queued", "review")
        ids = [r["id"] for r in self.store.q(
            f"SELECT id FROM imports WHERE state IN ({','.join('?' * len(states))})", states)]
        return self.remove(ids, purge_data) if ids else dict(removed=0, files_deleted=0, sources=0, entities=0)

    def purge(self, jid, delete_file=True):
        """Remove everything this file added to the database (and the stored raw file, if it was kept)."""
        job = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not job:
            return None
        if job["state"] in ("running", "analyzing"):
            raise RuntimeError("the file is being processed — wait for it to finish")
        res = self.store.purge_import(jid)
        if delete_file and job["path"] and os.path.exists(job["path"]):
            os.remove(job["path"])
        return res

    def detail(self, jid):
        r = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        if not r:
            return None
        d = {k: r[k] for k in r.keys() if k not in ("path",)}
        for k in ("preview", "summary", "overrides"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        d["file_kept"] = bool(r["path"] and os.path.exists(r["path"]))
        return d

    def _set(self, jid, **kw):
        cols = ",".join(f"{k}=?" for k in kw)
        with self.store.tx() as c:
            c.execute(f"UPDATE imports SET {cols} WHERE id=?", (*kw.values(), jid))

    def _next(self):
        with self.store.tx() as c:
            r = c.execute("SELECT * FROM imports WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
            if r:
                c.execute("UPDATE imports SET state='running' WHERE id=?", (r["id"],))
                return dict(r)
        return None

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.scan_inbox()
            except OSError:
                pass
            job = self._next()
            if job:
                self._run_one(job)
            else:
                self._wake.wait(3.0)
                self._wake.clear()

    def start(self):
        # recover jobs left 'running' by a crash
        with self.store.tx() as c:
            c.execute("UPDATE imports SET state='queued' WHERE state IN ('running','analyzing')")
        self._thread = threading.Thread(target=self._loop, daemon=True, name="osnit-import")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def list(self, limit=200):
        out = []
        for r in self.store.q(
                "SELECT id,name,bytes,detected,state,total,done,records,documents,failed,error,created,updated,review,"
                "summary, preview IS NOT NULL has_preview FROM imports ORDER BY id DESC LIMIT ?", (limit,)):
            d = dict(r)
            summ = json.loads(d.pop("summary") or "{}")
            d["added"] = summ.get("by_type", {})
            d["linked"] = sum(summ.get("linked", {}).values())
            d["fields"] = len(summ.get("attributes", []))
            out.append(d)
        return out

    def run_pending(self, max_jobs=100):
        """Synchronous drain for the CLI/tests."""
        n = 0
        self.scan_inbox(settle=0)
        while n < max_jobs:
            job = self._next()
            if not job:
                break
            self._run_one(job)
            n += 1
        return n
