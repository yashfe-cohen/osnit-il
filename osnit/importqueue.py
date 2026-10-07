"""Background import queue: files dropped in the inbox (or uploaded via the UI) are detected,
parsed and folded into the one database, with live per-file progress. Raw files are deleted after
a successful import when asked; crawled web content is never written to disk at all.
"""
import os
import re
import shutil
import threading
import time

from .detect import detect
from .ingest import SUPPORTED, import_path
from .importdb import import_db

TABULAR = (".db", ".sqlite", ".sqlite3", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".sql", ".dump")


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
        if ext in (".csv", ".tsv", ".jsonl", ".ndjson"):
            with open(path, "rb") as f:
                return max(0, sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b"")) - 1)
        if ext in (".sql", ".dump"):
            with open(path, "rb") as f:
                data = f.read()
            return len(re.findall(rb"\)\s*,\s*\(", data)) + len(re.findall(rb"VALUES\s*\(", data, re.I))
    except Exception:
        pass
    return 0


class ImportQueue:
    def __init__(self, engine, inbox="data/inbox", trust=0.8):
        self.engine, self.store, self.trust = engine, engine.store, trust
        self.inbox = inbox
        os.makedirs(inbox, exist_ok=True)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None

    # ------------------------------------------------------------ enqueue
    def add_file(self, src_path, name=None, delete_raw=None, move=False):
        name = name or os.path.basename(src_path)
        dest = self._stash(src_path, name, move)
        return self._enqueue(dest, name, delete_raw)

    def add_bytes(self, body: bytes, name: str, delete_raw=True):
        safe = re.sub(r"[^\w.\-]+", "_", name) or "upload"
        dest = os.path.join(self.inbox, f"{int(time.time()*1000)}_{safe}")
        with open(dest, "wb") as f:
            f.write(body)
        return self._enqueue(dest, name, delete_raw)

    def _stash(self, src, name, move):
        safe = re.sub(r"[^\w.\-]+", "_", name)
        dest = os.path.join(self.inbox, f"{int(time.time()*1000)}_{safe}")
        (shutil.move if move else shutil.copy2)(src, dest)
        return dest

    def _enqueue(self, path, name, delete_raw):
        if delete_raw is None:
            delete_raw = getattr(self.engine.cfg, "delete_imported", False)
        with open(path, "rb") as f:
            head = f.read(16384)
        det = detect(head + (b"" if len(head) < 16384 else b""), name)
        now = time.time()
        with self.store.tx() as c:
            cur = c.execute(
                "INSERT INTO imports(name,path,bytes,detected,state,total,delete_raw,created,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (name, path, os.path.getsize(path), det["kind"], "queued", estimate_total(path),
                 1 if delete_raw else 0, now, now))
        self._wake.set()
        return dict(id=cur.lastrowid, detected=det)

    def scan_inbox(self):
        known = {r["path"] for r in self.store.q("SELECT path FROM imports")}
        for fn in sorted(os.listdir(self.inbox)):
            p = os.path.join(self.inbox, fn)
            if os.path.isfile(p) and p not in known and os.path.splitext(fn)[1].lower() in (SUPPORTED | set(TABULAR)):
                self._enqueue(p, fn, None)

    # ------------------------------------------------------------ worker
    def _run_one(self, job):
        jid, path = job["id"], job["path"]
        ext = os.path.splitext(path)[1].lower()
        self._set(jid, state="running", updated=time.time())

        def progress(stats):
            done = stats.get("records", 0) + stats.get("documents", 0)
            self._set(jid, done=done, records=stats.get("records", 0), documents=stats.get("documents", 0),
                      failed=stats.get("failed", 0), updated=time.time())
        try:
            if not os.path.exists(path):
                raise FileNotFoundError("the file is no longer on disk")
            if ext in TABULAR:
                res = import_db(self.engine, path, label=job["name"], trust=self.trust,
                                delete_raw=bool(job["delete_raw"]), progress=progress)
            else:
                res = import_path(self.engine, path, delete_raw=bool(job["delete_raw"]))
                res.setdefault("records", res.get("imported", 0))
            done = res.get("records", 0) + res.get("documents", 0)
            self._set(jid, state="done", done=done, total=max(done, job["total"]), records=res.get("records", 0),
                      documents=res.get("documents", 0), failed=res.get("failed", 0), updated=time.time())
            if bool(job["delete_raw"]) and os.path.exists(path):
                os.remove(path)
        except Exception as e:
            self._set(jid, state="error", error=f"{type(e).__name__}: {e}"[:300], updated=time.time())

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
            c.execute("UPDATE imports SET state='queued' WHERE state='running'")
        self._thread = threading.Thread(target=self._loop, daemon=True, name="osnit-import")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def list(self, limit=50):
        return [dict(r) for r in self.store.q(
            "SELECT id,name,bytes,detected,state,total,done,records,documents,failed,error,created,updated "
            "FROM imports ORDER BY id DESC LIMIT ?", (limit,))]

    def run_pending(self, max_jobs=100):
        """Synchronous drain for the CLI/tests."""
        n = 0
        self.scan_inbox()
        while n < max_jobs:
            job = self._next()
            if not job:
                break
            self._run_one(job)
            n += 1
        return n
