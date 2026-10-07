"""SQLite store: sources, entities, evidence (with first/last seen), relations, subjects, jobs, events."""
import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from difflib import SequenceMatcher

from .textnorm import fold, name_key, tokens
from .urls import registered_domain, host_of

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, domain TEXT, kind TEXT, title TEXT,
  state TEXT NOT NULL DEFAULT 'pending', priority INTEGER DEFAULT 0, depth INTEGER DEFAULT 0,
  origin TEXT, subject_id INTEGER, raw_hash TEXT, text_hash TEXT, etag TEXT, last_modified TEXT,
  http_status INTEGER, error TEXT, bytes INTEGER, hit INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL, last_scanned REAL, last_changed REAL,
  next_scan_at REAL DEFAULT 0, scan_interval REAL DEFAULT 0, lease_until REAL DEFAULT 0,
  scan_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS sources_sched ON sources(state, next_scan_at, priority);
CREATE INDEX IF NOT EXISTS sources_domain ON sources(domain);
CREATE TABLE IF NOT EXISTS entities(
  id INTEGER PRIMARY KEY, type TEXT NOT NULL, key TEXT NOT NULL, display TEXT,
  first_seen REAL, last_seen REAL, UNIQUE(type, key));
CREATE TABLE IF NOT EXISTS aliases(
  entity_id INTEGER NOT NULL, alias_key TEXT NOT NULL, alias TEXT, source_id INTEGER,
  first_seen REAL, last_seen REAL, PRIMARY KEY(entity_id, alias_key));
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, source_id INTEGER NOT NULL, snippet TEXT,
  snippet_hash TEXT, confidence REAL, first_seen REAL, last_seen REAL,
  UNIQUE(entity_id, source_id, snippet_hash));
CREATE INDEX IF NOT EXISTS evidence_source ON evidence(source_id);
CREATE TABLE IF NOT EXISTS relations(
  id INTEGER PRIMARY KEY, a_id INTEGER NOT NULL, b_id INTEGER NOT NULL, kind TEXT NOT NULL,
  first_seen REAL, last_seen REAL, UNIQUE(a_id, b_id, kind));
CREATE INDEX IF NOT EXISTS rel_b ON relations(b_id);
CREATE TABLE IF NOT EXISTS rel_evidence(
  id INTEGER PRIMARY KEY, relation_id INTEGER NOT NULL, source_id INTEGER NOT NULL, snippet TEXT,
  snippet_hash TEXT, confidence REAL, first_seen REAL, last_seen REAL,
  UNIQUE(relation_id, source_id, snippet_hash));
CREATE INDEX IF NOT EXISTS relev_source ON rel_evidence(source_id);
CREATE TABLE IF NOT EXISTS source_changes(
  id INTEGER PRIMARY KEY, source_id INTEGER, at REAL, kind TEXT, added INTEGER, removed INTEGER);
CREATE TABLE IF NOT EXISTS subjects(
  id INTEGER PRIMARY KEY, query TEXT UNIQUE, kind TEXT, canonical TEXT, entity_type TEXT, entity_key TEXT,
  variants TEXT, status TEXT DEFAULT 'active', created REAL, deadline REAL, rounds INTEGER DEFAULT 0,
  last_round_at REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS subject_entities(
  subject_id INTEGER NOT NULL, entity_id INTEGER NOT NULL, how TEXT, score REAL,
  PRIMARY KEY(subject_id, entity_id));
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY, subject_id INTEGER, provider TEXT, query TEXT, state TEXT DEFAULT 'pending',
  created REAL, ran_at REAL, found INTEGER DEFAULT 0, error TEXT, UNIQUE(subject_id, provider, query));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, subject_id INTEGER, at REAL, kind TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS events_subject ON events(subject_id, id);
"""


def h(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:16]


def _ed1(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        d = [i for i in range(len(a)) if a[i] != b[i]]
        return len(d) == 1 or (len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = next((i for i in range(len(s)) if s[i] != l[i]), len(s))
    return s[i:] == l[i + 1:]


def similar_person_keys(ka: str, kb: str) -> bool:
    """Same person under a typo: equal token count, every token equal or (len>=5 and edit distance 1)."""
    ta, tb = ka.split(), kb.split()
    if len(ta) != len(tb):
        return False
    rest = list(tb)
    for x in ta:
        m = next((y for y in rest if x == y or (len(x) >= 5 and len(y) >= 5 and _ed1(x, y))), None)
        if m is None:
            return False
        rest.remove(m)
    return True


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            import os
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self._wlock = threading.RLock()
        self._uri = path if path != ":memory:" else f"file:osnit_mem_{id(self)}?mode=memory&cache=shared"
        self._keep = self._connect()   # keeps shared in-memory db alive
        self._keep.executescript(SCHEMA)
        for table, col, decl in (("subjects", "intent", "TEXT"), ("sources", "quality", "REAL"),
                                 ("sources", "page_type", "TEXT")):
            try:
                self._keep.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass   # already there

    def _connect(self):
        c = sqlite3.connect(self._uri, timeout=30, check_same_thread=False, uri=self._uri.startswith("file:"),
                            isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL" if self.path != ":memory:" else "PRAGMA synchronous=OFF")
        c.execute("PRAGMA busy_timeout=30000")
        return c

    @property
    def conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = self._local.c = self._connect()
        return c

    @contextmanager
    def tx(self):
        depth = getattr(self._local, "depth", 0)
        with self._wlock:
            c = self.conn
            if depth == 0:
                c.execute("BEGIN IMMEDIATE")
            self._local.depth = depth + 1
            try:
                yield c
            except BaseException:
                self._local.depth = depth
                if depth == 0:
                    c.execute("ROLLBACK")
                raise
            self._local.depth = depth
            if depth == 0:
                c.execute("COMMIT")

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()

    # ------------------------------------------------------------ sources
    def add_source(self, url, priority=0, depth=0, origin=None, subject_id=None, now=None):
        """Returns (id, is_new). Re-adding only raises priority/subject binding; never resets a scanned source."""
        now = now or time.time()
        with self.tx() as c:
            r = c.execute("SELECT id, priority FROM sources WHERE url=?", (url,)).fetchone()
            if r:
                if priority > r["priority"]:
                    c.execute("UPDATE sources SET priority=?, subject_id=COALESCE(?,subject_id) WHERE id=?",
                              (priority, subject_id, r["id"]))
                return r["id"], False
            cur = c.execute("INSERT INTO sources(url,domain,priority,depth,origin,subject_id,first_seen,last_seen) "
                            "VALUES(?,?,?,?,?,?,?,?)",
                            (url, registered_domain(host_of(url)), priority, depth, origin, subject_id, now, now))
            return cur.lastrowid, True

    def domain_count(self, domain):
        return self.q1("SELECT COUNT(*) n FROM sources WHERE domain=?", (domain,))["n"]

    def claim(self, n, now, exclude_domains=(), lease=300):
        with self.tx() as c:
            rows = c.execute(
                "SELECT * FROM sources WHERE lease_until<=? AND (state='pending' OR "
                "(state IN ('scanned','error') AND next_scan_at<=?)) ORDER BY priority DESC, next_scan_at ASC LIMIT 200",
                (now, now)).fetchall()
            out, seen = [], set(exclude_domains)
            for r in rows:
                if r["domain"] in seen:
                    continue
                seen.add(r["domain"])
                out.append(r)
                if len(out) >= n:
                    break
            for r in out:
                c.execute("UPDATE sources SET lease_until=? WHERE id=?", (now + lease, r["id"]))
            return out

    def update_source(self, sid, **kw):
        cols = ",".join(f"{k}=?" for k in kw)
        with self.tx() as c:
            c.execute(f"UPDATE sources SET {cols} WHERE id=?", (*kw.values(), sid))

    # ------------------------------------------------------------ entities
    def resolve_entity(self, etype, key, display, now):
        """Exact (type,key), else fuzzy for persons (typo tolerant); returns entity id."""
        with self.tx() as c:
            r = c.execute("SELECT id FROM entities WHERE type=? AND key=?", (etype, key)).fetchone()
            if r:
                c.execute("UPDATE entities SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?) WHERE id=?",
                          (now, now, r["id"]))
                return r["id"]
            if etype == "person" and key:
                longest = max(key.split(), key=len)
                for cand in c.execute("SELECT id,key FROM entities WHERE type='person' AND key LIKE ? LIMIT 200",
                                      (f"%{longest[:3]}%",)).fetchall():
                    if similar_person_keys(key, cand["key"]):
                        c.execute("UPDATE entities SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?) WHERE id=?",
                                  (now, now, cand["id"]))
                        self.add_alias(cand["id"], display, None, now)
                        return cand["id"]
            return c.execute("INSERT INTO entities(type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?)",
                             (etype, key, display, now, now)).lastrowid

    def add_alias(self, eid, alias, source_id, now):
        ak = name_key(alias) if alias else ""
        if not ak:
            return
        with self.tx() as c:
            c.execute("INSERT INTO aliases(entity_id,alias_key,alias,source_id,first_seen,last_seen) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(entity_id,alias_key) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen), "
                      "first_seen=MIN(first_seen,excluded.first_seen)",
                      (eid, ak + "|" + fold(alias), alias, source_id, now, now))

    def add_evidence(self, eid, sid, snippet, conf, now):
        """Returns True if this (entity, source, snippet) is new."""
        with self.tx() as c:
            hs = h(snippet)
            r = c.execute("SELECT id, confidence FROM evidence WHERE entity_id=? AND source_id=? AND snippet_hash=?",
                          (eid, sid, hs)).fetchone()
            if r:
                c.execute("UPDATE evidence SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?), "
                          "confidence=MAX(confidence,?) WHERE id=?", (now, now, conf, r["id"]))
                return False
            c.execute("INSERT INTO evidence(entity_id,source_id,snippet,snippet_hash,confidence,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?,?)", (eid, sid, snippet, hs, conf, now, now))
            return True

    def add_relation(self, a, b, kind, now):
        a, b = (a, b) if a < b else (b, a)
        with self.tx() as c:
            r = c.execute("SELECT id FROM relations WHERE a_id=? AND b_id=? AND kind=?", (a, b, kind)).fetchone()
            if r:
                c.execute("UPDATE relations SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?) WHERE id=?",
                          (now, now, r["id"]))
                return r["id"]
            return c.execute("INSERT INTO relations(a_id,b_id,kind,first_seen,last_seen) VALUES(?,?,?,?,?)",
                             (a, b, kind, now, now)).lastrowid

    def add_rel_evidence(self, rid, sid, snippet, conf, now):
        with self.tx() as c:
            hs = h(snippet)
            r = c.execute("SELECT id FROM rel_evidence WHERE relation_id=? AND source_id=? AND snippet_hash=?",
                          (rid, sid, hs)).fetchone()
            if r:
                c.execute("UPDATE rel_evidence SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?), "
                          "confidence=MAX(confidence,?) WHERE id=?", (now, now, conf, r["id"]))
                return False
            c.execute("INSERT INTO rel_evidence(relation_id,source_id,snippet,snippet_hash,confidence,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?,?)", (rid, sid, snippet, hs, conf, now, now))
            return True

    def touch_source_evidence(self, sid, now):
        """Unchanged source: everything it evidenced is still visible."""
        with self.tx() as c:
            c.execute("UPDATE evidence SET last_seen=? WHERE source_id=?", (now, sid))
            c.execute("UPDATE rel_evidence SET last_seen=? WHERE source_id=?", (now, sid))

    def count_stale(self, sid, before):
        return sum(self.q1(f"SELECT COUNT(*) n FROM {t} WHERE source_id=? AND last_seen<?", (sid, before))["n"]
                   for t in ("evidence", "rel_evidence"))

    def count_new(self, sid, since):
        return sum(self.q1(f"SELECT COUNT(*) n FROM {t} WHERE source_id=? AND first_seen>=?", (sid, since))["n"]
                   for t in ("evidence", "rel_evidence"))

    def add_change(self, sid, now, kind, added, removed):
        with self.tx() as c:
            c.execute("INSERT INTO source_changes(source_id,at,kind,added,removed) VALUES(?,?,?,?,?)",
                      (sid, now, kind, added, removed))

    # ------------------------------------------------------------ subjects / jobs / events
    def add_event(self, subject_id, kind, payload, now=None):
        with self.tx() as c:
            c.execute("INSERT INTO events(subject_id,at,kind,payload) VALUES(?,?,?,?)",
                      (subject_id, now or time.time(), kind, json.dumps(payload, ensure_ascii=False)))

    def add_job(self, subject_id, provider, query, now=None):
        with self.tx() as c:
            cur = c.execute("INSERT OR IGNORE INTO jobs(subject_id,provider,query,created) VALUES(?,?,?,?)",
                            (subject_id, provider, query, now or time.time()))
            return cur.rowcount > 0

    def forget(self, needle: str) -> dict:
        """Erase entities whose display/key/alias contains `needle` with all their evidence and relations."""
        like = f"%{needle}%"
        with self.tx() as c:
            ids = [r["id"] for r in c.execute(
                "SELECT id FROM entities WHERE display LIKE ? OR key LIKE ? OR id IN "
                "(SELECT entity_id FROM aliases WHERE alias LIKE ?)", (like, like, like.lower()))]
            ph = ",".join("?" * len(ids)) or "NULL"
            rels = [r["id"] for r in c.execute(f"SELECT id FROM relations WHERE a_id IN ({ph}) OR b_id IN ({ph})", ids + ids)]
            rp = ",".join("?" * len(rels)) or "NULL"
            c.execute(f"DELETE FROM rel_evidence WHERE relation_id IN ({rp})", rels)
            c.execute(f"DELETE FROM relations WHERE id IN ({rp})", rels)
            c.execute(f"DELETE FROM evidence WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM aliases WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM subject_entities WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM entities WHERE id IN ({ph})", ids)
        return {"entities": len(ids), "relations": len(rels)}

    def stats(self):
        g = lambda sql: self.q1(sql)["n"]
        return {
            "sources": g("SELECT COUNT(*) n FROM sources"),
            "sources_pending": g("SELECT COUNT(*) n FROM sources WHERE state='pending'"),
            "sources_scanned": g("SELECT COUNT(*) n FROM sources WHERE state='scanned'"),
            "sources_error": g("SELECT COUNT(*) n FROM sources WHERE state IN ('error','blocked','skipped')"),
            "entities": g("SELECT COUNT(*) n FROM entities"),
            "evidence": g("SELECT COUNT(*) n FROM evidence"),
            "relations": g("SELECT COUNT(*) n FROM relations"),
            "subjects": g("SELECT COUNT(*) n FROM subjects"),
            "by_type": {r["type"]: r["n"] for r in self.q("SELECT type, COUNT(*) n FROM entities GROUP BY type")},
        }
