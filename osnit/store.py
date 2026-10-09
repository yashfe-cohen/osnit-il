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
CREATE TABLE IF NOT EXISTS imports(
  id INTEGER PRIMARY KEY, name TEXT, path TEXT, bytes INTEGER, detected TEXT, mapping TEXT,
  state TEXT DEFAULT 'queued', total INTEGER DEFAULT 0, done INTEGER DEFAULT 0,
  records INTEGER DEFAULT 0, documents INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
  error TEXT, delete_raw INTEGER DEFAULT 0, created REAL, updated REAL);
CREATE INDEX IF NOT EXISTS imports_state ON imports(state, id);
CREATE TABLE IF NOT EXISTS attributes(
  id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, source_id INTEGER NOT NULL, name TEXT NOT NULL, value TEXT,
  kind TEXT, first_seen REAL, last_seen REAL, UNIQUE(entity_id, source_id, name, value));
CREATE INDEX IF NOT EXISTS attributes_source ON attributes(source_id);
CREATE INDEX IF NOT EXISTS attributes_name ON attributes(name);
CREATE TABLE IF NOT EXISTS field_memory(
  header_key TEXT PRIMARY KEY, header TEXT, type TEXT NOT NULL, source TEXT DEFAULT 'auto', hits INTEGER DEFAULT 1,
  updated REAL);
CREATE TABLE IF NOT EXISTS custom_types(
  key TEXT PRIMARY KEY, label TEXT NOT NULL, headers TEXT, pattern TEXT, examples TEXT, identifier INTEGER DEFAULT 1,
  sensitive INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS ai_cache(
  sig TEXT PRIMARY KEY, template TEXT, model TEXT, created REAL);
CREATE TABLE IF NOT EXISTS sensitive(
  id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, source_id INTEGER, kind TEXT, family TEXT, severity TEXT,
  value TEXT, confidence REAL, link TEXT, link_confidence REAL, reasoning TEXT, first_seen REAL, last_seen REAL,
  UNIQUE(entity_id, kind, value));
CREATE INDEX IF NOT EXISTS sensitive_entity ON sensitive(entity_id);
CREATE TABLE IF NOT EXISTS span_rules(
  header_key TEXT NOT NULL, label TEXT NOT NULL, type TEXT NOT NULL, rule TEXT NOT NULL, examples TEXT,
  hits INTEGER DEFAULT 1, updated REAL, PRIMARY KEY(header_key, label));
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
                                 ("sources", "page_type", "TEXT"), ("sources", "import_id", "INTEGER"),
                                 ("imports", "preview", "TEXT"), ("imports", "review", "INTEGER DEFAULT 0"),
                                 ("imports", "overrides", "TEXT"), ("imports", "summary", "TEXT"),
                                 ("imports", "ai", "TEXT")):
            try:
                self._keep.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass   # already there
        self._keep.execute("CREATE INDEX IF NOT EXISTS sources_import ON sources(import_id)")

    def _connect(self):
        c = sqlite3.connect(self._uri, timeout=30, check_same_thread=False, uri=self._uri.startswith("file:"),
                            isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL" if self.path != ":memory:" else "PRAGMA synchronous=OFF")
        c.execute("PRAGMA busy_timeout=30000")
        if self.path != ":memory:":
            # WAL + NORMAL is crash-safe for the database and far faster for large imports than FULL
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA wal_autocheckpoint=20000")   # fewer, larger checkpoints during a big import
        # scale the page cache and memory-map to the machine's RAM so a strong computer actually uses its memory
        try:
            from .sysmem import memory
            total = memory()[0]
            cache_mb = max(128, min(512, total // (64 * 1024 ** 2)))   # up to 512 MB page cache on a big machine
            c.execute(f"PRAGMA cache_size=-{cache_mb * 1024}")
            if self.path != ":memory:":
                c.execute(f"PRAGMA mmap_size={min(2 * 1024 ** 3, total // 4)}")   # memory-map reads, up to 2 GB
        except Exception:
            c.execute("PRAGMA cache_size=-131072")       # ~128 MB page cache (fallback)
        c.execute("PRAGMA temp_store=MEMORY")
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
    def add_source(self, url, priority=0, depth=0, origin=None, subject_id=None, now=None, import_id=None):
        """Returns (id, is_new). Re-adding only raises priority/subject binding; never resets a scanned source."""
        now = now or time.time()
        with self.tx() as c:
            r = c.execute("SELECT id, priority FROM sources WHERE url=?", (url,)).fetchone()
            if r:
                if priority > r["priority"]:
                    c.execute("UPDATE sources SET priority=?, subject_id=COALESCE(?,subject_id) WHERE id=?",
                              (priority, subject_id, r["id"]))
                return r["id"], False
            cur = c.execute("INSERT INTO sources(url,domain,priority,depth,origin,subject_id,first_seen,last_seen,import_id) "
                            "VALUES(?,?,?,?,?,?,?,?,?)",
                            (url, registered_domain(host_of(url)), priority, depth, origin, subject_id, now, now,
                             import_id))
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
    def resolve_entity(self, etype, key, display, now, fuzzy=True):
        """Exact (type,key), else fuzzy for persons (typo tolerant); returns entity id.
        fuzzy=False (bulk file imports) is a single indexed UPSERT — the typo scan is O(people) per new person and
        made multi-million-row files quadratic. Spelling variants are still joined at query time (dossier/search)."""
        if not fuzzy or etype != "person":
            with self.tx() as c:
                return c.execute(
                    "INSERT INTO entities(type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(type,key) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen), "
                    "first_seen=MIN(first_seen,excluded.first_seen) RETURNING id",
                    (etype, key, display, now, now)).fetchone()[0]
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

    def add_evidence_fast(self, eid, sid, snippet, conf, now):
        """Single-statement UPSERT (no is-new answer) — the bulk-import path."""
        with self.tx() as c:
            c.execute("INSERT INTO evidence(entity_id,source_id,snippet,snippet_hash,confidence,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?,?) ON CONFLICT(entity_id,source_id,snippet_hash) DO UPDATE SET "
                      "last_seen=MAX(last_seen,excluded.last_seen), first_seen=MIN(first_seen,excluded.first_seen), "
                      "confidence=MAX(confidence,excluded.confidence)",
                      (eid, sid, snippet, h(snippet), conf, now, now))

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

    def add_attribute(self, eid, sid, name, value, kind, now):
        with self.tx() as c:
            c.execute("INSERT INTO attributes(entity_id,source_id,name,value,kind,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) "
                      "ON CONFLICT(entity_id,source_id,name,value) DO UPDATE SET "
                      "last_seen=MAX(last_seen,excluded.last_seen), first_seen=MIN(first_seen,excluded.first_seen)",
                      (eid, sid, name, value, kind, now, now))

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
        """Facts (entities/relations) this source showed before and no longer shows."""
        return sum(self.q1(f"SELECT COUNT(*) n FROM (SELECT {k} FROM {t} WHERE source_id=? GROUP BY {k} "
                           f"HAVING MAX(last_seen)<?)", (sid, before))["n"]
                   for t, k in (("evidence", "entity_id"), ("rel_evidence", "relation_id")))

    def count_new(self, sid, since):
        """Facts this source shows for the first time."""
        return sum(self.q1(f"SELECT COUNT(*) n FROM (SELECT {k} FROM {t} WHERE source_id=? GROUP BY {k} "
                           f"HAVING MIN(first_seen)>=?)", (sid, since))["n"]
                   for t, k in (("evidence", "entity_id"), ("rel_evidence", "relation_id")))

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
            c.execute(f"DELETE FROM attributes WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM aliases WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM subject_entities WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM entities WHERE id IN ({ph})", ids)
        return {"entities": len(ids), "relations": len(rels)}

    # ------------------------------------------------------------ what columns mean (learned / taught)
    def field_memory(self) -> dict:
        return {r["header_key"]: dict(r) for r in self.q("SELECT * FROM field_memory")}

    def learn_fields(self, items, source="auto"):
        """Remember header -> type. A user's teaching is never overwritten by automatic learning."""
        now = time.time()
        with self.tx() as c:
            for hk, header, t in items:
                c.execute("INSERT INTO field_memory(header_key,header,type,source,hits,updated) VALUES(?,?,?,?,1,?) "
                          "ON CONFLICT(header_key) DO UPDATE SET hits=hits+1, updated=excluded.updated, "
                          "type=CASE WHEN field_memory.source='user' AND excluded.source!='user' THEN field_memory.type "
                          "ELSE excluded.type END, "
                          "source=CASE WHEN field_memory.source='user' THEN 'user' ELSE excluded.source END",
                          (hk, header, t, source, now))

    def forget_field(self, header_key):
        with self.tx() as c:
            c.execute("DELETE FROM field_memory WHERE header_key=?", (header_key,))

    def add_sensitive(self, entity_id, source_id, f, now):
        """Persist one sensitive finding against the individual it concerns (dossier aggregation)."""
        with self.tx() as c:
            c.execute("INSERT INTO sensitive(entity_id,source_id,kind,family,severity,value,confidence,link,"
                      "link_confidence,reasoning,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                      "ON CONFLICT(entity_id,kind,value) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen), "
                      "confidence=MAX(confidence,excluded.confidence)",
                      (entity_id, source_id, f["kind"], f["family"], f["severity"], f["value"], f["confidence"],
                       f["link"], f["link_confidence"], f["reasoning"], now, now))

    def sensitive_for(self, eids):
        if not eids:
            return []
        ph = ",".join(str(int(i)) for i in eids)
        return [dict(r) for r in self.q(f"SELECT * FROM sensitive WHERE entity_id IN ({ph}) ORDER BY confidence DESC")]

    def ai_template_get(self, sig):
        """A cached, already-validated AI template for this (header-set, content-kinds) signature, or None."""
        r = self.q1("SELECT template FROM ai_cache WHERE sig=?", (sig,))
        return json.loads(r["template"]) if r and r["template"] else None if r is None else {}

    def ai_template_put(self, sig, template, model):
        import time
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO ai_cache(sig,template,model,created) VALUES(?,?,?,?)",
                      (sig, json.dumps(template, ensure_ascii=False), model, time.time()))

    def custom_types(self):
        from .semantic import CustomType
        out = []
        for r in self.q("SELECT * FROM custom_types ORDER BY created"):
            out.append(CustomType(r["key"], r["label"], tuple(json.loads(r["headers"] or "[]")), r["pattern"] or "",
                                  bool(r["identifier"]), bool(r["sensitive"])))
        return out

    def custom_type_rows(self):
        return [dict(r, headers=json.loads(r["headers"] or "[]"), examples=json.loads(r["examples"] or "[]"))
                for r in self.q("SELECT * FROM custom_types ORDER BY created")]

    def save_custom_type(self, key, label, headers=(), pattern="", examples=(), identifier=True, sensitive=False):
        with self.tx() as c:
            c.execute("INSERT INTO custom_types(key,label,headers,pattern,examples,identifier,sensitive,created) "
                      "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET label=excluded.label, headers=excluded.headers, "
                      "pattern=excluded.pattern, examples=excluded.examples, identifier=excluded.identifier, "
                      "sensitive=excluded.sensitive",
                      (key, label, json.dumps(list(headers), ensure_ascii=False), pattern,
                       json.dumps(list(examples), ensure_ascii=False), 1 if identifier else 0, 1 if sensitive else 0,
                       time.time()))

    def delete_custom_type(self, key):
        with self.tx() as c:
            c.execute("DELETE FROM custom_types WHERE key=?", (key,))
            c.execute("DELETE FROM field_memory WHERE type=?", (key,))

    # ------------------------------------------------------------ marker-taught piece rules (learned per header)
    def span_rules(self) -> dict:
        out = {}
        for r in self.q("SELECT * FROM span_rules ORDER BY hits DESC"):
            out.setdefault(r["header_key"], []).append(dict(label=r["label"], type=r["type"],
                                                             rule=json.loads(r["rule"]),
                                                             examples=json.loads(r["examples"] or "[]")))
        return out

    def save_span_rule(self, header_key, label, type_, rule, examples):
        with self.tx() as c:
            c.execute("INSERT INTO span_rules(header_key,label,type,rule,examples,hits,updated) VALUES(?,?,?,?,?,1,?) "
                      "ON CONFLICT(header_key,label) DO UPDATE SET type=excluded.type, rule=excluded.rule, "
                      "examples=excluded.examples, hits=hits+1, updated=excluded.updated",
                      (header_key, label, type_, json.dumps(rule, ensure_ascii=False),
                       json.dumps(examples[-30:], ensure_ascii=False), time.time()))

    def delete_span_rule(self, header_key, label):
        with self.tx() as c:
            c.execute("DELETE FROM span_rules WHERE header_key=? AND label=?", (header_key, label))

    # ------------------------------------------------------------ deletion by origin
    FILE_SOURCES = "(import_id IS NOT NULL OR state='imported' OR url LIKE 'import://%' OR url LIKE 'file://%')"

    def purge_sources(self, where: str, args=()) -> dict:
        """Delete sources matching `where` with everything they evidence; then drop entities and relations that
        no remaining source supports. A fact also seen elsewhere survives with its other evidence."""
        with self.tx() as c:
            c.execute("CREATE TEMP TABLE IF NOT EXISTS _purge(id INTEGER PRIMARY KEY)")
            c.execute("DELETE FROM _purge")
            c.execute(f"INSERT INTO _purge SELECT id FROM sources WHERE {where}", args)
            n_src = c.execute("SELECT COUNT(*) FROM _purge").fetchone()[0]
            before = c.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            for t in ("evidence", "rel_evidence", "attributes", "source_changes"):
                c.execute(f"DELETE FROM {t} WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("UPDATE aliases SET source_id=NULL WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("DELETE FROM sources WHERE id IN (SELECT id FROM _purge)")
            c.execute("DELETE FROM relations WHERE id NOT IN (SELECT relation_id FROM rel_evidence)")
            c.execute("DELETE FROM entities WHERE id NOT IN (SELECT entity_id FROM evidence) "
                      "AND id NOT IN (SELECT a_id FROM relations) AND id NOT IN (SELECT b_id FROM relations) "
                      "AND id NOT IN (SELECT entity_id FROM attributes)")
            c.execute("DELETE FROM aliases WHERE entity_id NOT IN (SELECT id FROM entities)")
            c.execute("DELETE FROM subject_entities WHERE entity_id NOT IN (SELECT id FROM entities)")
            after = c.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            c.execute("DELETE FROM _purge")
        return {"sources": n_src, "entities": before - after}

    def purge_import(self, import_id: int) -> dict:
        res = self.purge_sources("import_id=?", (import_id,))
        with self.tx() as c:
            c.execute("UPDATE imports SET state='purged', updated=? WHERE id=?", (time.time(), import_id))
        return res

    def reset(self, scope: str = "all") -> dict:
        """scope: files (everything imported from files) | web (everything crawled) | all (the whole picture;
        searches, their history and the import list are cleared too)."""
        if scope == "files":
            res = self.purge_sources(self.FILE_SOURCES)
            with self.tx() as c:
                c.execute("UPDATE imports SET state='purged', updated=? WHERE state IN ('done','error')", (time.time(),))
            return res
        if scope == "web":
            return self.purge_sources(f"NOT {self.FILE_SOURCES}")
        if scope != "all":
            raise ValueError("scope must be files, web or all")
        n = self.stats()
        with self.tx() as c:
            for t in ("rel_evidence", "relations", "evidence", "attributes", "aliases", "subject_entities", "entities",
                      "source_changes", "sources", "events", "jobs", "subjects"):
                c.execute(f"DELETE FROM {t}")
            # keep import rows (so files kept in the inbox are not picked up again) but mark them gone
            c.execute("UPDATE imports SET state='purged', updated=? WHERE state!='running'", (time.time(),))
        return {"sources": n["sources"], "entities": n["entities"]}

    def delete_import_rows(self, ids) -> list:
        """Remove entries from the file list (their extracted data is untouched). Returns their stored paths."""
        ids = [int(i) for i in ids]
        if not ids:
            return []
        ph = ",".join("?" * len(ids))
        paths = [r["path"] for r in self.q(f"SELECT path FROM imports WHERE id IN ({ph})", ids) if r["path"]]
        with self.tx() as c:
            c.execute(f"DELETE FROM imports WHERE id IN ({ph})", ids)
        return paths

    def vacuum(self):
        """Give the freed space back to the disk (after big deletions the .db file otherwise stays large)."""
        if self.path == ":memory:":
            return
        with self._wlock:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("VACUUM")

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
