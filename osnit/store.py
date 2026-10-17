"""SQLite store: sources, entities, evidence (with first/last seen), relations, subjects, jobs, events."""
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from difflib import SequenceMatcher

from .extract import norm_phone_il
from .textnorm import fold, name_key, tokens

from .urls import registered_domain, host_of


def name_tokens(name):
    """The folded words of a person name, as the per-word name index stores them."""
    return [t for t in (name_key(name) or "").split() if len(t) >= 2]

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, domain TEXT, kind TEXT, title TEXT,
  state TEXT NOT NULL DEFAULT 'pending', priority INTEGER DEFAULT 0, depth INTEGER DEFAULT 0,
  origin TEXT, subject_id INTEGER, raw_hash TEXT, text_hash TEXT, etag TEXT, last_modified TEXT,
  http_status INTEGER, error TEXT, bytes INTEGER, hit INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL, last_scanned REAL, last_changed REAL,
  next_scan_at REAL DEFAULT 0, scan_interval REAL DEFAULT 0, lease_until REAL DEFAULT 0,
  scan_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0,
  archive_path TEXT, lineage TEXT, sha256 TEXT);
CREATE INDEX IF NOT EXISTS sources_sched ON sources(state, next_scan_at, priority);
CREATE INDEX IF NOT EXISTS sources_domain ON sources(domain);
CREATE INDEX IF NOT EXISTS sources_subject ON sources(subject_id, state);
  CREATE TABLE IF NOT EXISTS entities(
  id INTEGER PRIMARY KEY, type TEXT NOT NULL, key TEXT NOT NULL, display TEXT,
  first_seen REAL, last_seen REAL, UNIQUE(type, key));
CREATE INDEX IF NOT EXISTS entities_key ON entities(key);
CREATE TABLE IF NOT EXISTS aliases(
  entity_id INTEGER NOT NULL, alias_key TEXT NOT NULL, alias TEXT, source_id INTEGER,
  first_seen REAL, last_seen REAL, PRIMARY KEY(entity_id, alias_key));
CREATE INDEX IF NOT EXISTS aliases_key ON aliases(alias_key);
CREATE INDEX IF NOT EXISTS aliases_source ON aliases(source_id);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, source_id INTEGER NOT NULL, snippet TEXT,
  snippet_hash TEXT, confidence REAL, first_seen REAL, last_seen REAL,
  UNIQUE(entity_id, source_id, snippet_hash));
CREATE INDEX IF NOT EXISTS evidence_source ON evidence(source_id);
CREATE INDEX IF NOT EXISTS evidence_entity ON evidence(entity_id);
CREATE TABLE IF NOT EXISTS relations(
  id INTEGER PRIMARY KEY, a_id INTEGER NOT NULL, b_id INTEGER NOT NULL, kind TEXT NOT NULL,
  first_seen REAL, last_seen REAL, UNIQUE(a_id, b_id, kind));
CREATE INDEX IF NOT EXISTS rel_a ON relations(a_id);
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
CREATE INDEX IF NOT EXISTS subject_entities_ent ON subject_entities(entity_id);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY, subject_id INTEGER, provider TEXT, query TEXT, state TEXT DEFAULT 'pending',
  created REAL, ran_at REAL, found INTEGER DEFAULT 0, error TEXT, UNIQUE(subject_id, provider, query));
CREATE INDEX IF NOT EXISTS jobs_subject ON jobs(subject_id, state);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, subject_id INTEGER, at REAL, kind TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS events_subject ON events(subject_id, id);
CREATE TABLE IF NOT EXISTS imports(
  id INTEGER PRIMARY KEY, name TEXT, path TEXT, bytes INTEGER, detected TEXT, mapping TEXT,
  state TEXT DEFAULT 'queued', total INTEGER DEFAULT 0, done INTEGER DEFAULT 0,
  records INTEGER DEFAULT 0, documents INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
  error TEXT, delete_raw INTEGER DEFAULT 0, created REAL, updated REAL,
  archive_path TEXT, lineage TEXT, sha256 TEXT);
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
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS subject_cache(subject_id INTEGER PRIMARY KEY, built REAL, payload TEXT);
CREATE TABLE IF NOT EXISTS identity_links(a INTEGER NOT NULL, b INTEGER NOT NULL, decision TEXT NOT NULL, score REAL,
  reasons TEXT, at REAL, PRIMARY KEY(a, b));
CREATE INDEX IF NOT EXISTS identity_links_b ON identity_links(b);
CREATE TABLE IF NOT EXISTS name_index(skel TEXT NOT NULL, entity_id INTEGER NOT NULL, PRIMARY KEY(skel, entity_id));
CREATE INDEX IF NOT EXISTS entities_type_seen ON entities(type, last_seen);
CREATE INDEX IF NOT EXISTS name_index_ent ON name_index(entity_id);
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
  source_id UNINDEXED,
  file_path UNINDEXED,
  location_ref UNINDEXED,
  raw_text,
  tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS osint_findings(
  id INTEGER PRIMARY KEY,
  entity_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT,
  url TEXT DEFAULT '',
  extracted_data_json TEXT DEFAULT '{}',
  confidence REAL DEFAULT 0.8,
  timestamp REAL,
  UNIQUE(entity_id, category, source_tool, url, title)
);
CREATE INDEX IF NOT EXISTS osint_findings_entity ON osint_findings(entity_id, confidence DESC);
CREATE TABLE IF NOT EXISTS osint_cache(
  query_key TEXT NOT NULL,
  tool TEXT NOT NULL,
  response_json TEXT,
  timestamp REAL,
  PRIMARY KEY(query_key, tool)
);
CREATE TABLE IF NOT EXISTS entity_images(
  id INTEGER PRIMARY KEY,
  entity_id INTEGER NOT NULL,
  image_url TEXT NOT NULL,
  local_path TEXT DEFAULT '',
  source_url TEXT DEFAULT '',
  source_type TEXT DEFAULT 'avatar',
  caption TEXT DEFAULT '',
  confidence REAL DEFAULT 0.8,
  face_verified INTEGER DEFAULT 0,
  is_primary INTEGER DEFAULT 0,
  timestamp REAL,
  UNIQUE(entity_id, image_url)
);
CREATE INDEX IF NOT EXISTS entity_images_entity ON entity_images(entity_id, is_primary DESC, confidence DESC);
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


# ---------------------------------------------------------------- people as identities, not names
# A person entity is ONE identity. Its key is "<name_key>|<anchor>": the anchor is the first personal identifier the
# record carried ("n:<national id>", "e:<email>", "p:<mobile>"), or "r:<record hash>" for a record that carried a
# name only. Records join an existing person only on a shared personal identifier and a compatible name; a name
# alone never merges two records (see resolve_person_record). Legacy/free-text persons keep the bare name_key.
GENERIC_IDENTIFIER_LIMIT = 25     # an identifier shared by more people than this is not personal (office, call centre)
_ANCHOR = {"national_id": "n", "id_number": "n", "email": "e", "phone": "p"}
_STRENGTH = {"national_id": 0, "id_number": 0, "email": 1, "phone": 2}


def person_base_key(key: str) -> str:
    """The name part of a person key (strips the identity anchor)."""
    return (key or "").split("|", 1)[0]


def is_personal_identifier(etype: str, key: str) -> bool:
    """Identifiers that point at ONE person: a national ID, a non-role email, a mobile (a landline is a household)."""
    if etype in ("national_id", "id_number"):
        return bool(key)
    if etype == "email":
        from .quality import is_role_mailbox
        return bool(key) and not is_role_mailbox(key)
    if etype == "phone":
        k = key or ""
        return k.startswith("+9725") or (k.startswith("+") and not k.startswith("+972"))
    return False


def similar_person_keys(ka: str, kb: str) -> bool:
    """Same person under a typo: equal token count, every token equal or (len>=5 and edit distance 1)."""
    ta, tb = person_base_key(ka).split(), person_base_key(kb).split()
    if len(ta) != len(tb):
        return False
    rest = list(tb)
    for x in ta:
        m = next((y for y in rest if x == y or (len(x) >= 5 and len(y) >= 5 and _ed1(x, y))), None)
        if m is None:
            return False
        rest.remove(m)
    return True


# OSNIT_SLOW_SQL=<seconds>: log every read query slower than this to stderr (a profiling aid for big databases).
try:
    _SLOW_SQL = float(os.environ.get("OSNIT_SLOW_SQL") or 0)
except ValueError:
    _SLOW_SQL = 0.0


def _log_slow(sql, dt):
    if dt >= _SLOW_SQL:
        print(f"[slow-sql] {dt:.3f}s  {' '.join(sql.split())[:400]}", file=sys.stderr, flush=True)


class _ThreadConnHolder:
    """Closes a thread-local SQLite connection automatically when the thread exits or Store.close() runs."""
    def __init__(self, conn, conns_set, lock):
        self.conn = conn
        self._conns_set = conns_set
        self._lock = lock

    def close(self):
        c = self.conn
        self.conn = None
        if c is not None:
            with self._lock:
                self._conns_set.discard(c)
            try:
                c.close()
            except Exception:
                pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Store:
    _HIGH_SCALE_INDEXES = (
        ("entities_key", "entities", "CREATE INDEX IF NOT EXISTS entities_key ON entities(key)"),
        ("entities_type_seen", "entities", "CREATE INDEX IF NOT EXISTS entities_type_seen ON entities(type, last_seen)"),
        ("aliases_key", "aliases", "CREATE INDEX IF NOT EXISTS aliases_key ON aliases(alias_key)"),
        ("aliases_source", "aliases", "CREATE INDEX IF NOT EXISTS aliases_source ON aliases(source_id)"),
        ("evidence_source", "evidence", "CREATE INDEX IF NOT EXISTS evidence_source ON evidence(source_id)"),
        ("evidence_entity", "evidence", "CREATE INDEX IF NOT EXISTS evidence_entity ON evidence(entity_id)"),
        ("rel_a", "relations", "CREATE INDEX IF NOT EXISTS rel_a ON relations(a_id)"),
        ("rel_b", "relations", "CREATE INDEX IF NOT EXISTS rel_b ON relations(b_id)"),
        ("relev_source", "rel_evidence", "CREATE INDEX IF NOT EXISTS relev_source ON rel_evidence(source_id)"),
        ("attributes_source", "attributes", "CREATE INDEX IF NOT EXISTS attributes_source ON attributes(source_id)"),
        ("attributes_name", "attributes", "CREATE INDEX IF NOT EXISTS attributes_name ON attributes(name)"),
        ("name_index_ent", "name_index", "CREATE INDEX IF NOT EXISTS name_index_ent ON name_index(entity_id)"),
        ("sources_subject", "sources", "CREATE INDEX IF NOT EXISTS sources_subject ON sources(subject_id, state)"),
        ("jobs_subject", "jobs", "CREATE INDEX IF NOT EXISTS jobs_subject ON jobs(subject_id, state)"),
        ("subject_entities_ent", "subject_entities", "CREATE INDEX IF NOT EXISTS subject_entities_ent ON subject_entities(entity_id)"),
    )

    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            import os
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self._wlock = threading.RLock()
        self._conn_lock = threading.Lock()
        self._conns = set()
        self._writes = 0   # monotonic data-version: bumped on every committed write (see tx); lets the dashboard
        #                    cache serve its last snapshot untouched while the database is idle (no new data)
        self._uri = path if path != ":memory:" else f"file:osnit_mem_{id(self)}?mode=memory&cache=shared"
        self._keep = self._connect()   # keeps shared in-memory db alive
        if path != ":memory:":
            self._build_missing_indexes_with_progress()
        self._keep.executescript(SCHEMA)
        for table, col, decl in (("subjects", "intent", "TEXT"), ("sources", "quality", "REAL"),
                                 ("sources", "page_type", "TEXT"), ("sources", "import_id", "INTEGER"),
                                 ("sources", "archive_path", "TEXT"), ("sources", "lineage", "TEXT"),
                                 ("sources", "sha256", "TEXT"),
                                 ("imports", "preview", "TEXT"), ("imports", "review", "INTEGER DEFAULT 0"),
                                 ("imports", "overrides", "TEXT"), ("imports", "summary", "TEXT"),
                                 ("imports", "ai", "TEXT"),
                                 ("imports", "archive_path", "TEXT"), ("imports", "lineage", "TEXT"),
                                 ("imports", "sha256", "TEXT")):
            try:
                self._keep.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass   # already there
        self._keep.execute("CREATE INDEX IF NOT EXISTS sources_import ON sources(import_id)")
        try:
            self._keep.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
              source_id UNINDEXED,
              file_path UNINDEXED,
              location_ref UNINDEXED,
              raw_text,
              tokenize = 'unicode61 remove_diacritics 2'
            );
            """)
        except sqlite3.OperationalError:
            pass
        if path != ":memory:":
            try:
                # reclaim a -wal file left huge by a prior run that never checkpointed (startup is single-threaded,
                # so TRUNCATE fully resets it); without this a 100GB+ WAL makes every read crawl.
                wal_path = f"{path}-wal"
                large_wal = os.path.exists(wal_path) and os.path.getsize(wal_path) > 32 * 1024 * 1024
                if large_wal:
                    import sys
                    print("==> [DB] Checkpointing WAL file (reclaiming disk space)...", file=sys.stderr, flush=True)
                self._keep.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.OperationalError:
                pass

    def _build_missing_indexes_with_progress(self):
        """On an existing populated database (e.g., 10M-20M entities), build any missing high-scale B-tree indexes
        one by one with live terminal progress so each completed index is immediately persisted on disk."""
        try:
            existing_tables = {
                r[0] for r in self._keep.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "entities" not in existing_tables:
                return
            has_rows = self._keep.execute("SELECT 1 FROM entities LIMIT 1").fetchone() is not None
            if not has_rows:
                return
            existing_idx = {
                r[0] for r in self._keep.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
            }
            missing = [
                (idx_name, tbl, ddl)
                for idx_name, tbl, ddl in self._HIGH_SCALE_INDEXES
                if tbl in existing_tables and idx_name not in existing_idx
            ]
            if not missing:
                return
            import sys
            total = len(missing)
            print(
                f"==> [DB] Optimizing existing database: building {total} missing high-scale index(es) "
                f"(one-time setup, please wait - do not close the window)...",
                file=sys.stderr,
                flush=True,
            )
            for i, (idx_name, tbl, ddl) in enumerate(missing, 1):
                t0 = time.time()
                print(f"==> [DB] ({i}/{total}) Building index '{idx_name}' on '{tbl}' ...", file=sys.stderr, flush=True)
                self._keep.execute(ddl)
                dt = time.time() - t0
                print(f"==> [DB] ({i}/{total}) Index '{idx_name}' ready ({dt:.1f}s)", file=sys.stderr, flush=True)
            print("==> [DB] High-scale database indexes ready.", file=sys.stderr, flush=True)
        except Exception:
            pass

    def _connect(self):
        c = sqlite3.connect(self._uri, timeout=30, check_same_thread=False, uri=self._uri.startswith("file:"),
                            isolation_level=None)
        c.row_factory = sqlite3.Row
        # busy_timeout FIRST: every later pragma/query waits out a momentary lock (up to 30s)
        c.execute("PRAGMA busy_timeout=30000")
        if self.path != ":memory:":
            try:
                c.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA wal_autocheckpoint=2000")
        else:
            c.execute("PRAGMA synchronous=OFF")
        c.execute("PRAGMA temp_store=MEMORY")
        try:
            from .sysmem import memory
            total = memory()[0]
            cache_mb = max(128, min(500, total // (64 * 1024 ** 2)))
            c.execute(f"PRAGMA cache_size=-{cache_mb * 1024}")
            if self.path != ":memory:":
                c.execute(f"PRAGMA mmap_size={min(3000000000, max(2 * 1024 ** 3, total // 4))}")
        except Exception:
            c.execute("PRAGMA cache_size=-500000")
            if self.path != ":memory:":
                c.execute("PRAGMA mmap_size=3000000000")
        with self._conn_lock:
            self._conns.add(c)
        return c

    @property
    def conn(self):
        holder = getattr(self._local, "holder", None)
        if holder is None or holder.conn is None:
            c = self._connect()
            holder = _ThreadConnHolder(c, self._conns, self._conn_lock)
            self._local.holder = holder
            self._local.c = c
        return holder.conn

    @contextmanager
    def tx(self, silent=False):
        """A write transaction. On the outermost commit it bumps the data-version (self._writes) so readers can tell
        the database changed — unless silent=True, used for writes that are not user data (e.g. the dashboard caching
        its own snapshot) and must not look like new data, or the dashboard would recompute itself forever."""
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
                if not silent:
                    self._writes += 1

    @property
    def data_version(self) -> int:
        """Monotonic counter of committed data writes. Equal values mean nothing changed in between."""
        return self._writes

    def meta_get(self, key):
        r = self.q1("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else None

    def meta_set(self, key, value):
        """Store a small key/value (e.g. a cached dashboard snapshot). silent: never counts as a data change."""
        with self.tx(silent=True) as c:
            c.execute("INSERT INTO meta(key,value,updated) VALUES(?,?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                      (key, value, time.time()))

    def q(self, sql, args=()):
        if _SLOW_SQL:
            t = time.perf_counter()
            rows = self.conn.execute(sql, args).fetchall()
            _log_slow(sql, time.perf_counter() - t)
            return rows
        return self.conn.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        if _SLOW_SQL:
            t = time.perf_counter()
            row = self.conn.execute(sql, args).fetchone()
            _log_slow(sql, time.perf_counter() - t)
            return row
        return self.conn.execute(sql, args).fetchone()

    def checkpoint(self):
        """Merge the WAL back into the database and truncate the -wal file. Constant readers keep SQLite's passive
        autocheckpoint from ever resetting the WAL, so it can grow to many GB and slow every read; calling this at
        quiet moments (e.g. after each imported file) keeps it bounded. Best-effort — a concurrent reader only
        limits how much is reclaimed, and the next call catches up."""
        if self.path == ":memory:":
            return
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError:
            pass

    def get_writer(self):
        """Returns the Single-Writer Queue thread, starting it if not active."""
        with self._wlock:
            if not hasattr(self, "_writer") or self._writer is None or not self._writer.is_alive():
                from .import_worker import DBWriterThread
                self._writer = DBWriterThread(self)
                self._writer.start()
            return self._writer

    def enqueue_batch(self, batch, wait=False):
        """Pushes a ParsedBatch to the Single-Writer Queue."""
        return self.get_writer().push(batch, wait=wait)

    def flush_writer(self):
        """Flushes the Single-Writer Queue and waits for completion.
        IMPORTANT: _wlock must NOT be held while waiting (would deadlock on Windows
        because the writer thread's _commit_batch() used to need _wlock via tx()).
        The writer now uses its own private connection, but we still release the lock
        before waiting to be safe and correct.
        """
        writer = None
        with self._wlock:
            if hasattr(self, "_writer") and self._writer is not None and self._writer.is_alive():
                writer = self._writer
        if writer is not None:
            writer.flush()  # wait OUTSIDE _wlock

    def close(self):
        """Flushes and stops the background writer thread and closes connections.
        _wlock is released before the blocking stop() call to prevent deadlocks.
        """
        writer = None
        if hasattr(self, "_wlock"):
            with self._wlock:
                if hasattr(self, "_writer") and self._writer is not None and self._writer.is_alive():
                    writer = self._writer
                    self._writer = None
        if writer is not None:
            try:
                writer.stop()  # flush + join OUTSIDE _wlock
            except Exception:
                pass
        if hasattr(self, "_local"):
            holder = getattr(self._local, "holder", None)
            if holder is not None:
                holder.close()
                self._local.holder = None
            self._local.c = None
        conns_to_close = []
        if hasattr(self, "_conn_lock") and hasattr(self, "_conns"):
            with self._conn_lock:
                conns_to_close = list(self._conns)
                self._conns.clear()
        for c in conns_to_close:
            try:
                c.close()
            except Exception:
                pass
        if hasattr(self, "_keep") and self._keep:
            try:
                self._keep.close()
            except Exception:
                pass
            self._keep = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------ documents_fts (FTS5)
    def index_document_fts(self, source_id, file_path, location_ref, raw_text):
        """Indexes one document or table row into FTS5 for instant sub-millisecond search."""
        if not raw_text or not str(raw_text).strip():
            return
        with self.tx(silent=True) as c:
            c.execute("INSERT INTO documents_fts(source_id, file_path, location_ref, raw_text) VALUES(?,?,?,?)",
                      (source_id, file_path or "", location_ref or "", str(raw_text)))

    def index_documents_fts_batch(self, items):
        """Batch-indexes rows: [(source_id, file_path, location_ref, raw_text), ...]"""
        clean_items = [(sid, fp or "", loc or "", str(txt)) for sid, fp, loc, txt in items if txt and str(txt).strip()]
        if not clean_items:
            return
        with self.tx(silent=True) as c:
            c.executemany("INSERT INTO documents_fts(source_id, file_path, location_ref, raw_text) VALUES(?,?,?,?)",
                          clean_items)

    def search_fts(self, query: str, limit: int = 50) -> list:
        """
        Full-text search over indexed documents and raw SQL/CSV rows using SQLite FTS5.
        Returns matching records with accurate source file, line reference, full text and highlighted snippet.
        """
        q = (query or "").strip()
        if not q:
            return []
        # Extract alphanumeric and Hebrew tokens for FTS5
        tokens = re.findall(r'[\w\u0590-\u05fe]+', q)
        if not tokens:
            return []
        # Support prefix search on tokens
        fts_expr = " AND ".join(f'"{t}"*' for t in tokens)
        try:
            rows = self.q("""
                SELECT rowid, source_id, file_path, location_ref, raw_text,
                       snippet(documents_fts, 3, '<b>', '</b>', '...', 15) AS snippet,
                       bm25(documents_fts) AS rank
                FROM documents_fts
                WHERE documents_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (fts_expr, limit))
            return [dict(r) for r in rows]
        except Exception:
            try:
                safe_q = f'"{q.replace(chr(34), chr(34)+chr(34))}"'
                rows = self.q("""
                    SELECT rowid, source_id, file_path, location_ref, raw_text,
                           snippet(documents_fts, 3, '<b>', '</b>', '...', 15) AS snippet,
                           bm25(documents_fts) AS rank
                    FROM documents_fts
                    WHERE documents_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """, (safe_q, limit))
                return [dict(r) for r in rows]
            except Exception:
                return []

    # ------------------------------------------------------------ sources
    def add_source(self, url, priority=0, depth=0, origin=None, subject_id=None, now=None, import_id=None,
                   archive_path=None, lineage=None, sha256=None):
        """Returns (id, is_new). Re-adding only raises priority/subject binding; never resets a scanned source."""
        now = now or time.time()
        with self.tx() as c:
            r = c.execute("SELECT id, priority, archive_path, lineage, sha256 FROM sources WHERE url=?", (url,)).fetchone()
            if r:
                upd = []
                args = []
                if priority > r["priority"]:
                    upd.append("priority=?")
                    args.append(priority)
                if subject_id:
                    upd.append("subject_id=COALESCE(?,subject_id)")
                    args.append(subject_id)
                if archive_path and not r["archive_path"]:
                    upd.append("archive_path=?")
                    args.append(archive_path)
                if lineage and not r["lineage"]:
                    upd.append("lineage=?")
                    args.append(lineage)
                if sha256 and not r["sha256"]:
                    upd.append("sha256=?")
                    args.append(sha256)
                if upd:
                    args.append(r["id"])
                    c.execute(f"UPDATE sources SET {', '.join(upd)} WHERE id=?", tuple(args))
                return r["id"], False
            cur = c.execute("INSERT INTO sources(url,domain,priority,depth,origin,subject_id,first_seen,last_seen,import_id,archive_path,lineage,sha256) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (url, registered_domain(host_of(url)), priority, depth, origin, subject_id, now, now,
                             import_id, archive_path, lineage, sha256))
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
    def resolve_entity(self, etype, key, display=None, now=None, fuzzy=True):
        """Exact (type,key), else fuzzy for persons (typo tolerant); returns entity id.
        When called as resolve_entity(etype, key) with display=None and now=None, performs a fast read-only
        lookup (without inserting a new entity) and returns the existing entity id or None.
        fuzzy=False (bulk file imports) is a single indexed UPSERT — the typo scan is O(people) per new person and
        made multi-million-row files quadratic. Spelling variants are still joined at query time (dossier/search)."""
        if display is None and now is None:
            if not key:
                return None
            r = self.q1("SELECT id FROM entities WHERE type=? AND key=?", (etype, key))
            if r:
                return r["id"]
            if etype in ("national_id", "id_number"):
                alt = "id_number" if etype == "national_id" else "national_id"
                r = self.q1("SELECT id FROM entities WHERE type=? AND key=?", (alt, key))
                if r:
                    return r["id"]
            if etype == "phone":
                pk = norm_phone_il(key)
                if pk and pk != key:
                    r = self.q1("SELECT id FROM entities WHERE type='phone' AND key=?", (pk,))
                    if r:
                        return r["id"]
                digits = re.sub(r"\D", "", key)
                if len(digits) >= 9:
                    tail = digits[-9:]
                    for cand_k in ("+972" + tail, "0" + tail, tail):
                        r = self.q1("SELECT id FROM entities WHERE type='phone' AND key=?", (cand_k,))
                        if r:
                            return r["id"]
            if etype == "person":
                nk = name_key(key)
                if nk:
                    r = self.q1("SELECT id FROM entities WHERE type='person' AND (key=? OR (key>=? AND key<?)) "
                                "ORDER BY id LIMIT 1", (nk, nk + "|", nk + "|\uffff"))
                    if r:
                        return r["id"]
                    ar = self.q1(
                        "SELECT entity_id FROM aliases WHERE alias_key >= ? AND alias_key < ? LIMIT 1",
                        (nk + "|", nk + "|\uffff"),
                    )
                    if ar:
                        return ar["entity_id"]
            return None

        if now is None:
            now = time.time()
        if display is None:
            display = key
        if etype == "person":
            from .name_validator import is_valid_person_name
            if not is_valid_person_name(display or key):
                return -1
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
                pfx = key[:3]
                cands = c.execute(
                    "SELECT id,key FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT 200",
                    (pfx, pfx + "\uffff"),
                ).fetchall()
                if not cands and len(key.split()) > 1:
                    longest = max(key.split(), key=len)[:3]
                    cands = c.execute(
                        "SELECT id,key FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT 200",
                        (longest, longest + "\uffff"),
                    ).fetchall()
                for cand in cands:
                    if similar_person_keys(key, cand["key"]):
                        c.execute("UPDATE entities SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?) WHERE id=?",
                                  (now, now, cand["id"]))
                        self.add_alias(cand["id"], display, None, now)
                        return cand["id"]
            return c.execute("INSERT INTO entities(type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?)",
                             (etype, key, display, now, now)).lastrowid

    def reindex_names(self, limit=5000, blocking=True):
        """Index a batch of not-yet-indexed person entities by cross-script name skeletons, so search finds a name in
        any spelling or script ('bareket cohen' -> 'ברקת כהן'). Incremental via a high-water mark in meta, so it
        backfills existing data in the background without slowing imports (inline indexing would make a multi-million
        row import quadratic). Returns how many entities were indexed this call (0 when caught up)."""
        if not blocking:
            if not self._wlock.acquire(blocking=False):
                return 0
            try:
                return self._reindex_names_locked(min(limit, 250))
            finally:
                self._wlock.release()
        return self._reindex_names_locked(limit)

    _NAME_HWM = "name_index_v2_hwm"   # v2 adds the per-word "t:<word>" keys; a v1 index is re-walked once

    def _reindex_names_locked(self, limit=5000):
        try:
            hwm = int(self.meta_get(self._NAME_HWM) or 0)
        except (TypeError, ValueError):
            hwm = 0
        with self.tx(silent=True) as c:
            # read inside the write transaction: read-then-write outside it raced a concurrent purge, which left
            # index rows for deleted people (and SQLite may hand their ids to new, unrelated people later)
            rows = c.execute("SELECT id, key, display FROM entities WHERE type='person' AND id>? ORDER BY id LIMIT ?",
                             (hwm, limit)).fetchall()
            if not rows:
                return 0
            self._index_name_rows(c, rows, rows[-1]["id"])
        return len(rows)

    def _index_name_rows(self, c, rows, hwm):
        from .xling import name_skeleton_keys
        batch = []
        for r in rows:
            for sk in name_skeleton_keys(r["display"] or r["key"] or ""):
                batch.append((sk, r["id"]))
            for tk in name_tokens(r["display"] or r["key"] or ""):
                batch.append(("t:" + tk, r["id"]))
        c.executemany("INSERT OR IGNORE INTO name_index(skel, entity_id) VALUES(?,?)", batch)
        c.execute("INSERT INTO meta(key,value,updated) VALUES(?,?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                  (self._NAME_HWM, str(hwm), time.time()))

    def start_name_indexer(self, batch=5000, idle=3.0):
        """Keep the cross-script / per-word name index current in the background: big batches until caught up,
        then a cheap poll. Without it the index only advanced 250 people per search request, so on a database of
        millions most people could not be found by part of their name for a long time."""
        if getattr(self, "_name_indexer", None) or self.path == ":memory:":
            return
        stop = self._name_indexer_stop = threading.Event()

        def run():
            while not stop.is_set():
                try:
                    n = self.reindex_names(batch, blocking=True)
                except Exception:
                    n = 0
                stop.wait(0.02 if n else idle)

        self._name_indexer = threading.Thread(target=run, daemon=True, name="name-indexer")
        self._name_indexer.start()

    def persons_by_token(self, tokens_, limit=200):
        """Person ids whose name contains every given word (folded), via the per-word index. Starts from the rarest
        word, so 'כהן' alone or 'דוד כהן' never scans the whole people table."""
        toks = [t for t in dict.fromkeys(tokens_) if t]
        if not toks:
            return []
        counts = []
        for t in toks:
            n = self.q1("SELECT COUNT(*) n FROM (SELECT 1 FROM name_index WHERE skel=? LIMIT 50001)", ("t:" + t,))["n"]
            if n == 0:
                return []
            counts.append((n, t))
        counts.sort()
        first = counts[0][1]
        rest = [t for _, t in counts[1:]]
        sql = "SELECT n0.entity_id id FROM name_index n0"
        for i in range(1, len(rest) + 1):      # each further word: a primary-key probe per candidate
            sql += f" CROSS JOIN name_index n{i} ON n{i}.skel=? AND n{i}.entity_id=n0.entity_id"
        sql += " WHERE n0.skel=? ORDER BY n0.entity_id DESC LIMIT ?"
        args = ["t:" + t for t in rest] + ["t:" + first, limit]
        return [r["id"] for r in self.q(sql, tuple(args))]

    def persons_by_skeleton(self, name, limit=200):
        """Candidate person entities whose name shares a cross-script consonant skeleton with `name`."""
        from .xling import name_skeleton_keys
        keys = [k for k in name_skeleton_keys(name) if k]
        if not keys:
            return []
        ph = ",".join("?" * len(keys))
        return self.q(f"SELECT DISTINCT e.id, e.key, e.display FROM name_index n CROSS JOIN entities e ON e.id=n.entity_id "
                      f"WHERE n.skel IN ({ph}) AND e.type='person' LIMIT ?", (*keys, limit))

    def resolve_person_record(self, name_key_, display, identifiers, record_text, now):
        """The person entity a tabular record belongs to. identifiers: [(type, key)] the record links to this name.
        Joins an existing person only through a shared PERSONAL identifier (national ID > email > mobile) whose
        holder has a compatible name and no conflicting national ID; an identifier held by more than
        GENERIC_IDENTIFIER_LIMIT people is ignored. Otherwise a new identity anchored on the record's strongest
        identifier, or on the record itself (a name-only record is its own person until the operator links it).
        Caller holds the write transaction. Returns (entity id, how) with how in joined|new|record."""
        from .identity import _name_matches
        personal = sorted({(t, k) for t, k in identifiers if is_personal_identifier(t, k)},
                          key=lambda tk: (_STRENGTH.get(tk[0], 9), tk[1]))
        row_ids = {k for t, k in personal if t in ("national_id", "id_number")}
        generic = set()
        for t, k in personal:
            iid = self.q1("SELECT id FROM entities WHERE type=? AND key=?", (t, k))
            if not iid:
                continue
            holders = self.q(
                "SELECT e.id, e.key, e.display FROM (SELECT a_id AS pid FROM relations WHERE b_id=? "
                f"UNION SELECT b_id FROM relations WHERE a_id=?) r CROSS JOIN entities e ON e.id = r.pid "
                f"WHERE e.type='person' LIMIT {GENERIC_IDENTIFIER_LIMIT + 1}", (iid["id"], iid["id"]))
            if len(holders) > GENERIC_IDENTIFIER_LIMIT:
                generic.add((t, k))                       # shared by too many people: not a personal identifier
                continue
            for h in holders:
                hk = person_base_key(h["key"])
                if not (hk == name_key_ or _name_matches(display, h["display"] or hk)):
                    continue
                if row_ids and self._has_other_national_id(h["id"], row_ids):
                    continue                              # two different national IDs are never one person
                self._touch(h["id"], now)
                return h["id"], "joined"
        anchors = [tk for tk in personal if tk not in generic]
        if anchors:
            t, k = anchors[0]
            anchor, how = f"{_ANCHOR[t]}:{k}", "new"
        else:
            anchor = "r:" + hashlib.sha1((record_text or display or "").encode("utf-8")).hexdigest()[:16]
            how = "record"
        key = f"{name_key_}|{anchor}"
        return self.conn.execute(
            "INSERT INTO entities(type,key,display,first_seen,last_seen) VALUES('person',?,?,?,?) "
            "ON CONFLICT(type,key) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen), "
            "first_seen=MIN(first_seen,excluded.first_seen) RETURNING id", (key, display, now, now)).fetchone()[0], how

    def _has_other_national_id(self, pid, ids):
        for r in self.q(
                "SELECT o.key FROM (SELECT b_id oid FROM relations WHERE a_id=? UNION SELECT a_id FROM relations "
                "WHERE b_id=?) r CROSS JOIN entities o ON o.id = r.oid WHERE o.type IN ('national_id','id_number') "
                "LIMIT 20", (pid, pid)):
            if r["key"] not in ids:
                return True
        return False

    def _touch(self, eid, now):
        self.conn.execute("UPDATE entities SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?) WHERE id=?",
                          (now, now, eid))

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
        if not str(kind).startswith("kinship:"):
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
            c.execute(f"DELETE FROM sensitive WHERE entity_id IN ({ph})", ids)   # erase the person's credential findings too
            c.execute(f"DELETE FROM osint_findings WHERE entity_id IN ({ph})", ids)
            c.execute(f"DELETE FROM entity_images WHERE entity_id IN ({ph})", ids)
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

    # ------------------------------------------------------------ Deep OSINT findings, images & cache
    def add_osint_finding(self, entity_id: int, category: str, source_tool: str = "", title: str = "",
                          summary: str = "", url: str = "", extracted_data: dict | None = None,
                          confidence: float = 0.8, timestamp: float | None = None,
                          tool: str = "", raw: dict | None = None) -> int:
        """Persist or update a Deep OSINT finding for an entity."""
        ts = timestamp if timestamp is not None else time.time()
        src_tool = source_tool or tool or "OSINT"
        ext_data = extracted_data if extracted_data is not None else (raw if raw is not None else {})
        data_json = json.dumps(ext_data, ensure_ascii=False)
        with self.tx() as c:
            row = c.execute(
                "INSERT INTO osint_findings(entity_id, category, source_tool, title, summary, url, "
                "extracted_data_json, confidence, timestamp) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(entity_id, category, source_tool, url, title) DO UPDATE SET "
                "summary=excluded.summary, extracted_data_json=excluded.extracted_data_json, "
                "confidence=MAX(confidence, excluded.confidence), timestamp=MAX(timestamp, excluded.timestamp) "
                "RETURNING id",
                (int(entity_id), str(category), str(src_tool), str(title), str(summary or ""),
                 str(url or ""), data_json, float(confidence), float(ts))
            ).fetchone()
            return row[0] if row else 0

    def osint_findings_for(self, eids) -> list[dict]:
        """Return all Deep OSINT findings for one entity ID or an iterable of entity IDs."""
        if isinstance(eids, int):
            eids = [eids]
        if not eids:
            return []
        ph = ",".join(str(int(i)) for i in eids)
        rows = self.q(f"SELECT * FROM osint_findings WHERE entity_id IN ({ph}) ORDER BY confidence DESC, timestamp DESC")
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["extracted_data"] = json.loads(d.get("extracted_data_json") or "{}")
            except Exception:
                d["extracted_data"] = {}
            d["tool"] = d.get("source_tool") or ""
            d["raw"] = d["extracted_data"]
            out.append(d)
        return out

    def add_entity_image(self, entity_id: int, image_url: str, local_path: str = "",
                         source_url: str = "", source_type: str = "avatar",
                         caption: str = "", confidence: float = 0.85,
                         face_verified: bool = False, is_primary: bool = False,
                         timestamp: float | None = None,
                         source_page_url: str = "", width: int = 0, height: int = 0,
                         **kwargs) -> int:
        """Persist or update a target image in `entity_images`."""
        ts = timestamp if timestamp is not None else time.time()
        img_u = str(image_url or "").strip()
        if not img_u:
            return 0
        eff_source_url = str(source_url or source_page_url or "").strip()
        with self.tx() as c:
            existing_primary = c.execute(
                "SELECT id FROM entity_images WHERE entity_id=? AND is_primary=1 LIMIT 1",
                (int(entity_id),),
            ).fetchone()
            make_primary = 1 if (is_primary or not existing_primary) else 0
            if is_primary and existing_primary:
                c.execute("UPDATE entity_images SET is_primary=0 WHERE entity_id=?", (int(entity_id),))
            row = c.execute(
                "INSERT INTO entity_images(entity_id, image_url, local_path, source_url, source_type, "
                "caption, confidence, face_verified, is_primary, timestamp) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(entity_id, image_url) DO UPDATE SET "
                "local_path=CASE WHEN excluded.local_path!='' THEN excluded.local_path ELSE entity_images.local_path END, "
                "source_url=CASE WHEN excluded.source_url!='' THEN excluded.source_url ELSE entity_images.source_url END, "
                "caption=CASE WHEN excluded.caption!='' THEN excluded.caption ELSE entity_images.caption END, "
                "confidence=MAX(entity_images.confidence, excluded.confidence), "
                "face_verified=MAX(entity_images.face_verified, excluded.face_verified), "
                "is_primary=MAX(entity_images.is_primary, excluded.is_primary), "
                "timestamp=MAX(entity_images.timestamp, excluded.timestamp) "
                "RETURNING id",
                (
                    int(entity_id),
                    img_u,
                    str(local_path or ""),
                    eff_source_url,
                    str(source_type or "avatar"),
                    str(caption or ""),
                    float(confidence),
                    1 if face_verified else 0,
                    make_primary,
                    float(ts),
                ),
            ).fetchone()
            return row[0] if row else 0

    def entity_images_for(self, eids) -> list[dict]:
        """Return all verified target images for one entity ID or an iterable of entity IDs."""
        if isinstance(eids, int):
            eids = [eids]
        if not eids:
            return []
        ph = ",".join(str(int(i)) for i in eids)
        rows = self.q(
            f"SELECT * FROM entity_images WHERE entity_id IN ({ph}) "
            "ORDER BY is_primary DESC, face_verified DESC, confidence DESC, timestamp DESC"
        )
        out = []
        seen_urls: set[str] = set()
        for r in rows:
            d = dict(r)
            u = d.get("image_url") or ""
            if u in seen_urls:
                continue
            seen_urls.add(u)
            d["face_verified"] = bool(d.get("face_verified"))
            d["face_detected"] = d["face_verified"]
            d["is_primary"] = bool(d.get("is_primary"))
            d["source_page_url"] = d.get("source_url") or ""
            lp = d.get("local_path") or ""
            if lp and os.path.basename(lp):
                d["display_url"] = f"/api/avatars/{os.path.basename(lp)}"
            else:
                d["display_url"] = u
            out.append(d)
        return out

    def primary_avatar_for(self, eids) -> dict | None:
        """Return the best primary avatar image record for an entity or cluster (or None if none exists)."""
        imgs = self.entity_images_for(eids)
        if imgs:
            return imgs[0]
        return None

    def osint_cache_get(self, query_key: str, tool: str, max_age_s: float = 86400.0):
        """Return cached OSINT tool response if newer than max_age_s (default 24h), else None."""
        r = self.q1("SELECT response_json, timestamp FROM osint_cache WHERE query_key=? AND tool=?",
                    (str(query_key).strip().lower(), str(tool).strip().lower()))
        if not r:
            return None
        if max_age_s and (time.time() - float(r["timestamp"] or 0)) > max_age_s:
            return None
        try:
            return json.loads(r["response_json"])
        except Exception:
            return None

    def osint_cache_put(self, query_key: str, tool: str, response_obj, timestamp: float | None = None):
        """Cache an OSINT tool response silently (does not bump data_version)."""
        ts = timestamp if timestamp is not None else time.time()
        payload = json.dumps(response_obj, ensure_ascii=False)
        with self.tx(silent=True) as c:
            c.execute(
                "INSERT INTO osint_cache(query_key, tool, response_json, timestamp) VALUES(?,?,?,?) "
                "ON CONFLICT(query_key, tool) DO UPDATE SET response_json=excluded.response_json, "
                "timestamp=excluded.timestamp",
                (str(query_key).strip().lower(), str(tool).strip().lower(), payload, float(ts))
            )

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

    def purge_sources(self, where: str, args=(), batch: int = None) -> dict:
        """Delete sources matching `where` with everything they evidence; then drop entities and relations that
        no remaining source supports. A fact also seen elsewhere survives with its other evidence.
        Optimized for 10M-20M entity scale by tracking affected relations/entities via indexed temp tables.
        With `batch`, only that many matching sources are handled in this (short) transaction — call again until
        it reports 0 sources, so a multi-million-row file is removed without holding the write lock for minutes."""
        lim = f" LIMIT {int(batch)}" if batch else ""
        with self.tx() as c:
            c.execute("CREATE TEMP TABLE IF NOT EXISTS _purge(id INTEGER PRIMARY KEY)")
            c.execute("CREATE TEMP TABLE IF NOT EXISTS _purge_rel(id INTEGER PRIMARY KEY)")
            c.execute("CREATE TEMP TABLE IF NOT EXISTS _purge_ent(id INTEGER PRIMARY KEY)")
            c.execute("DELETE FROM _purge")
            c.execute("DELETE FROM _purge_rel")
            c.execute("DELETE FROM _purge_ent")
            c.execute(f"INSERT INTO _purge SELECT id FROM sources WHERE {where}{lim}", args)
            n_src = c.execute("SELECT COUNT(*) FROM _purge").fetchone()[0]
            if n_src == 0:
                return {"sources": 0, "entities": 0}
            n_ent = 0

            # Collect affected relations and entities BEFORE deleting evidence/attributes
            c.execute("INSERT OR IGNORE INTO _purge_rel SELECT DISTINCT relation_id FROM rel_evidence WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("INSERT OR IGNORE INTO _purge_ent SELECT DISTINCT entity_id FROM evidence WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("INSERT OR IGNORE INTO _purge_ent SELECT DISTINCT entity_id FROM attributes WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("INSERT OR IGNORE INTO _purge_ent SELECT DISTINCT entity_id FROM aliases WHERE source_id IN (SELECT id FROM _purge) AND entity_id IS NOT NULL")
            c.execute("INSERT OR IGNORE INTO _purge_ent SELECT DISTINCT a_id FROM relations WHERE id IN (SELECT id FROM _purge_rel)")
            c.execute("INSERT OR IGNORE INTO _purge_ent SELECT DISTINCT b_id FROM relations WHERE id IN (SELECT id FROM _purge_rel)")

            for t in ("evidence", "rel_evidence", "attributes", "source_changes"):
                c.execute(f"DELETE FROM {t} WHERE source_id IN (SELECT id FROM _purge)")
            try:
                c.execute("DELETE FROM documents_fts WHERE source_id IN (SELECT id FROM _purge)")
            except sqlite3.OperationalError:
                pass
            c.execute("UPDATE aliases SET source_id=NULL WHERE source_id IN (SELECT id FROM _purge)")
            c.execute("DELETE FROM sources WHERE id IN (SELECT id FROM _purge)")

            # Remove relations from _purge_rel that still have surviving evidence, then delete the orphaned ones
            c.execute("DELETE FROM _purge_rel WHERE EXISTS (SELECT 1 FROM rel_evidence WHERE relation_id = _purge_rel.id)")
            c.execute("DELETE FROM relations WHERE id IN (SELECT id FROM _purge_rel)")

            # Remove entities from _purge_ent that still have surviving evidence, relations, or attributes
            c.execute(
                "DELETE FROM _purge_ent WHERE "
                "EXISTS (SELECT 1 FROM evidence WHERE entity_id = _purge_ent.id) OR "
                "EXISTS (SELECT 1 FROM relations WHERE a_id = _purge_ent.id) OR "
                "EXISTS (SELECT 1 FROM relations WHERE b_id = _purge_ent.id) OR "
                "EXISTS (SELECT 1 FROM attributes WHERE entity_id = _purge_ent.id)"
            )
            n_ent = c.execute("SELECT COUNT(*) FROM _purge_ent").fetchone()[0]
            if n_ent > 0:
                c.execute("DELETE FROM entities WHERE id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM aliases WHERE entity_id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM subject_entities WHERE entity_id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM sensitive WHERE entity_id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM osint_findings WHERE entity_id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM entity_images WHERE entity_id IN (SELECT id FROM _purge_ent)")
                c.execute("DELETE FROM name_index WHERE entity_id IN (SELECT id FROM _purge_ent)")

            c.execute("DELETE FROM _purge")
            c.execute("DELETE FROM _purge_rel")
            c.execute("DELETE FROM _purge_ent")
            if n_ent:
                c.execute("DELETE FROM subject_cache")     # saved investigation pages may show removed data
        return {"sources": n_src, "entities": n_ent}

    def purge_import(self, import_id: int) -> dict:
        res = self.purge_sources("import_id=?", (import_id,))
        with self.tx() as c:
            c.execute("UPDATE imports SET state='purged', updated=? WHERE id=?", (time.time(), import_id))
        return res

    def delete_entity(self, entity_id: int) -> dict:
        """Erase a single entity by its ID with all its evidence, relations, attributes, aliases, and findings."""
        with self.tx() as c:
            rels = [r["id"] for r in c.execute("SELECT id FROM relations WHERE a_id=? OR b_id=?", (entity_id, entity_id))]
            rp = ",".join("?" * len(rels)) or "NULL"
            if rels:
                c.execute(f"DELETE FROM rel_evidence WHERE relation_id IN ({rp})", rels)
                c.execute(f"DELETE FROM relations WHERE id IN ({rp})", rels)
            c.execute("DELETE FROM evidence WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM attributes WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM sensitive WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM osint_findings WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM entity_images WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM aliases WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM subject_entities WHERE entity_id=?", (entity_id,))
            c.execute("DELETE FROM entities WHERE id=?", (entity_id,))
            c.execute("DELETE FROM subject_cache")             # saved investigation pages may show it
        return {"entity_id": entity_id, "relations_removed": len(rels)}

    def purge_invalid_persons(self) -> dict:
        """Scan all existing 'person' entities in the DB and delete any non-person / false-positive entities."""
        from .name_validator import purge_invalid_persons as _purge_fn
        return _purge_fn(self)

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
            for t in ("rel_evidence", "relations", "evidence", "attributes", "sensitive", "osint_findings",
                      "entity_images", "aliases", "subject_entities", "entities", "source_changes", "sources", "events", "jobs", "subjects",
                      "subject_cache"):
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

    _STATS_KEYS = ("sources", "sources_pending", "sources_scanned", "sources_error", "entities", "evidence",
                   "relations", "subjects")

    def _compute_stats(self):
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

    def _stats_bg(self, v):
        try:
            self._stats_cache = (v, self._compute_stats())
        except Exception:
            pass
        finally:
            self._stats_computing = False

    def stats(self, blocking=True):
        """Counts for the header/overview. These are whole-table COUNT(*) scans (seconds on a multi-GB database) and
        the UI polls them on a loop, so they are memoised by the data-version: unchanged data is served instantly.
        With blocking=False (the polled endpoint) a cold/stale cache is refreshed in a background thread and the last
        known counts (or zeros) are returned at once, so a huge database never makes the request hang and time out."""
        v = self._writes
        cached = getattr(self, "_stats_cache", None)
        if cached and cached[0] == v:
            return cached[1]
        if not blocking:
            if not getattr(self, "_stats_computing", False):
                self._stats_computing = True
                threading.Thread(target=self._stats_bg, args=(v,), daemon=True, name="stats").start()
            return cached[1] if cached else {**{k: 0 for k in self._STATS_KEYS}, "by_type": {}}
        data = self._compute_stats()
        self._stats_cache = (v, data)
        return data
