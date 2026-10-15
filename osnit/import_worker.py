"""
osnit.import_worker: Single-Writer Queue architecture & parallel import processing.
Eliminates SQLite write locks ('Database is locked') by decoupling parsing workers
from SQLite writes, streaming all insertions to a dedicated DBWriterThread that
performs large atomic batch commits (up to 10,000 records or 1.5s interval).

תיקון Deadlock ב-Windows:
- ה-DBWriterThread משתמש בחיבור SQLite **פרטי משלו** (לא דרך store.tx() / _wlock).
- flush() ו-stop() ב-store.py **אינם מחזיקים** את _wlock בזמן ההמתנה לאירוע.
- כתוצאה: אפס Deadlock, הבדיקות מסתיימות תוך שניות בודדות גם ב-Windows.
"""
import logging
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import List, Tuple, Any, Optional, Callable

logger = logging.getLogger("osnit.import_worker")

BATCH_SIZE_LIMIT = 10000
BATCH_TIME_LIMIT = 1.5


@dataclass
class ParsedBatch:
    """Holds parsed records ready for insertion without touching SQLite directly."""
    entities: List[Tuple[str, str, str, float, float]] = field(default_factory=list)
    attributes: List[Tuple[int, int, str, str, str, float, float]] = field(default_factory=list)
    evidence: List[Tuple[int, int, str, str, float, float, float]] = field(default_factory=list)
    relations: List[Tuple[int, int, str, float, float]] = field(default_factory=list)
    rel_evidence: List[Tuple[int, int, str, str, float, float, float]] = field(default_factory=list)
    fts_items: List[Tuple[int, str, str, str]] = field(default_factory=list)
    custom_ops: List[Callable[[Any], None]] = field(default_factory=list)
    event: Optional[threading.Event] = None

    def total_count(self) -> int:
        return (len(self.entities) + len(self.attributes) + len(self.evidence) +
                len(self.relations) + len(self.rel_evidence) + len(self.fts_items) +
                len(self.custom_ops))

    def is_empty(self) -> bool:
        return self.total_count() == 0


class DBWriterThread(threading.Thread):
    """
    Dedicated single writer thread for SQLite.
    Collects ParsedBatch objects from multiple worker threads and commits them in batches
    of up to 10,000 records (or every 1.5 seconds), preventing database lock contention.

    חשוב: הוא פותח חיבור SQLite **פרטי משלו** ישירות (ולא דרך store.tx()), כדי
    להימנע מ-Deadlock עם _wlock של ה-store כאשר flush() ממתין לאירוע.
    """
    def __init__(self, store, max_batch_size: int = BATCH_SIZE_LIMIT, flush_interval: float = BATCH_TIME_LIMIT):
        super().__init__(name="osnit-db-writer", daemon=True)
        self.store = store
        self.max_batch_size = max_batch_size
        self.flush_interval = flush_interval
        self.q: queue.Queue = queue.Queue(maxsize=5000)
        self._stop_event = threading.Event()
        self.committed_records = 0
        self.committed_batches = 0
        # חיבור פרטי – נפתח ב-run() בתוך ה-Thread עצמו
        self._conn: Optional[sqlite3.Connection] = None

    # ---------------------------------------------------------------------- public API

    def push(self, batch: ParsedBatch, wait: bool = False):
        """Push a ParsedBatch. If wait=True, blocks until it is committed."""
        if wait and batch.event is None:
            batch.event = threading.Event()
        self.q.put(batch)
        if wait and batch.event is not None:
            batch.event.wait(timeout=30)

    def flush(self):
        """Flush all queued items and wait until they are committed (no _wlock held)."""
        done_evt = threading.Event()
        sentinel = ParsedBatch(event=done_evt)
        self.q.put(sentinel)
        done_evt.wait(timeout=30)

    def stop(self, timeout: float = 10.0):
        """Flush, then stop the thread. Safe to call from outside _wlock."""
        if self.is_alive():
            self.flush()
            self._stop_event.set()
            self.q.put(None)  # wake up the loop immediately
            self.join(timeout=timeout)

    # ---------------------------------------------------------------------- internal

    def _open_connection(self) -> sqlite3.Connection:
        """Open a dedicated write connection with WAL pragmas."""
        path = self.store.path
        conn = sqlite3.connect(path, check_same_thread=False, timeout=60)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=3000000000")
        conn.execute("PRAGMA cache_size=-500000")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def run(self):
        """Main writer loop – runs entirely in the writer thread."""
        self._conn = self._open_connection()
        current_batch: List[ParsedBatch] = []
        current_count = 0
        last_flush_time = time.time()

        try:
            while not self._stop_event.is_set():
                try:
                    timeout = max(0.05, self.flush_interval - (time.time() - last_flush_time))
                    item = self.q.get(timeout=timeout)
                except queue.Empty:
                    item = _TIMEOUT_SENTINEL

                if item is None:
                    # Stop sentinel – commit whatever is left and exit
                    if current_batch:
                        self._commit_batch(current_batch)
                    break

                if item is not _TIMEOUT_SENTINEL:
                    current_batch.append(item)
                    current_count += item.total_count()

                # Decide whether to flush now
                time_due = (time.time() - last_flush_time) >= self.flush_interval
                count_due = current_count >= self.max_batch_size
                has_event = any(b.event for b in current_batch)

                if current_batch and (count_due or time_due or item is _TIMEOUT_SENTINEL or has_event):
                    self._commit_batch(current_batch)
                    current_batch = []
                    current_count = 0
                    last_flush_time = time.time()
        finally:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _commit_batch(self, batches: List[ParsedBatch]):
        """Write one mega-transaction. Runs entirely on the writer thread's own connection."""
        all_ents = []
        all_attrs = []
        all_ev = []
        all_rels = []
        all_relev = []
        all_fts = []
        all_ops = []
        events_to_signal = []

        for b in batches:
            all_ents.extend(b.entities)
            all_attrs.extend(b.attributes)
            all_ev.extend(b.evidence)
            all_rels.extend(b.relations)
            all_relev.extend(b.rel_evidence)
            all_fts.extend(b.fts_items)
            all_ops.extend(b.custom_ops)
            if b.event:
                events_to_signal.append(b.event)

        total_ops = (len(all_ents) + len(all_attrs) + len(all_ev) +
                     len(all_rels) + len(all_relev) + len(all_fts) + len(all_ops))

        # Signal even if nothing to write (flush sentinel with empty batch)
        if total_ops == 0:
            for evt in events_to_signal:
                evt.set()
            return

        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            c = conn.cursor()

            if all_ents:
                c.executemany("""
                    INSERT INTO entities(type, key, display, first_seen, last_seen)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(type, key) DO UPDATE SET
                        last_seen=MAX(entities.last_seen, excluded.last_seen),
                        display=COALESCE(excluded.display, entities.display)
                """, all_ents)

            if all_attrs:
                c.executemany("""
                    INSERT INTO attributes(entity_id, source_id, name, value, kind, first_seen, last_seen)
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(entity_id, source_id, name, value) DO UPDATE SET
                        last_seen=MAX(attributes.last_seen, excluded.last_seen)
                """, all_attrs)

            if all_ev:
                c.executemany("""
                    INSERT OR IGNORE INTO evidence(entity_id, source_id, snippet, snippet_hash, confidence, first_seen, last_seen)
                    VALUES(?,?,?,?,?,?,?)
                """, all_ev)

            if all_rels:
                c.executemany("""
                    INSERT INTO relations(a_id, b_id, kind, first_seen, last_seen)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(a_id, b_id, kind) DO UPDATE SET
                        last_seen=MAX(relations.last_seen, excluded.last_seen)
                """, all_rels)

            if all_relev:
                c.executemany("""
                    INSERT OR IGNORE INTO rel_evidence(relation_id, source_id, snippet, snippet_hash, confidence, first_seen, last_seen)
                    VALUES(?,?,?,?,?,?,?)
                """, all_relev)

            if all_fts:
                c.executemany("""
                    INSERT INTO documents_fts(source_id, file_path, location_ref, raw_text)
                    VALUES(?,?,?,?)
                """, all_fts)

            for op in all_ops:
                try:
                    op(c)
                except Exception as e:
                    logger.warning("Custom batch operation failed: %s", e)

            conn.execute("COMMIT")
            # Tell the store that new data exists (increment _writes counter)
            self.store._writes += 1
            self.committed_records += total_ops
            self.committed_batches += 1

        except Exception as e:
            logger.error("DBWriterThread commit failed: %s", e)
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        finally:
            for evt in events_to_signal:
                evt.set()


# Sentinel object used instead of a string to avoid collisions with real data
_TIMEOUT_SENTINEL = object()


def run_parallel_import(engine, paths: List[str], max_workers: int = 4) -> dict:
    """
    Parses multiple files or chunks across parallel threads without database lock errors.
    Each worker imports a file; WAL mode + busy_timeout handles any transient contention.
    The Single-Writer Queue is used by each worker via engine.store.enqueue_batch().
    """
    results = {"total_files": len(paths), "errors": 0, "error_list": []}
    errors: List[str] = []
    lock = threading.Lock()

    def _worker(file_path):
        try:
            from .importdb import import_db
            import_db(engine, file_path, delete_raw=False)
        except Exception as err:
            with lock:
                errors.append(str(err))

    threads = []
    for p in paths:
        t = threading.Thread(target=_worker, args=(p,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Flush any pending batches enqueued by the workers
    engine.store.flush_writer()

    results["errors"] = len(errors)
    results["error_list"] = errors
    return results
