"""
Tests for Phase 4: Single-Writer Queue (import_worker.py)
מוודא שהארכיטקטורה של Single-Writer Queue עובדת ב-Windows ללא Deadlock.
"""
import os
import shutil
import tempfile
import threading
import time
import unittest

from osnit.import_worker import DBWriterThread, ParsedBatch, run_parallel_import
from osnit.store import Store
from tests import helpers


class TestSingleWriterQueue(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="osnit_swq_")
        self.db_path = os.path.join(self.tmpdir, "test_writer.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        # Stop writer BEFORE closing the store to avoid ResourceWarning
        try:
            writer = getattr(self.store, "_writer", None)
            if writer is not None and writer.is_alive():
                writer.stop(timeout=8)
        except Exception:
            pass
        try:
            self.store.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------

    def test_writer_thread_basic_batch_commit(self):
        """Pushing a batch with wait=True returns only after the data is committed."""
        batch = ParsedBatch(
            entities=[("person", "dana cohen", "Dana Cohen", 100.0, 100.0)],
            fts_items=[(1, "test.csv", "table=t:line=1", "Dana Cohen | dana@example.com")],
        )
        self.store.enqueue_batch(batch, wait=True)

        row = self.store.q1("SELECT key FROM entities WHERE type='person' AND key='dana cohen'")
        self.assertIsNotNone(row, "Entity should be in DB after wait=True enqueue")
        fts_row = self.store.search_fts("dana cohen")
        self.assertEqual(len(fts_row), 1)

    def test_concurrent_threads_zero_locks(self):
        """10 concurrent worker threads can write via the queue without database lock errors."""
        num_threads = 10
        items_per_thread = 200  # reduced for speed; still exercises concurrency
        errors = []

        def worker_task(thread_idx):
            try:
                for i in range(items_per_thread):
                    key = f"user_{thread_idx}_{i}"
                    batch = ParsedBatch(
                        entities=[("person", key, f"User {thread_idx}-{i}", 100.0, 100.0)],
                        fts_items=[(1, "bulk.sql",
                                    f"table=users:line={thread_idx * 1000 + i}",
                                    f"name: User {thread_idx}-{i}")],
                    )
                    self.store.enqueue_batch(batch, wait=False)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker_task, args=(t,), daemon=True)
                   for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # Flush everything before asserting counts
        self.store.flush_writer()

        self.assertEqual(errors, [], f"Encountered errors: {errors}")
        count = self.store.q1("SELECT COUNT(*) n FROM entities WHERE type='person'")["n"]
        self.assertEqual(count, num_threads * items_per_thread)

    def test_flush_writer_is_not_deadlocked(self):
        """flush_writer() must return within a few seconds (not deadlock) on Windows."""
        for i in range(50):
            batch = ParsedBatch(
                entities=[("org", f"company_{i}", f"Company {i}", 1.0, 1.0)],
            )
            self.store.enqueue_batch(batch, wait=False)

        start = time.time()
        self.store.flush_writer()
        elapsed = time.time() - start
        self.assertLess(elapsed, 15, f"flush_writer() took too long ({elapsed:.1f}s) – possible deadlock")

        count = self.store.q1("SELECT COUNT(*) n FROM entities WHERE type='org'")["n"]
        self.assertEqual(count, 50)

    def test_run_parallel_import_multiple_files(self):
        """run_parallel_import() imports 4 CSV files in parallel with 0 lock errors."""
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            files = []
            for i in range(4):
                fp = os.path.join(self.tmpdir, f"file_{i}.csv")
                with open(fp, "w", encoding="utf-8") as f:
                    f.write("name,phone\n")
                    for j in range(50):
                        f.write(f"Person_{i}_{j},050{i:03d}{j:04d}\n")
                files.append(fp)

            res = run_parallel_import(eng, files, max_workers=4)
            self.assertEqual(res["errors"], 0,
                             f"Parallel import had errors: {res.get('error_list')}")
            self.assertEqual(res["total_files"], 4)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
