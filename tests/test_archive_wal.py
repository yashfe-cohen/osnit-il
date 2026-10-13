import json
import os
import shutil
import tempfile
import unittest

from osnit import archive
from osnit.store import Store
from tests import helpers


class TestArchiveWal(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_wal.db")
        self.archive_dir = os.path.join(self.tmpdir, "archive")
        self.inbox_dir = os.path.join(self.tmpdir, "inbox")
        os.makedirs(self.archive_dir, exist_ok=True)
        os.makedirs(self.inbox_dir, exist_ok=True)
        self.store = Store(self.db_path)

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_wal_mode_enabled(self):
        row = self.store.q1("PRAGMA journal_mode")
        self.assertEqual(row[0].lower(), "wal")
        busy = self.store.q1("PRAGMA busy_timeout")
        self.assertGreaterEqual(busy[0], 30000)

    def test_archive_file_and_lineage(self):
        sample_path = os.path.join(self.tmpdir, "customers.csv")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write("name,phone\nDana,0501234567\nRon,0527654321\n")

        res = archive.archive_file(sample_path, archive_dir=self.archive_dir)
        self.assertIn("sha256", res)
        self.assertTrue(os.path.exists(res["archive_path"]))
        self.assertTrue(res["archive_path"].startswith(os.path.abspath(self.archive_dir)))

        # Verify lineage builder
        lineage = archive.build_lineage("archive/dump.sql", inner_path="users", location_ref="table=wp_users:line=2")
        self.assertIn("wp_users:line=2", lineage)
        self.assertIn("archive/dump.sql::users", lineage)

    def test_view_archive_content_by_line(self):
        sample_path = os.path.join(self.archive_dir, "test.sql")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2: sensitive data\nline 3\n")

        # add source to store
        sid, _ = self.store.add_source("file://test.sql", archive_path=sample_path, lineage="archive/test.sql")
        view = archive.view_archive_content(self.store, source_id=sid, location_ref="table=t:line=2")
        self.assertEqual(view["line"], 2)
        self.assertEqual(view["content"], "line 2: sensitive data")
        self.assertEqual(view["table"], "t")

    def test_import_queue_archives_file(self):
        from osnit.importqueue import ImportQueue
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            q = ImportQueue(eng, inbox=self.inbox_dir)
            sample_file = os.path.join(self.inbox_dir, "data.csv")
            with open(sample_file, "w", encoding="utf-8") as f:
                f.write("name,email\nDana Cohen,dana@example.com\n")

            job = q.add_file(sample_file, name="data.csv", delete_raw=False)
            q.run_pending()

            rec = store.q1("SELECT archive_path, sha256, lineage FROM imports WHERE id=?", (job["id"],))
            self.assertIsNotNone(rec)
            self.assertIsNotNone(rec["archive_path"])
            self.assertTrue(os.path.exists(rec["archive_path"]))
            self.assertIsNotNone(rec["sha256"])
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
