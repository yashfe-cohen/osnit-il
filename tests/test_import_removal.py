"""Removing a file from the import list: a file whose import failed half-way loses its partial data, a large
file's data is deleted in the background in short transactions (the request returns at once), and nothing is
left behind — no orphan records, full-text rows or name-index rows."""
import os
import tempfile
import time
import unittest

import osnit.importqueue as iq
from osnit.importqueue import ImportQueue
from tests import helpers


def _csv(n):
    rows = ["שם פרטי,שם משפחה,טלפון"]
    for i in range(n):
        rows.append(f"אדם{chr(0x05d0 + i % 22)},משפחה{chr(0x05d0 + (i // 22) % 22)}{chr(0x05d0 + (i // 484) % 22)},05{2 + i % 7}{1000000 + i * 7919 % 8999999:07d}")
    return ("\n".join(rows) + "\n").encode("utf-8")


class ImportRemoval(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def _left(self):
        return {t: self.store.q1(f"SELECT COUNT(*) n FROM {t}")["n"]
                for t in ("sources", "entities", "relations", "evidence", "attributes", "documents_fts", "name_index")}

    def _empty(self):
        return {k: 0 for k in self._left()}

    def test_failed_midway_then_removed_leaves_nothing(self):
        real = iq.import_db
        calls = {"n": 0}

        def failing(*a, **kw):                    # the import dies after its second batch of rows
            prog = kw.get("progress")

            def boom(stats):
                calls["n"] += 1
                if prog:
                    prog(stats)
                if calls["n"] >= 2:
                    raise RuntimeError("disk error")
            kw["progress"] = boom
            return real(*a, **kw)

        iq.import_db = failing
        try:
            job = self.q.add_bytes(_csv(3000), "people.csv")
            self.q.run_pending()
        finally:
            iq.import_db = real
        row = self.store.q1("SELECT state, error FROM imports WHERE id=?", (job["id"],))
        self.assertEqual(row["state"], "error")
        self.store.reindex_names(10000)
        self.assertGreater(self._left()["entities"], 0)         # partial data is in the DB
        res = self.q.remove(job["id"])                          # plain "remove" (no explicit purge)
        self.assertEqual(res["removed"], 1)
        self.assertEqual(self._left(), self._empty())
        self.assertIsNone(self.store.q1("SELECT 1 FROM imports WHERE id=?", (job["id"],)))

    def test_large_file_is_purged_in_background(self):
        job = self.q.add_bytes(_csv(3000), "big.csv")
        self.q.run_pending()
        self.store.reindex_names(10000)
        self.q.SYNC_PURGE_SOURCES = 2            # treat this file as "large"
        self.q.PURGE_BATCH = 1
        t = time.time()
        res = self.q.remove(job["id"], purge=True)
        self.assertLess(time.time() - t, 2.0)
        self.assertEqual(res["purging"], [job["id"]])
        for _ in range(200):
            if not self.store.q1("SELECT 1 FROM imports WHERE id=?", (job["id"],)):
                break
            time.sleep(0.05)
        self.assertIsNone(self.store.q1("SELECT 1 FROM imports WHERE id=?", (job["id"],)))
        self.assertEqual(self._left(), self._empty())

    def test_delete_data_keeps_the_row_as_purged(self):
        job = self.q.add_bytes(_csv(1200), "f.csv")
        self.q.run_pending()
        self.q.SYNC_PURGE_SOURCES = 1
        self.q.purge(job["id"])
        for _ in range(200):
            if self.store.q1("SELECT state FROM imports WHERE id=?", (job["id"],))["state"] == "purged":
                break
            time.sleep(0.05)
        self.assertEqual(self.store.q1("SELECT state FROM imports WHERE id=?", (job["id"],))["state"], "purged")
        self.assertEqual(self._left()["entities"], 0)

    def test_other_files_survive(self):
        a = self.q.add_bytes("שם פרטי,שם משפחה,טלפון\nרונית,ברק,054-7718293\n".encode("utf-8"), "a.csv")
        b = self.q.add_bytes("שם פרטי,שם משפחה,טלפון\nיואב,שגיא,052-6612309\n".encode("utf-8"), "b.csv")
        self.q.run_pending()
        self.q.remove(a["id"], purge=True)
        names = {r["display"] for r in self.store.q("SELECT display FROM entities WHERE type='person'")}
        self.assertEqual(names, {"יואב שגיא"})
        self.assertIsNotNone(self.store.q1("SELECT 1 FROM imports WHERE id=?", (b["id"],)))


if __name__ == "__main__":
    unittest.main()
