"""Regression tests for the review-found defects: credential findings must follow the person through every
erasure path (forget / per-file purge / full reset), forced kind='domain' must not crash on a non-domain query,
and a UTF-8 file whose multibyte char is split by the 64KB detection window must still be read as UTF-8."""
import os
import tempfile
import unittest

from osnit import search
from osnit.catalog import plan_columns
from osnit.importdb import _detect_encoding
from osnit.store import Store


class StoreFixes(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))

    def _seed_secret(self, name="דנה אברמוב", nid="312345678"):
        with self.store.tx() as c:
            eid = c.execute("INSERT INTO entities(type,key,display) VALUES('person',?,?)", (name, name)).lastrowid
            sid = c.execute("INSERT INTO sources(url,domain,import_id,first_seen,last_seen) VALUES(?,?,1,0,0)",
                            (f"import://x/{name}", "x")).lastrowid
            c.execute("INSERT INTO evidence(entity_id,source_id,snippet,confidence) VALUES(?,?,'s',1.0)", (eid, sid))
            c.execute("INSERT INTO sensitive(entity_id,source_id,kind,value,confidence) VALUES(?,?,?,?,1.0)",
                      (eid, sid, "national_id", nid))
        return eid, sid

    def _sensitive(self):
        return self.store.q1("SELECT COUNT(*) n FROM sensitive")["n"]

    def test_forget_also_erases_sensitive(self):
        self._seed_secret()
        self.assertEqual(self._sensitive(), 1)
        self.store.forget("דנה אברמוב")                      # removal request must leave nothing behind
        self.assertEqual(self._sensitive(), 0)

    def test_purge_drops_orphaned_sensitive(self):
        self._seed_secret()
        self.store.purge_sources("import_id=1")              # deleting the file's source GCs the person...
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM entities")["n"], 0)
        self.assertEqual(self._sensitive(), 0)               # ...and must not orphan their credential findings

    def test_reset_all_clears_sensitive(self):
        self._seed_secret()
        self.store.reset("all")
        self.assertEqual(self._sensitive(), 0)

    def test_search_prepare_domain_never_crashes_on_nondomain(self):
        d, t, k, v = search.prepare("acme corp", "domain")   # forced kind on a non-strict-domain query
        self.assertEqual(t, "domain")                        # used to raise AttributeError (None.group)

    def test_card_column_is_kept_as_attribute_not_dropped(self):
        plan = plan_columns(["name", "credit_card"],
                            [{"name": "דוד לוי", "credit_card": "4111111111111111"}])
        col = next(c for c in plan.columns if c.name == "credit_card")
        self.assertEqual(col.status, "attribute")        # was 'entity' with no builder -> silently dropped
        self.assertIn(col, plan.attrs)                   # so it is now stored under its own labelled field

    def test_stats_memoised_until_data_changes(self):
        self._seed_secret()
        s1 = self.store.stats()
        self.assertIs(self.store.stats(), s1)            # no write between -> cached, no whole-table re-scan
        with self.store.tx() as c:
            c.execute("INSERT INTO entities(type,key,display) VALUES('org','acme','Acme')")
        s3 = self.store.stats()
        self.assertIsNot(s3, s1)                         # a committed write invalidates the memo
        self.assertEqual(s3["by_type"].get("org"), 1)

    def test_checkpoint_truncates_the_wal(self):
        for i in range(300):                             # many commits grow the -wal file
            with self.store.tx() as c:
                c.execute("INSERT INTO entities(type,key,display) VALUES('person',?,?)", (f"k{i}", f"d{i}"))
        self.store.checkpoint()                          # must merge + truncate it back down
        wal = self.store.path + "-wal"
        self.assertTrue(not os.path.exists(wal) or os.path.getsize(wal) == 0)

    def test_detect_encoding_handles_utf8_char_split_by_sample_window(self):
        p = os.path.join(tempfile.mkdtemp(), "big.txt")
        with open(p, "wb") as f:
            f.write(b"a" * 65535)                             # 65535 ascii bytes, so the 2-byte...
            f.write("ת".encode("utf-8"))                      # ...Hebrew char straddles bytes 65535-65536
            f.write(("ישראל " * 80).encode("utf-8"))          # (the 65536-byte sample cuts it in half)
        self.assertIn(_detect_encoding(p), ("utf-8", "utf-8-sig"))   # not a wrong windows-1255 fallback


if __name__ == "__main__":
    unittest.main()
