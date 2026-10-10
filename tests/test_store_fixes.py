"""Regression tests for the review-found defects: credential findings must follow the person through every
erasure path (forget / per-file purge / full reset), forced kind='domain' must not crash on a non-domain query,
and a UTF-8 file whose multibyte char is split by the 64KB detection window must still be read as UTF-8."""
import os
import tempfile
import unittest

from osnit import search
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

    def test_detect_encoding_handles_utf8_char_split_by_sample_window(self):
        p = os.path.join(tempfile.mkdtemp(), "big.txt")
        with open(p, "wb") as f:
            f.write(b"a" * 65535)                             # 65535 ascii bytes, so the 2-byte...
            f.write("ת".encode("utf-8"))                      # ...Hebrew char straddles bytes 65535-65536
            f.write(("ישראל " * 80).encode("utf-8"))          # (the 65536-byte sample cuts it in half)
        self.assertIn(_detect_encoding(p), ("utf-8", "utf-8-sig"))   # not a wrong windows-1255 fallback


if __name__ == "__main__":
    unittest.main()
