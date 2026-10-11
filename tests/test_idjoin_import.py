"""End to end: a file whose ת"ז is split into a 7-digit column + a 2-digit 'family' column is auto-detected in
analysis, and importing with the id-join directive reconstructs the full, valid national IDs as linking entities."""
import os
import tempfile
import unittest

from osnit.analyze import analyze_file
from osnit.importdb import import_db
from osnit.semantic import il_id_ok
from tests import helpers


def _valid_ids(n):
    out, x = [], 100000000
    while len(out) < n and x < 500000000:
        if il_id_ok(str(x)):
            out.append(str(x))
        x += 7
    return out


class IdJoinImport(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def _file(self, ids):
        p = os.path.join(tempfile.mkdtemp(), "people.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("name,tz,family\n")
            for k, i in enumerate(ids):
                f.write(f"Person{k},{i[2:]},{i[:2]}\n")        # family = first 2 digits, tz = last 7  (pattern bb+a)
        return p

    def test_analysis_detects_the_split(self):
        p = self._file(_valid_ids(20))
        a = analyze_file(self.store, p)
        j = a["tables"][0]["id_join"]
        self.assertIsNotNone(j)
        self.assertEqual(j["pattern"], "bb+a")
        self.assertEqual(j["tz"], "tz")
        self.assertEqual(j["family"], "family")
        self.assertGreaterEqual(j["valid_rate"], 0.99)

    def test_import_reconstructs_full_ids(self):
        ids = _valid_ids(20)
        p = self._file(ids)
        a = analyze_file(self.store, p)
        tbl, j = a["tables"][0]["table"], a["tables"][0]["id_join"]
        import_db(self.eng, p, crawl_urls=False,
                  overrides={tbl: {"__idjoin__": {"tz": j["tz"], "family": j["family"], "pattern": j["pattern"]}}})
        for i in ids[:6]:                                      # the full, valid ID is now a linking entity
            self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='national_id' AND key=?", (i,)), i)


if __name__ == "__main__":
    unittest.main()
