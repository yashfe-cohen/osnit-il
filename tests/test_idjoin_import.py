"""End to end: a file whose ת"ז is split into a 7-digit column + a 2-digit 'family' column is auto-detected in
analysis, and importing with the id-join directive reconstructs the full, valid national IDs as linking entities."""
import json
import os
import tempfile
import unittest
import urllib.request

from osnit.analyze import analyze_file
from osnit.importdb import import_db
from osnit.importqueue import ImportQueue
from osnit.server import make_server, serve_in_thread
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


class IdJoinMarkEndpoint(unittest.TestCase):
    """The operator marks TWO columns; POST /api/imports/{id}/idjoin tries all 6 combinations and returns the one
    that builds valid Israeli IDs (by the check digit), or ok=False when no combination works."""
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))
        ids = _valid_ids(15)
        lines = [f"P{k},{i[2:]},{i[:2]},{i[:7]}" for k, i in enumerate(ids)]   # 15 complete people (pattern bb+a)
        lines += [f"Q{k},{i[2:]}," for k, i in enumerate(_valid_ids(20)[15:20])]  # 5 rows MISSING the family field
        lines += [lines[0], lines[1]]                                           # 2 duplicate rows (same people)
        rows = "name,tz,family,other\n" + "\n".join(lines) + "\n"
        self.q.add_bytes(rows.encode(), "p.csv", review=True)
        self.q.run_pending()
        self.jid = self.store.q1("SELECT id FROM imports ORDER BY id DESC LIMIT 1")["id"]
        self.table = json.loads(self.store.q1("SELECT preview FROM imports WHERE id=?", (self.jid,))["preview"])["tables"][0]["table"]
        self.api = make_server(self.svc, "127.0.0.1", 0, queue=self.q)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def _idjoin(self, tz, family):
        req = urllib.request.Request(self.url + f"/api/imports/{self.jid}/idjoin",
                                     data=json.dumps({"table": self.table, "tz": tz, "family": family}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        return json.loads(urllib.request.urlopen(req).read())

    def test_marking_the_right_two_columns_finds_the_pattern(self):
        r = self._idjoin("tz", "family")
        self.assertTrue(r["ok"])
        self.assertEqual(r["pattern"], "bb+a")               # family(2) + tz(7)
        self.assertEqual(r["tz"], "tz")
        self.assertEqual(r["family"], "family")
        self.assertGreaterEqual(r["valid_rate"], 0.99)
        self.assertGreaterEqual(r["tested"], 10)             # at least ~10 complete people checked
        self.assertLessEqual(r["tested"], 15)                # incomplete rows (missing family) and duplicates excluded

    def test_order_does_not_matter(self):
        # mark the columns the OTHER way round; the system still works out which one is the 7-digit id
        r = self._idjoin("family", "tz")
        self.assertTrue(r["ok"])
        self.assertEqual(r["tz"], "tz")                      # it figured out the id column regardless of order
        self.assertEqual(r["family"], "family")

    def test_marking_wrong_columns_reports_no_valid_combination(self):
        r = self._idjoin("tz", "other")                      # 'other' is not the family part
        self.assertFalse(r["ok"])

    def test_same_column_twice_is_rejected(self):
        req = urllib.request.Request(self.url + f"/api/imports/{self.jid}/idjoin",
                                     data=json.dumps({"table": self.table, "tz": "tz", "family": "tz"}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)


if __name__ == "__main__":
    unittest.main()