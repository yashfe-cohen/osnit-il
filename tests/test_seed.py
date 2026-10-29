"""Person search seeds its first web round from the identifiers the DB already holds for the subject (phone in
every written variation, email, …), ranks the strongest identifier first, and never lets discovery read or
download from generic-knowledge sites."""
import os
import tempfile
import unittest

from osnit.extract import phone_variants
from osnit.importqueue import ImportQueue
from tests import helpers


class Seed(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, self.prov = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def imp(self, body, name):
        self.q.add_bytes(body.encode("utf-8"), name, delete_raw=False, review=False)
        self.q.run_pending()

    def jobs_for(self, sid):
        return [r["query"] for r in self.store.q("SELECT query FROM jobs WHERE subject_id=?", (sid,))]

    def test_first_round_seeds_db_phone_variations(self):
        self.imp('שם,טלפון,מייל\nדן לוי,050-831-7945,dan@dan.co.il\n', "c.csv")
        sid = self.svc.search("דן לוי")["subject_id"]
        qs = self.jobs_for(sid)
        blob = "\n".join(qs)
        for v in phone_variants("+972508317945", cap=6):
            self.assertIn(v, blob, v)                              # every written form of the phone is queried
        self.assertTrue(any('"דן לוי"' in q and "508317945" in q.replace("-", "").replace(" ", "") for q in qs),
                        "a combined name+phone query is present")
        self.assertTrue(any(q.strip('"') in phone_variants("+972508317945", cap=6) for q in qs),
                        "a bare phone query is present")

    def test_db_identifiers_ranked_and_capped(self):
        self.imp('שם,ת"ז,מייל,טלפון\nדנה כהן,123456782,dana@walla.co.il,0546613972\n', "d.csv")
        sid = self.svc.search("דנה כהן")["subject_id"]
        idents = self.svc._db_identifiers(sid)
        types = [t for t, _ in idents]
        self.assertEqual(types[0], "national_id")                 # strongest personal identifier first
        self.assertLess(types.index("email"), types.index("phone"))
        self.assertLessEqual(len(idents), 6)
        self.assertEqual(len(idents), len(set(idents)))           # no duplicates

    def test_discovery_excludes_generic_sites(self):
        self.srv2, base2, store2, eng2, svc2, prov2 = helpers.make(["/p"])
        try:
            prov2.urls = ["https://he.wikipedia.org/wiki/X", base2 + "/p"]
            helpers.PAGES["/p"] = ("<html><body>דן לוי profile</body></html>", "text/html")
            svc2.search("דן לוי")
            eng2.run_jobs_once()
            doms = {r["domain"] for r in store2.q("SELECT domain FROM sources WHERE domain IS NOT NULL")}
            self.assertFalse(any("wikipedia.org" in (d or "") for d in doms))
        finally:
            helpers.PAGES.pop("/p", None)
            self.srv2.shutdown()


if __name__ == "__main__":
    unittest.main()
