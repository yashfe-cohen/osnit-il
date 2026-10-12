"""Multi-field lookup: find the person matching several known clues at once, normalised and ranked by how many
clues (and how strong) matched. A suggestion layer — it never asserts identity on its own."""
import json
import os
import tempfile
import unittest
import urllib.request

from osnit.importdb import import_db
from osnit.multisearch import multi_find
from osnit.server import make_server, serve_in_thread
from tests import helpers


class MultiSearch(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "d.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("name,phone,email,national_id,city,org\n"
                    "אסתר כהן,054-5566123,esti@gmail.com,123456782,חיפה,עמותת אור\n"
                    "משה לוי,052-3456789,moshe@walla.co.il,,תל אביב,חברת אלפא\n")
        import_db(self.eng, p, label="t")

    def tearDown(self):
        self.srv.shutdown()

    def _names(self, res):
        return [r["name"] for r in res["results"]]

    def test_two_clues_outrank_one(self):
        r = multi_find(self.store, {"name": "אסתר כהן", "phone": "+972545566123"})
        self.assertEqual(r["results"][0]["name"], "אסתר כהן")
        self.assertEqual(r["results"][0]["match_count"], 2)         # both clues matched
        self.assertGreater(r["results"][0]["score"], 1.0)

    def test_phone_normalised_local_matches_e164(self):
        r = multi_find(self.store, {"phone": "054-55-66-123"})       # messy local format
        self.assertEqual(self._names(r), ["אסתר כהן"])

    def test_email_canonicalised(self):
        r = multi_find(self.store, {"email": "E.S.T.I@gmail.com"})    # gmail dots + case
        self.assertEqual(self._names(r), ["אסתר כהן"])

    def test_national_id_matches(self):
        r = multi_find(self.store, {"national_id": "123456782"})
        self.assertEqual(self._names(r), ["אסתר כהן"])

    def test_wrong_clue_is_not_matched(self):
        r = multi_find(self.store, {"name": "אסתר כהן", "phone": "0500000000"})
        self.assertEqual(r["results"][0]["match_count"], 1)          # only the name matched
        self.assertNotIn("phone", {m["field"] for m in r["results"][0]["matched"]})

    def test_endpoint(self):
        api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(api)
        try:
            url = f"http://127.0.0.1:{api.server_address[1]}/api/find"
            req = urllib.request.Request(url, data=json.dumps({"name": "משה לוי", "org": "חברת אלפא"}).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            d = json.loads(urllib.request.urlopen(req).read())
            self.assertEqual(d["results"][0]["name"], "משה לוי")
            self.assertEqual(d["results"][0]["match_count"], 2)
        finally:
            api.shutdown()


if __name__ == "__main__":
    unittest.main()
