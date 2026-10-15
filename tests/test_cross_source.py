"""Cross-source identity correlation: two differently-named person records that share exclusive details are
ranked as a possible same identity (with reasons and a confidence tier), but a national-ID conflict blocks it."""
import os
import tempfile
import unittest

from osnit.identity import dossier
from osnit.importqueue import ImportQueue
from tests import helpers


class CrossSource(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def _all_candidates(self, d):
        return {s["name"]: s for c in d["clusters"] for s in c.get("same_identity", [])}

    def test_shared_exclusive_detail_links_two_names(self):
        # two different names that share an (exclusive) phone and an org — not auto-merged (different names), but
        # surfaced as a possible same identity
        self.q.add_bytes("name,phone,org\nברקת כהן,0545566123,אלפא\nדליה לוי,0545566123,אלפא\n".encode(), "a.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת כהן")
        cands = self._all_candidates(d)
        self.assertIn("דליה לוי", cands)
        c = cands["דליה לוי"]
        self.assertGreaterEqual(c["score"], 0.7)                     # a shared exclusive phone is strong
        self.assertIn(c["tier"], ("ודאי", "סביר מאוד"))
        self.assertTrue(any("טלפון" in r for r in c["reasons"]))     # explained
        self.assertEqual(c["relation"], "same_person")               # a shared mobile -> same person

    def test_shared_org_only_is_related_not_same_person(self):
        # share only an org (a shared place), different names -> a relationship, not the same individual
        self.q.add_bytes("name,org\nברקת כהן,חברת אלפא\nדליה לוי,חברת אלפא\n".encode(), "o.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת כהן")
        c = self._all_candidates(d).get("דליה לוי")
        self.assertIsNotNone(c)
        self.assertEqual(c["relation"], "related")

    def test_different_national_ids_never_link(self):
        # same shared phone, but each has a DIFFERENT national id -> the hard rule blocks the suggestion
        self.q.add_bytes(("name,phone,national_id\n"
                          "ברקת כהן,0523456789,123456782\n"
                          "דליה לוי,0523456789,671782597\n").encode(), "b.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת כהן")
        self.assertNotIn("דליה לוי", self._all_candidates(d))

    def test_unrelated_person_is_not_a_candidate(self):
        self.q.add_bytes(("name,phone,org\n"
                          "ברקת כהן,0545566123,אלפא\n"
                          "מישהו אחר,0523456789,בטא\n").encode(), "c.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת כהן")
        self.assertNotIn("מישהו אחר", self._all_candidates(d))


if __name__ == "__main__":
    unittest.main()
