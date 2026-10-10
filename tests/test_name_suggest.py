"""A person written with an extra middle name ('ברקת כהן' vs 'ברקת צביה כהן') is surfaced as a *possible* same
person — a suggestion for the operator, never an automatic merge (precision-first)."""
import os
import tempfile
import unittest

from osnit.identity import _subset_name, dossier, suggest_same_person
from osnit.importqueue import ImportQueue
from tests import helpers


class NameSuggest(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def test_subset_name_rules(self):
        self.assertTrue(_subset_name(["ברקת", "כהן"], ["ברקת", "צביה", "כהן"]))   # extra middle name
        self.assertFalse(_subset_name(["ברקת", "כהן"], ["ברקת", "לוי"]))          # different surname
        self.assertFalse(_subset_name(["ברקת", "כהן"], ["דן", "צביה", "כהן"]))     # different given name
        self.assertFalse(_subset_name(["כהן"], ["ברקת", "כהן"]))                  # a single token is not enough

    def test_middle_name_suggested_but_not_merged(self):
        self.q.add_bytes("name\nברקת כהן\nברקת צביה כהן\nברקת לוי\n".encode(), "p.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת כהן")
        sug = {s["name"]: s["reason"] for s in d["suggested"]}
        self.assertIn("ברקת צביה כהן", sug)                      # same person, extra name -> surfaced
        self.assertIn("צביה", sug["ברקת צביה כהן"])               # the reason names the extra token
        self.assertNotIn("ברקת לוי", sug)                        # different surname -> not suggested
        # precision: the extra-name record is NOT pulled into ברקת כהן's own identity cluster
        clustered = {r.get("name") for c in d["clusters"] for r in c.get("records", [])}
        self.assertNotIn("ברקת צביה כהן", clustered)

    def test_suggestion_is_symmetric(self):
        self.q.add_bytes("name\nברקת כהן\nברקת צביה כהן\n".encode(), "p.csv")
        self.q.run_pending()
        d = dossier(self.store, name="ברקת צביה כהן")             # from the longer name, the shorter is suggested too
        self.assertIn("ברקת כהן", {s["name"] for s in d["suggested"]})


if __name__ == "__main__":
    unittest.main()
