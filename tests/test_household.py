"""Same-name family members and households (Phase 5): a grandfather and his grandson named after him, at one address
with one home landline, are TWO people of one family — never one person, never "possibly the same". A landline is a
household, not a person (rule 5); the birth years name the relationship (one generation: parent/child, two:
grandparent/grandchild, the same: siblings)."""
import os
import tempfile
import unittest

from osnit.identity import dossier
from osnit.importdb import import_db
from osnit.kinship import kin_from_birth_gap
from tests import helpers


class BirthGap(unittest.TestCase):
    def test_generations(self):
        self.assertEqual(kin_from_birth_gap({1940}, {1995})[0], "grandchild")    # the other is two generations younger
        self.assertEqual(kin_from_birth_gap({1995}, {1940})[0], "grandparent")
        self.assertEqual(kin_from_birth_gap({1960}, {1988})[0], "child")
        self.assertEqual(kin_from_birth_gap({1988}, {1960})[0], "parent")
        self.assertEqual(kin_from_birth_gap({1980}, {1982})[0], "sibling")
        self.assertIsNone(kin_from_birth_gap({1980}, {1990}))                    # 10 years: nothing to say
        self.assertIsNone(kin_from_birth_gap(set(), {1990}))


class Household(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "registry.csv")
        with open(p, "w", encoding="utf-8") as f:
            # no national IDs: only the household (address + landline) and the birth years tell them apart
            f.write("שם,כתובת,טלפון בבית,תאריך לידה\n"
                    "יצחק כהן,הרצל 12 גן יבנה,08-8571234,03/05/1941\n"
                    "יצחק כהן,הרצל 12 גן יבנה,08-8571234,17/09/1996\n")
        import_db(self.eng, p, label="reg")
        self.store.reindex_names(5000)

    def tearDown(self):
        self.srv.shutdown()

    def test_a_shared_landline_never_makes_them_one_person(self):
        d = dossier(self.store, name="יצחק כהן")
        people = [c for c in d["clusters"] if c.get("type") in (None, "person")]
        self.assertEqual(len(people), 2, [c.get("records") for c in people])

    def test_they_are_recognised_as_grandfather_and_grandson(self):
        d = dossier(self.store, name="יצחק כהן")
        roles = {k["role"] for k in d["kinship"]}
        self.assertTrue(roles & {"grandparent", "grandchild"}, d["kinship"])
        why = " ".join(k["reason"] for k in d["kinship"])
        self.assertIn("אותו שם", why)                                    # same name, but two people — said plainly

    def test_search_shows_two_people_of_one_family(self):
        from osnit.multisearch import multi_find
        res = multi_find(self.store, {"name": "יצחק כהן", "city": "גן יבנה"})
        inds = res["individuals"]
        self.assertEqual(len(inds), 2)                                    # two people, not one, not "maybe one"
        roles = {f["role"] for i in inds for f in i["family"]}
        self.assertEqual(roles, {"grandparent", "grandchild"})            # each sees the other's tie

    def test_not_offered_as_the_same_person(self):
        from osnit.possible import possible_matches
        ids = [r["id"] for r in self.store.q("SELECT id FROM entities WHERE type='person' ORDER BY id")]
        cands = {c["id"]: c for c in possible_matches(self.store, ids[0])["candidates"]}
        if ids[1] in cands:                                              # born 55 years apart: not one person
            self.assertLess(cands[ids[1]]["probability"], 0.5)


if __name__ == "__main__":
    unittest.main()
