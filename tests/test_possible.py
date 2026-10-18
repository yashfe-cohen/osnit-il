"""'Possible same person': ranked candidates with reasons, never merged without the operator; decisions win."""
import os
import tempfile
import unittest

from osnit.importdb import import_db
from osnit.identity import dossier
from osnit.possible import decide, possible_matches
from tests import helpers


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


ID_A, ID_B = _il_id(3933742), _il_id(30011221)


class PossibleMatches(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "p.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז,טלפון,עיר,תאריך לידה\n"
                    f"יצחק,כהן,{ID_A},,גן יבנה,1980-04-02\n"        # A: the ID
                    "יצחק,כהן,,054-7718293,גן יבנה,\n"               # B: a phone, same small town
                    f"יצחק,כהן,{ID_B},,חיפה,\n"                      # C: another ID -> never the same as A
                    "יצחק,כהן,,052-6612309,אילת,1971-09-30\n")       # D: other town, other birth date
        import_db(self.eng, p, label="t")
        rows = self.store.q("SELECT id, key FROM entities WHERE type='person' ORDER BY id")
        self.a, self.b, self.c, self.d = [r["id"] for r in rows]

    def tearDown(self):
        self.srv.shutdown()

    def _cands(self, eid):
        return {c["id"]: c for c in possible_matches(self.store, eid)["candidates"]}

    def test_same_name_same_town_is_a_likely_match_with_reasons(self):
        c = self._cands(self.a)
        self.assertIn(self.b, c)
        self.assertIn("אותה עיר: גן יבנה", c[self.b]["reasons"])
        self.assertGreaterEqual(c[self.b]["probability"], 0.5)

    def test_different_national_id_is_never_offered(self):
        self.assertNotIn(self.c, self._cands(self.a))

    def test_conflicting_details_rank_low(self):
        c = self._cands(self.a)
        if self.d in c:
            self.assertLess(c[self.d]["probability"], c[self.b]["probability"])

    def test_nothing_merges_until_the_operator_decides(self):
        d = dossier(self.store, name="יצחק כהן")
        self.assertFalse([cl for cl in d["clusters"] if len(cl["records"]) >= 2])
        decide(self.store, self.a, self.b, "same")
        d = dossier(self.store, name="יצחק כהן")
        joined = [cl for cl in d["clusters"] if {r["id"] for r in cl["records"]} >= {self.a, self.b}]
        self.assertEqual(len(joined), 1)
        self.assertEqual(self._cands(self.a)[self.b]["decision"], "same")

    def test_not_the_same_keeps_them_apart_and_clear_forgets(self):
        decide(self.store, self.a, self.b, "different")
        self.assertEqual(self._cands(self.a)[self.b]["decision"], "different")
        decide(self.store, self.a, self.b, "clear")
        self.assertIsNone(self._cands(self.a)[self.b]["decision"])

    def test_a_later_record_with_both_details_is_found_through_either(self):
        # B has only the phone; once a record shows ID_A together with that phone, B shares a personal identifier
        p = os.path.join(tempfile.mkdtemp(), "q.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"שם פרטי,שם משפחה,ת.ז,טלפון\nיצחק,כהן,{ID_A},054-7718293\n")
        import_db(self.eng, p, label="q")
        c = self._cands(self.a)
        self.assertTrue(any(r.startswith("מזהה אישי משותף") for r in c[self.b]["reasons"]))
        self.assertGreaterEqual(c[self.b]["probability"], 0.95)


if __name__ == "__main__":
    unittest.main()
