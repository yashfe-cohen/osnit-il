"""The operator loop (Phase 8): an uncertain candidate says what would settle it (the smart question, with the
probability either way); a "not the same" decision separates the two PEOPLE (A is B, B is not C -> A is not C); and
every decision is kept in an audit trail."""
import os
import tempfile
import unittest

from osnit.importdb import import_db
from osnit.possible import decide, decision_log, possible_matches
from tests import helpers


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


class OperatorLoop(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "p.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז,טלפון,עיר,תאריך לידה\n"
                    f"יצחק,כהן,{_il_id(3933742)},,גן יבנה,1980-04-02\n"      # A
                    "יצחק,כהן,,054-7718293,גן יבנה,\n"                      # B
                    "יצחק,כהן,,052-6612309,גן יבנה,\n")                     # C
        import_db(self.eng, p, label="t")
        self.a, self.b, self.c = [r["id"] for r in self.store.q("SELECT id FROM entities WHERE type='person' ORDER BY id")]

    def tearDown(self):
        self.srv.shutdown()

    def _cands(self, eid):
        return {c["id"]: c for c in possible_matches(self.store, eid)["candidates"]}

    def test_an_uncertain_candidate_says_what_would_settle_it(self):
        asked = [q for c in self._cands(self.a).values() for q in c.get("ask", [])]
        for q in asked:
            self.assertGreater(q["if_same"], q["if_different"])     # each answer moves it apart
        fields = {q["field"] for q in asked}
        self.assertTrue(fields & {"birth", "nid", "mobile"}, asked)  # A has a birth date and an ID; B / C do not

    def test_not_the_same_propagates_through_the_same_person(self):
        decide(self.store, self.a, self.b, "same")
        decide(self.store, self.b, self.c, "different")
        c = self._cands(self.a)
        self.assertEqual(c[self.c]["decision"] if self.c in c else "different", "different")
        self.assertTrue(self.c not in c or c[self.c]["probability"] < 0.2)

    def test_decisions_are_logged(self):
        decide(self.store, self.a, self.b, "same", reasons=["אותה עיר: גן יבנה"], score=0.7)
        log = decision_log(self.store)
        self.assertEqual(log[0]["decision"], "same")
        self.assertEqual({log[0]["a"], log[0]["b"]}, {self.a, self.b})
        self.assertEqual(log[0]["reasons"], ["אותה עיר: גן יבנה"])


if __name__ == "__main__":
    unittest.main()
