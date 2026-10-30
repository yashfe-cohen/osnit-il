"""The operator's rule: two records are offered as possibly one person only when they share a concrete detail — a
town, an address, a phone, an email, an ID, a birth date, an org — never on a name alone, however close."""
import os
import tempfile
import unittest

from osnit.importdb import import_db
from osnit.possible import decide, possible_matches
from tests import helpers


class SuggestOnlyWithSomethingInCommon(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "p.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,עיר\n"
                    "יעקב שטרנברג,052-6612309,גן יבנה\n"       # A
                    "יעקב שטרנברג,053-4417290,\n"              # B: only the name in common with A
                    "יעקב שטרנברג,054-7718293,Gan Yavne\n")    # C: the same town, written in English
        import_db(self.eng, p, label="t")
        self.a, self.b, self.c = [r["id"] for r in self.store.q("SELECT id FROM entities WHERE type='person' ORDER BY id")]

    def tearDown(self):
        self.srv.shutdown()

    def _cands(self, eid):
        return {c["id"]: c for c in possible_matches(self.store, eid)["candidates"]}

    def test_a_name_alone_is_never_offered(self):
        self.assertNotIn(self.b, self._cands(self.a))

    def test_the_same_town_in_another_script_is_in_common(self):
        c = self._cands(self.a)
        self.assertIn(self.c, c)
        self.assertIn("עיר", c[self.c]["in_common"])
        self.assertIn("אותה עיר: גן יבנה", c[self.c]["reasons"])

    def test_a_decision_is_always_shown(self):
        decide(self.store, self.a, self.b, "same")
        self.assertEqual(self._cands(self.a)[self.b]["decision"], "same")


if __name__ == "__main__":
    unittest.main()
