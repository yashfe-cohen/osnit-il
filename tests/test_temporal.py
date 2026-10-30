"""Temporal reasoning (Phase 6): a mobile number recycled to a new owner (or a family line) is held by two people with
DIFFERENT national IDs — it must never join them, and never count as "the same identifier" for anyone else; and a
person known to have moved makes "another town" weaker evidence against."""
import os
import tempfile
import unittest

from osnit import resolve
from osnit.importdb import import_db
from osnit.possible import _features, possible_matches, recycled_identifiers
from tests import helpers


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


ID_OLD, ID_NEW = _il_id(3933742), _il_id(30011221)
PHONE = "054-7718293"


def _f(nids=(), mob=(), rec=frozenset()):
    return dict(ids={("phone", m) for m in mob}, nids=set(nids), emails=set(), addresses=set(), cities=set(),
                orgs=set(), birth=set(), files=set(), srcs=set(), recycled=rec)


class CoresNeverJoinTwoIDs(unittest.TestCase):
    def test_conflicting_ids_stay_apart_even_through_a_shared_mobile(self):
        feats = {1: _f({ID_OLD}, {"+972547718293"}), 2: _f({ID_NEW}, {"+972547718293"}), 3: _f((), {"+972547718293"})}
        cores, core_of, nids = resolve._cores([1, 2, 3], feats, {})
        self.assertNotEqual(core_of[1], core_of[2])
        for k, ns in nids.items():
            self.assertLessEqual(len(ns), 1)                       # never two IDs in one core, in any join order


class Recycled(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז,טלפון,עיר\n"
                    f"דוד,לוי,{ID_OLD},{PHONE},חיפה\n"           # the number's old owner
                    f"רונית,אברמוביץ,{ID_NEW},{PHONE},אילת\n")     # its new owner (another person, another ID)
        import_db(self.eng, p, label="a")
        q = os.path.join(tempfile.mkdtemp(), "b.csv")
        with open(q, "w", encoding="utf-8") as f:
            f.write(f"שם מלא,טלפון נייד\nדוד לוי,{PHONE}\n")       # a record with only that number
        import_db(self.eng, q, label="b")
        self.store.reindex_names(5000)

    def tearDown(self):
        self.srv.shutdown()

    def test_the_number_is_recognised_as_recycled(self):
        self.assertIn("+972547718293", recycled_identifiers(self.store, {"+972547718293"}))

    def test_a_recycled_number_is_not_proof(self):
        people = {r["display"]: r["id"] for r in self.store.q("SELECT id, display FROM entities WHERE type='person'")}
        ids = [r["id"] for r in self.store.q("SELECT id FROM entities WHERE type='person' AND display='דוד לוי'")]
        self.assertGreaterEqual(len(ids), 1)
        for eid in ids:
            for c in possible_matches(self.store, eid)["candidates"]:
                self.assertFalse(any(r.startswith("מזהה אישי משותף") for r in c["reasons"]), c)
                if c["id"] == people.get("רונית אברמוביץ"):
                    self.assertLess(c["probability"], 0.5)           # a shared old number is not the same person


class Moves(unittest.TestCase):
    def test_another_town_is_weaker_against_a_known_mover(self):
        from osnit import matchmodel as mm
        mod = mm.Model()
        me = dict(id=1, key="דוד לוי", display="דוד לוי")
        base = dict(ids=set(), nids=set(), emails=set(), addresses=set(), orgs=set(), birth=set(), files=set(),
                    srcs=set(), recycled=frozenset())
        stay = dict(base, cities={"חיפה"})
        moved = dict(base, cities={"חיפה", "עכו"})
        other = dict(base, cities={"אילת"})
        sc_stay = mm.Scorer(None, mod, me, stay)
        sc_moved = mm.Scorer(None, mod, me, moved)
        g = {"name": "exact", "town": "different"}
        b_stay = [b for b, f, *_ in sc_stay.evidence(g, set(), 1.0, other["cities"]) if f == "town"][0]
        b_moved = [b for b, f, *_ in sc_moved.evidence(g, set(), 1.0, other["cities"]) if f == "town"][0]
        self.assertGreater(b_moved, b_stay)                        # less negative for someone who moves


if __name__ == "__main__":
    unittest.main()
