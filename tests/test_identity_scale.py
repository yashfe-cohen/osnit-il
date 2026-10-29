"""Scale (Phase 9): a huge block of one common name stays fast and stays honest. The joint resolution runs on the
strongest candidates only; resolved blocks are cached (several, per data version); the duplicates fit is bounded so
a file where EVERYONE is "יצחק כהן" is never read as one person recorded hundreds of times."""
import os
import random
import tempfile
import time
import unittest

from osnit import matchmodel as mm
from osnit.importdb import import_db
from osnit.possible import RESOLVE_MAX, possible_matches
from tests import helpers


class FitBounds(unittest.TestCase):
    def test_a_degenerate_dataset_cannot_make_everyone_one_person(self):
        # 200 identities, one name, 150 same-file namesakes each, no variation in x: not identifiable
        obs = [(150, 0, 60.0, 0.95)] * 200
        ds, do, beta = mm.fit_duplicates(obs, files=1)
        self.assertLessEqual(ds, mm.MAX_DUP_SAME)
        self.assertLessEqual(do, 0.02)                                  # one file: no other files to recur in
        self.assertGreater(beta, 1.0)                                   # the rest are namesakes


class CommonNameBlock(unittest.TestCase):
    N = 150

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base, cls.store, cls.eng, cls.svc, _ = helpers.make([])
        rng = random.Random(1)
        towns = ["ירושלים", "חיפה", "גן יבנה", "אילת", "נתניה"]
        p = os.path.join(tempfile.mkdtemp(), "big.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,טלפון,עיר\n")
            for _ in range(cls.N):                                     # 150 different people, one name
                f.write(f"יצחק,כהן,05{rng.choice('02348')}{rng.randint(1000000, 9999999)},{rng.choice(towns)}\n")
        import_db(cls.eng, p, label="big")
        cls.store.reindex_names(100000)
        cls.ids = [r["id"] for r in cls.store.q("SELECT id FROM entities WHERE type='person' ORDER BY id")]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_distinct_phones_are_not_offered_as_one_person(self):
        res = possible_matches(self.store, self.ids[0])
        self.assertEqual(res["considered"], self.N - 1)
        self.assertFalse([c for c in res["candidates"] if c["probability"] >= 0.5], res["candidates"][:3])
        self.assertLessEqual(mm.get_model(self.store).delta_same, mm.MAX_DUP_SAME)

    def test_fast_after_the_fit_and_cached(self):
        mm.get_model(self.store)                                      # the one-time fit (done in the background in use)
        t = time.time()
        possible_matches(self.store, self.ids[1])
        first = time.time() - t
        t = time.time()
        possible_matches(self.store, self.ids[1])
        again = time.time() - t
        self.assertLess(first, 15.0)                                   # generous for a slow CI machine
        self.assertLess(again, first + 0.5)
        self.assertLessEqual(RESOLVE_MAX, 80)                          # the quadratic part stays bounded

    def test_several_blocks_are_cached(self):
        possible_matches(self.store, self.ids[2])
        possible_matches(self.store, self.ids[3])
        self.assertGreaterEqual(len(self.store._block_cache), 2)


if __name__ == "__main__":
    unittest.main()
