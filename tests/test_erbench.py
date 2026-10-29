"""The identity-resolution benchmark (osnit/erbench.py): the generator is deterministic and contains the hard cases
(several people with one name in one town, a grandfather and grandson with the same name at the same address), every
generated row maps back to the identity it became, and the importer never merges two different people."""
import unittest

from osnit import erbench


class ErBench(unittest.TestCase):
    def test_generator_is_deterministic_and_has_the_hard_cases(self):
        p1, f1 = erbench.generate(seed=3, people=120)
        p2, f2 = erbench.generate(seed=3, people=120)
        self.assertEqual(f1["contacts"]["rows"], f2["contacts"]["rows"])
        same_town = [p for p in p1 if (p["first"], p["last"], p["town"]) == ("יצחק", "כהן", "גן יבנה")]
        self.assertEqual(len(same_town), 3)                               # the operator's own example
        self.assertEqual(len({p["nid"] for p in same_town}), 3)          # three DIFFERENT people
        households = {}
        for p in p1:
            if p["household"] is not None:
                households.setdefault(p["household"], []).append(p)
        same_name_family = [m for hh in households.values() for m in hh
                            if sum((x["first"], x["last"]) == (m["first"], m["last"]) for x in hh) > 1]
        self.assertTrue(same_name_family)                                 # a same-name grandfather/grandson exists
        for label, f in f1.items():
            self.assertEqual(len(f["rows"]), len(f["gold"]), label)
        self.assertEqual(set(f1), {"contacts", "registry", "misc"})

    def test_importer_never_merges_two_people(self):
        res = erbench.run(seed=3, people=120, suggest=False)
        auto = res["auto"]
        self.assertEqual(auto["false_merges"], 0, auto["false_merge_examples"])
        self.assertEqual(auto["namesake_false_merges"], 0)
        self.assertEqual(auto["precision"], 1.0)
        self.assertLess(res["unlinked_rows"], res["rows"] * 0.05)       # nearly every row became a person
        self.assertGreater(auto["bcubed_recall"], 0.4)

    def test_suggest_metrics_are_reported(self):
        res = erbench.run(seed=3, people=80, suggest=True)
        s = res["suggest"]
        for k in ("claims", "brier", "recall_at_05", "precision_at_05", "incoherent", "worst_claim_sum"):
            self.assertIn(k, s)
        self.assertGreater(s["claims"], 0)
        self.assertTrue(0.0 <= s["brier"] <= 1.0)


if __name__ == "__main__":
    unittest.main()
