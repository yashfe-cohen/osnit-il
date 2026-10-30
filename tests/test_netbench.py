"""The network benchmark itself (osnit/netbench.py): deterministic, and its traps are what they claim to be."""
import unittest

from osnit import netbench


class NetBenchTest(unittest.TestCase):
    def test_generator_is_deterministic_and_disjoint(self):
        a, b = netbench.generate(3, families=12), netbench.generate(3, families=12)
        self.assertEqual(a[4], b[4])
        truth, traps = a[4], a[5]
        self.assertFalse(set(truth) & set(traps))                      # a pair is never both
        self.assertTrue({"household", "coworker", "text"} <= set(truth.values()))
        self.assertTrue({"big_employer", "co_mentioned"} <= set(traps.values()))

    def test_small_run_scores(self):
        r = netbench.run(3, families=12)
        self.assertEqual(r["resolved"], r["people"])
        self.assertGreater(r["r_precision"], 0.8)
        self.assertGreater(r["order_auc"], 0.8)


if __name__ == "__main__":
    unittest.main()
