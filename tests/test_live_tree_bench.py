import unittest

from tools.live_tree_bench import format_ascii_tree, run_calibration_benchmark


class TestLiveTreeCalibrationBenchmark(unittest.TestCase):
    def test_simulated_calibration_benchmark_on_username(self):
        res = run_calibration_benchmark(query="matanshi", simulate=True, auto_confirm_top_candidate=True)
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["findings_count"], 3)
        tree = res["tree"]
        self.assertIsNotNone(tree["root"])
        self.assertGreaterEqual(len(tree["nodes"]), 4)
        self.assertGreaterEqual(tree["stats"]["max_depth"], 1)
        report = format_ascii_tree(tree)
        self.assertIn("INVESTIGATION TREE REPORT", report)
        self.assertIn("matanshi", report)


if __name__ == "__main__":
    unittest.main()
