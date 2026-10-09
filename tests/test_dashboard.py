"""The dashboard paints instantly (cheap counts first) and fills the heavy sections in the background, so the main
panel never sits blank on a large database."""
import time
import unittest

from osnit import analytics
from osnit.ingest import import_parsed
from osnit.parse import Parsed
from tests import helpers


class Dashboard(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def test_fast_first_paint_then_background_fill(self):
        import_parsed(self.eng, "https://x.co.il/a",
                      Parsed("html", "דוד מזרחי, מייל david@x.co.il, טלפון 054-5566123, חברת אלפא", "a"))
        first = analytics.dashboard(self.store)             # cold: cheap counts now, heavy computed in background
        self.assertTrue(first.get("partial"))
        self.assertGreaterEqual(first["counts"]["emails"], 1)
        self.assertEqual(len(first["activity"]), 30)        # the sparkline is present immediately
        self.assertEqual(first["top_orgs"], [])             # heavy section not ready yet
        for _ in range(50):                                 # let the background refresh land
            time.sleep(0.1)
            full = analytics.dashboard(self.store)
            if not full.get("partial") and not full.get("stale"):
                break
        self.assertFalse(full.get("partial"))
        self.assertIn("complete", full["completeness"])

    def test_fast_counts_are_cheap(self):
        f = analytics.fast(self.store)
        self.assertIn("people", f["counts"])
        self.assertTrue(f["partial"])


if __name__ == "__main__":
    unittest.main()
