"""The dashboard paints instantly (cheap counts first) and fills the heavy sections in the background, so the main
panel never sits blank on a large database."""
import time
import unittest

from osnit import analytics
from osnit.ingest import import_parsed
from osnit.parse import Parsed
from osnit.store import Store
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


class DashboardCache(unittest.TestCase):
    """Once computed, the full dashboard is served unchanged until new data actually arrives, and the last snapshot
    survives a restart — so an idle database never pays to recompute and a fresh process is never blank."""

    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self._real_full = analytics._full
        self.calls = {"n": 0}
        analytics._full = lambda store: (self.calls.__setitem__("n", self.calls["n"] + 1), self._real_full(store))[1]
        self._min = analytics._MIN_RECOMPUTE
        analytics._MIN_RECOMPUTE = 0.0            # drop the active-import throttle so the test is fast + deterministic
        self.addCleanup(setattr, analytics, "_full", self._real_full)
        self.addCleanup(setattr, analytics, "_MIN_RECOMPUTE", self._min)

    def tearDown(self):
        self.srv.shutdown()

    def _settle(self, timeout=8):
        t0 = time.time()
        while time.time() - t0 < timeout:
            d = analytics.dashboard(self.store)
            if not d.get("partial") and not d.get("stale"):
                return d
            time.sleep(0.03)
        self.fail("dashboard did not settle fresh")

    def _import(self, url, text):
        import_parsed(self.eng, url, Parsed("html", text, "t"))

    def test_idle_database_is_not_recomputed(self):
        self._import("https://x.co.il/a", "דוד מזרחי, david@x.co.il, 054-5566123, חברת אלפא")
        self._settle()
        n = self.calls["n"]                       # one heavy compute so far
        for _ in range(20):                       # poll repeatedly with no new data
            d = analytics.dashboard(self.store)
            self.assertFalse(d.get("stale"))
            self.assertFalse(d.get("partial"))
        self.assertEqual(self.calls["n"], n, "an unchanging database must not be recomputed")

    def test_new_data_triggers_one_recompute(self):
        self._import("https://x.co.il/a", "דוד מזרחי, david@x.co.il, 054-5566123, חברת אלפא")
        self._settle()
        n, v = self.calls["n"], self.store.data_version
        self._import("https://y.co.il/b", "נועה בר, noa@y.co.il, 052-1112233, חברת בטא")
        self.assertGreater(self.store.data_version, v, "a write must bump the data-version")
        d = self._settle()
        self.assertEqual(self.calls["n"], n + 1, "new data should trigger exactly one recompute")
        self.assertGreaterEqual(d["counts"]["emails"], 2)

    def test_snapshot_survives_a_restart(self):
        self._import("https://x.co.il/a", "דוד מזרחי, david@x.co.il, 054-5566123, חברת אלפא")
        self._settle()                            # persists the snapshot to the meta table
        other = Store(self.store.path)            # a fresh process opening the same database
        d = analytics.dashboard(other)
        self.assertFalse(d.get("partial"), "a restart must show the last full picture, not the blank partial paint")
        self.assertTrue(d.get("stale"))           # served from disk, refreshing in the background
        self.assertIn("complete", d["completeness"])
        self.assertGreaterEqual(d["counts"]["emails"], 1)


if __name__ == "__main__":
    unittest.main()
