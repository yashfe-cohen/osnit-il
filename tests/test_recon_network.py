"""Deep web research must say when the network did not answer, and one failed run must not poison the cache: an
empty cached answer (which may be a failed request) is trusted only briefly."""
import os
import tempfile
import time
import unittest

from osnit.store import Store
from osnit.web_osint import SearchTargetProfile, UnifiedReconEngine


def _dead(url, headers):                    # no internet / a firewall: every request fails
    return (0, "", {})


def _alive(url, headers):                   # sites answer (nothing found), search returns a hit
    return (404, "", {})


class ReconNetwork(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), "r.db"))
        self.prof = lambda: SearchTargetProfile.from_raw(name="דנה לוי", phones=["054-7718293"],
                                                        emails=["dana.levi.test@example.com"])

    def _run(self, fetcher, search):
        eng = UnifiedReconEngine(store=self.store, http_fetcher=fetcher, search_fn=search,
                                 image_search_fn=lambda q: [], max_depth=1)
        return eng.run_recon_sync(profile=self.prof())

    def test_no_network_is_reported(self):
        res = self._run(_dead, lambda q: [])
        self.assertEqual(res["network"].get("http_ok", 0), 0)
        self.assertGreater(res["network"]["http_total"], 0)
        self.assertTrue(any("לא קיבלה תשובה" in w for w in res["warnings"]))
        self.assertTrue(any("מנועי החיפוש" in w for w in res["warnings"]))

    def test_working_network_has_no_warning(self):
        hit = [{"url": "https://www.example.co.il/a", "title": "דנה לוי", "snippet": "דנה לוי 054-7718293"}]
        res = self._run(_alive, lambda q: hit)
        self.assertEqual(res["warnings"], [])
        self.assertGreater(res["network"]["search_ok"], 0)

    def test_empty_cached_answer_expires_quickly(self):
        old = time.time() - self.store.OSINT_EMPTY_TTL - 5
        self.store.osint_cache_put("q1", "dork_search", [], timestamp=old)
        self.store.osint_cache_put("q2", "dork_search", [{"url": "u"}], timestamp=old)
        self.assertIsNone(self.store.osint_cache_get("q1", "dork_search"))
        self.assertEqual(self.store.osint_cache_get("q2", "dork_search"), [{"url": "u"}])
        self.store.osint_cache_put("q3", "dork_search", [])
        self.assertEqual(self.store.osint_cache_get("q3", "dork_search"), [])     # a fresh empty answer is kept


if __name__ == "__main__":
    unittest.main()
