"""Keyless username-presence manifests (WhatsMyName/Sherlock schema) fold into Layer 3 precision-first:
a site is probed through the same async checker, counts as a hit only on an explicit exists-string with an
accepted status code and no missing-marker, and never duplicates a curated platform."""
import asyncio
import unittest

import osnit.manifests as M
from osnit.web_osint import SOCIAL_PLATFORMS, check_username_on_platform, run_layer3_username_intel


def _run(coro):
    return asyncio.run(coro)


class ManifestConversion(unittest.TestCase):
    def test_account_placeholder_becomes_username_and_fields_map(self):
        p = M.wmn_to_platform({"name": "GitLab", "uri_check": "https://x/api?u={account}",
                               "uri_pretty": "https://x/{account}", "e_string": "\"username\":\"{account}\"",
                               "e_code": 200, "m_string": "[]", "cat": "coding"})
        self.assertEqual(p["url"], "https://x/api?u={username}")
        self.assertEqual(p["display_url"], "https://x/{username}")
        self.assertEqual(p["positive"], ["\"username\":\"{username}\""])
        self.assertEqual(p["negative"], ["[]"])
        self.assertEqual(p["exist_code"], (200,))
        self.assertTrue(p["from_manifest"])

    def test_a_site_without_an_exists_string_is_dropped(self):
        self.assertIsNone(M.wmn_to_platform({"name": "X", "uri_check": "https://x/{account}"}))
        self.assertIsNone(M.wmn_to_platform({"name": "X", "uri_check": "https://x/no-placeholder",
                                             "e_string": "hi"}))

    def test_bundled_manifest_loads_and_excludes_curated(self):
        curated = {p["name"].lower() for p in SOCIAL_PLATFORMS}
        plats = M.manifest_platforms(exclude_names=curated)
        self.assertGreater(len(plats), 0)
        for p in plats:
            self.assertNotIn(p["name"].lower(), curated)
            self.assertTrue(p["positive"] and p["positive"][0])
            self.assertTrue(p.get("from_manifest"))
        src = M.manifest_source()
        self.assertGreaterEqual(src["usable_sites"], len(plats))

    def test_limit_caps_the_count(self):
        self.assertLessEqual(len(M.manifest_platforms(limit=2)), 2)


class ManifestChecker(unittest.TestCase):
    PLAT = {"name": "DemoNet", "url": "https://demo/api/{username}", "display_url": "https://demo/{username}",
            "positive": ["\"handle\":\"{username}\""], "negative": ["not_found"], "exist_code": (200,),
            "from_manifest": True}

    def _fetch(self, status, body):
        def f(url, headers):
            return (status, body, {})
        return f

    def test_exists_string_on_accepted_code_is_a_hit(self):
        r = _run(check_username_on_platform("danale", self.PLAT,
                                            http_fetcher=self._fetch(200, '{"handle":"danale","bio":"hi"}')))
        self.assertIsNotNone(r)
        self.assertEqual(r["extracted_data"]["username"], "danale")

    def test_wrong_status_code_is_not_a_hit(self):
        self.assertIsNone(_run(check_username_on_platform(
            "danale", self.PLAT, http_fetcher=self._fetch(404, '{"handle":"danale"}'))))

    def test_missing_marker_blocks_a_false_positive(self):
        self.assertIsNone(_run(check_username_on_platform(
            "danale", self.PLAT, http_fetcher=self._fetch(200, '{"handle":"danale"} not_found'))))

    def test_status_code_alone_never_asserts_presence(self):
        self.assertIsNone(_run(check_username_on_platform(
            "danale", self.PLAT, http_fetcher=self._fetch(200, '{"other":"page"}'))))


class ManifestLayer3(unittest.TestCase):
    def setUp(self):
        self._orig = M.manifest_platforms
        M.manifest_platforms = lambda exclude_names=None, limit=None: [
            {"name": "DemoNet", "url": "https://demo/{username}", "positive": ["profile of {username}"],
             "negative": ["missing"], "exist_code": (200,), "from_manifest": True}]

    def tearDown(self):
        M.manifest_platforms = self._orig

    def test_manifest_site_produces_a_finding_through_layer3(self):
        def fetch(url, headers):
            return (200, "profile of danale", {}) if "demo/danale" in url else (0, "", {})
        res = _run(run_layer3_username_intel(["danale"], http_fetcher=fetch))
        self.assertTrue(any(f["extracted_data"].get("platform") == "DemoNet" for f in res))


if __name__ == "__main__":
    unittest.main()
