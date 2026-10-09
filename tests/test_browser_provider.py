"""The no-API Chromium discovery provider, tested entirely offline with a FAKE node (no browser launched). Proves:
it degrades to [] when the browser is absent / blocked / returns junk, its results flow through the generic-site
filter, it is opt-in, and its document download honours robots + SSRF."""
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from osnit import providers
from osnit.config import Config
from osnit.providers import BrowserSearch, build_providers, clean_results
from tests import helpers


def fake_node(dirpath, reply=None, sleep=0, garbage=False):
    """Write an executable stand-in for `node` that ignores the bridge and emits a canned bridge response."""
    path = os.path.join(dirpath, "fakenode")
    if garbage:
        prog = "import sys; sys.stdin.read(); print('not json <<<')"
    elif sleep:
        prog = f"import sys,time; sys.stdin.read(); time.sleep({sleep}); print('{{}}')"
    else:
        prog = "import sys,json; sys.stdin.read(); print(%r)" % json.dumps(reply or {})
    with open(path, "w") as f:
        f.write("#!/usr/bin/env python3\n" + prog + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class BrowserProvider(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        BrowserSearch._no_node = False
        BrowserSearch._last = 0.0
        self.cfg = Config(db_path=os.path.join(self.dir, "t.db"), browser_delay=0, browser_timeout=2)

    def prov(self, **kw):
        return BrowserSearch(self.cfg, inbox=os.path.join(self.dir, "inbox"), **kw)

    def test_absent_node_returns_empty(self):
        self.cfg.browser_node = os.path.join(self.dir, "nope")   # a path that does not exist
        with self.assertLogs("osnit.providers", level="WARNING"):
            self.assertEqual(self.prov().search("דני", 5), [])

    def test_no_browser_degrades_and_is_cached(self):
        self.cfg.browser_node = fake_node(self.dir, {"ok": False, "code": "no-browser", "error": "x"})
        p = self.prov()
        with self.assertLogs("osnit.providers", level="WARNING"):
            self.assertEqual(p.search("דני", 5), [])
        self.assertTrue(BrowserSearch._no_node)                  # a missing browser is remembered

    def test_parses_urls_and_generic_sites_are_dropped(self):
        self.cfg.browser_node = fake_node(self.dir, {"ok": True,
                                                     "urls": ["https://a.co.il/x", "https://he.wikipedia.org/wiki/Y"]})
        urls = self.prov().search("דני", 5)
        self.assertEqual(urls, ["https://a.co.il/x", "https://he.wikipedia.org/wiki/Y"])   # passthrough
        self.assertEqual(clean_results(urls), ["https://a.co.il/x"])                       # wikipedia dropped

    def test_bad_json_degrades(self):
        self.cfg.browser_node = fake_node(self.dir, garbage=True)
        with self.assertLogs("osnit.providers", level="WARNING"):
            self.assertEqual(self.prov().search("דני", 5), [])

    def test_timeout_degrades(self):
        self.cfg.browser_node = fake_node(self.dir, {"ok": True, "urls": []})
        with mock.patch.object(providers.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("node", 1)):
            with self.assertLogs("osnit.providers", level="WARNING"):
                self.assertEqual(self.prov().search("דני", 5), [])

    def test_opt_in_registration_and_fetcher_injection(self):
        self.assertNotIn("browser", build_providers(Config()))            # default roster is 'archive' only
        built = build_providers(Config(providers=["browser"]), fetcher="FETCH")
        self.assertIn("browser", built)
        self.assertEqual(built["browser"].fetcher, "FETCH")

    def test_download_saves_allowed_skips_robots_and_private(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            helpers.PAGES["/doc.pdf"] = (b"%PDF-1.4 hello", "application/pdf")
            helpers.PAGES["/private/no.pdf"] = (b"%PDF-1.4 secret", "application/pdf")   # robots.txt disallows /private
            self.cfg.browser_download = True
            self.cfg.allow_private_hosts = True        # the test server is on 127.0.0.1 (same as helpers.make)
            self.cfg.browser_node = fake_node(self.dir, {"ok": True, "urls": [base + "/doc.pdf", base + "/page"],
                                                         "doc_links": [base + "/doc.pdf", base + "/private/no.pdf"]})
            p = self.prov(fetcher=eng.fetcher)
            urls = p.search("דני", 5)
            inbox = os.listdir(os.path.join(self.dir, "inbox"))
            self.assertTrue(any(n.endswith(".pdf") for n in inbox))        # the allowed pdf was saved
            self.assertEqual(len(inbox), 1)                                # the robots-disallowed one was not
            self.assertFalse(any(n.endswith(".part") for n in inbox))      # atomic: no partial left behind
            self.assertNotIn(base + "/doc.pdf", urls)                      # a downloaded file is not also crawled
            self.assertIn(base + "/page", urls)
        finally:
            helpers.PAGES.pop("/doc.pdf", None)
            helpers.PAGES.pop("/private/no.pdf", None)
            srv.shutdown()

    def test_download_ssrf_blocks_private_host(self):
        self.cfg.allow_private_hosts = False
        self.cfg.browser_download = True
        fetch = mock.Mock()
        p = self.prov(fetcher=fetch)
        saved = p._download(["http://10.1.2.3/x.pdf", "http://169.254.0.1/y.pdf"])
        self.assertEqual(saved, set())
        fetch.fetch.assert_not_called()                                   # never even attempted for a private host


if __name__ == "__main__":
    unittest.main()
