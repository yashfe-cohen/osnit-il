"""Aggressive, RAM-governed parallel browser scanning: the memory planner, the batch search across many queries,
and the immediate local identifier scan of a downloaded file. All offline (fake node, no browser)."""
import json
import os
import stat
import tempfile
import unittest

from osnit import sysmem
from osnit.config import Config
from osnit.ingest import scan_file_for_identifiers
from osnit.providers import BrowserSearch


def fake_node(dirpath, reply):
    path = os.path.join(dirpath, "fakenode")
    with open(path, "w") as f:
        f.write("#!/usr/bin/env python3\nimport sys,json; sys.stdin.read(); print(%r)\n" % json.dumps(reply))
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class Planner(unittest.TestCase):
    def test_memory_reads_something_sane(self):
        total, avail = sysmem.memory()
        self.assertGreater(total, 128 * 1024 ** 2)
        self.assertGreaterEqual(total, avail)

    def test_concurrency_scales_and_clamps(self):
        # a bigger RAM fraction allows more workers; a bigger per-task footprint allows fewer; always within [floor,cap]
        lo = sysmem.plan_concurrency(per_task_mb=350, target_fraction=0.5, cap=16)
        hi = sysmem.plan_concurrency(per_task_mb=350, target_fraction=0.9, cap=64)
        self.assertGreaterEqual(hi, lo)
        self.assertLessEqual(sysmem.plan_concurrency(per_task_mb=350, cap=8), 8)
        self.assertGreaterEqual(sysmem.plan_concurrency(per_task_mb=10 ** 9, cap=16), 1)   # floor holds


class Batch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        BrowserSearch._no_node = False
        self.cfg = Config(db_path=os.path.join(self.dir, "t.db"), browser_delay=0, browser_timeout=2)

    def prov(self, **kw):
        return BrowserSearch(self.cfg, inbox=os.path.join(self.dir, "inbox"), **kw)

    def test_search_many_parses_per_query_and_filters_generic(self):
        reply = {"ok": True, "engine": "bing", "results": [
            {"query": "q1", "urls": ["https://a.co.il/x", "https://he.wikipedia.org/wiki/Y"]},
            {"query": "q2", "urls": ["https://b.org.il/z"]},
            {"query": "q3", "code": "nav-failed", "error": "x"}]}
        self.cfg.browser_node = fake_node(self.dir, reply)
        out = self.prov().search_many(["q1", "q2", "q3"])
        self.assertEqual(out["q1"], ["https://a.co.il/x"])          # wikipedia dropped by clean_results
        self.assertEqual(out["q2"], ["https://b.org.il/z"])
        self.assertEqual(out.get("q3"), [])

    def test_plan_concurrency_respects_cap_and_items(self):
        p = self.prov()
        self.cfg.browser_concurrency = 0                           # auto
        self.cfg.browser_max_workers = 4
        self.assertLessEqual(p.plan_concurrency(100), 4)
        self.assertEqual(p.plan_concurrency(2), min(2, p.plan_concurrency(100)) if p.plan_concurrency(100) >= 2 else 1)
        self.cfg.browser_concurrency = 7                           # explicit setting, still capped by max_workers
        self.assertEqual(p.plan_concurrency(100), 4)

    def test_absent_browser_returns_empty_map(self):
        self.cfg.browser_node = os.path.join(self.dir, "nope")
        self.assertEqual(self.prov().search_many(["q1", "q2"]), {})


class ImmediateScan(unittest.TestCase):
    def test_scan_file_pulls_identifiers(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "leak.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("דוד לוי — ליצירת קשר: david@example.co.il, טלפון 054-5566123, ת.ז 123456782.")
        hit = scan_file_for_identifiers(p)
        self.assertIn("david@example.co.il", hit["emails"])
        self.assertTrue(any("972545566123" in ph.replace("-", "").replace(" ", "").replace("+", "") or "054" in ph
                            for ph in hit["phones"]))
        self.assertIn("123456782", hit["national_ids"])

    def test_scan_file_never_raises_on_garbage(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        with open(p, "wb") as f:
            f.write(bytes(range(256)) * 10)
        hit = scan_file_for_identifiers(p)
        self.assertIn("emails", hit)                                # returns a dict, no exception


if __name__ == "__main__":
    unittest.main()
