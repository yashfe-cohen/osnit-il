import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from osnit.config import Config
from osnit.engine import Engine
from osnit.store import Store
from osnit.importdb import import_db
from osnit.providers import (
    NativeMetaSearchProvider,
    build_providers,
    clean_results
)


class TestNativeSearchAndOfflineDecoupling(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_test_search_")
        self.db_path = os.path.join(self.tmp_dir, "test.db")
        self.store = Store(self.db_path)
        self.engine = Engine(self.store)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_offline_import_decoupling(self):
        """
        Verifies that file imports do NOT queue any web search URLs (crawl_urls=False by default).
        Offline import is strictly decoupled from web crawl.
        """
        csv_path = os.path.join(self.tmp_dir, "offline_users.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("name,phone,website\n")
            f.write("דניאל כהן,050-1234567,https://daniel-tech.co.il\n")
            f.write("מיכל לוי,052-7654321,https://michal-law.co.il\n")

        stats = import_db(self.engine, csv_path, label="offline_test", crawl_urls=False)
        # crawl_urls must be False, so urls_queued is strictly 0
        self.assertEqual(stats["urls_queued"], 0)

        # Check in the database: no external URLs were added to sources
        external_sources = self.store.q("SELECT * FROM sources WHERE url LIKE 'http%'")
        self.assertEqual(len(external_sources), 0)

    def test_native_meta_provider_registration(self):
        cfg = Config(db_path=self.db_path)
        provs = build_providers(cfg)
        self.assertIn("native_meta", provs)
        self.assertIsInstance(provs["native_meta"], NativeMetaSearchProvider)

    def test_native_meta_search_layer_b_cdx(self):
        cfg = Config(db_path=self.db_path)
        provider = NativeMetaSearchProvider(cfg)

        # Mock CDX response
        mock_cdx_data = [
            ["timestamp", "original", "mimetype"],
            ["20230101120000", "https://example.gov.il/docs/report.pdf", "application/pdf"],
            ["20230201120000", "https://example.gov.il/about", "text/html"]
        ]

        with patch("osnit.providers._get", return_value=b'[["timestamp","original","mimetype"],["20230101120000","https://example.gov.il/docs/report.pdf","application/pdf"]]'), \
             patch.object(provider, "_search_playwright_stealth", return_value=[]):
            results = provider.search("site:example.gov.il report", limit=10)
            self.assertTrue(len(results) >= 1)
            self.assertTrue(any("web.archive.org" in u and "report.pdf" in u for u in results))

    def test_native_meta_search_playwright_layer(self):
        cfg = Config(db_path=self.db_path)
        provider = NativeMetaSearchProvider(cfg)

        mock_urls = [
            "https://israel-defense.co.il/article/123",
            "https://calcalist.co.il/local/456"
        ]

        with patch.object(provider, "_search_open_repositories", return_value=[]), \
             patch.object(provider, "_search_playwright_stealth", return_value=mock_urls):
            results = provider.search("מערכות ביטחון", limit=5)
            self.assertEqual(len(results), 2)
            self.assertIn("https://israel-defense.co.il/article/123", results)

    def test_clean_results_dedup_and_generic_filter(self):
        urls = [
            "https://example.com/page1",
            "https://example.com/page1",  # duplicate
            "https://en.wikipedia.org/wiki/Israel",  # generic knowledge filter
            "https://example.com/page2",
        ]
        cleaned = clean_results(urls)
        self.assertEqual(len(cleaned), 2)
        self.assertEqual(cleaned, ["https://example.com/page1", "https://example.com/page2"])
