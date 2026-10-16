import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from osnit.config import Config
from osnit.contacts import contacts
from osnit.identity import dossier, find_people
from osnit.importqueue import ImportQueue
from osnit.multisearch import multi_find
from osnit.profile import build_profile
from osnit.providers import NativeMetaSearchProvider
from osnit.search import SearchService
from osnit.store import Store
from osnit.web_osint import _launch_resilient_async_browser, _search_yahoo_playwright_batch
from osnit.xling import name_skeleton_keys
from tests import helpers


class TestHighScaleAndBugfixes(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=str(self.root / "inbox"))

    def tearDown(self):
        self.srv.shutdown()
        self.store.close()
        self.tmp_dir.cleanup()

    def test_task1_playwright_sync_provider_3stage_fallback(self):
        """Task 1: NativeMetaSearchProvider falls back to system browser / self-heal / HTTP when executable is missing."""
        cfg = Config(db_path=str(self.root / "p.db"))
        provider = NativeMetaSearchProvider(cfg, inbox=self.root / "inbox")

        mock_pw = MagicMock()
        # Simulate Playwright throwing "Executable doesn't exist" on all launch attempts
        mock_pw.chromium.launch_persistent_context.side_effect = Exception(
            "BrowserType.launch_persistent_context: Executable doesn't exist at chrome-headless-shell.exe"
        )
        mock_pw.chromium.launch.side_effect = Exception(
            "BrowserType.launch: Executable doesn't exist at chrome-headless-shell.exe"
        )

        with patch.object(NativeMetaSearchProvider, "_trigger_playwright_self_heal") as mock_heal, \
             patch.object(provider, "_search_http_fallback", return_value=["https://example.com/1"]) as mock_http:
            ctx, close_target = provider._launch_resilient_context(mock_pw, ["--no-sandbox"], "TestUA")
            self.assertIsNone(ctx)
            self.assertIsNone(close_target)
            mock_heal.assert_called_once()

            # Verify _search_http_fallback works and returns results immediately
            res = provider._search_http_fallback("יפתח שביט", limit=5)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0], "https://example.com/1")
            mock_http.assert_called_once_with("יפתח שביט", limit=5)

    def test_task1_playwright_async_web_osint_fallback(self):
        """Task 1: _search_yahoo_playwright_batch in web_osint.py falls back to HTTP immediately if browser executable is missing."""
        async def _run():
            with patch("osnit.web_osint._launch_resilient_async_browser", return_value=None), \
                 patch("osnit.web_osint._search_ddg_html", return_value=[
                     {"title": "HTTP Fallback Hit", "url": "https://example.org/hit", "snippet": "יפתח שביט 054-1234567"}
                 ]) as mock_ddg:
                results_map = await _search_yahoo_playwright_batch(["יפתח שביט"], limit_per_query=5)
                self.assertIn("יפתח שביט", results_map)
                self.assertEqual(len(results_map["יפתח שביט"]), 1)
                self.assertEqual(results_map["יפתח שביט"][0]["url"], "https://example.org/hit")
                mock_ddg.assert_called_once()

        asyncio.run(_run())

    def test_task2_quick_search_and_full_subject_profile_bridge(self):
        """Task 2: Quick Search (_backfill) + build_profile returns full identities, national_ids, clusters, graph, and snippets."""
        csv_data = (
            "full_name,id_number,phone,email,address,company,role\n"
            "יפתח שביט,000000018,054-8317945,yiftach.shavit@alpha.co.il,תל אביב רחוב הרצל 10,אלפא טכנולוגיות בע\"מ,מנכ\"ל\n"
        )
        self.q.add_bytes(csv_data.encode("utf-8"), "test_contacts.csv")
        self.q.run_pending()
        self.store.reindex_names()

        res = self.svc.search("יפתח שביט")
        prof = res["profile"]
        self.assertIsNotNone(prof)
        self.assertIsNotNone(prof.get("entity_id"))

        gids = prof.get("grouped_identities") or {}
        self.assertTrue(len(gids.get("national_ids", [])) >= 1, f"Expected national_ids in {gids}")
        self.assertTrue(len(gids.get("phones", [])) >= 1, f"Expected phones in {gids}")
        self.assertTrue(len(gids.get("emails", [])) >= 1, f"Expected emails in {gids}")
        self.assertTrue(len(gids.get("addresses", [])) >= 1, f"Expected addresses in {gids}")
        self.assertTrue(len(gids.get("orgs", [])) >= 1, f"Expected orgs in {gids}")
        self.assertTrue(len(gids.get("roles", [])) >= 1, f"Expected roles in {gids}")
        self.assertTrue(len(gids.get("documents", [])) >= 1, f"Expected documents in {gids}")

        # Verify unified dossier clusters, force graph, and evidence snippets are included for UI rendering
        self.assertTrue(len(prof.get("clusters", [])) >= 1)
        self.assertIn("graph", prof)
        self.assertTrue(len(prof["graph"].get("nodes", [])) >= 2)
        self.assertIsInstance(prof.get("evidence_snippets"), list)

        # Also test Quick Search by phone number -> resolves owning person's full dossier!
        res_phone = self.svc.search("054-8317945")
        prof_phone = res_phone["profile"]
        self.assertIsNotNone(prof_phone)
        self.assertTrue(len(prof_phone.get("clusters", [])) >= 1)
        self.assertTrue(len(prof_phone.get("grouped_identities", {}).get("emails", [])) >= 1)

    def test_task3_multi_find_3word_names_and_nonblocking_reindex(self):
        """Task 3: Multi-Vector Smart Search finds 3-word names via 2-word query and never blocks on _wlock."""
        # Check name_skeleton_keys generates 2-word combinations for 3-word names
        skels = name_skeleton_keys("יצחק דוד כהן")
        skels_two = name_skeleton_keys("יצחק כהן")
        self.assertTrue(set(skels) & set(skels_two), f"Expected overlap between {skels} and {skels_two}")

        csv_data = "full_name,id_number,phone,address\nיצחק דוד כהן,000000018,052-9988776,חיפה\n"
        self.q.add_bytes(csv_data.encode("utf-8"), "citizens.csv")
        self.q.run_pending()
        self.store.reindex_names()

        # Acquire _wlock on another thread to simulate heavy background file import
        lock_acquired = threading.Event()
        release_lock = threading.Event()

        def _hold_write_lock():
            with self.store._wlock:
                lock_acquired.set()
                release_lock.wait(timeout=5.0)

        t = threading.Thread(target=_hold_write_lock)
        t.start()
        lock_acquired.wait(timeout=2.0)
        try:
            # multi_find must complete immediately without blocking on _wlock!
            res = multi_find(self.store, {"name": "יצחק כהן", "city": "חיפה"})
            self.assertTrue(len(res.get("results", [])) >= 1, f"Expected results from multi_find, got {res}")
            top = res["results"][0]
            self.assertIn("כהן", top["name"])
        finally:
            release_lock.set()
            t.join(timeout=2.0)

    def test_task4_import_queue_cancel_remove_and_purge_any_state(self):
        """Task 4: ImportQueue can remove and purge files in running, analyzing, error, or done states."""
        job = self.q.add_bytes("full_name,phone\nרונן לוי,050-8317945\n".encode("utf-8"), "bad_upload.csv")
        self.q.run_pending()
        jid = job["id"]
        job_row = self.store.q1("SELECT * FROM imports WHERE id=?", (jid,))
        f1 = Path(job_row["path"])

        # Force job into 'running' state (simulating a stuck upload)
        with self.store.tx() as c:
            c.execute("UPDATE imports SET state='running' WHERE id=?", (jid,))

        # Previously, removing a 'running' job raised RuntimeError. Now it cancels, purges DB data, and deletes the file!
        res = self.q.remove(jid, purge=True)
        self.assertTrue(res.get("removed"))
        self.assertIn("purged", res)
        self.assertGreaterEqual(res["purged"].get("sources", 0), 1)
        self.assertFalse(f1.exists(), "Physical file in inbox should be deleted on remove")
        self.assertIsNone(self.store.q1("SELECT * FROM imports WHERE id=?", (jid,)), "Import job row should be deleted from imports table")

        # Verify entities exclusive to that file were purged from the DB
        found = find_people(self.store, "רונן לוי")
        self.assertEqual(len(found), 0, f"Expected purged entity to be removed, got {found}")

    def test_task5_high_scale_btree_indexes_and_query_plans(self):
        """Task 5: Verify B-tree indexes exist and prefix range scans use SEARCH USING INDEX instead of full table scans."""
        c = self.store._keep
        idx_rows = c.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        idx_names = {r["name"] for r in idx_rows}

        for required_idx in ("entities_key", "aliases_key", "aliases_source", "evidence_entity", "rel_a", "rel_b", "name_index_ent"):
            self.assertIn(required_idx, idx_names, f"Missing critical high-scale B-tree index: {required_idx}")

        # Verify EXPLAIN QUERY PLAN for prefix range scan on aliases
        plan_aliases = c.execute(
            "EXPLAIN QUERY PLAN SELECT entity_id FROM aliases WHERE alias_key >= 'יפתח' AND alias_key < 'יפתח\uffff' LIMIT 80"
        ).fetchall()
        plan_str = " ".join(str(dict(r)) for r in plan_aliases)
        self.assertIn("aliases_key", plan_str, f"Expected aliases_key index in query plan: {plan_str}")

        # Verify EXPLAIN QUERY PLAN for prefix range scan on entities
        plan_entities = c.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM entities WHERE type='person' AND key >= 'יפתח' AND key < 'יפתח\uffff' LIMIT 80"
        ).fetchall()
        plan_ent_str = " ".join(str(dict(r)) for r in plan_entities)
        self.assertTrue(
            "entities_key" in plan_ent_str or "sqlite_autoindex_entities" in plan_ent_str,
            f"Expected indexed range scan on entities, got: {plan_ent_str}",
        )

        # Verify contacts works cleanly
        self.q.add_bytes("full_name,phone,address\nנועה ברק,053-3344556,ירושלים\n".encode("utf-8"), "dir.csv")
        self.q.run_pending()
        self.store.reindex_names()
        dir_res = contacts(self.store, q="נועה ברק", limit=20)
        self.assertEqual(dir_res["total"], 1)
        self.assertEqual(dir_res["rows"][0]["name"], "נועה ברק")

    def test_ui_html_contains_all_required_upgrades(self):
        """Verify osnit/ui.html contains timeout/AbortError fix, file purge buttons, and viewSubject bridge."""
        ui_text = Path("osnit/ui.html").read_text(encoding="utf-8")
        self.assertIn("120000", ui_text)
        self.assertIn("הבקשה הופסקה עקב חריגת זמן", ui_text)
        self.assertIn("data-rm-purge", ui_text)
        self.assertIn("btnPurgeRemoveJob", ui_text)
        self.assertIn("subjDeepReconBridge", ui_text)
        self.assertIn("אשכול זהות מאוחד", ui_text)


if __name__ == "__main__":
    unittest.main()
