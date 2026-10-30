import os
import tempfile
import time
import unittest

from osnit.store import Store
from osnit.web_osint import (
    InvestigationTreeBuilder,
    SearchTargetProfile,
    UnifiedReconEngine,
)


class TestInvestigationTreeStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp.name, "tree_test.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_upsert_nodes_edges_and_hierarchical_tree(self):
        """Verify parent->child tree construction, status priority protection, and top-3 candidate extraction."""
        job_id = "recon_test_101"
        root_eid = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", time.time(), fuzzy=False)

        root_nid = self.store.upsert_investigation_node(
            job_id=job_id,
            root_entity_id=root_eid,
            parent_node_id=None,
            depth=0,
            node_type="seed",
            canonical_key="seed:matan_shinar",
            label="מתן שנער",
            platform="OSINT Root",
            status="verified",
            confidence=1.0,
            discovery_reason="יעד חקירה ראשי",
            metadata={"seed_query": "מתן שנער"},
        )
        self.assertGreater(root_nid, 0)

        # Depth-1 username seed
        u_nid = self.store.upsert_investigation_node(
            job_id=job_id,
            root_entity_id=root_eid,
            parent_node_id=root_nid,
            depth=1,
            node_type="username",
            canonical_key="matanshi",
            label="@matanshi",
            platform="Username Seed",
            status="verified",
            confidence=0.9,
            discovery_reason="שם משתמש עוגן",
        )
        self.store.add_investigation_edge(
            job_id=job_id,
            from_node_id=root_nid,
            to_node_id=u_nid,
            relation_kind="seed_identifier",
            relation_label="שם משתמש",
            confidence=0.9,
        )

        # Depth-2 candidate social profiles (Top-3 candidates)
        ig1_nid = self.store.upsert_investigation_node(
            job_id=job_id,
            root_entity_id=root_eid,
            parent_node_id=u_nid,
            depth=2,
            node_type="social_profile",
            canonical_key="https://www.instagram.com/matanshi",
            label="Instagram: Matan Shinar (@matanshi)",
            platform="Instagram",
            status="candidate_top3",
            confidence=0.84,
            candidate_rank=1,
            discovery_reason="התאמת שם מלא + כינוי + עיר תל אביב",
            source_url="https://www.instagram.com/matanshi",
            metadata={"followers": 420},
        )
        self.store.add_investigation_edge(
            job_id=job_id,
            from_node_id=u_nid,
            to_node_id=ig1_nid,
            relation_kind="matched_handle",
            relation_label="התאמת שם משתמש",
            confidence=0.84,
        )

        ig2_nid = self.store.upsert_investigation_node(
            job_id=job_id,
            root_entity_id=root_eid,
            parent_node_id=u_nid,
            depth=2,
            node_type="social_profile",
            canonical_key="https://www.instagram.com/matan_shinar_tlv",
            label="Instagram: Matan S (@matan_shinar_tlv)",
            platform="Instagram",
            status="candidate_top3",
            confidence=0.72,
            candidate_rank=2,
            discovery_reason="התאמת שם דו-לשונית",
            source_url="https://www.instagram.com/matan_shinar_tlv",
        )
        self.store.add_investigation_edge(
            job_id=job_id,
            from_node_id=u_nid,
            to_node_id=ig2_nid,
            relation_kind="matched_handle",
            relation_label="וריאציית שם משתמש",
            confidence=0.72,
        )

        # Confirm candidate #1 by user and verify subsequent weaker upsert does NOT downgrade status
        updated = self.store.update_investigation_node_status(
            ig1_nid,
            status="confirmed_by_user",
            confidence=0.98,
            metadata_patch={"confirmed_at": 12345},
        )
        self.assertEqual(updated["status"], "confirmed_by_user")
        self.assertEqual(updated["metadata"]["followers"], 420)
        self.assertEqual(updated["metadata"]["confirmed_at"], 12345)

        # Re-upserting with 'discovered' must keep 'confirmed_by_user' and merge metadata
        same_nid = self.store.upsert_investigation_node(
            job_id=job_id,
            root_entity_id=root_eid,
            parent_node_id=u_nid,
            depth=2,
            node_type="social_profile",
            canonical_key="https://www.instagram.com/matanshi",
            label="Instagram: Matan Shinar (@matanshi)",
            platform="Instagram",
            status="discovered",
            confidence=0.60,
            metadata={"posts_count": 19},
        )
        self.assertEqual(same_nid, ig1_nid)
        re_read = self.store.get_investigation_node(ig1_nid)
        self.assertEqual(re_read["status"], "confirmed_by_user")
        self.assertGreaterEqual(re_read["confidence"], 0.98)
        self.assertEqual(re_read["metadata"]["followers"], 420)
        self.assertEqual(re_read["metadata"]["posts_count"], 19)

        # Fetch full tree by job_id and by root_entity_id
        tree_by_job = self.store.get_investigation_tree(job_id=job_id)
        tree_by_ent = self.store.get_investigation_tree(root_entity_id=root_eid)
        self.assertEqual(tree_by_job["stats"]["total_nodes"], 4)
        self.assertEqual(tree_by_ent["stats"]["total_nodes"], 4)
        self.assertEqual(tree_by_job["stats"]["max_depth"], 2)
        self.assertEqual(len(tree_by_job["tree"]), 1)
        root_tree = tree_by_job["tree"][0]
        self.assertEqual(root_tree["id"], root_nid)
        self.assertEqual(len(root_tree["children"]), 1)
        self.assertEqual(root_tree["children"][0]["id"], u_nid)
        self.assertEqual(len(root_tree["children"][0]["children"]), 2)

        # Verify delete_entity cleans up investigation_nodes & investigation_edges
        self.store.delete_entity(root_eid)
        after_del = self.store.get_investigation_tree(job_id=job_id)
        self.assertEqual(after_del["stats"]["total_nodes"], 0)
        self.assertEqual(after_del["stats"]["total_edges"], 0)

    def test_streaming_recon_persists_layer_by_layer_before_completion(self):
        """Verify UnifiedReconEngine streams findings to SQLite and InvestigationTree during intermediate layers."""
        eid = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", time.time(), fuzzy=False)
        prof = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com 0547283832", entity_id=eid)

        mid_run_snapshots = []

        async def mock_fetcher(url, headers=None):
            if "gravatar.com" in url:
                return 200, '{"entry":[{"displayName":"Matan Shinar","preferredUsername":"matanshi","aboutMe":"Tel Aviv"}]}', {}
            if "t.me/matanshi" in url:
                return 200, '<html><head><meta property="og:title" content="Matan Shinar"/></head><body><div class="tgme_page_title">Matan Shinar</div></body></html>', {}
            return 404, "", {}

        def on_progress(layer_num, text, extra):
            if layer_num == 3 and "tree" in extra:
                # At the start of Layer 3, Layer 2 findings MUST already be persisted in SQLite!
                db_findings = self.store.osint_findings_for(eid)
                db_tree = self.store.get_investigation_tree(root_entity_id=eid)
                mid_run_snapshots.append({
                    "layer": layer_num,
                    "db_findings_count": len(db_findings),
                    "tree_nodes_count": db_tree["stats"]["total_nodes"],
                })

        engine = UnifiedReconEngine(store=self.store, http_fetcher=mock_fetcher, search_fn=lambda q: [], max_depth=1)
        res = engine.run_recon_sync(entity_id=eid, profile=prof, progress_cb=on_progress, job_id="stream_job_1")

        self.assertTrue(len(mid_run_snapshots) >= 1, "Expected progress callback at Layer 3 with mid-run snapshot")
        self.assertGreaterEqual(
            mid_run_snapshots[0]["db_findings_count"],
            1,
            "Layer 2 findings must already be saved to osint_findings before Layer 3 runs!",
        )
        self.assertGreaterEqual(
            mid_run_snapshots[0]["tree_nodes_count"],
            4,
            "Seed and Layer 2 nodes must already be in investigation_nodes before Layer 3 runs!",
        )
        self.assertIn("tree", res)
        self.assertGreaterEqual(res["tree"]["stats"]["total_nodes"], 5)
        self.assertGreaterEqual(res["tree"]["stats"]["total_edges"], 4)


if __name__ == "__main__":
    unittest.main()
