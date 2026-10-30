import json
import unittest
import urllib.error
import urllib.request

from osnit.server import make_server, serve_in_thread
from osnit.web_osint import (
    InvestigationTreeBuilder,
    SearchTargetProfile,
    cross_match_and_pivot_local_db,
)
from tests import helpers
from tests.helpers import PAGES
from tests.test_pipeline import TEAM


class TestStreamingReconAndTreeApi(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        PAGES["/team"] = (TEAM, "text/html")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/team"])
        self.api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def call(self, path, body=None):
        h = {"Content-Type": "application/json"}
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers=h,
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_investigation_tree_api_endpoints_and_ui_hooks(self):
        person_eid = self.store.resolve_entity("person", "נועם לוי", "נועם לוי", 1.0)
        profile = SearchTargetProfile(
            entity_id=person_eid,
            primary_name="נועם לוי",
            hebrew_names=["נועם לוי"],
            english_names=["Noam Levy"],
            usernames=["noam_levy"],
        )
        builder = InvestigationTreeBuilder(
            self.store,
            job_id="job_api_test_1",
            profile=profile,
        )
        builder.init_seed_nodes()
        cand1 = builder._upsert_node(
            node_type="social_profile",
            canonical_key="instagram:noam_levy",
            label="Noam Levy (@noam_levy)",
            parent_node_id=builder.root_node_id,
            depth=1,
            platform="Instagram",
            status="candidate_top3",
            confidence=0.84,
            candidate_rank=1,
            discovery_reason="התאמת כינוי מדויקת ואימות עיר מגורים תל אביב",
            source_url="https://www.instagram.com/noam_levy",
            metadata={"candidate_rank": 1, "bio": "Co-founder with @dana_levy_sister | mail: noam@cyber.co.il"},
            relation_kind="candidate_match",
            relation_label="מועמד #1",
        )
        cand2 = builder._upsert_node(
            node_type="social_profile",
            canonical_key="instagram:noam_music",
            label="Noam Levy Music (@noam_music)",
            parent_node_id=builder.root_node_id,
            depth=1,
            platform="Instagram",
            status="candidate_top3",
            confidence=0.51,
            candidate_rank=2,
            discovery_reason="התאמת שם חלקית בלבד",
            source_url="https://www.instagram.com/noam_music",
            metadata={"candidate_rank": 2},
            relation_kind="candidate_match",
            relation_label="מועמד #2",
        )

        # 1. GET /api/recon/tree/<job_id>
        code, body = self.call("/api/recon/tree/job_api_test_1")
        self.assertEqual(code, 200)
        tree = json.loads(body)
        self.assertIsNotNone(tree["root"])
        self.assertEqual(len(tree["top3_candidates"]), 2)

        # 2. GET /api/recon/tree/<entity_id>
        code, body = self.call(f"/api/recon/tree/{person_eid}")
        self.assertEqual(code, 200)
        tree_by_eid = json.loads(body)
        self.assertEqual(tree_by_eid["root"]["id"], builder.root_node_id)

        # 3. POST /api/recon/node/confirm (reject candidate 2)
        code, body = self.call(
            "/api/recon/node/confirm",
            {"node_id": cand2, "decision": "reject", "auto_expand": False},
        )
        self.assertEqual(code, 200)
        res_rej = json.loads(body)
        self.assertTrue(res_rej["ok"])
        self.assertEqual(res_rej["status"], "rejected")

        # 4. POST /api/recon/node/confirm (confirm candidate 1 with auto_expand)
        code, body = self.call(
            "/api/recon/node/confirm",
            {"node_id": cand1, "decision": "confirm", "auto_expand": True},
        )
        self.assertEqual(code, 200)
        res_conf = json.loads(body)
        self.assertTrue(res_conf["ok"])
        self.assertEqual(res_conf["status"], "verified")
        self.assertGreaterEqual(len(res_conf["spawned_children"]), 1)

        # 5. POST /api/recon/node/expand on cand1
        code, body = self.call("/api/recon/node/expand", {"node_id": cand1})
        self.assertEqual(code, 200)
        res_exp = json.loads(body)
        self.assertTrue(res_exp["ok"])
        self.assertIn("tree", res_exp)

        # 6. GET /api/recon/findings?eid=<person_eid> includes tree
        code, body = self.call(f"/api/recon/findings?eid={person_eid}")
        self.assertEqual(code, 200)
        findings_payload = json.loads(body)
        self.assertIn("tree", findings_payload)
        self.assertIsNotNone(findings_payload["tree"]["root"])

        # 7. GET /api/entities/<person_eid> and GET /api/dossier?eid=<person_eid> include investigation_tree
        code, body = self.call(f"/api/entities/{person_eid}")
        self.assertEqual(code, 200)
        ent_payload = json.loads(body)
        self.assertIn("investigation_tree", ent_payload)
        self.assertIsNotNone(ent_payload["investigation_tree"]["root"])

        code, body = self.call(f"/api/dossier?eid={person_eid}")
        self.assertEqual(code, 200)
        dos_payload = json.loads(body)
        self.assertIn("investigation_tree", dos_payload)
        self.assertIsNotNone(dos_payload["investigation_tree"]["root"])

        # 8. UI HTML contains the new Investigation Tree components
        code, html_bytes = self.call("/")
        self.assertEqual(code, 200)
        html_str = html_bytes.decode("utf-8", errors="ignore")
        self.assertIn("renderInvestigationTreePanel", html_str)
        self.assertIn("confirmReconCandidate", html_str)
        self.assertIn("expandReconNode", html_str)
        self.assertIn("inv-close-pivot-hub", html_str)
        self.assertIn("inv-rev-check-bar", html_str)
        self.assertIn("filterInvTreeTier", html_str)
        self.assertIn("filterOsintStrength", html_str)

    def test_reverse_pivot_close_ties_branch_and_connection_tiers(self):
        # Create target entity and another local entity sharing an email discovered online
        target_eid = self.store.resolve_entity("person", "מתן שינר", "מתן שינר", 1.0, fuzzy=False)
        other_local_eid = self.store.resolve_entity("person", "matan shinar", "Matan Shinar", 1.0, fuzzy=False)
        shared_email_eid = self.store.resolve_entity("email", "matan.pivot@cyber.co.il", "matan.pivot@cyber.co.il", 1.0)
        self.store.add_relation(other_local_eid, shared_email_eid, "email", 1.0)

        profile = SearchTargetProfile(
            entity_id=target_eid,
            primary_name="מתן שינר",
            hebrew_names=["מתן שינר"],
            english_names=["Matan Shinar"],
            usernames=["matanshi"],
        )
        builder = InvestigationTreeBuilder(
            self.store,
            job_id="job_pivot_tiers_1",
            profile=profile,
        )
        builder.init_seed_nodes()

        leads = [
            {
                "type": "email",
                "value": "matan.pivot@cyber.co.il",
                "confidence": 0.91,
                "source_tool": "github_commit",
                "reason": "חולץ מהיסטוריית קומיטים",
            }
        ]
        builder.ingest_leads(leads)

        pivot_findings = cross_match_and_pivot_local_db(self.store, profile, leads, [])
        self.assertGreaterEqual(len(pivot_findings), 1)
        builder.ingest_findings_batch(pivot_findings, layer_num=7)

        # Also add a medium-confidence and a low-confidence network finding
        builder.ingest_findings_batch(
            [
                {
                    "category": "web_mention",
                    "source_tool": "open_web_search",
                    "title": "אזכור בכנס טכנולוגי — מתן שינר",
                    "summary": "אזכור חלקי של השם ברשימת משתתפים",
                    "url": "https://example.com/conf-list",
                    "confidence": 0.68,
                    "extracted_data": {"discovery_reason": "התאמת שם בכנס ללא מזהה נוסף"},
                },
                {
                    "category": "web_mention",
                    "source_tool": "open_web_search",
                    "title": "פוסט כללי ברשת — M. Shinar",
                    "summary": "אזכור שם משפחה בלבד",
                    "url": "https://example.com/weak-mention",
                    "confidence": 0.42,
                    "extracted_data": {"discovery_reason": "דמיון חלקי בשם משפחה בלבד"},
                },
            ],
            layer_num=3,
        )

        tree = self.store.get_investigation_tree(job_id="job_pivot_tiers_1", root_entity_id=target_eid)
        self.assertIn("close_ties_branch", tree)
        self.assertIn("reverse_check_summary", tree)
        self.assertIn("tiers_summary", tree)

        self.assertGreaterEqual(tree["close_ties_branch"]["total_count"], 1)
        self.assertGreaterEqual(len(tree["close_ties_branch"]["db_entity_pivots"]), 1)
        self.assertGreaterEqual(tree["reverse_check_summary"]["total_checked"], 1)
        self.assertGreaterEqual(tree["reverse_check_summary"]["total_matched"], 1)

        self.assertGreaterEqual(len(tree["tiers_summary"]["close_pivot"]), 1)
        self.assertGreaterEqual(len(tree["tiers_summary"]["medium"]), 1)
        self.assertGreaterEqual(len(tree["tiers_summary"]["low"]), 1)

        # Verify every node has connection_tier, connection_badge_he, why_connected_he, and parent_chain_he
        for nd in tree["nodes"]:
            self.assertIn("connection_tier", nd)
            self.assertIn("connection_badge_he", nd)
            self.assertIn("why_connected_he", nd)
            self.assertIn("parent_chain_he", nd)
            self.assertTrue(bool(nd["why_connected_he"]))


if __name__ == "__main__":
    unittest.main()
