import json
import unittest
import urllib.error
import urllib.request

from osnit.server import make_server, serve_in_thread
from osnit.web_osint import InvestigationTreeBuilder, SearchTargetProfile
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


if __name__ == "__main__":
    unittest.main()
