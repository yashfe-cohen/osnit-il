"""A social profile is auto-verified only by a hard anchor (web_osint.CandidateProfileMatcher, rule 5): a full name, an
exact handle, a city and a face in the picture are exactly what a namesake has too."""
import unittest

from osnit.web_osint import CandidateProfileMatcher, SearchTargetProfile


def _finding(url, username, full_name, bio, face=False):
    return {"category": "social_profile", "source_tool": "Instagram", "title": f"Instagram: {full_name} (@{username})",
            "summary": bio, "url": url, "confidence": 0.7,
            "extracted_data": {"platform": "Instagram", "username": username, "full_name": full_name, "bio": bio,
                               "face_detected": face, "avatar_url": url + "/avatar.jpg" if face else ""}}


class CandidatePrecisionTest(unittest.TestCase):
    def setUp(self):
        self.prof = SearchTargetProfile.from_query("יוסי כהן yossi.cohen77@gmail.com 0521234987")
        self.prof.cities.append("תל אביב")

    def test_a_namesake_with_name_handle_city_and_a_face_is_only_a_candidate(self):
        f = _finding("https://www.instagram.com/yossicohen", "yossicohen", "Yossi Cohen",
                     "Living in Tel Aviv | תל אביב", face=True)
        r = CandidateProfileMatcher.score_candidate(f, self.prof)
        self.assertFalse(r["hard_anchor"])
        self.assertNotEqual(r["recommended_status"], "verified")
        self.assertFalse(r["signals"].get("visual_match"))      # a detected face is not the target's face

    def test_the_targets_own_phone_verifies(self):
        f = _finding("https://www.instagram.com/yc_77", "yc_77", "Yossi Cohen", "call me 052-123-4987")
        r = CandidateProfileMatcher.score_candidate(f, self.prof)
        self.assertTrue(r["hard_anchor"])
        self.assertEqual(r["recommended_status"], "verified")


if __name__ == "__main__":
    unittest.main()


class ForgetErasesTheTreeTest(unittest.TestCase):
    def test_forget_removes_the_persons_investigation_tree(self):
        import os
        import tempfile
        import time
        from osnit.store import Store
        st = Store(os.path.join(tempfile.mkdtemp(), "x.db"))
        eid = st.resolve_entity("person", "יוסי כהן", "יוסי כהן", time.time(), fuzzy=False)
        root = st.upsert_investigation_node("j1", "seed", "seed:yossi", "יוסי כהן", root_entity_id=eid)
        leaf = st.upsert_investigation_node("j1", "social_profile", "ig:yossicohen", "@yossicohen", root_entity_id=eid,
                                            parent_node_id=root, depth=1, avatar_url="https://x/a.jpg")
        st.add_investigation_edge("j1", root, leaf, "found") if hasattr(st, "add_investigation_edge") else None
        st.forget("יוסי כהן")
        self.assertIsNone(st.q1("SELECT 1 x FROM investigation_nodes WHERE root_entity_id=?", (eid,)))
        self.assertIsNone(st.q1("SELECT 1 x FROM investigation_edges"))


class TreeCarriesDbTiesTest(unittest.TestCase):
    def test_the_tree_payload_gets_the_maps_close_ties(self):
        import os
        import tempfile
        from osnit.config import Config
        from osnit.engine import Engine
        from osnit.importdb import import_db
        from osnit.network import with_db_close_ties
        from osnit.store import Store
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        st = Store(cfg.db_path)
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,כתובת\nדנה גל,0521112233,הרצל 5 גן יבנה\nרון כהן,0534445566,הרצל 5 גן יבנה\n")
        import_db(Engine(st, cfg, providers={}), p, label="a", crawl_urls=False)
        dana = st.q1("SELECT id FROM entities WHERE display='דנה גל'")["id"]
        st.upsert_investigation_node("j1", "seed", "seed:dana", "דנה גל", root_entity_id=dana)
        tree = with_db_close_ties(st, st.get_investigation_tree(entity_id=dana))
        self.assertEqual([t["name"] for t in tree["db_close_ties"]], ["רון כהן"])
        self.assertIn("הרצל 5", tree["db_close_ties"][0]["why"])
        self.assertEqual(tree["db_network_entity_id"], dana)
