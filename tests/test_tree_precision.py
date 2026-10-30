"""Precision in the investigation tree and the recon pivot (found in the full review of the merged tree work)."""
import os
import tempfile
import time
import unittest

from osnit.store import Store
from osnit.web_osint import SearchTargetProfile, cross_match_and_pivot_local_db


class PivotPrecisionTest(unittest.TestCase):
    def setUp(self):
        self.st = Store(os.path.join(tempfile.mkdtemp(), "x.db"))
        now = time.time()
        self.target = self.st.resolve_entity("person", "יצחק כהן", "יצחק כהן", now, fuzzy=False)
        # two other people named Yitzhak Cohen (namesakes), and an employer many people share
        from osnit.textnorm import name_key
        self.namesakes = [self.st.resolve_entity("person", f"{name_key('יצחק כהן')}|p:{i}", "יצחק כהן", now,
                                                 fuzzy=False) for i in range(2)]
        from osnit.extract import org_key
        city = self.st.resolve_entity("org", org_key("משרד הביטחון"), "משרד הביטחון", now, fuzzy=False)
        self.townsfolk = [self.st.resolve_entity("person", n, n, now, fuzzy=False)
                          for n in ("דנה לוי", "רון מזרחי", "שרה פרץ", "אבי גבאי", "מאיה גל")]
        assert all(p > 0 for p in self.townsfolk)
        for p in self.townsfolk:
            self.st.add_relation(p, city, "affiliated_with", now)
        self.profile = SearchTargetProfile(entity_id=self.target, primary_name="יצחק כהן", hebrew_names=["יצחק כהן"],
                                           english_names=["Yitzhak Cohen"])

    def pivots(self):
        return {r["b_id"] if r["a_id"] == self.target else r["a_id"] for r in self.st.q(
            "SELECT a_id, b_id FROM relations WHERE kind='pivot_match' AND (a_id=? OR b_id=?)",
            (self.target, self.target))}

    def test_a_namesake_is_reported_never_linked(self):
        found = cross_match_and_pivot_local_db(self.st, self.profile, [], [])
        self.assertEqual(self.pivots(), set())
        names = [f for f in found if f["extracted_data"].get("pivot_type") == "local_name_match"]
        self.assertEqual({f["extracted_data"]["matched_entity_id"] for f in names}, set(self.namesakes))
        self.assertTrue(all(f["extracted_data"]["connection_tier"] != "close_pivot" for f in names))

    def test_a_name_found_online_is_not_the_targets_alias(self):
        cross_match_and_pivot_local_db(self.st, self.profile, [{"type": "person", "value": "משה פרץ"}], [])
        aliases = {r["alias"] for r in self.st.q("SELECT alias FROM aliases WHERE entity_id=?", (self.target,))}
        self.assertNotIn("משה פרץ", aliases)
        self.assertIn("Yitzhak Cohen", aliases)                  # its own transliteration is

    def test_an_employer_links_nobody(self):
        from osnit.extract import org_key
        cross_match_and_pivot_local_db(self.st, self.profile, [{"type": "org", "value": org_key("משרד הביטחון")}], [])
        self.assertEqual(self.pivots() & set(self.townsfolk), set())

    def test_an_exclusive_personal_identifier_still_links(self):
        now = time.time()
        other = self.st.resolve_entity("person", "י. כהן", "י. כהן", now, fuzzy=False)
        em = self.st.resolve_entity("email", "itz.cohen@gmail.com", "itz.cohen@gmail.com", now, fuzzy=False)
        self.st.add_relation(other, em, "contact", now)
        cross_match_and_pivot_local_db(self.st, self.profile, [{"type": "email", "value": "itz.cohen@gmail.com"}], [])
        self.assertIn(other, self.pivots())


class TreeStatusTest(unittest.TestCase):
    def setUp(self):
        self.st = Store(os.path.join(tempfile.mkdtemp(), "x.db"))
        self.eid = self.st.resolve_entity("person", "יצחק כהן", "יצחק כהן", time.time(), fuzzy=False)
        self.root = self.st.upsert_investigation_node("j", "seed", "seed", "יצחק כהן", root_entity_id=self.eid)

    def node(self, **kw):
        return self.st.upsert_investigation_node("j", "social_profile", "ig:yc", "@yc", root_entity_id=self.eid,
                                                 parent_node_id=self.root, depth=1, **kw)

    def test_the_operators_rejection_sticks_across_runs(self):
        nid = self.node(status="candidate_top3", candidate_rank=1, confidence=0.8)
        self.st.confirm_or_reject_candidate_node(nid, "reject")
        self.node(status="candidate_top3", candidate_rank=1, confidence=0.9)        # the next recon finds it again
        n = self.st.get_investigation_node(nid)
        self.assertEqual(n["status"], "rejected")
        self.assertEqual(n["candidate_rank"], 0)
        self.assertLess(n["confidence"], 0.5)
        tree = self.st.get_investigation_tree(entity_id=self.eid)
        self.assertNotIn(nid, [c["id"] for c in tree["top_candidates"]])

    def test_a_high_score_alone_is_not_verified(self):
        nid = self.node(status="discovered", confidence=0.95)
        tree = self.st.get_investigation_tree(entity_id=self.eid)
        tier = next(n["connection_tier"] for n in tree["nodes"] if n["id"] == nid)
        self.assertNotEqual(tier, "high_verified")


if __name__ == "__main__":
    unittest.main()
