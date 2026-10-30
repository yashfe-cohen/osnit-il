import os
import tempfile
import time
import unittest

from osnit.store import Store
from osnit.web_osint import (
    CandidateProfileMatcher,
    InvestigationTreeBuilder,
    SearchTargetProfile,
)


class TestCandidateTop3Matcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp.name, "top3_test.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_auto_verify_top3_ranking_and_surname_contradiction(self):
        """Verify auto-confirmation (>=0.88/hard anchor), Top-3 candidate ranking, and surname contradiction rejection."""
        eid = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", time.time(), fuzzy=False)
        prof = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com 0547283832", entity_id=eid)
        prof.cities.append("תל אביב")
        prof.organizations.append("Shinar Cyber")

        findings = [
            # 1. Hard-anchor profile (contains phone 054-728-3832 in bio) -> MUST be auto-verified!
            {
                "category": "social_profile",
                "source_tool": "Telegram",
                "title": "Telegram: Matan Shinar (@matanshi_tg)",
                "summary": "Cyber researcher | Contact: 054-728-3832",
                "url": "https://t.me/matanshi_tg",
                "confidence": 0.75,
                "extracted_data": {
                    "platform": "Telegram",
                    "username": "matanshi_tg",
                    "full_name": "Matan Shinar",
                    "bio": "Cyber researcher | Contact: 054-728-3832",
                },
            },
            # 2. Candidate #1: Exact handle + full name (score ~0.77)
            {
                "category": "social_profile",
                "source_tool": "Instagram",
                "title": "Instagram: Matan Shinar (@matanshi)",
                "summary": "Matan Shinar on Instagram",
                "url": "https://www.instagram.com/matanshi",
                "confidence": 0.70,
                "extracted_data": {
                    "platform": "Instagram",
                    "username": "matanshi",
                    "full_name": "Matan Shinar",
                    "bio": "Photography & Tech",
                },
            },
            # 3. Candidate #2: Full Hebrew name + partial handle
            {
                "category": "social_profile",
                "source_tool": "Facebook",
                "title": "Facebook: מתן שנער",
                "summary": "פרופיל פייסבוק של מתן שנער",
                "url": "https://www.facebook.com/matan.shinar.7",
                "confidence": 0.68,
                "extracted_data": {
                    "platform": "Facebook",
                    "username": "matan.shinar.7",
                    "full_name": "מתן שנער",
                    "bio": "Lives in Israel",
                },
            },
            # 4. Candidate #3: Exact handle + avatar (no full name in title)
            {
                "category": "social_profile",
                "source_tool": "TikTok",
                "title": "TikTok: @matanshi",
                "summary": "TikTok profile",
                "url": "https://www.tiktok.com/@matanshi",
                "confidence": 0.60,
                "extracted_data": {
                    "platform": "TikTok",
                    "username": "matanshi",
                    "display_name": "matanshi",
                    "avatar_url": "https://cdn.tiktok.com/avatar_matan.jpg",
                },
            },
            # 5. Candidate #4: Weak partial handle only -> should fall outside Top-3
            {
                "category": "social_profile",
                "source_tool": "X",
                "title": "X: @matan_sh_99",
                "summary": "X profile",
                "url": "https://x.com/matan_sh_99",
                "confidence": 0.50,
                "extracted_data": {
                    "platform": "X",
                    "username": "matan_sh_99",
                    "display_name": "Matan",
                },
            },
            # 6. Contradictory Surname ("Matan Cohen" / "מתן כהן") -> MUST be penalized and excluded from Top-3!
            {
                "category": "social_profile",
                "source_tool": "LinkedIn",
                "title": "LinkedIn: Matan Cohen",
                "summary": "Matan Cohen - Accountant in Tel Aviv",
                "url": "https://www.linkedin.com/in/matan-cohen-123",
                "confidence": 0.75,
                "extracted_data": {
                    "platform": "LinkedIn",
                    "username": "matan-cohen-123",
                    "full_name": "Matan Cohen",
                    "bio": "Accountant in Tel Aviv, Israel",
                },
            },
        ]

        job_id = "job_top3_test"
        builder = InvestigationTreeBuilder(store=self.store, job_id=job_id, profile=prof)
        builder.init_seed_nodes()
        builder.ingest_findings_batch(findings, layer_num=3)

        ranked = CandidateProfileMatcher.rank_and_tag_top3_candidates(
            findings,
            prof,
            store=self.store,
            job_id=job_id,
            max_top_candidates=3,
        )

        # 1. Verify hard-anchor Telegram profile was auto-verified
        verified_urls = [f["url"] for f in ranked["verified_profiles"]]
        self.assertIn("https://t.me/matanshi_tg", verified_urls)

        # 2. Verify exactly 3 candidates are in Top-3 and ranked in descending score order
        top3 = ranked["top3_candidates"]
        self.assertEqual(len(top3), 3)
        self.assertEqual(top3[0]["url"], "https://www.instagram.com/matanshi")
        self.assertEqual(top3[0]["extracted_data"]["candidate_rank"], 1)
        self.assertEqual(top3[1]["url"], "https://www.facebook.com/matan.shinar.7")
        self.assertEqual(top3[1]["extracted_data"]["candidate_rank"], 2)
        self.assertEqual(top3[2]["url"], "https://www.tiktok.com/@matanshi")
        self.assertEqual(top3[2]["extracted_data"]["candidate_rank"], 3)

        # 3. Verify "Matan Cohen" was penalized for surname contradiction and excluded from Top-3
        top3_urls = [f["url"] for f in top3]
        self.assertNotIn("https://www.linkedin.com/in/matan-cohen-123", top3_urls)
        cohen_finding = next(f for f in findings if "matan-cohen-123" in f["url"])
        self.assertTrue(cohen_finding["extracted_data"]["candidate_evaluation"]["surname_contradiction"])
        self.assertLess(cohen_finding["confidence"], 0.45)

        # 4. Verify SQLite tree snapshot reflects the Top-3 candidates and auto-verified node
        tree_snap = self.store.get_investigation_tree(job_id=job_id)
        self.assertEqual(len(tree_snap["top_candidates"]), 3)
        self.assertEqual(tree_snap["top_candidates"][0]["candidate_rank"], 1)
        self.assertEqual(tree_snap["top_candidates"][0]["source_url"], "https://www.instagram.com/matanshi")
        self.assertEqual(tree_snap["top_candidates"][1]["candidate_rank"], 2)
        self.assertEqual(tree_snap["top_candidates"][2]["candidate_rank"], 3)


if __name__ == "__main__":
    unittest.main()
