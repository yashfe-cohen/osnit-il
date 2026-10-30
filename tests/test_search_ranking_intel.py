"""Discovery-engine upgrades: relevance-ranked crawl priority, and SERP snippet-intel harvesting
(capturing identifiers that appear in result titles/snippets — reaching data on pages that block the
crawler — gated to snippets that actually name the subject, so precision is preserved)."""
import unittest

from osnit.engine import rank_source_priority
from tests import helpers


class _SnippetProvider(helpers.FakeProvider):
    """A FakeProvider that also exposes SERP snippets, like the real meta-search/DDG providers."""
    def __init__(self, urls, snippets):
        super().__init__(urls)
        self.last_snippets = snippets
        self.last_snippet_intel = {}


class RankSourcePriority(unittest.TestCase):
    def setUp(self):
        self.toks = {"דנה", "לוי", "dana", "levi"}

    def test_domain_class_ordering(self):
        gov = rank_source_priority("https://www.gov.il/he/dep/dana-levi", 0, self.toks)
        social = rank_source_priority("https://linkedin.com/in/dana-levi", 0, self.toks)
        news = rank_source_priority("https://ynet.co.il/article/9", 0, self.toks)
        rand = rank_source_priority("https://randomblog.com/p/9", 0, self.toks)
        self.assertGreater(gov, social)
        self.assertGreater(social, news)
        self.assertGreater(news, rand)

    def test_serp_position_decays(self):
        first = rank_source_priority("https://ex.com/a", 0, set())
        tenth = rank_source_priority("https://ex.com/a", 10, set())
        self.assertGreater(first, tenth)

    def test_document_and_subject_token_boosts(self):
        doc = rank_source_priority("https://ex.com/files/cv.pdf", 3, set())
        page = rank_source_priority("https://ex.com/page", 3, set())
        self.assertGreater(doc, page)
        named = rank_source_priority("https://ex.com/profiles/dana", 3, {"dana"})
        plain = rank_source_priority("https://ex.com/profiles/x", 3, {"dana"})
        self.assertGreater(named, plain)

    def test_empty_url_is_safe(self):
        self.assertEqual(rank_source_priority("", 0, set()), 100)


class SerpSnippetIntel(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def _findings_for_subject(self, sid):
        eids = [r["entity_id"] for r in self.store.q(
            "SELECT entity_id FROM subject_entities WHERE subject_id=?", (sid,))]
        return self.store.osint_findings_for(eids) if eids else []

    def test_harvests_subject_gated_contacts_and_skips_unrelated(self):
        snippets = [
            {"title": "דנה לוי - פרופיל מקצועי", "url": "https://linkedin.com/in/dana-levi",
             "snippet": "דנה לוי · צרו קשר 054-1234567 · dana@acme.co.il"},
            {"title": "יוסי כהן רואה חשבון", "url": "https://x.com/yossi",
             "snippet": "יוסי כהן · טלפון 052-9999999"},
        ]
        prov = _SnippetProvider([self.base + "/x"], snippets)
        self.eng.providers["fake"] = prov

        sid = self.svc.search("דנה לוי")["subject_id"]
        self.eng.run_jobs_once(limit=50)

        findings = self._findings_for_subject(sid)
        serp = [f for f in findings if f["category"] == "serp_contact"]
        blob = " ".join(f.get("title", "") + " " + str(f.get("extracted_data_json") or f.get("extracted_data") or "")
                        for f in serp)
        # the subject's own phone + email (co-mentioned with her name) are captured
        self.assertIn("+972541234567", blob)
        self.assertIn("dana@acme.co.il", blob)
        # the unrelated person's number must never be attributed to the subject
        self.assertNotIn("9999999", blob)

    def test_no_subject_name_in_snippet_harvests_nothing(self):
        snippets = [{"title": "לוח מודעות", "url": "https://board.example.co.il",
                     "snippet": "למכירה דירה · 03-5556677"}]
        prov = _SnippetProvider([self.base + "/y"], snippets)
        self.eng.providers["fake"] = prov
        sid = self.svc.search("דנה לוי")["subject_id"]
        self.eng.run_jobs_once(limit=50)
        serp = [f for f in self._findings_for_subject(sid) if f["category"] == "serp_contact"]
        self.assertEqual(serp, [])


if __name__ == "__main__":
    unittest.main()
