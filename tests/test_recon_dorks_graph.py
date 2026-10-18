"""Deep-research breadth and depth: the dork builder covers many public Israeli source categories while every
query stays anchored on a target identifier (so relevance scoring still gates precision), and the Maltego-style
recon graph links each discovered profile/lead back to the identifier that surfaced it."""
import unittest

from osnit.web_osint import (SearchTargetProfile, build_israeli_dorks, recon_entity_graph, score_search_result)


def _profile():
    return SearchTargetProfile.from_raw(
        name="דנה לוי", names=["Dana Levi"], emails=["dana.levi.demo@example.com"],
        phones=["054-7718293"], cities=["גן יבנה"], organizations=["אלפא בעמ"])


class Dorks(unittest.TestCase):
    def setUp(self):
        self.p = _profile()
        self.dorks = build_israeli_dorks(self.p)

    def test_many_public_source_categories_are_covered(self):
        cats = {d["category"] for d in self.dorks}
        self.assertTrue({"legal_doc", "social_profile", "open_web_article", "phone_intel"} <= cats)
        self.assertGreaterEqual(len(self.dorks), 12)

    def test_every_query_is_anchored_on_a_target_identifier(self):
        # breadth must not cost precision: a hit on each query can only score when it matches the target
        for d in self.dorks:
            self.assertGreaterEqual(
                score_search_result(d["query"], "", "https://example.co.il/x", self.p), 0.4,
                f"query not anchored on the target: {d['label']}")

    def test_strong_identifiers_survive_the_cap(self):
        labels = " ".join(d["label"] for d in self.dorks)
        self.assertIn("אימייל", labels)
        self.assertIn("טלפון", labels)

    def test_queries_are_deduplicated(self):
        qs = [d["query"] for d in self.dorks]
        self.assertEqual(len(qs), len(set(qs)))


class ReconGraph(unittest.TestCase):
    def setUp(self):
        self.p = _profile()
        self.p.usernames = ["danalevi"]
        self.findings = [
            {"category": "social_profile", "source_tool": "social_github", "title": "GitHub: danalevi",
             "url": "https://github.com/danalevi", "confidence": 0.9,
             "extracted_data": {"platform": "GitHub", "username": "danalevi"}},
            {"category": "pivot_link", "source_tool": "pivot_engine", "title": "pivot", "url": "#entity/5",
             "extracted_data": {"matched_entity_id": 5}},
        ]
        self.leads = [{"type": "email", "value": "dana.work@corp.com", "confidence": 0.85, "source_tool": "github"}]
        self.pivots = [{"category": "pivot_link", "title": "התאמה מקומית #5", "summary": "קושר דרך אימייל",
                        "extracted_data": {"matched_entity_id": 5}}]

    def test_graph_has_target_identifiers_findings_leads_and_pivots(self):
        g = recon_entity_graph(self.p, self.findings, self.leads, self.pivots)
        keys = {n["key"] for n in g["nodes"]}
        self.assertIn("target", keys)
        self.assertIn("u:danalevi", keys)
        self.assertIn("f:https://github.com/danalevi", keys)
        self.assertTrue(any(n["kind"] == "email" and "dana.work" in n["label"] for n in g["nodes"]))
        self.assertTrue(any(n["kind"] == "other_person" and n.get("id") == 5 for n in g["nodes"]))

    def test_a_finding_links_to_the_username_that_produced_it(self):
        g = recon_entity_graph(self.p, self.findings, self.leads, self.pivots)
        self.assertTrue(any(e["a"] == "u:danalevi" and e["b"] == "f:https://github.com/danalevi"
                            for e in g["edges"]))

    def test_every_edge_references_a_real_node_and_graph_is_bounded(self):
        g = recon_entity_graph(self.p, self.findings * 60, self.leads, self.pivots, max_nodes=25)
        keys = {n["key"] for n in g["nodes"]}
        self.assertLessEqual(len(g["nodes"]), 25)
        for e in g["edges"]:
            self.assertIn(e["a"], keys)
            self.assertIn(e["b"], keys)


if __name__ == "__main__":
    unittest.main()
