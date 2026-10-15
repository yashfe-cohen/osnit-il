"""
Phase 5 Deep E2E Test: Deep Web OSINT, Targeted Dorking, Redirect Unwrapping,
Snippet Intelligence Harvesting & Stealth Scraping.
"""
import base64
import unittest
from unittest.mock import MagicMock

from osnit.config import Config
from osnit.providers import (
    NativeMetaSearchProvider,
    apply_stealth,
    clean_results,
    extract_serp_snippets,
    harvest_snippet_intel,
    unwrap_search_redirect,
)
from osnit.search import build_osint_dorks
from tests import helpers
from tests.helpers import PAGES


class TestPhase5WebOsint(unittest.TestCase):
    def test_targeted_osint_dorks_generation(self):
        """
        Verifies that build_osint_dorks generates bilingual dorks (Hebrew + English),
        cross-identifier combinations (phone, email, city, org, national_id),
        social networks, legal/academic repositories, and document filetypes.
        """
        dorks = build_osint_dorks(
            "דניאל כהן",
            identifiers={
                "phone": "054-5551234",
                "email": "daniel.cohen@tech.co.il",
                "city": "תל אביב",
                "org": "אוניברסיטת תל אביב",
                "national_id": "000000018",
                "username": "danielc_dev",
            },
        )
        print("\n=== [PHASE 5] GENERATED OSINT DORKS (SAMPLE) ===")
        for d in dorks[:15]:
            print("  [DORK]", d)

        joined = "\n".join(dorks)
        # 1. Bilingual coverage (Hebrew + English transliteration)
        self.assertIn('"דניאל כהן"', joined)
        self.assertTrue("daniel cohen" in joined.lower(), "Must include English transliteration dorks")

        # 2. Cross-identifier combinations
        self.assertTrue(any("054-5551234" in d or "0545551234" in d for d in dorks))
        self.assertTrue(any("daniel.cohen@tech.co.il" in d for d in dorks))
        self.assertTrue(any("תל אביב" in d for d in dorks))
        self.assertTrue(any("אוניברסיטת תל אביב" in d for d in dorks))
        self.assertTrue(any("000000018" in d for d in dorks))

        # 3. Social media platforms
        for platform in ("site:linkedin.com/in", "site:facebook.com", "site:instagram.com",
                         "site:x.com", "site:twitter.com", "site:t.me", "site:github.com"):
            self.assertIn(platform, joined)

        # 4. Academic, Legal & Government repositories
        for repo in ("site:gov.il", "site:ac.il", "תולעת המשפט", "פסק דין", "site:nevo.co.il"):
            self.assertIn(repo, joined)

        # 5. Exposed document filetypes
        for ft in ("filetype:pdf", "filetype:xlsx", "filetype:docx"):
            self.assertIn(ft, joined)

    def test_redirect_unwrapping_and_noise_filtering(self):
        """
        Verifies unwrapping of DuckDuckGo, Google, Bing, and Yahoo redirects,
        removal of tracking parameters, and filtering of generic/noise domains.
        """
        ddg_redir = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.gov.il%2Fhe%2Fdepartments%2Fdoc.pdf%3Futm_source%3Dddg"
        google_redir = "https://www.google.com/url?q=https%3A%2F%2Ftau.ac.il%2Fresearch%2Fpaper.pdf%26fbclid%3D123&sa=U"
        bing_target = "https://www.linkedin.com/in/daniel-cohen-il"
        bing_b64 = base64.urlsafe_b64encode(bing_target.encode("utf-8")).decode("ascii").rstrip("=")
        bing_redir = f"https://www.bing.com/ck/a?!&&p=123&u=a1{bing_b64}&ntb=1"
        yahoo_redir = "https://r.search.yahoo.com/_ylt=A0/RV=2/RE=1/RO=10/RU=https%3A%2F%2Fgithub.com%2Fdanielc/RK=2/RS=xyz"

        self.assertEqual(unwrap_search_redirect(ddg_redir), "https://www.gov.il/he/departments/doc.pdf?utm_source=ddg")
        self.assertEqual(unwrap_search_redirect(bing_redir), bing_target)
        self.assertEqual(unwrap_search_redirect(yahoo_redir), "https://github.com/danielc")

        raw_urls = [
            ddg_redir,
            google_redir,
            bing_redir,
            yahoo_redir,
            "https://he.wikipedia.org/wiki/דניאל_כהן",
            "https://www.sefaria.org.il/Genesis.1",
            "https://duckduckgo.com/?q=test",
            "https://www.bing.com/search?q=test",
        ]
        cleaned = clean_results(raw_urls)
        print("\n=== [PHASE 5] CLEANED & UNWRAPPED URLS ===")
        for u in cleaned:
            print("  [CLEAN URL]", u)

        self.assertIn("https://www.gov.il/he/departments/doc.pdf", cleaned)
        self.assertIn("https://www.linkedin.com/in/daniel-cohen-il", cleaned)
        self.assertIn("https://github.com/danielc", cleaned)
        self.assertFalse(any("wikipedia.org" in u for u in cleaned))
        self.assertFalse(any("sefaria.org" in u for u in cleaned))
        self.assertFalse(any("duckduckgo.com" in u for u in cleaned))
        self.assertFalse(any("utm_source" in u for u in cleaned))

    def test_serp_snippet_extraction_and_intel_harvesting(self):
        """
        Verifies direct harvesting of titles, snippets, phones, emails, national IDs,
        and social profiles from SERP HTML.
        """
        sample_serp_html = """
        <div class="result">
            <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.linkedin.com%2Fin%2Fdaniel-cohen-8200">
                דניאל כהן (Daniel Cohen) - Senior Cyber Researcher | LinkedIn
            </a>
            <a class="result__snippet">
                ליצירת קשר עם דניאל כהן: נייד 054-5551234, אימייל daniel.cohen@cyber.co.il, ת.ז 000000018. בוגר אוניברסיטת תל אביב.
            </a>
        </div>
        <li class="b_algo">
            <h2><a href="https://github.com/daniel-cohen-il">daniel-cohen-il (Daniel Cohen) · GitHub</a></h2>
            <p>Open-source intelligence researcher in Tel Aviv. Contact: d.cohen@ac.il</p>
        </li>
        """
        snippets = extract_serp_snippets(sample_serp_html)
        self.assertEqual(len(snippets), 2)
        self.assertEqual(snippets[0]["url"], "https://www.linkedin.com/in/daniel-cohen-8200")

        intel = harvest_snippet_intel(snippets)
        print("\n=== [PHASE 5] HARVESTED SERP SNIPPET INTEL ===")
        print("  Phones:", intel["phones"])
        print("  Emails:", intel["emails"])
        print("  National IDs:", intel["national_ids"])
        print("  Social Profiles:", [p["url"] for p in intel["social_profiles"]])

        self.assertIn("+972545551234", intel["phones"])
        self.assertIn("daniel.cohen@cyber.co.il", intel["emails"])
        self.assertIn("d.cohen@ac.il", intel["emails"])
        self.assertIn("000000018", intel["national_ids"])
        self.assertEqual(len(intel["social_profiles"]), 2)

    def test_stealth_compatibility_and_real_web_pipeline(self):
        """
        Verifies apply_stealth stability across Playwright Stealth versions and runs a real
        discovery + crawl pipeline via NativeMetaSearchProvider and Engine.
        """
        # 1. Verify apply_stealth never crashes on mock/real page objects
        fake_page = MagicMock()
        self.assertTrue(apply_stealth(fake_page))
        self.assertTrue(fake_page.add_init_script.called)

        # 2. Live/Real execution of NativeMetaSearchProvider (no crash, returns clean list)
        cfg = Config(db_path=":memory:")
        prov = NativeMetaSearchProvider(cfg)
        live_urls = prov.search('"אוניברסיטת תל אביב" site:ac.il', limit=5)
        print(f"\n=== [PHASE 5] LIVE PROVIDER SEARCH RETURNED {len(live_urls)} URLS ===")
        for u in live_urls:
            print("  [LIVE URL]", u)
            self.assertTrue(u.startswith("http"))
            self.assertNotIn("duckduckgo.com/l/", u)

        # 3. Full E2E SearchService + Engine discovery & extraction against local HTTP server
        PAGES.clear()
        PAGES["/profile"] = (
            """<html><head><title>עמית טוליאן - פרופיל חוקר</title></head>
            <body>
                <h1>עמית טוליאן (Amit Tulian)</h1>
                <p>טלפון: 052-8884321 | אימייל: amit.tulian@example.co.il</p>
                <p>מוסד: אוניברסיטת תל אביב</p>
            </body></html>""",
            "text/html; charset=utf-8",
        )
        srv, base, store, eng, svc, fake_prov = helpers.make(["/profile"])
        try:
            res = svc.search("עמית טוליאן")
            sid = res["subject_id"]
            eng.drain()
            prof = svc.profile(sid)
            phones = [p["value"] for i in prof["identities"] for p in i["phones"]]
            emails = [e["value"] for i in prof["identities"] for e in i["emails"]]
            print("\n=== [PHASE 5] E2E WEB CRAWL PROFILE RESULTS ===")
            print("  Subject:", prof["subject"]["canonical"])
            print("  Extracted Phones:", phones)
            print("  Extracted Emails:", emails)
            self.assertIn("+972528884321", phones)
            self.assertIn("amit.tulian@example.co.il", emails)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
