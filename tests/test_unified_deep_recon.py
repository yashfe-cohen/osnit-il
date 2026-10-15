import asyncio
import json
import os
import tempfile
import time
import unittest
from urllib.request import urlopen

from osnit.config import Config
from osnit.identity import dossier
from osnit.search import SearchService
from osnit.server import make_server, serve_in_thread
from osnit.store import Store
from osnit.web_osint import (
    SOCIAL_PLATFORMS,
    ReconJobManager,
    SearchTargetProfile,
    UnifiedReconEngine,
    analyze_phone_number,
    build_israeli_dorks,
    check_github,
    check_gravatar,
    check_hudsonrock,
    check_ignorant_phone,
    check_username_on_platform,
    check_xposedornot,
    deep_enrich_facebook,
    deep_enrich_instagram,
    deep_enrich_linkedin,
    generate_phone_permutations,
    harvest_usernames_from_emails,
    run_deep_platform_enrichers,
    score_search_result,
    transliterate_name_bidirectional,
)


class TestUnifiedDeepRecon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp.name, "test_osnit.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_layer1_target_profile_expansion(self):
        """Layer 1: Test Hebrew<->English transliteration, email prefix harvesting, and Israeli phone permutations."""
        # 1. Phone permutations
        perms = generate_phone_permutations("054-7283832")
        for expected in (
            "0547283832",
            "054-7283832",
            "054-728-3832",
            "054 728 3832",
            "+972547283832",
            "+972-54-7283832",
            "972547283832",
        ):
            self.assertIn(expected, perms, f"Missing phone permutation: {expected}")

        # 2. Email username harvesting + generic filter
        usernames = harvest_usernames_from_emails([
            "matanshi@gmail.com",
            "matan.shinar@company.co.il",
            "info@company.co.il",
            "admin@domain.com",
            "office@test.org.il",
        ])
        self.assertIn("matanshi", usernames)
        self.assertIn("matan.shinar", usernames)
        self.assertIn("matanshinar", usernames)
        self.assertIn("matan_shinar", usernames)
        self.assertNotIn("info", usernames)
        self.assertNotIn("admin", usernames)
        self.assertNotIn("office", usernames)

        # 3. Bidirectional Hebrew <-> English transliteration with email/username hint alignment
        he_names, en_names = transliterate_name_bidirectional(
            ["מתן שנער"],
            hint_emails=["matanshi@gmail.com"],
            hint_usernames=["matanshi"],
        )
        self.assertIn("מתן שנער", he_names)
        lower_en = [v.lower() for v in en_names]
        self.assertIn("matan shinar", lower_en)
        self.assertTrue(
            any("shinar" in v or "shenar" in v for v in lower_en),
            f"Expected Matan Shinar/Shenar in {en_names}",
        )
        # Hint-boosted variant ("matan shinar" matching "matanshi") should rank near the top
        self.assertTrue(lower_en[0].startswith("matan sh"))

        # 4. Build SearchTargetProfile from query
        prof = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com 0547283832")
        self.assertIn("מתן שנער", prof.hebrew_names)
        self.assertIn("matanshi@gmail.com", prof.emails)
        self.assertIn("matanshi", prof.usernames)
        all_perms = [p for plist in prof.phone_permutations.values() for p in plist]
        self.assertIn("+972547283832", all_perms)
        self.assertTrue(any(n.lower() == "matan shinar" for n in prof.english_names))

    def test_layer2_email_breach_and_code_intel_with_cache(self):
        """Layer 2: Test Gravatar, HudsonRock, XposedOrNot, and GitHub commit/user extraction + SQLite caching."""
        call_count = {"n": 0}

        async def mock_fetcher(url, headers=None):
            call_count["n"] += 1
            if "gravatar.com" in url:
                return 200, json.dumps({
                    "entry": [{
                        "displayName": "Matan Shinar",
                        "preferredUsername": "matanshi",
                        "thumbnailUrl": "https://www.gravatar.com/avatar/12345",
                        "aboutMe": "Security Researcher in Tel Aviv",
                        "currentLocation": "Tel Aviv, Israel",
                        "accounts": [{"shortname": "github", "url": "https://github.com/matanshi"}],
                    }]
                }), {}
            if "cavalier.hudsonrock.com" in url:
                return 200, json.dumps({
                    "stealers": [{
                        "computer_name": "MATAN-PC",
                        "operating_system": "Windows 11 Pro",
                        "date_compromised": "2025-01-15",
                        "ip": "1.2.3.4",
                    }]
                }), {}
            if "xposedornot.com" in url:
                return 200, json.dumps({"breaches": [["LinkedIn", "Dropbox"]]}), {}
            if "api.github.com/search/users" in url:
                return 200, json.dumps({
                    "items": [{"login": "matanshi", "html_url": "https://github.com/matanshi", "avatar_url": "https://avatars.githubusercontent.com/u/1"}]
                }), {}
            if "api.github.com/users/matanshi" in url:
                return 200, json.dumps({
                    "login": "matanshi",
                    "name": "Matan Shinar",
                    "company": "Shinar Cyber Ltd",
                    "location": "Israel",
                    "bio": "OSINT & Cyber",
                    "email": "matanshi@gmail.com",
                    "html_url": "https://github.com/matanshi",
                }), {}
            if "api.github.com/search/commits" in url:
                return 200, json.dumps({
                    "items": [{
                        "commit": {
                            "author": {"name": "Matan Shinar", "email": "matanshi@gmail.com"}
                        }
                    }]
                }), {}
            return 404, "", {}

        async def run_checks():
            g = await check_gravatar("matanshi@gmail.com", store=self.store, http_fetcher=mock_fetcher)
            hr = await check_hudsonrock("matanshi@gmail.com", is_email=True, store=self.store, http_fetcher=mock_fetcher)
            xon = await check_xposedornot("matanshi@gmail.com", store=self.store, http_fetcher=mock_fetcher)
            gh = await check_github(email="matanshi@gmail.com", username="matanshi", store=self.store, http_fetcher=mock_fetcher)
            return g, hr, xon, gh

        g, hr, xon, gh = asyncio.run(run_checks())
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]["extracted_data"]["display_name"], "Matan Shinar")
        self.assertEqual(len(hr), 1)
        self.assertEqual(hr[0]["category"], "email_breach")
        self.assertEqual(len(xon), 1)
        self.assertIn("LinkedIn", xon[0]["summary"])
        self.assertTrue(len(gh) >= 1)
        self.assertEqual(gh[0]["extracted_data"]["full_name"], "Matan Shinar")

        # Verify SQLite osint_cache prevents duplicate network fetches on second run
        calls_before = call_count["n"]
        asyncio.run(run_checks())
        self.assertEqual(call_count["n"], calls_before, "Second run should be served 100% from SQLite osint_cache")

    def test_layer3_social_false_positive_filter_and_opengraph(self):
        """Layer 3: Test strict 200-OK false-positive filtering and OpenGraph metadata extraction."""
        tg_platform = next(p for p in SOCIAL_PLATFORMS if p["name"] == "Telegram")

        # Case 1: Telegram 200 OK page for a NON-EXISTENT user (no tgme_page_title) -> must return None!
        async def fake_tg_empty(url, headers=None):
            html_body = """
            <html><head><meta property="og:title" content="Telegram: Contact @nonexistent_user_123"/></head>
            <body><div class="tgme_page_description">If you have Telegram, you can contact @nonexistent_user_123 right away.</div></body></html>
            """
            return 200, html_body, {}

        res_empty = asyncio.run(
            check_username_on_platform("nonexistent_user_123", tg_platform, http_fetcher=fake_tg_empty)
        )
        self.assertIsNone(res_empty, "Non-existent Telegram page (200 OK without tgme_page_title) must be filtered out")

        # Case 2: Real Telegram profile with tgme_page_title, og:description, and outbound link
        async def fake_tg_real(url, headers=None):
            html_body = """
            <html>
            <head>
              <meta property="og:title" content="Matan Shinar"/>
              <meta property="og:description" content="Founder @ ShinarSecurity | Tel Aviv"/>
              <meta property="og:image" content="https://cdn4.telegram-cdn.org/file/avatar.jpg"/>
            </head>
            <body>
              <div class="tgme_page_title"><span>Matan Shinar</span></div>
              <div class="tgme_page_extra">@matanshi</div>
              <a href="https://linkedin.com/in/matan-shinar">LinkedIn</a>
            </body>
            </html>
            """
            return 200, html_body, {}

        res_real = asyncio.run(
            check_username_on_platform("matanshi", tg_platform, http_fetcher=fake_tg_real)
        )
        self.assertIsNotNone(res_real)
        self.assertEqual(res_real["category"], "social_profile")
        self.assertIn("Matan Shinar", res_real["title"])
        self.assertEqual(res_real["extracted_data"]["avatar_url"], "https://cdn4.telegram-cdn.org/file/avatar.jpg")
        self.assertIn("https://linkedin.com/in/matan-shinar", res_real["extracted_data"]["outbound_links"])

    def test_layer4_phone_intelligence(self):
        """Layer 4: Test Israeli mobile number carrier/line analysis and WhatsApp link generation."""
        info = analyze_phone_number("054-7283832")
        self.assertTrue(info["valid"])
        self.assertIn("Partner", info["carrier"])
        self.assertEqual(info["e164"], "+972547283832")
        self.assertEqual(info["whatsapp_url"], "https://wa.me/972547283832")

        async def fake_phone_http(url, headers=None):
            return 404, "", {}

        findings = asyncio.run(check_ignorant_phone(info, store=self.store, http_fetcher=fake_phone_http))
        self.assertTrue(len(findings) >= 1)
        phone_f = findings[0]
        self.assertEqual(phone_f["category"], "phone_intel")
        self.assertIn("Partner", phone_f["summary"])
        self.assertEqual(phone_f["url"], "https://wa.me/972547283832")

    def test_layer5_israeli_dorks_and_relevance_scorer(self):
        """Layer 5: Verify Israeli legal/registry/document dork generation and result relevance scoring."""
        prof = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com 0547283832")
        dorks = build_israeli_dorks(prof)
        categories = {d["category"] for d in dorks}
        self.assertIn("legal_doc", categories)
        self.assertIn("social_profile", categories)
        self.assertIn("web_mention", categories)
        queries_joined = " | ".join(d["query"] for d in dorks)
        self.assertIn("psakdin.co.il", queries_joined)
        self.assertIn("guidestar.org.il", queries_joined)
        self.assertIn("linkedin.com/in/", queries_joined)
        self.assertIn("filetype:pdf", queries_joined)

        # Relevance scoring
        high_score = score_search_result(
            "פסק דין: מתן שנער נגד חברת בדיקה בע\"מ",
            "בית המשפט קבע כי מתן שנער (דוא\"ל matanshi@gmail.com) זכאי לפיצוי.",
            "https://www.psakdin.co.il/Court/12345",
            prof,
        )
        low_score = score_search_result(
            "חדשות הספורט היום",
            "משחק כדורגל מרתק התקיים אתמול בחיפה",
            "https://example.com/sports",
            prof,
        )
        self.assertGreaterEqual(high_score, 0.70)
        self.assertLess(low_score, 0.40)

    def test_layer6_recursive_pivot_and_full_6_layer_e2e(self):
        """Layer 6 E2E: Hebrew entity 'מתן שנער' with 'matanshi@gmail.com' pivots via web OSINT to unify with English entity 'Matan Shinar' in osnit.db."""
        now = time.time()
        # 1. Seed local database with two separate records:
        # Record A: Hebrew person "מתן שנער" with email "matanshi@gmail.com"
        src_he, _ = self.store.add_source("file://local/hebrew_roster.csv", origin="file", now=now)
        self.store.update_source(src_he, title="hebrew_roster.csv", state="imported", kind="file")
        eid_he = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", now, fuzzy=False)
        eid_email = self.store.resolve_entity("email", "matanshi@gmail.com", "matanshi@gmail.com", now, fuzzy=False)
        self.store.add_evidence(eid_he, src_he, "מתן שנער - matanshi@gmail.com", 0.95, now)
        self.store.add_evidence(eid_email, src_he, "matanshi@gmail.com", 0.95, now)
        rel1 = self.store.add_relation(eid_he, eid_email, "contact", now)
        self.store.add_rel_evidence(rel1, src_he, "מתן שנער <matanshi@gmail.com>", 0.95, now)

        # Record B: Separate English person "Matan Shinar" in another local file (no shared email in DB yet!)
        src_en, _ = self.store.add_source("file://local/english_contractors.xlsx", origin="file", now=now)
        self.store.update_source(src_en, title="english_contractors.xlsx", state="imported", kind="file")
        eid_en = self.store.resolve_entity("person", "matan shinar", "Matan Shinar", now, fuzzy=False)
        eid_phone = self.store.resolve_entity("phone", "0547283832", "054-7283832", now, fuzzy=False)
        eid_org = self.store.resolve_entity("org", "shinar cyber ltd", "Shinar Cyber Ltd", now, fuzzy=False)
        self.store.add_evidence(eid_en, src_en, "Matan Shinar - 054-7283832 - Shinar Cyber Ltd", 0.95, now)
        rel2 = self.store.add_relation(eid_en, eid_phone, "contact", now)
        self.store.add_rel_evidence(rel2, src_en, "Matan Shinar 054-7283832", 0.95, now)
        rel3 = self.store.add_relation(eid_en, eid_org, "affiliated_with", now)
        self.store.add_rel_evidence(rel3, src_en, "Matan Shinar - Shinar Cyber Ltd", 0.90, now)

        # Also index a local FTS5 document mentioning 'matanshi'
        self.store.index_document_fts(src_en, "english_contractors.xlsx", "Row 12", "Contractor profile for Matan Shinar (handle: matanshi), Tel Aviv.")

        # 2. Mock external OSINT responses that discover "Matan Shinar" from "matanshi@gmail.com"
        async def mock_http(url, headers=None):
            if "api.github.com/search/commits" in url:
                return 200, json.dumps({
                    "items": [{
                        "commit": {
                            "author": {"name": "Matan Shinar", "email": "matanshi@gmail.com"}
                        }
                    }]
                }), {}
            if "api.github.com/search/users" in url:
                return 200, json.dumps({
                    "items": [{"login": "matanshi", "html_url": "https://github.com/matanshi", "avatar_url": "https://avatars.githubusercontent.com/u/42"}]
                }), {}
            if "api.github.com/users/matanshi" in url:
                return 200, json.dumps({
                    "login": "matanshi",
                    "name": "Matan Shinar",
                    "company": "Shinar Cyber Ltd",
                    "location": "Tel Aviv",
                    "bio": "Cyber Researcher",
                    "email": "matanshi@gmail.com",
                    "html_url": "https://github.com/matanshi",
                }), {}
            if "gravatar.com" in url:
                return 200, json.dumps({
                    "entry": [{
                        "displayName": "Matan Shinar",
                        "preferredUsername": "matanshi",
                        "thumbnailUrl": "https://www.gravatar.com/avatar/matanshi",
                    }]
                }), {}
            if "t.me/matanshi" in url:
                return 200, """
                <html><head><meta property="og:title" content="Matan Shinar"/><meta property="og:description" content="Tel Aviv"/></head>
                <body><div class="tgme_page_title"><span>Matan Shinar</span></div></body></html>
                """, {}
            return 404, "", {}

        def mock_search(query):
            if "psakdin.co.il" in query:
                return [{
                    "url": "https://www.psakdin.co.il/Court/998877",
                    "title": "פסק דין: מתן שנער (Matan Shinar) - תיק אזרחי",
                    "snippet": "פסק דין בעניין מתן שנער, טלפון 054-7283832, דוא\"ל matanshi@gmail.com.",
                }]
            return []

        # 3. Run the 6-Layer UnifiedReconEngine on the Hebrew entity
        layer_events = []

        def on_progress(layer_num, status_text, extra):
            layer_events.append((layer_num, status_text))

        engine = UnifiedReconEngine(
            store=self.store,
            http_fetcher=mock_http,
            search_fn=mock_search,
            max_depth=2,
        )
        result = engine.run_recon_sync(entity_id=eid_he, progress_cb=on_progress)

        # Verify all 6 layers reported progress
        reached_layers = {num for num, _ in layer_events}
        self.assertEqual(reached_layers, {1, 2, 3, 4, 5, 6})

        # Verify OSINT findings were persisted to osint_findings table
        stored_findings = self.store.osint_findings_for([eid_he])
        self.assertTrue(len(stored_findings) >= 4)
        categories_found = {f["category"] for f in stored_findings}
        self.assertIn("code_intel", categories_found)
        self.assertIn("social_profile", categories_found)
        self.assertIn("legal_doc", categories_found)
        self.assertIn("pivot_link", categories_found)

        # Verify Layer 6 Recursive Pivot linked eid_he ("מתן שנער") and eid_en ("Matan Shinar") in osnit.db!
        pivots = result["pivots"]
        self.assertTrue(
            any(p.get("extracted_data", {}).get("matched_entity_id") == eid_en for p in pivots),
            f"Expected Layer 6 Pivot to match local entity 'Matan Shinar' (eid={eid_en}), got: {pivots}",
        )
        pivot_ev = self.store.q(
            "SELECT re.snippet FROM relations r JOIN rel_evidence re ON re.relation_id=r.id "
            "WHERE (r.a_id=? AND r.b_id=?) OR (r.a_id=? AND r.b_id=?)",
            (eid_he, eid_en, eid_en, eid_he),
        )
        self.assertTrue(len(pivot_ev) >= 1)
        self.assertTrue(any("אוחד/קושר באמצעות ממצא רשת (Pivot)" in r["snippet"] for r in pivot_ev))

        # Verify Dossier now unifies BOTH "מתן שנער" and "Matan Shinar" into a single cluster with osint_findings!
        dos = dossier(self.store, eid=eid_he)
        self.assertEqual(len(dos["clusters"]), 1, "Hebrew and English entities should now be unified in 1 cluster")
        cluster_record_ids = {r["id"] for r in dos["clusters"][0]["records"]}
        self.assertIn(eid_he, cluster_record_ids)
        self.assertIn(eid_en, cluster_record_ids)
        self.assertTrue(len(dos["osint_findings"]) >= 4)

    def test_recon_http_api_endpoints(self):
        """Test /api/recon/start, /api/recon/status/<job_id>, and /api/recon/findings HTTP endpoints."""
        now = time.time()
        src, _ = self.store.add_source("file://local/test.csv", origin="file", now=now)
        self.store.update_source(src, title="test.csv", state="imported", kind="file")
        eid = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", now, fuzzy=False)
        self.store.add_evidence(eid, src, "מתן שנער", 0.9, now)
        self.store.add_osint_finding(
            entity_id=eid,
            category="code_intel",
            source_tool="github",
            title="GitHub: matanshi",
            summary="Name: Matan Shinar",
            url="https://github.com/matanshi",
            confidence=0.92,
        )

        from osnit.engine import Engine
        cfg = Config(db_path=self.db_path)
        svc = SearchService(Engine(self.store, cfg, providers={}))
        srv = make_server(svc, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        serve_in_thread(srv)
        try:
            # GET /api/recon/findings?eid=<eid>
            with urlopen(f"http://127.0.0.1:{port}/api/recon/findings?eid={eid}", timeout=5) as r:
                data = json.loads(r.read().decode("utf-8"))
                self.assertEqual(len(data["findings"]), 1)
                self.assertEqual(data["findings"][0]["title"], "GitHub: matanshi")

            # GET /api/entities/<eid> includes osint_findings
            with urlopen(f"http://127.0.0.1:{port}/api/entities/{eid}", timeout=5) as r:
                ent = json.loads(r.read().decode("utf-8"))
                self.assertEqual(len(ent["osint_findings"]), 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_chained_deep_platform_enrichers_and_hebrew_finals(self):
        """Test Hebrew final letter transliteration, first-name false-positive rejection, and second-stage Chained Deep Enrichers."""
        # 1. English -> Hebrew transliteration preserves proper final letters (ך, ם, ן, ף, ץ)
        he_amit, en_amit = transliterate_name_bidirectional(["Amit Tulian"], hint_emails=["amit.tuli2@gmail.com"])
        self.assertIn("עמית טוליאן", he_amit)
        self.assertFalse(any(w.endswith(("כ", "מ", "נ", "פ", "צ")) for nm in he_amit for w in nm.split()))

        he_dan, _ = transliterate_name_bidirectional(["Daniel Steinberg"])
        self.assertIn("דניאל שטיינברג", he_dan)

        # 2. First-name-only search hits ("Amit Kumar") must be rejected (< 0.40) when searching for "Amit Tulian"
        prof_amit = SearchTargetProfile.from_raw(name="Amit Tulian", emails=["amit.tuli2@gmail.com"])
        unrelated_score = score_search_result(
            "Amit Kumar - Software Engineer | LinkedIn",
            "View Amit Kumar's profile on LinkedIn, a professional community of 1 billion members.",
            "https://www.linkedin.com/in/amit-kumar-12345",
            prof_amit,
        )
        self.assertLess(unrelated_score, 0.40, "First-name-only match for unrelated surname must score below 0.40")

        # 3. Chained Deep Enrichers ("תוצאה מתוך תוצאה") on discovered LinkedIn, Facebook, Instagram, and GitHub URLs
        async def mock_deep_http(url, headers=None):
            if "linkedin.com/in/daniel-steinberg" in url:
                html_li = """
                <html><head>
                <meta property="og:title" content="דניאל שטיינברג - Cyber Lead - Blink Ops | LinkedIn"/>
                <meta property="og:description" content="ניסיון: Blink Ops · חינוך: Tel Aviv University · מיקום: Israel · 500+ חיבורים על LinkedIn."/>
                <meta property="og:image" content="https://media.licdn.com/avatar.jpg"/>
                </head><body></body></html>
                """
                return 200, html_li, {}
            if "facebook.com/amit.tulian" in url:
                html_fb = """
                <html><head>
                <meta property="og:title" content="Amit Tulian | Facebook"/>
                <meta property="og:description" content="Amit Tulian is on Facebook. Works at Blink Ops. Lives in Tel Aviv, Israel."/>
                <meta property="og:image" content="https://scontent.xx.fbcdn.net/avatar.jpg"/>
                </head><body></body></html>
                """
                return 200, html_fb, {}
            if "instagram.com/amit_tulian" in url:
                html_ig = """
                <html><head>
                <meta property="og:title" content="Amit Tulian (@amit_tulian) • Instagram photos and videos"/>
                <meta property="og:description" content="686 Followers, 1,116 Following, 123 Posts - See Instagram photos and videos from Amit Tulian (@amit_tulian)"/>
                <meta property="og:image" content="https://scontent.cdninstagram.com/ig_avatar.jpg"/>
                </head><body></body></html>
                """
                return 200, html_ig, {}
            if "api.github.com/users/amittuli/repos" in url:
                return 200, json.dumps([
                    {"name": "python-scraping", "description": "OSINT scraper", "language": "Python", "stargazers_count": 5, "html_url": "https://github.com/amittuli/python-scraping"}
                ]), {}
            if "api.github.com/users/amittuli/events/public" in url:
                return 200, json.dumps([
                    {"type": "PushEvent", "repo": {"name": "amittuli/python-scraping"}, "payload": {"commits": [{"author": {"name": "Amit Tulian", "email": "amit.tuli2@gmail.com"}}]}}
                ]), {}
            if "api.github.com/users/amittuli" in url:
                return 200, json.dumps({
                    "login": "amittuli",
                    "name": "Amit Tulian",
                    "company": "Blink Ops",
                    "location": "Israel",
                    "bio": "Security PM",
                    "public_repos": 1,
                    "followers": 4,
                    "html_url": "https://github.com/amittuli",
                }), {}
            return 404, "", {}

        initial_findings = [
            {"category": "social_profile", "source_tool": "dork_search", "url": "https://il.linkedin.com/in/daniel-steinberg", "title": "LinkedIn result"},
            {"category": "social_profile", "source_tool": "dork_search", "url": "https://www.facebook.com/amit.tulian", "title": "Facebook result"},
            {"category": "social_profile", "source_tool": "dork_search", "url": "https://www.instagram.com/amit_tulian/", "title": "Instagram result"},
            {"category": "social_profile", "source_tool": "social_github", "url": "https://github.com/amittuli", "title": "GitHub HTML result"},
        ]

        deep_results = asyncio.run(
            run_deep_platform_enrichers(initial_findings, store=self.store, http_fetcher=mock_deep_http)
        )
        by_tool = {r["source_tool"]: r for r in deep_results}
        self.assertIn("linkedin_deep", by_tool)
        self.assertIn("Blink Ops", by_tool["linkedin_deep"]["extracted_data"]["orgs"])
        self.assertIn("Tel Aviv University", by_tool["linkedin_deep"]["extracted_data"]["education"])

        self.assertIn("facebook_deep", by_tool)
        self.assertIn("Blink Ops", by_tool["facebook_deep"]["extracted_data"]["orgs"])
        self.assertIn("Tel Aviv, Israel", by_tool["facebook_deep"]["extracted_data"]["locations"])

        self.assertIn("instagram_deep", by_tool)
        self.assertEqual(by_tool["instagram_deep"]["extracted_data"]["stats"]["followers"], "686")
        self.assertEqual(by_tool["instagram_deep"]["extracted_data"]["stats"]["posts"], "123")

        self.assertIn("github", by_tool)
        self.assertEqual(by_tool["github"]["extracted_data"]["repositories"][0]["name"], "python-scraping")
        self.assertEqual(by_tool["github"]["extracted_data"]["commit_authors"][0]["email"], "amit.tuli2@gmail.com")


if __name__ == "__main__":
    unittest.main()

