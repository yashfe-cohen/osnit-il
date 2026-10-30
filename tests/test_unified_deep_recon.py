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
    build_open_web_queries,
    check_github,
    check_gravatar,
    check_hudsonrock,
    check_ignorant_phone,
    check_username_on_platform,
    check_xposedornot,
    deep_enrich_facebook,
    deep_enrich_instagram,
    deep_enrich_linkedin,
    extract_article_context_and_entities,
    extract_in_article_images,
    generate_phone_permutations,
    harvest_usernames_from_emails,
    is_noise_or_logo_image,
    run_deep_platform_enrichers,
    run_layer6_image_recon,
    score_search_result,
    transliterate_name_bidirectional,
    verify_human_face_in_image,
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

        # Verify all 7 layers reported progress
        reached_layers = {num for num, _ in layer_events}
        self.assertEqual(reached_layers, {1, 2, 3, 4, 5, 6, 7})

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
        # The local "Matan Shinar" record is surfaced as a candidate (same name across scripts), NOT auto-merged:
        # a name alone, even a transliteration, is a possible match the operator confirms (rule 5) — two people
        # can share a name. So no automatic pivot_match relation is created between the two person entities by name.
        name_pivots = [p for p in pivots if p.get("extracted_data", {}).get("matched_entity_id") == eid_en]
        self.assertTrue(name_pivots, "the local namesake 'Matan Shinar' should be surfaced as a candidate")
        self.assertTrue(all(p["extracted_data"].get("pivot_type") == "local_name_match" for p in name_pivots))
        self.assertTrue(all(p["extracted_data"].get("connection_tier") != "close_pivot" for p in name_pivots))
        auto_merge = self.store.q(
            "SELECT re.snippet FROM relations r JOIN rel_evidence re ON re.relation_id=r.id "
            "WHERE r.kind='pivot_match' AND ((r.a_id=? AND r.b_id=?) OR (r.a_id=? AND r.b_id=?))",
            (eid_he, eid_en, eid_en, eid_he),
        )
        self.assertEqual(len(auto_merge), 0, "two person entities must not be auto-merged by name alone")

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

            # GET /api/dossier/export in HTML, Markdown, and JSON formats
            with urlopen(f"http://127.0.0.1:{port}/api/dossier/export?eid={eid}&format=html", timeout=5) as r:
                html_rep = r.read().decode("utf-8")
                self.assertIn("דו\"ח מחקר מודיעיני מאוחד", html_rep)
                self.assertIn("GitHub: matanshi", html_rep)
            with urlopen(f"http://127.0.0.1:{port}/api/dossier/export?eid={eid}&format=md", timeout=5) as r:
                md_rep = r.read().decode("utf-8")
                self.assertIn("# 🕵️‍♂️ דו\"ח מחקר מודיעיני מאוחד", md_rep)
                self.assertIn("GitHub: matanshi", md_rep)
            with urlopen(f"http://127.0.0.1:{port}/api/dossier/export?eid={eid}&format=json", timeout=5) as r:
                js_rep = json.loads(r.read().decode("utf-8"))
                self.assertIn("exported_at", js_rep)
                self.assertEqual(len(js_rep["osint_findings"]), 1)
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

    def test_step2_open_web_queries_and_article_context_extractor(self):
        """Step 2: Test Open-Web Comment/Post Identifier Hunting, Name+Context Matrix, and Deep Article Paragraph Extractor."""
        prof = SearchTargetProfile.from_raw(
            name="מתן שנער",
            emails=["matanshi@gmail.com"],
            phones=["0547283832"],
            orgs=["Shinar Cyber Ltd"],
            locations=["תל אביב"],
            relatives=["נועה שנער"],
        )

        # 1. Verify Open-Web query matrix (comment hunting + combinatorial Name + City/Org/Phone/Relative)
        ow_queries = build_open_web_queries(prof)
        ow_cats = {q["category"] for q in ow_queries}
        self.assertIn("social_comment", ow_cats)
        self.assertIn("open_web_article", ow_cats)
        joined_q = " || ".join(q["query"] for q in ow_queries)
        # Comment hunting queries for phone permutations & email
        self.assertIn('"054-7283832" OR "0547283832"', joined_q)
        self.assertIn('"matanshi@gmail.com"', joined_q)
        # Combinatorial Name + Context queries
        self.assertIn('"מתן שנער" "תל אביב"', joined_q)
        self.assertIn('"מתן שנער" "Shinar Cyber Ltd"', joined_q)
        self.assertIn('"מתן שנער" "נועה שנער"', joined_q)

        # 2. Verify Deep Article & Comment Content Extractor:
        #    - strips <nav>, <header>, <footer>, <aside>
        #    - extracts target paragraph TOGETHER WITH 1 paragraph before and 1 paragraph after
        #    - highlights matched identifiers with <mark class="osint-hl">...</mark>
        #    - runs NER/Regex to extract new phone, email, role, age, and org for the Pivot loop
        sample_article_html = """
        <html>
        <head><title>ראיון מיוחד עם מומחי סייבר בישראל</title></head>
        <body>
          <nav>תפריט ראשי | דף הבית | צור קשר | פרסומות</nav>
          <article>
            <p>פסקה 1 (לפני): כנס הסייבר השנתי נערך השבוע במרכז הכנסים בתל אביב בהשתתפות מאות חוקרים.</p>
            <p>פסקה 2 (היעד): במהלך המושב המרכזי הציג מתן שנער, בן 34, מנכ"ל ב-Aegis Cyber Defense Ltd, מחקר חדש. ניתן ליצור קשר בטלפון 052-9988776 או במייל matanshi@gmail.com לפרטים נוספים.</p>
            <p>פסקה 3 (אחרי): בסיום ההרצאה נערך פאנל שאלות ותשובות שעסק בהגנה על תשתיות קריטיות.</p>
            <figure>
              <img src="https://news.example.co.il/images/matan_shinar_keynote.jpg" alt="מתן שנער בכנס הסייבר בתל אביב" width="640" height="480"/>
              <figcaption>מתן שנער נואם בכנס הסייבר השנתי</figcaption>
            </figure>
          </article>
          <footer>כל הזכויות שמורות 2026 | תקנון האתר</footer>
        </body>
        </html>
        """
        extracted = extract_article_context_and_entities(
            sample_article_html,
            "https://news.example.co.il/cyber-conference-2026",
            prof,
            fallback_title="ראיון מיוחד",
        )
        # Must NOT include nav/footer noise
        self.assertNotIn("תפריט ראשי", extracted["context_text"])
        self.assertNotIn("כל הזכויות שמורות", extracted["context_text"])

        # Must include 1 paragraph before, the target paragraph, and 1 paragraph after
        self.assertIn("פסקה 1 (לפני): כנס הסייבר השנתי", extracted["context_text"])
        self.assertIn("פסקה 2 (היעד): במהלך המושב המרכזי הציג מתן שנער", extracted["context_text"])
        self.assertIn("פסקה 3 (אחרי): בסיום ההרצאה נערך פאנל", extracted["context_text"])

        # Highlighted HTML must wrap matched identifiers in <mark class="osint-hl">
        self.assertIn('<mark class="osint-hl">מתן שנער</mark>', extracted["highlighted_html"])
        self.assertIn('<mark class="osint-hl">matanshi@gmail.com</mark>', extracted["highlighted_html"])

        # NER / Regex entities extracted from the article window for Layer 7 Pivot
        ents = extracted["extracted_entities"]
        self.assertIn("052-9988776", ents["phones"])
        self.assertIn("34", ents["ages"])
        self.assertTrue(any("Aegis Cyber Defense" in o for o in ents["orgs"]))

        # In-article image candidate (Source B) must be harvested with caption
        self.assertEqual(len(extracted["candidate_images"]), 1)
        cand_img = extracted["candidate_images"][0]
        self.assertEqual(cand_img["image_url"], "https://news.example.co.il/images/matan_shinar_keynote.jpg")
        self.assertEqual(cand_img["source_type"], "article_image")
        self.assertIn("מתן שנער", cand_img["caption"])

    def test_step3_layer6_image_recon_face_verification_and_persistence(self):
        """Step 3: Test Layer 6 Target Image & Visual Recon Engine (Sources A/B/C, logo/<80x80 filter, face check, DB & avatar serving)."""
        now = time.time()
        eid = self.store.resolve_entity("person", "מתן שנער", "מתן שנער", now, fuzzy=False)
        prof = SearchTargetProfile.from_raw(
            name="מתן שנער",
            emails=["matanshi@gmail.com"],
            phones=["0547283832"],
            entity_id=eid,
        )

        # 1. Verify logo / icon / SVG / placeholder URL filter
        self.assertTrue(is_noise_or_logo_image("https://site.co.il/assets/site-logo.png"))
        self.assertTrue(is_noise_or_logo_image("https://site.co.il/icons/share-icon.svg"))
        self.assertTrue(is_noise_or_logo_image("https://www.gravatar.com/avatar/000?d=identicon"))
        self.assertTrue(is_noise_or_logo_image("https://site.co.il/photo.jpg", width=48, height=48))
        self.assertFalse(is_noise_or_logo_image("https://cdn.example.com/profiles/matan_shinar.jpg", alt="Matan Shinar", width=400, height=400))

        # 2. Construct valid PNG bytes:
        #    - a tiny 32x32 PNG icon (must be rejected as < 80x80)
        #    - a 200x200 PNG without a face (must have face_detected=False)
        #    - a 240x240 PNG with human face (verified via OpenCV / synthetic face marker)
        def make_png_bytes(width: int, height: int, payload: bytes = b"") -> bytes:
            header = (
                b"\x89PNG\r\n\x1a\n"
                + b"\x00\x00\x00\rIHDR"
                + width.to_bytes(4, "big")
                + height.to_bytes(4, "big")
                + b"\x08\x02\x00\x00\x00"
            )
            return header + b"\x00" * 64 + payload

        tiny_png = make_png_bytes(32, 32, b"OSNIT_SYNTHETIC_FACE")
        no_face_png = make_png_bytes(200, 200, b"LANDSCAPE_BUILDING_IMAGE")
        valid_face_png = make_png_bytes(240, 240, b"OSNIT_SYNTHETIC_FACE")

        res_tiny = verify_human_face_in_image(tiny_png)
        self.assertFalse(res_tiny["valid_size"], "Images smaller than 80x80 must be rejected")
        self.assertFalse(res_tiny["face_detected"])

        res_no_face = verify_human_face_in_image(no_face_png)
        self.assertTrue(res_no_face["valid_size"])
        self.assertFalse(res_no_face["face_detected"])

        res_face = verify_human_face_in_image(valid_face_png)
        self.assertTrue(res_face["valid_size"])
        self.assertTrue(res_face["face_detected"])
        self.assertEqual(res_face["width"], 240)
        self.assertEqual(res_face["height"], 240)

        # 3. Test Layer 6 across Source A (direct_avatar), Source B (article_image), and Source C (search_image)
        prior_findings = [
            # Source A: Direct avatar from GitHub / Telegram
            {
                "category": "code_intel",
                "source_tool": "github",
                "title": "פרופיל GitHub: matanshi (Matan Shinar)",
                "url": "https://github.com/matanshi",
                "confidence": 0.92,
                "extracted_data": {
                    "avatar_url": "https://avatars.githubusercontent.com/u/424242?v=4",
                },
            },
            # Source B: In-article image harvested during Layer 5 article scraping
            {
                "category": "open_web_article",
                "source_tool": "article_scraper",
                "title": "כתבה: מתן שנער בכנס הסייבר",
                "url": "https://news.example.co.il/article/100",
                "confidence": 0.85,
                "extracted_data": {
                    "candidate_images": [
                        {
                            "image_url": "https://news.example.co.il/img/matan_shinar_stage.png",
                            "source_page_url": "https://news.example.co.il/article/100",
                            "source_type": "article_image",
                            "caption": "מתן שנער בכנס הסייבר",
                            "matched_token": "מתן שנער",
                            "confidence": 0.84,
                        },
                        # Also include a tiny icon that must be filtered out
                        {
                            "image_url": "https://news.example.co.il/img/tiny_badge.png",
                            "source_page_url": "https://news.example.co.il/article/100",
                            "source_type": "article_image",
                            "caption": "מתן שנער",
                            "matched_token": "מתן שנער",
                            "confidence": 0.65,
                        },
                    ],
                },
            },
        ]

        async def mock_img_http(url, headers=None):
            # Source C: Bing Images search page returning a photo of Matan Shinar
            if "bing.com/images/search" in url:
                bing_html = """
                <html><body>
                <a class="iusc" m='{"murl":"https://cdn.conference.org/speakers/matan-shinar-portrait.png","purl":"https://conference.org/speakers/matan-shinar","t":"Matan Shinar - Keynote Speaker"}'></a>
                <a class="iusc" m='{"murl":"https://cdn.conference.org/assets/site-logo.png","purl":"https://conference.org","t":"Site Logo"}'></a>
                </body></html>
                """
                return 200, bing_html, {}
            return 404, "", {}

        async def mock_bytes_fetcher(url, timeout=8.0):
            if "avatars.githubusercontent.com" in url:
                return 200, valid_face_png, "image/png"
            if "matan_shinar_stage.png" in url:
                return 200, valid_face_png, "image/png"
            if "matan-shinar-portrait.png" in url:
                return 200, valid_face_png, "image/png"
            if "tiny_badge.png" in url:
                return 200, tiny_png, "image/png"
            return 404, b"", ""

        img_findings = asyncio.run(
            run_layer6_image_recon(
                prof,
                prior_findings,
                store=self.store,
                http_fetcher=mock_img_http,
                bytes_fetcher=mock_bytes_fetcher,
            )
        )

        # Verify all 3 valid images (Source A, Source B, Source C) were verified & saved, and tiny_badge/logo were rejected!
        self.assertEqual(len(img_findings), 3)
        source_types = {f["extracted_data"]["source_type"] for f in img_findings}
        self.assertEqual(source_types, {"direct_avatar", "article_image", "search_image"})
        for f in img_findings:
            self.assertEqual(f["category"], "target_image")
            self.assertTrue(f["extracted_data"]["face_detected"])
            self.assertTrue(os.path.exists(f["extracted_data"]["local_path"]))

        # Verify SQLite entity_images table and primary_avatar selection
        db_images = self.store.entity_images_for([eid])
        self.assertEqual(len(db_images), 3)
        primary = self.store.primary_avatar_for([eid])
        self.assertIsNotNone(primary)
        self.assertEqual(primary["source_type"], "direct_avatar")
        self.assertTrue(primary["face_detected"])

        # Verify Dossier includes images and primary_avatar
        dos = dossier(self.store, eid=eid)
        self.assertEqual(len(dos["images"]), 3)
        self.assertIsNotNone(dos["primary_avatar"])
        self.assertEqual(dos["primary_avatar"]["image_url"], "https://avatars.githubusercontent.com/u/424242?v=4")

    def test_unified_search_and_ui_endpoints(self):
        """Test unified entity search across /api/overview, /api/contacts, /api/entities, /api/find, /api/search, and /api/subjects/<id>."""
        from urllib.parse import quote
        from urllib.request import Request
        from osnit.engine import Engine

        now = time.time()
        src, _ = self.store.add_source("file://local/contacts_test.csv", origin="file", now=now)
        self.store.update_source(src, title="contacts_test.csv", state="imported", kind="file")
        eid = self.store.resolve_entity("person", "יפתח שביט", "יפתח שביט", now, fuzzy=False)
        pid = self.store.resolve_entity("phone", "+972549777235", "+972549777235", now, fuzzy=False)
        emid = self.store.resolve_entity("email", "yshavit@gmail.com", "yshavit@gmail.com", now, fuzzy=False)
        self.store.add_evidence(eid, src, "יפתח שביט - 054-9777235", 0.95, now)
        rel_p = self.store.add_relation(eid, pid, "has_phone", now)
        self.store.add_rel_evidence(rel_p, src, "054-9777235", 0.95, now)
        rel_e = self.store.add_relation(eid, emid, "has_email", now)
        self.store.add_rel_evidence(rel_e, src, "yshavit@gmail.com", 0.95, now)
        self.store.add_attribute(eid, src, "telecom_carrier", "Partner / Orange", "observed", now)
        self.store.add_osint_finding(
            entity_id=eid,
            category="email_breach",
            source_tool="xposedornot",
            title="דליפת מייל (XposedOrNot): yshavit@gmail.com",
            summary="נמצא במאגר הדליפות של Canva",
            url="https://xposedornot.com",
            confidence=0.92,
        )

        cfg = Config(db_path=self.db_path)
        svc = SearchService(Engine(self.store, cfg, providers={}))
        srv = make_server(svc, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        serve_in_thread(srv)
        base = f"http://127.0.0.1:{port}"
        try:
            # 1. /api/overview includes osint_count and phones
            with urlopen(f"{base}/api/overview", timeout=5) as r:
                ov = json.loads(r.read().decode("utf-8"))
                person_row = next(x for x in ov["entities"] if x["id"] == eid)
                self.assertEqual(person_row["osint_count"], 1)
                self.assertIn("+972549777235", person_row["phones"])

            # 2. /api/contacts by phone and bilingual name
            with urlopen(f"{base}/api/contacts?q=054-9777235", timeout=5) as r:
                c_phone = json.loads(r.read().decode("utf-8"))
                self.assertEqual(len(c_phone["rows"]), 1)
                self.assertEqual(c_phone["rows"][0]["id"], eid)
                self.assertEqual(c_phone["rows"][0]["osint_count"], 1)

            with urlopen(f"{base}/api/contacts?q={quote('Yiftach Shavit')}", timeout=5) as r:
                c_en = json.loads(r.read().decode("utf-8"))
                self.assertTrue(any(row["id"] == eid for row in c_en["rows"]))

            # 3. /api/entities by bilingual name and by OSINT finding tool
            with urlopen(f"{base}/api/entities?q={quote('Yiftach Shavit')}", timeout=5) as r:
                e_en = json.loads(r.read().decode("utf-8"))
                self.assertTrue(any(row["id"] == eid and row["osint_count"] == 1 for row in e_en))

            with urlopen(f"{base}/api/entities?q=XposedOrNot", timeout=5) as r:
                e_osint = json.loads(r.read().decode("utf-8"))
                self.assertTrue(any(row["id"] == eid for row in e_osint))

            # 4. /api/find multi-vector search includes osint_count, phones, emails
            req_find = Request(
                f"{base}/api/find",
                data=json.dumps({"name": "יפתח שביט"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req_find, timeout=5) as r:
                mf = json.loads(r.read().decode("utf-8"))
                self.assertTrue(len(mf["results"]) >= 1)
                self.assertEqual(mf["results"][0]["osint_count"], 1)
                self.assertIn("+972549777235", mf["results"][0]["phones"])

            # 5. /api/search -> /api/subjects/<id> returns entity_id, osint_findings, grouped_identities
            req_sr = Request(
                f"{base}/api/search",
                data=json.dumps({"query": "יפתח שביט"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req_sr, timeout=5) as r:
                sr = json.loads(r.read().decode("utf-8"))
                sid = sr["subject_id"]
            with urlopen(f"{base}/api/subjects/{sid}", timeout=5) as r:
                prof = json.loads(r.read().decode("utf-8"))
                self.assertEqual(prof["entity_id"], eid)
                self.assertEqual(len(prof["osint_findings"]), 1)
                self.assertTrue(len(prof["grouped_identities"]["phones"]) >= 1)
                self.assertTrue(len(prof["grouped_identities"]["emails"]) >= 1)
                self.assertTrue(len(prof["grouped_identities"]["attributes"]) >= 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_high_scale_anchor_guard_and_nonblocking_reindex(self):
        """Verify high-cardinality shared anchors (>60 relations) do not explode dossier/entity_detail/connections and reindex_names(blocking=False) yields when _wlock is held."""
        import threading
        from osnit.identity import dossier
        from osnit.linking import connections
        from osnit.server import entity_detail

        now = time.time()
        src_id, _ = self.store.add_source("https://example.org/city-directory", origin="web", now=now)
        self.store.update_source(src_id, title="City Directory", state="scanned", kind="page")
        city_id = self.store.resolve_entity("address", "תל אביב", "תל אביב", now, fuzzy=False)
        target_id = self.store.resolve_entity("person", "יפתח שביט", "יפתח שביט", now, fuzzy=False)
        phone_id = self.store.resolve_entity("phone", "+972549777235", "+972549777235", now, fuzzy=False)
        r_city = self.store.add_relation(target_id, city_id, "located_at", now)
        self.store.add_rel_evidence(r_city, src_id, "Lives in Tel Aviv", 0.9, now)
        r_phone = self.store.add_relation(target_id, phone_id, "has_phone", now)
        self.store.add_rel_evidence(r_phone, src_id, "Personal mobile", 0.95, now)

        # Link 80 other people to the same high-cardinality city anchor
        for i in range(80):
            pid = self.store.resolve_entity("person", f"תושב מספר {i}", f"תושב מספר {i}", now, fuzzy=False)
            rc = self.store.add_relation(pid, city_id, "located_at", now)
            self.store.add_rel_evidence(rc, src_id, f"Resident {i}", 0.8, now)

        # 1. connections(store, target_id) skips the >60 degree city anchor
        t0 = time.perf_counter()
        conn_res = connections(self.store, target_id)
        dt_conn = time.perf_counter() - t0
        self.assertLess(dt_conn, 1.0)
        self.assertEqual(len(conn_res["shared"]), 0)

        # 2. dossier(store, eid=target_id) skips back-fanout on the >60 degree anchor and finishes quickly
        t0 = time.perf_counter()
        dos = dossier(self.store, eid=target_id)
        dt_dos = time.perf_counter() - t0
        self.assertLess(dt_dos, 1.0)
        self.assertEqual(len(dos["clusters"]), 1)

        # 3. entity_detail(store, target_id) finishes quickly
        t0 = time.perf_counter()
        ed = entity_detail(self.store, target_id)
        dt_ed = time.perf_counter() - t0
        self.assertLess(dt_ed, 1.0)
        self.assertIsNotNone(ed)
        self.assertEqual(ed["entity"]["id"], target_id)

        # 4. Non-blocking reindex_names returns 0 immediately if _wlock is held by another thread
        locked_evt = threading.Event()
        release_evt = threading.Event()

        def hold_lock():
            with self.store._wlock:
                locked_evt.set()
                release_evt.wait(timeout=5.0)

        th = threading.Thread(target=hold_lock, daemon=True)
        th.start()
        locked_evt.wait(timeout=2.0)
        try:
            t0 = time.perf_counter()
            res = self.store.reindex_names(100, blocking=False)
            dt_lock = time.perf_counter() - t0
            self.assertEqual(res, 0)
            self.assertLess(dt_lock, 0.2)
        finally:
            release_evt.set()
            th.join(timeout=2.0)

    def test_exact_match_phone_search_separates_same_name_clusters(self):
        """Verify searching a phone number belonging to a specific 'ברקת' keeps grouped_identities and exact_match strictly scoped to that exact 'ברקת' and separates other 'ברקת' clusters."""
        from osnit.contacts import contacts
        from osnit.engine import Engine

        now = time.time()
        src1, _ = self.store.add_source("file:///C:/data/voters_1.csv", origin="file", now=now)
        self.store.update_source(src1, title="voters_1.csv", state="scanned", kind="csv")
        src2, _ = self.store.add_source("file:///C:/data/other_2.csv", origin="file", now=now)
        self.store.update_source(src2, title="other_2.csv", state="scanned", kind="csv")

        # Exact target: נועה ברקת (record 1) with phone 052-8881111 and address רחוב הרצל 10 תל אביב
        p_exact = self.store.resolve_entity("person", "נועה ברקת", "נועה ברקת", now, fuzzy=False)
        ph_exact = self.store.resolve_entity("phone", "0528881111", "052-8881111", now, fuzzy=False)
        addr_exact = self.store.resolve_entity("address", "רחוב הרצל 10 תל אביב", "רחוב הרצל 10 תל אביב", now, fuzzy=False)
        self.store.add_evidence(p_exact, src1, "נועה ברקת | 052-8881111 | רחוב הרצל 10 תל אביב", 0.95, now)
        self.store.add_evidence(ph_exact, src1, "נועה ברקת | 052-8881111 | רחוב הרצל 10 תל אביב", 0.95, now)
        r1 = self.store.add_relation(p_exact, ph_exact, "has_phone", now)
        self.store.add_rel_evidence(r1, src1, "נועה ברקת | 052-8881111", 0.95, now)
        r2 = self.store.add_relation(p_exact, addr_exact, "located_at", now)
        self.store.add_rel_evidence(r2, src1, "נועה ברקת | רחוב הרצל 10 תל אביב", 0.95, now)
        self.store.add_attribute(p_exact, src1, "city", "תל אביב", "עיר", now)

        # Another person with the same name "נועה ברקת" (record 2) in a different city with a different phone
        p_other = self.store.resolve_entity("person", "נועה ברקת 2", "נועה ברקת", now, fuzzy=False)
        ph_other = self.store.resolve_entity("phone", "+972549992222", "054-9992222", now, fuzzy=False)
        addr_other = self.store.resolve_entity("address", "דרך יפו 55 חיפה", "דרך יפו 55 חיפה", now, fuzzy=False)
        self.store.add_evidence(p_other, src2, "נועה ברקת | 054-9992222 | דרך יפו 55 חיפה", 0.95, now)
        r3 = self.store.add_relation(p_other, ph_other, "has_phone", now)
        self.store.add_rel_evidence(r3, src2, "נועה ברקת | 054-9992222", 0.95, now)
        r4 = self.store.add_relation(p_other, addr_other, "located_at", now)
        self.store.add_rel_evidence(r4, src2, "נועה ברקת | דרך יפו 55 חיפה", 0.95, now)
        self.store.add_attribute(p_other, src2, "city", "חיפה", "עיר", now)

        # Search by phone "052-8881111" (which normalizes to +972528881111 while DB key is 0528881111)
        svc = SearchService(Engine(self.store, Config(db_path=self.db_path), providers={}))
        sr = svc.search("052-8881111")
        prof = sr["profile"]

        # 1. exact_match must point to p_exact ("נועה ברקת") and NOT include p_other's Haifa address or phone
        self.assertIn("exact_match", prof)
        exact = prof["exact_match"]
        self.assertTrue(exact["found"])
        self.assertEqual(exact["person_id"], p_exact)
        self.assertEqual(exact["person_name"], "נועה ברקת")

        addrs = [a["value"] for a in prof["grouped_identities"]["addresses"]]
        self.assertIn("רחוב הרצל 10 תל אביב", addrs)
        self.assertNotIn("דרך יפו 55 חיפה", addrs)

        phones = [p["value"] for p in prof["grouped_identities"]["phones"]]
        self.assertNotIn("054-9992222", phones)

        attr_vals = [a["value"] for a in prof["grouped_identities"]["attributes"]]
        self.assertIn("תל אביב", attr_vals)
        self.assertNotIn("חיפה", attr_vals)

        # 2. Clusters must mark p_exact's cluster as is_focus=True and p_other's cluster as is_focus=False
        focus_clusters = [c for c in prof["clusters"] if c.get("is_focus")]
        other_clusters = [c for c in prof["clusters"] if not c.get("is_focus")]
        self.assertEqual(len(focus_clusters), 1)
        self.assertIn(p_exact, focus_clusters[0]["person_ids"])
        self.assertEqual(len(other_clusters), 1)
        self.assertIn(p_other, other_clusters[0]["person_ids"])

        # 3. Verify contacts() phone lookup finds p_exact quickly via UNION ALL
        c_res = contacts(self.store, q="052-8881111")
        matched_ids = [r["id"] for r in c_res["rows"]]
        self.assertIn(p_exact, matched_ids)
        self.assertNotIn(p_other, matched_ids)


if __name__ == "__main__":
    unittest.main()
