"""
Phase 4 Real-World E2E Verification Suite:
Hebrew NER, Smart Entity Resolution & Kinship Graph (Entity Resolution & Kinship Inference)

Tests:
1. Advanced NER in Hebrew & English:
   - Full names (Hebrew, English, middle initials), 9-digit Israeli National IDs (with Luhn verification),
     mobile & landline phones in multiple formats (05X, +972, 03-), emails, street addresses + cities,
     birthdates, educational/work institutions, and military units (e.g. יחידה 8200 / Unit 8200).
2. Smart Entity Resolution & Cross-Script Merging:
   - Ingests a Hebrew certificate, an English CV ("Daniel J. Cohen"), and a database table ("דניאל יוסף כהן")
     for the same person alongside family members.
   - Verifies that all records of the subject unify into a single Dossier cluster (no duplicate split clusters),
     while relatives with distinct valid Luhn IDs remain separate entities linked via the kinship graph.
3. Explicit Kinship Extraction (Text & DB):
   - Verifies extraction of explicit family labels ("שם האב", "שם האם", "בת זוג", "אח", "איש קשר לחירום")
     from unstructured Hebrew/English documents and structured DB columns.
4. Heuristic Kinship Inference & Graph Edges:
   - Verifies automatic kinship detection between entities sharing a surname + residential address/city,
     shared landline phone, and sequential/proximate Israeli Luhn IDs, with confidence scores,
     Hebrew verbal explanations, and `kind="kinship"` edges in the Dossier graph.
"""
import os
import shutil
import sqlite3
import tempfile
import unittest

from osnit.extract import Extractor
from osnit.identity import dossier
from osnit.importqueue import ImportQueue
from osnit.semantic import il_id_ok
from tests import helpers


def _make_valid_id(prefix8: str) -> str:
    """Compute valid 9th Luhn check digit for an 8-digit prefix."""
    assert len(prefix8) == 8 and prefix8.isdigit()
    total = 0
    for i, ch in enumerate(prefix8):
        n = int(ch) * ((i % 2) + 1)
        total += n - 9 if n > 9 else n
    check = (10 - (total % 10)) % 10
    full = prefix8 + str(check)
    assert il_id_ok(full), f"Generated invalid ID: {full}"
    return full


class TestPhase4EntityKinship(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_phase4_")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.inbox = os.path.join(self.tmp_dir, "inbox")
        self.q = ImportQueue(self.eng, inbox=self.inbox)

    def tearDown(self):
        self.srv.shutdown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_1_advanced_hebrew_english_ner(self):
        """Verify extraction of names, Luhn IDs, phones, emails, addresses, birthdates, orgs, and military units."""
        valid_id = _make_valid_id("21695886")  # 216958868
        invalid_id = "216958861"               # fails Luhn check
        self.assertTrue(il_id_ok(valid_id))
        self.assertFalse(il_id_ok(invalid_id))

        sample_doc = f"""
        תיק אישי ומסמך אימות פרטים
        שם מלא: דניאל כהן
        מספר זהות: {valid_id}
        מספר שגוי לבדיקה: {invalid_id}
        תאריך לידה: 14/05/1995
        טלפון נייד: +972-54-888-9900
        טלפון נוסף: 052-3344556
        טלפון בבית: 03-6543210
        דוא"ל: daniel.cohen@cyberguard.co.il
        כתובת מגורים: רחוב הרצל 15, תל אביב
        מוסד לימודים: אוניברסיטת תל אביב
        השכלה נוספת: מכללת אורט תעופה וחלל
        שירות צבאי: יחידה 8200
        מקום עבודה: חברת סייברגארד בע"מ
        שם האב: אברהם כהן
        שם האם: שרה כהן
        בת זוג: מיכל כהן
        איש קשר לחירום: יונתן כהן
        """
        extractor = Extractor()
        ex = extractor.extract(sample_doc, title="אימות_פרטים.txt")

        # 1. Valid Luhn ID extracted, invalid Luhn ID rejected
        self.assertIn(("national_id", valid_id), ex.ents)
        self.assertNotIn(("national_id", invalid_id), ex.ents)

        # 2. Phones normalized to +972 format (mobile + landline)
        self.assertIn(("phone", "+972548889900"), ex.ents)
        self.assertIn(("phone", "+972523344556"), ex.ents)
        self.assertIn(("phone", "+97236543210"), ex.ents)

        # 3. Email extracted
        self.assertIn(("email", "daniel.cohen@cyberguard.co.il"), ex.ents)

        # 4. Street address extracted
        addresses = [v["display"] for (t, k), v in ex.ents.items() if t == "address"]
        self.assertTrue(any("הרצל 15" in a for a in addresses), f"Addresses found: {addresses}")

        # 5. Orgs & military units extracted
        orgs = [v["display"] for (t, k), v in ex.ents.items() if t == "org"]
        self.assertTrue(any("אוניברסיטת תל אביב" in o for o in orgs), f"Orgs: {orgs}")
        self.assertTrue(any("מכללת אורט תעופה וחלל" in o for o in orgs), f"Orgs: {orgs}")
        self.assertTrue(any("8200" in o for o in orgs), f"Orgs: {orgs}")
        self.assertTrue(any("סייברגארד" in o for o in orgs), f"Orgs: {orgs}")

        # 6. Birthdate & city attributes extracted
        attr_kinds = {a[3]: a[2] for a in ex.attrs}
        self.assertIn("birthdate", attr_kinds)
        self.assertIn("14/05/1995", attr_kinds["birthdate"])
        self.assertIn("city", attr_kinds)

        # 7. Primary person is Daniel Cohen, and explicit kinship links exist to relatives
        kin_links = [(a, b, kind) for (a, b, kind) in ex.links if kind.startswith("kinship:")]
        self.assertGreaterEqual(len(kin_links), 4, f"Expected >=4 kinship links, got: {kin_links}")

    def test_2_and_3_and_4_multi_source_entity_resolution_and_kinship_graph(self):
        """
        End-to-End Intelligence Scenario:
        Ingests 3 separate files across Hebrew, English, and SQLite DB for the same subject ("דניאל כהן" / "Daniel J. Cohen")
        and his family members ("אברהם כהן", "שרה כהן", "יונתן כהן", "מיכל כהן").
        Verifies:
        1. All records of Daniel Cohen merge into 1 unified Dossier cluster (zero duplicate split clusters).
        2. Family members with distinct IDs are NOT merged into Daniel's cluster.
        3. Both explicit kinship (from text & DB columns) and heuristic kinship (shared surname + address + landline + sequential IDs)
           are accurately inferred with confidence scores, Hebrew explanations, and graph edges.
        """
        daniel_id = _make_valid_id("03999999")   # 039999990
        yonatan_id = _make_valid_id("03999998")  # 039999982 (proximate/sequential ID, delta = 8)
        avraham_id = _make_valid_id("01234567")  # 012345674

        # File 1: Hebrew Study & Security Clearance Certificate (Text/Document)
        hebrew_cert = f"""אישור לימודים ופרטים אישיים - אוניברסיטת תל אביב
שם מלא: דניאל כהן
מספר זהות: {daniel_id}
תאריך לידה: 14/05/1995
טלפון נייד: 054-8889900
טלפון נייח: 03-6543210
כתובת מגורים: רחוב הרצל 15, תל אביב
יחידה צבאית: יחידה 8200
שם האב: אברהם כהן
שם האם: שרה כהן
איש קשר לחירום: מיכל כהן
"""
        self.q.add_bytes(hebrew_cert.encode("utf-8"), "hebrew_certificate.txt")

        # File 2: English Resume / CV with middle initial ("Daniel J. Cohen")
        english_cv = """CURRICULUM VITAE
Daniel J. Cohen
Software & Cyber Security Lead
Phone: +972-54-888-9900
Email: daniel.cohen@cyberguard.co.il
Education: Tel Aviv University
Military Service: Unit 8200
Experience: CyberGuard Ltd
"""
        self.q.add_bytes(english_cv.encode("utf-8"), "Daniel_Cohen_CV.txt")

        # File 3: SQLite Municipal / HR Database containing Daniel (with middle name) and his family members
        db_path = os.path.join(self.tmp_dir, "population_registry.sqlite")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE citizens (
                full_name TEXT,
                national_id TEXT,
                mobile_phone TEXT,
                home_phone TEXT,
                address TEXT,
                city TEXT,
                email TEXT,
                spouse_name TEXT,
                father_name TEXT,
                emergency_phone TEXT
            )
        """)
        cur.executemany(
            "INSERT INTO citizens VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                # Subject record with middle name
                ("דניאל יוסף כהן", daniel_id, "0548889900", "03-6543210", "רחוב הרצל 15, תל אביב", "תל אביב",
                 "daniel.cohen@cyberguard.co.il", "מיכל כהן", "אברהם כהן", "052-7771111"),
                # Brother living at the same address, sharing landline, with sequential/proximate National ID
                ("יונתן כהן", yonatan_id, "054-1112233", "03-6543210", "רחוב הרצל 15, תל אביב", "תל אביב",
                 "yonatan.c@gmail.com", "", "אברהם כהן", ""),
                # Father living in the same city and sharing family name
                ("אברהם כהן", avraham_id, "050-9998877", "03-6543210", "רחוב הרצל 15, תל אביב", "תל אביב",
                 "avraham.cohen@walla.co.il", "שרה כהן", "", ""),
            ],
        )
        conn.commit()
        conn.close()
        with open(db_path, "rb") as f:
            self.q.add_bytes(f.read(), "population_registry.sqlite")

        # Process all 3 files through the import queue
        processed = self.q.run_pending()
        self.assertEqual(processed, 3)

        # Build Dossier for "דניאל כהן"
        d_heb = dossier(self.store, name="דניאל כהן")
        print("\n=== [PHASE 4 DOSSIER CLUSTERS] ===")
        for c in d_heb["clusters"]:
            print(f"Cluster #{c['n']}: names={c['names']}, records={len(c['records'])}, files={c['files']}")
        print("=== [PHASE 4 KINSHIP GRAPH] ===")
        for k in d_heb.get("kinship", []):
            print(f" -> {k['name']} | {k['relation']} | conf={k['confidence']} | type={k['evidence_type']} | {k['reason']}")

        # 1. Verify Entity Resolution: All 3 records ("דניאל כהן", "Daniel J. Cohen", "דניאל יוסף כהן")
        #    MUST be unified into a single primary cluster!
        self.assertEqual(
            len(d_heb["clusters"]), 1,
            f"Expected all records of Daniel Cohen to unify into 1 cluster, got {len(d_heb['clusters'])}: {d_heb['clusters']}"
        )
        c1 = d_heb["clusters"][0]
        cluster_names = set(c1["names"])
        self.assertTrue(any("דניאל" in n for n in cluster_names), f"Missing Hebrew name in {cluster_names}")
        self.assertTrue(any("Daniel" in n for n in cluster_names), f"Missing English name in {cluster_names}")
        self.assertGreaterEqual(len(c1["files"]), 3, f"Expected evidence from all 3 files, got {c1['files']}")

        # Verify relatives with different National IDs were NOT merged into Daniel's cluster
        self.assertFalse(any("יונתן" in n for n in cluster_names), "Brother Yonatan must not merge into Daniel's cluster")
        self.assertFalse(any("אברהם" in n for n in cluster_names), "Father Avraham must not merge into Daniel's cluster")

        # Verify English query ("Daniel Cohen") produces the exact same unified cluster
        d_eng = dossier(self.store, name="Daniel Cohen")
        self.assertEqual(len(d_eng["clusters"]), 1)
        self.assertEqual(set(d_eng["clusters"][0]["names"]), cluster_names)

        # 2. Verify Kinship Inference (Explicit + Heuristic)
        kinship_list = d_heb.get("kinship", [])
        self.assertGreaterEqual(len(kinship_list), 4, f"Expected at least 4 relatives in kinship list, got {kinship_list}")
        kin_by_name = {k["name"]: k for k in kinship_list}

        # Check explicit & combined relatives: אברהם כהן (Father), שרה כהן (Mother), מיכל כהן (Spouse)
        self.assertIn("אברהם כהן", kin_by_name)
        self.assertIn("שרה כהן", kin_by_name)
        self.assertIn("מיכל כהן", kin_by_name)
        self.assertGreaterEqual(kin_by_name["אברהם כהן"]["confidence"], 0.9)
        self.assertIn("אב", kin_by_name["אברהם כהן"]["relation"])
        self.assertIn("אם", kin_by_name["שרה כהן"]["relation"])

        # Check heuristic kinship: יונתן כהן (Shared surname + shared street address + shared landline + proximate Luhn ID)
        self.assertIn("יונתן כהן", kin_by_name)
        yonatan_kin = kin_by_name["יונתן כהן"]
        self.assertGreaterEqual(yonatan_kin["confidence"], 0.85)
        self.assertIn("שם משפחה זהה", yonatan_kin["reason"])
        self.assertIn("כתובת מגורים משותפת", yonatan_kin["reason"])
        self.assertIn("טלפון נייח משותף", yonatan_kin["reason"])
        self.assertIn("ת\"ז עוקבים/קרובים", yonatan_kin["reason"])

        # 3. Verify Kinship Graph Edges in dossier["graph"]
        graph_edges = d_heb["graph"]["edges"]
        kinship_edges = [e for e in graph_edges if e.get("kind") == "kinship"]
        self.assertGreaterEqual(len(kinship_edges), 4, f"Expected >=4 kinship edges in graph, got {kinship_edges}")
        for ke in kinship_edges:
            self.assertTrue(ke.get("reason"), f"Kinship edge missing verbal explanation: {ke}")
            self.assertGreater(ke.get("w", 0), 0.5, f"Kinship edge confidence too low: {ke}")


if __name__ == "__main__":
    unittest.main()
