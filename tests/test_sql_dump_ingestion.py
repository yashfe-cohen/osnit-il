import tempfile
import unittest
from pathlib import Path

from osnit.config import Config
from osnit.engine import Engine
from osnit.extract import split_couple_names, norm_phone_il, extract_phone_from_identifier, extract_id_from_identifier
from osnit.identity import dossier
from osnit.importdb import import_db
from osnit.quality import is_dummy_name, is_dummy_value, is_empty_date, valid_national_id, valid_corporate_id
from osnit.store import Store
from osnit.xling import same_person_name


USERS_87_COL_SQL_DUMP = """-- MySQL dump 10.13  Distrib 5.7.42, for Linux (x86_64)
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*
  Multi-line header comment block with semicolons;
  Should be cleanly ignored by stream_sql_dump;
*/

CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_number` varchar(64) DEFAULT NULL,
  `user_login` varchar(120) DEFAULT NULL,
  `user_pass` varchar(255) DEFAULT NULL,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `user_contact` varchar(200) DEFAULT NULL,
  `user_email` varchar(190) DEFAULT NULL,
  `user_phone` varchar(50) DEFAULT NULL,
  `mobile_phone` varchar(50) DEFAULT NULL,
  `fax` varchar(50) DEFAULT NULL,
  `company_name` varchar(200) DEFAULT NULL,
  `company_number` varchar(50) DEFAULT NULL,
  `discount_number` varchar(64) DEFAULT NULL,
  `external_account_code` varchar(64) DEFAULT NULL,
  `street` varchar(150) DEFAULT NULL,
  `house_number` varchar(30) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `zip` varchar(20) DEFAULT NULL,
  `country` varchar(60) DEFAULT 'IL',
  `billing_first_name` varchar(100) DEFAULT NULL,
  `billing_last_name` varchar(100) DEFAULT NULL,
  `billing_company` varchar(150) DEFAULT NULL,
  `billing_address` varchar(255) DEFAULT NULL,
  `billing_city` varchar(100) DEFAULT NULL,
  `billing_zip` varchar(20) DEFAULT NULL,
  `billing_country` varchar(50) DEFAULT NULL,
  `billing_phone` varchar(50) DEFAULT NULL,
  `billing_email` varchar(190) DEFAULT NULL,
  `shipping_first_name` varchar(100) DEFAULT NULL,
  `shipping_last_name` varchar(100) DEFAULT NULL,
  `shipping_company` varchar(150) DEFAULT NULL,
  `shipping_address` varchar(255) DEFAULT NULL,
  `shipping_city` varchar(100) DEFAULT NULL,
  `shipping_zip` varchar(20) DEFAULT NULL,
  `shipping_country` varchar(50) DEFAULT NULL,
  `shipping_phone` varchar(50) DEFAULT NULL,
  `birth_date` date DEFAULT NULL,
  `gender` enum('M','F','U') DEFAULT 'U',
  `status` tinyint(1) NOT NULL DEFAULT '1',
  `is_vip` tinyint(1) NOT NULL DEFAULT '0',
  `newsletter` tinyint(1) NOT NULL DEFAULT '0',
  `sms_optin` tinyint(1) NOT NULL DEFAULT '0',
  `points_balance` decimal(10,2) DEFAULT '0.00',
  `credit_limit` decimal(12,2) DEFAULT '0.00',
  `total_orders` int(11) DEFAULT '0',
  `total_spent` decimal(12,2) DEFAULT '0.00',
  `last_order_date` datetime DEFAULT NULL,
  `registration_ip` varchar(45) DEFAULT NULL,
  `last_login_ip` varchar(45) DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `referer_url` varchar(255) DEFAULT NULL,
  `utm_source` varchar(100) DEFAULT NULL,
  `utm_medium` varchar(100) DEFAULT NULL,
  `utm_campaign` varchar(100) DEFAULT NULL,
  `affiliate_id` int(11) DEFAULT NULL,
  `sales_rep_id` int(11) DEFAULT NULL,
  `price_list_id` int(11) DEFAULT NULL,
  `tax_exempt` tinyint(1) DEFAULT '0',
  `payment_terms` varchar(50) DEFAULT NULL,
  `bank_code` varchar(10) DEFAULT NULL,
  `branch_code` varchar(10) DEFAULT NULL,
  `account_number` varchar(30) DEFAULT NULL,
  `cc_last4` varchar(4) DEFAULT NULL,
  `cc_token` varchar(128) DEFAULT NULL,
  `cc_exp` varchar(10) DEFAULT NULL,
  `notes` text,
  `internal_remarks` text,
  `delivery_instructions` text,
  `custom_field_1` varchar(100) DEFAULT NULL,
  `custom_field_2` varchar(100) DEFAULT NULL,
  `custom_field_3` varchar(100) DEFAULT NULL,
  `custom_field_4` varchar(100) DEFAULT NULL,
  `custom_field_5` varchar(100) DEFAULT NULL,
  `custom_field_6` varchar(100) DEFAULT NULL,
  `custom_field_7` varchar(100) DEFAULT NULL,
  `custom_field_8` varchar(100) DEFAULT NULL,
  `custom_field_9` varchar(100) DEFAULT NULL,
  `custom_field_10` varchar(100) DEFAULT NULL,
  `legacy_id` varchar(50) DEFAULT NULL,
  `sync_status` varchar(20) DEFAULT NULL,
  `synced_at` datetime DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `updated_by` int(11) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES
(5, 'USR-005', 'moshec100', 'e10adc3949ba59abbe56e057f20f883e', 'משה', 'כהן', 'משה כהן', 'moshec100@walla.com', '054-4545879', NULL, NULL, NULL, NULL, '053445227', NULL, 'הרצל', '18', 'ראשון לציון', '7526000', 'IL', 'משה', 'כהן', NULL, 'הרצל 18', 'ראשון לציון', '7526000', 'IL', '0544545879', 'moshec100@walla.com', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '1981-04-12', 'M', 1, 1, 1, 1, 120.50, 5000.00, 8, 3400.00, '2025-11-10 14:22:00', '84.108.22.11', '84.108.22.11', '2025-11-10 14:20:00', 'Mozilla/5.0', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'לקוח ותיק', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'ok', '2025-11-10 14:22:00', 1, 1, '2022-01-15 09:00:00', '2025-11-10 14:22:00'),
(7, 'USR-007', 'sarit_m', NULL, 'שרית', 'מזרחי', 'שרית מזרחי', '0526201912sarit@gmail.com', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'ויצמן', '42', 'כפר סבא', '4420100', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '0000-00-00', 'F', 1, 0, 0, 0, 0.00, 0.00, 1, 250.00, '0000-00-00 00:00:00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '0000-00-00 00:00:00', NULL, NULL, '2023-05-20 11:30:00', '0000-00-00 00:00:00'),
(11, 'USR-011', '013279476@bezeqint.net', NULL, 'רחל', 'וקנין', 'רחל וקנין', '013279476@bezeqint.net', '08-6421122', NULL, NULL, NULL, NULL, NULL, NULL, 'בן גוריון', '9', 'באר שבע', '8410000', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'F', 1, 0, 0, 0, 0.00, 0.00, 2, 410.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2023-07-01 10:00:00', '2023-07-01 10:00:00'),
(15, 'USR-015', 'levin_fam', NULL, 'דבורה וישראל', 'לבין', 'דבורה וישראל לבין', 'levin.family@gmail.com', '050-7654321', NULL, NULL, NULL, NULL, '039994256', NULL, 'ז''בוטינסקי', '55', 'רמת גן', '5252100', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'U', 1, 0, 0, 0, 0.00, 0.00, 3, 980.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2023-08-11 16:45:00', '2023-08-11 16:45:00'),
(20, 'USR-020', 'itzik_l', NULL, 'איציק', 'לוי', 'איציק לוי', 'itzik@levi-log.co.il', '052-3344556', NULL, NULL, 'לוי לוגיסטיקה בע"מ', '514521384', '514521384', NULL, 'המסגר', '12', 'תל אביב', '6777612', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'M', 1, 1, 0, 0, 0.00, 10000.00, 15, 22400.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2023-09-01 08:15:00', '2023-09-01 08:15:00'),
(25, 'USR-025', 'avinoam1', NULL, 'אבינועם', 'הכהן', 'אבינועם הכהן', 'avinoam.h@gmail.com', '053-8889900', NULL, NULL, NULL, NULL, '039199047', NULL, 'הנשיא', '4', 'חדרה', '3820200', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'M', 1, 0, 0, 0, 0.00, 0.00, 1, 150.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2024-01-10 12:00:00', '2024-01-10 12:00:00'),
(26, 'USR-026', 'avinoam2', NULL, 'אבינועם', 'הכהן', 'אבינועם הכהן', 'avinoam.h@gmail.com', '053-8889900', '050-9112233', NULL, NULL, NULL, '039199047', NULL, 'הנשיא', '4', 'חדרה', '3820200', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'M', 1, 0, 0, 0, 0.00, 0.00, 4, 890.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2024-03-14 15:20:00', '2024-03-14 15:20:00'),
(30, 'USR-030', 'ariel_he', NULL, 'אריאל', 'אדר', 'אריאל אדר', 'ariel.adar@example.co.il', '054-6112233', NULL, NULL, NULL, NULL, NULL, NULL, 'הפלמ"ח', '21', 'ירושלים', '9258300', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'M', 1, 0, 0, 0, 0.00, 0.00, 2, 500.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2024-05-01 10:00:00', '2024-05-01 10:00:00'),
(31, 'USR-031', 'ariel_en', NULL, 'Ariel', 'Adar', 'Ariel Adar', 'ariel.adar@example.co.il', '054-6112233', NULL, NULL, NULL, NULL, NULL, NULL, 'הפלמ"ח', '21', 'ירושלים', '9258300', 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'M', 1, 0, 0, 0, 0.00, 0.00, 1, 300.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2024-05-02 10:00:00', '2024-05-02 10:00:00'),
(99, 'USR-099', 'test', NULL, 'test', 'user', 'test user', 'test@test.com', '0000000000', '123456789', NULL, NULL, NULL, '000000000', NULL, NULL, NULL, NULL, NULL, 'IL', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '0000-00-00', 'U', 0, 0, 0, 0, 0.00, 0.00, 0, 0.00, '0000-00-00 00:00:00', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '0000-00-00 00:00:00', NULL, NULL, '0000-00-00 00:00:00', '0000-00-00 00:00:00');
"""


SINGLE_QUOTED_VOTER_CSV = """'o','First Name','Last Name','Tehudat Zhut','Phone','Address','s','t','Voted','City ID'
'10809','סאלם','אבו גווייעד','324841485','505495072','שבט אבו ג'ווייעד ','0',' )שבט אבו ג'ווייעד( 0','שבט אבו ג'ווייעד ''','0','1290'
'10810','מוחמד','אבו גווייעד','24486250','523344556','שבט אבו ג'ווייעד ','0',' )שבט אבו ג'ווייעד( 0','שבט אבו ג'ווייעד ''','1','1290'
'10811','יוסף','כהן','039994256','547681313','הרצל 10','0','','','1','5000'
"""


class TestSQLDumpAndDynamicIngestion(unittest.TestCase):
    def test_unit_helpers_phones_ids_couples_and_dummies(self):
        # 1. Missing leading zero mobile phone normalization
        self.assertIsNone(norm_phone_il("505495072", allow_missing_zero=False))
        self.assertEqual(norm_phone_il("505495072", allow_missing_zero=True), "+972505495072")
        self.assertEqual(norm_phone_il("523344556", allow_missing_zero=True), "+972523344556")

        # 2. Embedded phone & Israeli ID inside email local-parts / usernames
        self.assertEqual(extract_phone_from_identifier("0526201912sarit@gmail.com"), "+972526201912")
        self.assertEqual(extract_id_from_identifier("013279476@bezeqint.net"), "013279476")
        # Mobile prefix should not be mistaken for national ID in email local-part
        self.assertIsNone(extract_id_from_identifier("0526201912sarit@gmail.com"))

        # 3. Couple splitting
        self.assertEqual(split_couple_names("דבורה וישראל", "לבין"), ("דבורה לבין", "ישראל לבין"))
        self.assertEqual(split_couple_names("שרה ואברהם", "כהן"), ("שרה כהן", "אברהם כהן"))
        self.assertIsNone(split_couple_names("משה", "כהן"))

        # 4. Cross-script transliteration matching
        self.assertTrue(same_person_name("אריאל אדר", "Ariel Adar"))

        # 5. Dummy & empty date filtering
        self.assertTrue(is_empty_date("0000-00-00"))
        self.assertTrue(is_empty_date("0000-00-00 00:00:00"))
        self.assertTrue(is_dummy_name("test user"))
        self.assertTrue(is_dummy_value("test@test.com"))
        self.assertTrue(is_dummy_value("0000000000"))

        # 6. 7-9 digit Luhn national ID & corporate ID validation
        self.assertTrue(valid_national_id("053445227"))
        self.assertTrue(valid_national_id("324841485"))
        self.assertTrue(valid_national_id("24486250"))  # 8-digit valid ID -> 024486250
        self.assertTrue(valid_corporate_id("514521384"))

    def test_87_column_sql_dump_e2e_ingestion(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp_path = Path(tmp)
            sql_file = tmp_path / "users_dump.sql"
            sql_file.write_text(USERS_87_COL_SQL_DUMP, encoding="utf-8")

            db_path = str(tmp_path / "osnit.db")
            store = Store(db_path)
            eng = Engine(store, Config(db_path=db_path))
            try:
                res = import_db(eng, str(sql_file))
                self.assertGreaterEqual(res["records"], 9)

                persons = store.q("SELECT * FROM entities WHERE type='person'")
                person_names = {p["display"] for p in persons}

                # Row 5: משה כהן with discount_number='053445227' -> national_id 053445227
                self.assertIn("משה כהן", person_names)
                nat_ids = {e["key"]: e for e in store.q("SELECT * FROM entities WHERE type='national_id'")}
                self.assertIn("053445227", nat_ids, "discount_number '053445227' must be extracted as national_id")

                # Row 7: שרית מזרחי with embedded phone in 0526201912sarit@gmail.com
                self.assertIn("שרית מזרחי", person_names)
                phones = {e["key"]: e for e in store.q("SELECT * FROM entities WHERE type='phone'")}
                self.assertIn("+972526201912", phones, "Phone embedded in 0526201912sarit@gmail.com must be extracted")

                # Row 11: רחל וקנין with embedded ID in 013279476@bezeqint.net
                self.assertIn("רחל וקנין", person_names)
                self.assertIn("013279476", nat_ids, "ID embedded in 013279476@bezeqint.net must be extracted")

                # Row 15: Couple splitting 'דבורה וישראל' + 'לבין' -> 'דבורה לבין' & 'ישראל לבין' with spouse link
                self.assertIn("דבורה לבין", person_names)
                self.assertIn("ישראל לבין", person_names)
                dvora = next(p for p in persons if p["display"] == "דבורה לבין")
                yisrael = next(p for p in persons if p["display"] == "ישראל לבין")
                dvora_rels = store.q("SELECT * FROM relations WHERE a_id=? OR b_id=?", (dvora["id"], dvora["id"]))
                spouse_ids = {
                    (r["b_id"] if r["a_id"] == dvora["id"] else r["a_id"])
                    for r in dvora_rels if r["kind"] == "kinship:spouse"
                }
                self.assertIn(yisrael["id"], spouse_ids, "Split couple must be linked via kinship:spouse")

                # Row 20: איציק לוי with corporate ID 514521384 in company_number / discount_number
                self.assertIn("איציק לוי", person_names)
                orgs = {e["key"]: e for e in store.q("SELECT * FROM entities WHERE type='org'")}
                self.assertIn("il_company:514521384", orgs, "Corporate ID 514521384 must be extracted as org entity")

                # Rows 25 & 26: Duplicate אבינועם הכהן consolidated into a single person entity with both phones
                avinoam_list = [p for p in persons if p["display"] == "אבינועם הכהן"]
                self.assertEqual(len(avinoam_list), 1, "Duplicate אבינועם הכהן rows must merge into 1 person entity")
                av_id = avinoam_list[0]["id"]
                av_rels = store.q("SELECT * FROM relations WHERE a_id=? OR b_id=?", (av_id, av_id))
                av_neighbor_ids = [r["b_id"] if r["a_id"] == av_id else r["a_id"] for r in av_rels]
                avinoam_neighbors = {
                    store.q1("SELECT key FROM entities WHERE id=?", (nid,))["key"]
                    for nid in av_neighbor_ids
                }
                self.assertIn("+972538889900", avinoam_neighbors)
                self.assertIn("+972509112233", avinoam_neighbors)

                # Rows 30 & 31: Cross-script 'אריאל אדר' and 'Ariel Adar' merged into a single dossier cluster
                d_ariel = dossier(store, name="אריאל אדר")
                self.assertEqual(len(d_ariel["clusters"]), 1, "Cross-script 'אריאל אדר' and 'Ariel Adar' must resolve to 1 cluster")
                self.assertEqual(set(d_ariel["clusters"][0]["names"]), {"אריאל אדר", "Ariel Adar"})

                # Row 99: Dummy record 'test user' and empty dates '0000-00-00' filtered out
                lower_names = {n.lower() for n in person_names}
                self.assertNotIn("test user", lower_names)
                self.assertNotIn("test", lower_names)
                emails = {e["key"] for e in store.q("SELECT * FROM entities WHERE type='email'")}
                self.assertNotIn("test@test.com", emails)
                self.assertNotIn("000000000", nat_ids)
            finally:
                store.close()

    def test_single_quoted_csv_with_inner_apostrophes_and_fragmented_address(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp_path = Path(tmp)
            csv_file = tmp_path / "voters_single_quoted.csv"
            csv_file.write_text(SINGLE_QUOTED_VOTER_CSV, encoding="utf-8")

            db_path = str(tmp_path / "osnit.db")
            store = Store(db_path)
            eng = Engine(store, Config(db_path=db_path))
            try:
                res = import_db(eng, str(csv_file))
                self.assertEqual(res["records"], 3)

                persons = {p["display"]: p for p in store.q("SELECT * FROM entities WHERE type='person'")}
                self.assertIn("סאלם אבו גווייעד", persons)
                self.assertIn("מוחמד אבו גווייעד", persons)
                self.assertIn("יוסף כהן", persons)

                # Check missing-zero phones normalized
                phones = {e["key"] for e in store.q("SELECT * FROM entities WHERE type='phone'")}
                self.assertIn("+972505495072", phones)
                self.assertIn("+972523344556", phones)
                self.assertIn("+972547681313", phones)

                # Check 9-digit and 8-digit zero-padded national IDs
                nat_ids = {e["key"] for e in store.q("SELECT * FROM entities WHERE type='national_id'")}
                self.assertIn("324841485", nat_ids)
                self.assertIn("024486250", nat_ids)
                self.assertIn("039994256", nat_ids)

                # Check fragmented address cleaned of reversed parens and trailing 0/quotes
                addrs = [e["display"] for e in store.q("SELECT * FROM entities WHERE type='address'")]
                self.assertTrue(
                    any("שבט אבו ג'ווייעד" in a and ")שבט" not in a for a in addrs),
                    f"Expected clean 'שבט אבו ג'ווייעד' address in {addrs}",
                )
            finally:
                store.close()

    def test_opaque_headers_content_based_classification(self):
        """Even when column headers are completely opaque (c1..c4), content-based inspection classifies them."""
        opaque_csv = (
            "c1,c2,c3,c4\n"
            "דניאל לוי,039994256,547681313,daniel.levi@walla.co.il\n"
            "רונית שפירא,039199047,528877665,ronit.sh@gmail.com\n"
            "גילעד פרץ,324841485,505495072,gilad.p@cyber.org.il\n"
        )
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp_path = Path(tmp)
            csv_file = tmp_path / "opaque.csv"
            csv_file.write_text(opaque_csv, encoding="utf-8")

            db_path = str(tmp_path / "osnit.db")
            store = Store(db_path)
            eng = Engine(store, Config(db_path=db_path))
            try:
                res = import_db(eng, str(csv_file))
                self.assertEqual(res["records"], 3)

                persons = {p["display"] for p in store.q("SELECT * FROM entities WHERE type='person'")}
                self.assertIn("דניאל לוי", persons)
                self.assertIn("רונית שפירא", persons)
                self.assertIn("גילעד פרץ", persons)

                nat_ids = {e["key"] for e in store.q("SELECT * FROM entities WHERE type='national_id'")}
                self.assertIn("039994256", nat_ids)
                self.assertIn("039199047", nat_ids)
                self.assertIn("324841485", nat_ids)

                phones = {e["key"] for e in store.q("SELECT * FROM entities WHERE type='phone'")}
                self.assertIn("+972547681313", phones)
                self.assertIn("+972528877665", phones)
                self.assertIn("+972505495072", phones)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
