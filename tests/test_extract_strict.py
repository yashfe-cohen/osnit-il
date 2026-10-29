"""
Unit tests for Phase 6 (UPGRADE_PLAN v2.0):
Strict Type Guard, Dummy/Junk Rejection, Mathematical Israeli ID/Corp/Vehicle Validation,
and Unmapped/Notes Free-Text Entity Sweep.
"""
import unittest

from osnit.catalog import plan_columns
from osnit.extract import Extractor
from osnit.identity import name_key
from osnit.importdb import record_extraction
from osnit.quality import (
    is_dummy_name,
    is_dummy_value,
    valid_corporate_id,
    valid_email,
    valid_license_plate,
    valid_national_id,
    valid_phone,
)


class TestExtractStrict(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Strict Type Guard: Dummy Values & National ID Luhn
    # ------------------------------------------------------------------

    def test_strict_national_id_validation(self):
        """Rejects dummy sequences and invalid Luhn check digits, accepts real IDs."""
        self.assertFalse(valid_national_id("123456789"), "123456789 is dummy and invalid Luhn")
        self.assertFalse(valid_national_id("000000000"), "All zeros is dummy")
        self.assertFalse(valid_national_id("111111111"), "Repeated digits is dummy")
        self.assertFalse(valid_national_id("0501234567"), "Starts with 05 (phone prefix)")
        self.assertFalse(valid_national_id("N/A"), "N/A is dummy string")
        self.assertFalse(valid_national_id("100000009", autoincrement_seq=True), "Autoincrement is rejected")

        # Real Luhn IDs
        self.assertTrue(valid_national_id("100000009"))
        self.assertTrue(valid_national_id("100000017"))

    def test_strict_phone_validation(self):
        """Rejects repetitive, sequential, and dummy phones."""
        self.assertFalse(valid_phone("0500000000"))
        self.assertFalse(valid_phone("0522222222"))
        self.assertFalse(valid_phone("0501234567"))
        self.assertFalse(valid_phone("N/A"))

        # Real phones
        self.assertTrue(valid_phone("0528317945"))
        self.assertTrue(valid_phone("+972501112233"))
        self.assertTrue(valid_phone("03-6789123"))

    def test_strict_email_validation(self):
        """Rejects placeholder emails and dummy patterns."""
        self.assertFalse(valid_email("test@test.com"))
        self.assertFalse(valid_email("user@example.com"))
        self.assertFalse(valid_email("admin@mydomain.com"))
        self.assertFalse(valid_email("null"))

        # Real email
        self.assertTrue(valid_email("yossi.cohen@technion.ac.il"))
        self.assertTrue(valid_email("dana@startup.co.il"))

    def test_dummy_name_validation(self):
        """Rejects technical/dummy names from becoming owner entities."""
        self.assertTrue(is_dummy_name("admin"))
        self.assertTrue(is_dummy_name("test"))
        self.assertTrue(is_dummy_name("null"))
        self.assertTrue(is_dummy_name("N/A"))
        self.assertTrue(is_dummy_name("אין"))
        self.assertTrue(is_dummy_name("לקוח"))

        self.assertFalse(is_dummy_name("יוסי כהן"))
        self.assertFalse(is_dummy_name("Dana Levi"))

    # ------------------------------------------------------------------
    # 2. Corporate ID & Vehicle Plate Validation
    # ------------------------------------------------------------------

    def test_corporate_id_validation(self):
        """Validates 9-digit Israeli corporate IDs (ח.פ. / עמותה) starting with 51/52/55/57/58 with Luhn."""
        self.assertTrue(valid_corporate_id("510000003"))
        self.assertFalse(valid_corporate_id("123456789"))  # does not start with 5X
        self.assertFalse(valid_corporate_id("510000000"))  # invalid checksum

    def test_license_plate_validation(self):
        """Validates Israeli 7 or 8 digit license plates."""
        self.assertTrue(valid_license_plate("58-924-13"))
        self.assertTrue(valid_license_plate("123-45-987"))
        self.assertFalse(valid_license_plate("0000000"))
        self.assertFalse(valid_license_plate("123"))

    # ------------------------------------------------------------------
    # 3. Free-Text and Notes Entity Sweep
    # ------------------------------------------------------------------

    def test_notes_free_text_entity_sweep(self):
        """Entities hidden inside delivery notes or comments columns are extracted and linked."""
        rec = {
            "name": "יוסי כהן",
            "phone": "0501112233",
            "delivery_notes": "אם אני לא עונה תתקשרו לאשתי דנה כהן ב-052-8317945, ת.ז 100000009",
        }
        plan = plan_columns(list(rec.keys()), [rec])
        ex, _ = record_extraction(rec, plan, [], 0.8)

        # Main owner is Yossi Cohen
        owner_key = ("person", name_key(rec["name"]))
        self.assertIn(owner_key, ex.ents)

        # Notes sweep extracted phone, national_id, and wife's name
        self.assertIn(("phone", "+972528317945"), ex.ents)
        self.assertIn(("national_id", "100000009"), ex.ents)

        # Extracted entities from notes are linked to owner
        phone_key = ("phone", "+972528317945")
        self.assertTrue(
            any((ka == owner_key and kb == phone_key) or (ka == phone_key and kb == owner_key)
                for (ka, kb, _) in ex.links),
            "Extracted phone from notes should be linked to owner"
        )

    def test_strict_guard_rejects_dummy_entities_in_row(self):
        """Row with dummy values in mapped columns rejects the dummy entities."""
        rec = {
            "name": "N/A",  # dummy name
            "email": "test@test.com",  # dummy email
            "phone": "0500000000",  # dummy phone
            "national_id": "123456789",  # dummy invalid ID
            "real_id": "100000009",  # valid ID in custom column
        }
        plan = plan_columns(list(rec.keys()), [rec])
        ex, _ = record_extraction(rec, plan, [], 0.8)

        self.assertNotIn(("email", "test@test.com"), ex.ents)
        self.assertNotIn(("phone", "+972500000000"), ex.ents)
        self.assertNotIn(("national_id", "123456789"), ex.ents)
        self.assertNotIn(("person", "n/a"), ex.ents)


if __name__ == "__main__":
    unittest.main()
