"""The Israeli national ID ('מזהה מקומי'): canonicalization, the phone-vs-ID boundary, cross-file linking of the
same ID written differently, and the dossier hard rules — one valid ID merges records across spellings, two
different valid IDs never land in one cluster (even through an ID-less bridge), a typo'd ID never forces a split."""
import unittest

from osnit import identity
from osnit.extract import norm_phone_il
from osnit.semantic import il_id_key, il_id_ok, value_kind
from tests import helpers


class IdCheck(unittest.TestCase):
    def test_il_id_ok_checksum(self):
        for ok in ("123456782", "671782597", "521294181", "000000000"):   # all-zeros passes the raw checksum
            self.assertTrue(il_id_ok(ok), ok)
        for bad in ("123456789", "000000001", "039999999", "12345678", "1234567890"):
            self.assertFalse(il_id_ok(bad), bad)

    def test_il_id_key_canonicalizes(self):
        self.assertEqual(il_id_key("123456782"), "123456782")
        self.assertEqual(il_id_key(' 1-2345 6782 '), "123456782")       # stray separators
        self.assertEqual(il_id_key("18470054"), "018470054")            # 8-digit -> zero-padded to 9
        self.assertEqual(il_id_key("9123456782"), "123456782")          # 10-digit, inner valid 9-window
        self.assertEqual(il_id_key("123456789"), "123456789")           # invalid checksum still yields a key
        for empty in ("000000000", "0", "", "N/A", None):
            self.assertIsNone(il_id_key(empty), empty)

    def test_phone_vs_id_boundary_unchanged(self):
        self.assertEqual(value_kind("18470054"), "il_id")               # 8-digit zero-stripped now detected
        self.assertEqual(value_kind("000000000"), "il_id")              # no regression to 'phone'
        for not_phone in ("545566123", "35551234", "521294181"):       # bare 8-9 digits: never a phone
            self.assertIsNone(norm_phone_il(not_phone), not_phone)
        for phone in ("0545566123", "03-5551234", "972545566123"):
            self.assertTrue(norm_phone_il(phone), phone)


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = helpers.ImportQueue(self.eng, inbox=helpers.tempfile.mkdtemp()) if hasattr(helpers, "ImportQueue") \
            else __import__("osnit.importqueue", fromlist=["ImportQueue"]).ImportQueue(self.eng, inbox=self._inbox())

    def _inbox(self):
        import os
        import tempfile
        return os.path.join(tempfile.mkdtemp(), "inbox")

    def tearDown(self):
        self.srv.shutdown()

    def imp(self, body, name):
        job = self.q.add_bytes(body.encode("utf-8"), name, delete_raw=False, review=False)
        self.q.run_pending()
        return job

    def test_same_id_written_differently_links_to_one_entity(self):
        self.imp('שם,ת"ז\nRoni A,123456782\n', "a.csv")
        self.imp('שם,ת"ז\nרוני א,"1-2345 6782"\n', "b.csv")
        ids = self.store.q("SELECT id, key FROM entities WHERE type='national_id'")
        self.assertEqual([r["key"] for r in ids], ["123456782"])        # exactly one, canonical
        d = identity.dossier(self.store, name="Roni A")
        self.assertTrue(d["clusters"])
        names = {n for c in d["clusters"] for n in c["names"]}
        self.assertEqual(names, {"Roni A", "רוני א"})                   # merged across spellings on the shared ID

    def test_two_different_ids_never_merge_through_a_bridge(self):
        # an ID-less bridge record sharing a personal email with two records that carry DIFFERENT valid IDs
        self.imp('שם,מייל\nגיל דן,gil.shared@walla.co.il\n', "bridge.csv")
        self.imp('שם,ת"ז,מייל\nGil Dan,123456782,gil.shared@walla.co.il\n', "x.csv")
        self.imp('שם,ת"ז,מייל\nג. דן,671782597,gil.shared@walla.co.il\n', "y.csv")
        d = identity.dossier(self.store, name="גיל דן")
        id_clusters = [c for c in d["clusters"] if c["facets"].get("national_id")]
        self.assertEqual(len(id_clusters), 2)                           # the two IDs stay in separate clusters
        for c in id_clusters:
            self.assertEqual(len(c["facets"]["national_id"]), 1)

    def test_invalid_id_does_not_shatter_a_real_identity(self):
        # same name, shared phone, each carrying a DIFFERENT invalid-checksum number -> still one person
        self.imp('שם,טלפון,ת"ז\nדנה לוי,0545566123,123456789\n', "p.csv")
        self.imp('שם,טלפון,ת"ז\nדנה לוי,0545566123,111111111\n', "q.csv")
        d = identity.dossier(self.store, name="דנה לוי")
        self.assertEqual(len(d["clusters"]), 1)


if __name__ == "__main__":
    unittest.main()
