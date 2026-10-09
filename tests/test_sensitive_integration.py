"""The sensitive engine wired through the system: a document ingested through the engine attaches context-aware
sensitive findings to the right person's dossier."""
import unittest

from osnit import identity
from osnit.ingest import import_parsed
from osnit.parse import Parsed
from tests import helpers


class Integration(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def test_findings_land_on_the_dossier(self):
        text = ("דוד מזרחי הוא עובד חדש בחברה. תעודת הזהות שלו היא 123456782 "
                "והטלפון שלו 054-5566123. שרה כהן סובלת מדיכאון ונמצאת באשפוז.")
        import_parsed(self.eng, "https://example.co.il/hr", Parsed("html", text, "HR"))
        d = identity.dossier(self.store, name="דוד מזרחי")
        sens = [f for c in d["clusters"] for f in c.get("sensitive", [])]
        kinds = {f["kind"] for f in sens}
        self.assertIn("national_id", kinds)                        # attributed to דוד via coreference
        self.assertTrue(all(f["reasoning"] for f in sens))
        nid = next(f for f in sens if f["kind"] == "national_id")
        self.assertEqual(nid["value"], "123456782")
        self.assertGreaterEqual(nid["confidence"], 0.8)
        # שרה כהן's health fact lands on HER dossier, not דוד's
        ds = identity.dossier(self.store, name="שרה כהן")
        self.assertTrue(any(f["family"] == "HEALTH" for c in ds["clusters"] for f in c.get("sensitive", [])))

    def test_scan_off_by_flag(self):
        self.eng.cfg.sensitive_scan = False
        import_parsed(self.eng, "https://example.co.il/x",
                      Parsed("html", "דוד מזרחי, ת.ז 123456782, טלפון 054-5566123", "x"))
        self.assertEqual(self.store.q1("SELECT COUNT(*) c FROM sensitive")["c"], 0)


if __name__ == "__main__":
    unittest.main()
