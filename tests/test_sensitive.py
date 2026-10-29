"""The context-aware sensitive-information engine: deterministic detection, anchor-boosted confidence, negative-
context dampening, person coreference, subject/object-aware attribution, the sensitivity taxonomy, and
explainability."""
import unittest

from osnit import sensitive as S


class Contracts(unittest.TestCase):
    def test_findings_are_immutable(self):
        f = S.Finding(value="x", kind="email", family="CONTACT", severity="low",
                      span=S.Span(0, 1, "x"), confidence=0.8)
        with self.assertRaises(Exception):
            f.confidence = 0.1

    def test_sentences_keep_offsets(self):
        t = "משפט ראשון. משפט שני!\nשורה שלישית"
        sents = S.sentences(t)
        self.assertEqual([t[s.start:s.end] for s in sents], ["משפט ראשון", "משפט שני", "שורה שלישית"])


class Detection(unittest.TestCase):
    def one(self, text, kind=None, **kw):
        fs = S.analyze_text(text, **kw).findings
        return [f for f in fs if kind is None or f.kind == kind]

    def test_national_id_boosted_by_anchor_weak_without(self):
        boosted = self.one("תעודת זהות: 123456782", "national_id")[0]
        self.assertGreaterEqual(boosted.confidence, 0.8)
        self.assertEqual(boosted.anchor.category, "national_id")
        lone = self.one("המספר הוא 123456782 בלבד", "national_id")
        self.assertTrue(not lone or lone[0].confidence <= 0.5)        # a lone valid-checksum ID stays weak

    def test_invalid_id_is_not_flagged(self):
        self.assertEqual(self.one("תעודת זהות: 123456789", "national_id"), [])   # bad check digit

    def test_credit_card_requires_luhn(self):
        self.assertTrue(self.one("כרטיס אשראי 4111 1111 1111 1111", "credit_card"))
        self.assertEqual(self.one("מספר 4111 1111 1111 1112", "credit_card"), [])  # fails Luhn

    def test_phone_and_email(self):
        self.assertTrue(self.one("צרו קשר: dana@walla.co.il או 054-6613972", "email"))
        self.assertTrue(self.one("צרו קשר: dana@walla.co.il או 054-6613972", "phone"))

    def test_negative_context_dampens(self):
        self.assertEqual(self.one('אין למסור סיסמה כלשהי. למשל סיסמה: 1234', "password"), [])
        self.assertEqual(self.one("לדוגמה, תעודת זהות 123456782", "national_id"), [])


class Attribution(unittest.TestCase):
    def test_possessive_beats_sentence_subject(self):
        # the card belongs to the possessor (אבי), not the subject who moved it (verb-surname dropped)
        t = "יוסי העביר את כרטיס האשראי של אבי כהן: 4111 1111 1111 1111"
        f = [x for x in S.analyze_text(t).findings if x.kind == "credit_card"][0]
        self.assertEqual(f.subject, "אבי כהן")
        self.assertEqual(f.link, "possessive")
        self.assertNotIn("יוסי העביר", S.analyze_text(t).people)      # a verb is not taken as a surname

    def test_pronoun_coreference(self):
        t = "דוד לוי הוא עובד חדש. תעודת הזהות שלו היא 123456782"
        f = [x for x in S.analyze_text(t).findings if x.kind == "national_id"][0]
        self.assertEqual(f.subject, "דוד לוי")
        self.assertEqual(f.link, "coref")

    def test_health_fact_attributed_to_sentence_person(self):
        t = "שרה כהן סובלת מדיכאון ונמצאת באשפוז"
        f = [x for x in S.analyze_text(t).findings if x.family == "HEALTH"]
        self.assertTrue(f)
        self.assertEqual(f[0].subject, "שרה כהן")
        self.assertEqual(f[0].severity, "high")


class Report(unittest.TestCase):
    T = ("דוד לוי הוא מנהל. תעודת הזהות שלו 123456782 והטלפון 054-5566123. "
         "הסיסמה של דוד היא Secret99. שרה כהן סובלת מדיכאון.")

    def test_grouping_and_explainability(self):
        r = S.analyze_text(self.T, source="f.txt")
        self.assertEqual(r.source, "f.txt")
        by = r.by_person()
        self.assertIn("דוד לוי", by)
        self.assertTrue(all(f.reasoning for f in r.findings))         # every finding explains itself
        fams = set(r.by_family())
        self.assertTrue({"PII", "CONTACT", "CREDENTIAL", "HEALTH"} <= fams)

    def test_redaction_masks_values(self):
        r = S.analyze_text(self.T)
        red = S.redact(self.T, r)
        self.assertNotIn("123456782", red)
        self.assertNotIn("Secret99", red)
        self.assertIn("⟨national_id⟩", red)
        self.assertIn("דוד לוי", red)                                 # names are kept; only sensitive values masked

    def test_min_score_threshold(self):
        strict = S.analyze_text(self.T, min_score=0.95)
        self.assertTrue(all(f.confidence >= 0.95 for f in strict.findings))


if __name__ == "__main__":
    unittest.main()
