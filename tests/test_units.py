import unittest

from osnit.extract import Extractor, SubjectSpec, norm_phone_il
from osnit.parse import fix_reversed_hebrew, parse
from osnit.profile import combine
from osnit.store import similar_person_keys
from osnit.textnorm import clean, fold, name_key
from osnit.urls import normalize_url, registered_domain
from osnit.variants import build_matcher, name_variants


class Units(unittest.TestCase):
    def test_name_key_is_order_niqqud_final_insensitive(self):
        self.assertEqual(name_key("יוֹנָתָן חייט"), name_key("חייט  יונתן"))
        self.assertEqual(len(fold("ךםןףץ")), 5)

    def test_variants_and_matcher(self):
        m = build_matcher(name_variants("יונתן חייט"))
        text = fold(clean("שוחחנו עם Jonathan Hayat וגם עם חייט, יונתן ועם ליונתן חייט."))
        self.assertEqual(len(m.findall(text)), 3)
        self.assertFalse(m.search(fold("יונתן כהן")))

    def test_phones(self):
        for raw in ("050-8317945", "+972-50-831-7945", "972508317945", "0508317945"):
            self.assertEqual(norm_phone_il(raw), "+972508317945")
        self.assertEqual(norm_phone_il("03-5551234"), "+97235551234")
        self.assertIsNone(norm_phone_il("12345"))

    def test_obfuscated_email_and_no_false_positives(self):
        ex = Extractor().extract("Contact: info [at] acme-corp [dot] co.il\nfile logo@2x.png version 1.2.3 e.g. test")
        self.assertIn(("email", "info@acme-corp.co.il"), ex.ents)
        self.assertFalse([k for k in ex.ents if k[0] == "email" and k[1].endswith(".png")])

    def test_fuzzy_person_merge_rules(self):
        self.assertTrue(similar_person_keys("hayat yonatan", "hayat yonathan"))
        self.assertFalse(similar_person_keys("dana cohen", "dina cohen"))      # short tokens must match exactly
        self.assertFalse(similar_person_keys("hayat yonatan", "hayat david"))

    def test_confidence_independent_domains(self):
        one = combine([("a.com", 0.6), ("a.com", 0.6)])
        two = combine([("a.com", 0.6), ("b.com", 0.6)])
        self.assertEqual(one, 0.6)
        self.assertGreater(two, 0.8)
        self.assertLess(two, 0.99)

    def test_urls(self):
        self.assertEqual(normalize_url("HTTP://Example.com/a?utm_source=x&id=2#frag"), "http://example.com/a?id=2")
        self.assertIsNone(normalize_url("mailto:a@b.com"))
        self.assertEqual(registered_domain("www.cs.bgu.ac.il"), "bgu.ac.il")

    def test_parsers(self):
        self.assertIn("a@b.co", parse(b"name,mail\nDan,a@b.co\n", "http://x/f.csv", "text/csv").text)
        self.assertIn("Dan", parse(b'{"people":[{"name":"Dan","email":"a@b.co"}]}', "http://x/f.json", "application/json").text)
        vc = parse(b"BEGIN:VCARD\nFN:Dan Levi\nTEL:050-8317945\nEMAIL:d@l.co\nEND:VCARD\n", "http://x/c.vcf", "text/vcard")
        self.assertIn("Dan Levi, d@l.co, 050-8317945", vc.text)
        windows = "ד\"ר דן לוי".encode("windows-1255")
        self.assertIn("דן לוי", parse(windows, "http://x/a.txt", "text/plain").text)

    def test_reversed_hebrew_pdf_text_is_flipped(self):
        logical = "הדוח של החברה עם המנכל או היו\"ר של הקבוצה ושל הארגון"
        visual = "\n".join(w[::-1] for w in [logical])[::-1][::-1]
        rev = " ".join(w[::-1] for w in logical.split()[::-1])
        self.assertEqual(fix_reversed_hebrew(rev + "\n" + rev + "\n" + rev).split("\n")[0], logical)


if __name__ == "__main__":
    unittest.main()


class PhoneVariants(unittest.TestCase):
    def test_mobile_forms(self):
        from osnit.extract import phone_variants
        v = phone_variants("+972541234567")
        self.assertIn("054-123-4567", v)
        self.assertIn("0541234567", v)
        self.assertIn("+972-54-123-4567", v)
        self.assertIn("+972541234567", v)

    def test_landline_forms(self):
        from osnit.extract import phone_variants
        v = phone_variants("+97235551234")
        self.assertIn("03-5551234", v)
        self.assertIn("035551234", v)

    def test_all_normalize_back(self):
        from osnit.extract import phone_variants, norm_phone_il
        for form in phone_variants("+972541234567"):
            self.assertEqual(norm_phone_il(form), "+972541234567")
