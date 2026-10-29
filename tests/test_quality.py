import random
import unittest

from osnit.extract import Extractor, SubjectSpec
from osnit.textnorm import clean, name_key
from osnit.variants import build_matcher, name_variants


def spec():
    return SubjectSpec(1, "person", "יונתן חייט", name_key("יונתן חייט"), build_matcher(name_variants("יונתן חייט")))


def phone(i):
    r = random.Random(i)
    return f"05{r.randint(0, 8)}-{r.randint(2000000, 9899999)}"


class Quality(unittest.TestCase):
    def test_directory_page_only_keeps_same_row_with_capped_confidence(self):
        rows = [f"Person {i} | {phone(i)}" for i in range(30)]
        rows.insert(10, "יונתן חייט | 052-8814273")
        rows.insert(20, "יונתן חייט")           # name alone; next line's number belongs to someone else
        ex = Extractor([spec()]).extract(clean("רשימת טלפונים\n" + "\n".join(rows)))
        self.assertEqual(ex.page_type, "directory")
        links = {k: v for k, v in ex.links.items() if k[2] == "contact"}
        phones = {(a if a[0] == "phone" else b)[1]: max(c for _, c in v) for (a, b, _), v in links.items()}
        self.assertEqual(set(phones), {"+972528814273"})
        self.assertLessEqual(phones["+972528814273"], 0.5)

    def test_spam_page_yields_nothing(self):
        text = ("יונתן חייט התקשרו עכשיו 052-8814273 " * 14) + "\nמבצע"
        ex = Extractor([spec()]).extract(clean(text))
        self.assertEqual(ex.page_type, "spam")
        self.assertFalse(ex.links)
        self.assertFalse(ex.subject_hits)

    def test_shared_switchboard_not_personal(self):
        text = ('ד"ר דן לוי, מנהל מחלקה\nטלפון 03-6971234\n\nד"ר רונית כהן, מנהלת\nטלפון 03-6971234\n\n'
                'יונתן חייט, מנכ"ל\nטלפון 03-6971234\nנייד 052-8814273')
        ex = Extractor([spec()]).extract(clean(text))
        owners_of_switch = [k for k in ex.links if ("phone", "+97236971234") in k[:2]]
        self.assertEqual(owners_of_switch, [])
        self.assertTrue(any(("phone", "+972528814273") in k[:2] for k in ex.links))

    def test_fake_numbers_and_placeholders_rejected(self):
        ex = Extractor().extract("טלפון 050-0000000 או 052-1234567, mail name@example.com, real ronit@bgu.ac.il")
        self.assertEqual([k for k in ex.ents if k[0] == "phone"], [])
        self.assertEqual([k[1] for k in ex.ents if k[0] == "email"], ["ronit@bgu.ac.il"])

    def test_role_mailbox_weakly_tied_to_person(self):
        ex = Extractor([spec()]).extract(clean('יונתן חייט, מנכ"ל\ninfo@alpha-tech.co.il'))
        conf = [c for k, v in ex.links.items() if ("email", "info@alpha-tech.co.il") in k[:2] for _, c in v]
        self.assertTrue(conf and max(conf) <= 0.35)


if __name__ == "__main__":
    unittest.main()
