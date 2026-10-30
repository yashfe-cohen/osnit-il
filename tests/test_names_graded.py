"""Name intelligence (Phase 7): a declared name column keeps real Israeli names the free-text gate is right to doubt
("אברהם אברהם", a nickname first name "שרי") — rule 2, nothing is dropped — while free text stays strict; and two
names agree in graded levels (another script, a typo, a nickname, a middle name, an initial), each weighed apart."""
import os
import tempfile
import unittest

from osnit import matchmodel as mm
from osnit.importdb import import_db
from osnit.name_validator import is_valid_person_name
from tests import helpers


class StructuredNames(unittest.TestCase):
    def test_declared_columns_keep_real_names(self):
        for n in ("אברהם אברהם", "יוסף יוסף", "Yosef Yosef", "שרי כהן"):
            self.assertTrue(is_valid_person_name(n, structured=True), n)
            self.assertFalse(is_valid_person_name(n), n)                  # free text stays strict
        for n in ("כהן כהן", "משרד משרד", "שרי הממשלה"):
            self.assertFalse(is_valid_person_name(n, structured=True), n)  # still not names

    def test_import_keeps_them(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            p = os.path.join(tempfile.mkdtemp(), "n.csv")
            with open(p, "w", encoding="utf-8") as f:
                f.write("שם פרטי,שם משפחה,טלפון\nאברהם,אברהם,054-1239876\nשרי,כהן,052-7731846\n"
                        "Yosef,Yosef,050-6672819\nטסט,טסט,053-4417292\n")
            import_db(eng, p, label="n")
            got = {r["display"] for r in store.q("SELECT display FROM entities WHERE type='person'")}
            self.assertEqual(got, {"אברהם אברהם", "שרי כהן", "Yosef Yosef"})
        finally:
            srv.shutdown()


class GradedLevels(unittest.TestCase):
    def test_levels(self):
        cases = [("יצחק כהן", "יצחק כהן", "exact"), ("יצחק כהן", "Yitzhak Cohen", "translit"),
                 ("יוסף אזולאי", "יוסף אזולאיי", "typo"), ("יצחק כהן", "איציק כהן", "nickname"),
                 ("דוד כהן", "דוד יוסף כהן", "middle"), ("י. כהן", "יצחק כהן", "initial"),
                 ("דוד כהן", "משה לוי", "different")]
        for a, b, want in cases:
            self.assertEqual(mm.name_level(a, b), want, (a, b))

    def test_another_script_is_as_good_as_the_same_name(self):
        self.assertEqual(mm.NAME_ADJ["translit"], mm.NAME_ADJ["exact"])
        self.assertLess(mm.NAME_ADJ["typo"], mm.NAME_ADJ["translit"])     # "כהן"/"כהנא" may be two names
        self.assertLess(mm.NAME_ADJ["initial"], mm.NAME_ADJ["nickname"])

    def test_a_repeated_word_is_a_full_name(self):
        self.assertEqual(mm._name_words("אברהם אברהם"), ["אברהמ", "אברהמ"])   # first x surname, not one word


if __name__ == "__main__":
    unittest.main()
