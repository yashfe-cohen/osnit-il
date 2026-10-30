"""Fuzzy name search (osnit/fuzzyname.py): the name as it was meant, however it was typed — and never somebody else."""
import os
import tempfile
import unittest

from osnit import fuzzyname
from osnit.config import Config
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.store import Store


def _db(rows):
    d = tempfile.mkdtemp()
    cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
    cfg.providers = []
    st = Store(cfg.db_path)
    eng = Engine(st, cfg, providers={})
    p = os.path.join(d, "p.csv")
    with open(p, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד\n")
        for i, n in enumerate(rows):
            f.write(f"{n},05{2 + i % 7}{1000000 + i * 7919:07d}\n")
    import_db(eng, p, label="p", crawl_urls=False)
    st.reindex_names(100000)
    return st


class FuzzyNameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.st = _db(["יצחק כהן", "שרה לוי", "שרה לוין", "משה אברמוביץ", "רחל אזולאי", "מיכאל בן דוד", "אסתר פרץ"])

    def top(self, q):
        r = fuzzyname.find_people_any(self.st, q, limit=5)
        return r[0]["display"] if r else None

    def test_keyboard_layout_both_ways(self):
        self.assertEqual(self.top("hmje fvi"), "יצחק כהן")           # Hebrew typed on the English layout
        self.assertEqual(self.top("tx,r pr."), "אסתר פרץ")            # ',' and '.' are Hebrew letters there
        self.assertEqual(self.top("צםדיק שנרשצםהןבי"), "משה אברמוביץ")  # English typed on the Hebrew layout

    def test_slips_and_spelling_by_ear(self):
        self.assertEqual(self.top("יחצק כהן"), "יצחק כהן")
        self.assertEqual(self.top("רחל אזולי"), "רחל אזולאי")
        self.assertEqual(self.top("משה אברמוביטש"), "משה אברמוביץ")
        self.assertEqual(self.top("שרה לווי"), "שרה לוי")            # not her look-alike שרה לוין

    def test_english_cyrillic_joined_and_extras(self):
        self.assertEqual(self.top("Itzhak Koen"), "יצחק כהן")
        self.assertEqual(self.top("Rakel Azulay"), "רחל אזולאי")
        self.assertEqual(self.top("Ицхак Коэн"), "יצחק כהן")
        self.assertEqual(self.top("שרהלוי"), "שרה לוי")
        self.assertEqual(self.top("מיכאל-בן-דוד"), "מיכאל בן דוד")
        self.assertEqual(self.top('ד"ר משה Abramovich'), "משה אברמוביץ")

    def test_a_name_not_in_the_data_finds_nobody(self):
        for q in ["יצחק לוי", "שרה כהן", "Esther Azoulay", "יצחק לווי", "Sarah Cohen", "משה פרץ"]:
            self.assertEqual(fuzzyname.find_people_any(self.st, q), [], q)

    def test_hit_says_what_was_searched(self):
        r = fuzzyname.fuzzy_find(self.st, "hmje fvi")
        self.assertEqual(r[0]["corrected"], "יצחק כהנ")
        self.assertEqual(r[0]["how"], "layout")

    def test_distance_weights(self):
        self.assertLess(fuzzyname.distance("כהן", "קהן"), fuzzyname.distance("כהן", "להן"))   # confusable < arbitrary
        self.assertLess(fuzzyname.distance("levi", "lrvi"), 1.0)                             # neighbouring keys
        self.assertEqual(fuzzyname.phon("Sarah"), fuzzyname.phon("שרה"))

    def test_multi_find_reads_the_name_as_meant(self):
        from osnit.multisearch import multi_find
        r = multi_find(self.st, {"name": "hmje fvi"})
        self.assertTrue(r["results"])
        self.assertEqual(r["results"][0]["name"], "יצחק כהן")
        self.assertTrue(r["did_you_mean"])

    def test_reset_clears_the_name_index(self):
        st = _db(["דנה רבינוביץ"])
        st.reset("all")
        self.assertIsNone(st.q1("SELECT 1 x FROM name_vocab"))
        self.assertIsNone(st.q1("SELECT 1 x FROM name_index"))


class QueryBenchTest(unittest.TestCase):
    def test_generator_is_deterministic_and_covers_every_kind(self):
        from osnit import qbench
        a, b = qbench.generate(3), qbench.generate(3)
        self.assertEqual(a, b)
        self.assertEqual({k for k, _q, _i in a}, set(qbench.KINDS))
        self.assertEqual(qbench.typed_on_latin("יצחק כהן"), "hmje fvi")


if __name__ == "__main__":
    unittest.main()


class HebrewEnglishConventionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.st = _db(["צבי הרשקוביץ", "אלכסנדר פרידמן", "אברהם אוחיון", "יצחק כהן", "דמיטרי קוזלוב"])

    def top(self, q):
        r = fuzzyname.find_people_any(self.st, q, limit=5)
        return (r[0]["display"], r[0].get("why", "")) if r else (None, "")

    def test_russian_g_for_h_and_nicknames(self):
        self.assertEqual(self.top("Tsvi Gershkovich")[0], "צבי הרשקוביץ")
        self.assertEqual(self.top("Itzhak Kogan")[0], "יצחק כהן")            # Kogan is the Russian כהן
        name, why = self.top("Sasha Fridman")
        self.assertEqual(name, "אלכסנדר פרידמן")
        self.assertIn("כינוי", why)
        self.assertEqual(self.top("Avi Ohayon")[0], "אברהם אוחיון")
        self.assertEqual(self.top("Dima Kozlov")[0], "דמיטרי קוזלוב")

    def test_learned_from_one_persons_two_scripts(self):
        # the data shows 'דנה גל' and 'Dana Gelbart' are one person (the only two holders of one email): גל = Gelbart
        # (a Hebraized surname no sound rule could guess), so 'Ron Gelbart' finds 'רון גל'
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        st = Store(cfg.db_path)
        eng = Engine(st, cfg, providers={})
        for name, hdr, fn in (("דנה גל", "שם מלא,מייל", "a.csv"), ("Dana Gelbart", "full name,email", "b.csv"),
                              ("רון גל", "שם מלא,מייל", "c.csv")):
            with open(os.path.join(d, fn), "w", encoding="utf-8") as f:
                f.write(f"{hdr}\n{name},{'ron.gal77@gmail.com' if fn == 'c.csv' else 'dana.gelbart@gmail.com'}\n")
            import_db(eng, os.path.join(d, fn), label=fn, crawl_urls=False)
        st.reindex_names(1000)
        self.assertEqual(fuzzyname.find_people_any(st, "Ron Gelbart"), [])     # not before it was learned
        self.assertGreaterEqual(fuzzyname.learn_transliterations(st), 1)
        r = fuzzyname.find_people_any(st, "Ron Gelbart")
        self.assertTrue(r)
        self.assertEqual(r[0]["display"], "רון גל")
        self.assertIn("שנלמד", r[0]["why"])


class AIFallbackTest(unittest.TestCase):
    """The AI reading is a last resort, opt-in, and never replaces what the data itself finds."""

    def setUp(self):
        self.st = _db(["רון גל"])

    def cfg(self, on):
        c = Config(db_path=":memory:")
        c.ai_names, c.ai_key, c.ai_url, c.ai_model = on, "k", "http://x", "m"
        return c

    def test_off_by_default_and_only_when_nothing_else_found(self):
        from unittest import mock
        from osnit import ai
        with mock.patch.object(ai, "_name_expansions_call", return_value=["רון גל"]) as call:
            self.assertEqual(fuzzyname.find_people_any(self.st, "Ron Gelbart", cfg=self.cfg(False)), [])
            call.assert_not_called()
            r = fuzzyname.find_people_any(self.st, "Ron Gelbart", cfg=self.cfg(True))
            self.assertEqual(r[0]["display"], "רון גל")
            self.assertEqual(r[0]["how"], "ai")
            call.reset_mock()
            fuzzyname.find_people_any(self.st, "רון גל", cfg=self.cfg(True))   # found as typed: no model call
            call.assert_not_called()

    def test_model_failure_degrades_to_nothing(self):
        from unittest import mock
        from osnit import ai
        with mock.patch.object(ai, "_name_expansions_call", side_effect=OSError("down")):
            self.assertEqual(fuzzyname.find_people_any(self.st, "Ron Gelbart", cfg=self.cfg(True)), [])
