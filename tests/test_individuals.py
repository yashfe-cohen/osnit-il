"""A qualified search answers with distinct PEOPLE (individuals.py via multi_find): "יצחק כהן" in Gan Yavne born 1980
picks that person out of several namesakes, conflicting namesakes are set apart, and a record that may be one of
them is shown under it with a probability — never merged. Also: the query understands a birth year, an age and a
father's name."""
import os
import tempfile
import time
import unittest

from osnit.importdb import import_db
from osnit.multisearch import multi_find
from osnit.query import parse_query
from tests import helpers


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


ID_A, ID_C, ID_D = _il_id(3933742), _il_id(30011221), _il_id(21155433)


class QueryWho(unittest.TestCase):
    def _p(self, q):
        i = parse_query(q)
        return i.subject, i.clues

    def test_birth_year_and_town(self):
        self.assertEqual(self._p("יצחק כהן גן יבנה 1980"), ("יצחק כהן", {"birth_year": ["1980"], "city": ["גן יבנה"]}))
        self.assertEqual(self._p("יצחק כהן יליד 1980"), ("יצחק כהן", {"birth_year": ["1980"]}))

    def test_age(self):
        self.assertEqual(self._p("יצחק כהן בן 45"), ("יצחק כהן", {"age": ["45"]}))

    def test_father_only_after_a_full_name(self):
        self.assertEqual(self._p("יצחק כהן בן משה"), ("יצחק כהן", {"father": ["משה"]}))
        self.assertEqual(self._p("יוסי בן דוד"), ("יוסי בן דוד", {}))           # a surname, not a father
        self.assertEqual(self._p("דוד בן גוריון"), ("דוד בן גוריון", {}))

    def test_a_house_number_is_not_a_year(self):
        self.assertEqual(self._p("יואב אברמוביץ הרצל 12"), ("יואב אברמוביץ", {"address": ["הרצל 12"]}))


class KinshipHeaders(unittest.TestCase):
    def test_hebrew_headers_with_final_letters_are_recognised(self):
        # the header is folded ("שם האב" -> "שמ האב"); these were silently ignored at import before
        from osnit.kinship import detect_kinship_column_role, is_emergency_phone_column
        for header, role in (("שם האב", "father"), ("שם האם", "mother"), ("בן זוג", "spouse"), ("אם", "mother"),
                             ("שם אח", "sibling"), ("איש קשר לחירום", "emergency_contact"), ("father_name", "father")):
            self.assertEqual(detect_kinship_column_role(header), role, header)
        for header in ("שם", "שם פרטי", "שם משפחה", "עיר"):
            self.assertIsNone(detect_kinship_column_role(header), header)
        self.assertTrue(is_emergency_phone_column("טלפון איש קשר לחירום"))


class RelativeColumnIsNotTheOwnersName(unittest.TestCase):
    def test_father_column_never_names_the_record_owner(self):
        # "שם האב" holds first names; it used to take the first-name slot and save the person under his FATHER's name
        import osnit.importdb as idb
        p = os.path.join(tempfile.mkdtemp(), "r.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז,שם האב\n"
                    f"יצחק,כהן,{ID_A},משה\nדוד,לוי,,\nשרה,מזרחי,,\n")
        for _t, plan, rows in idb.read_tables(p):
            self.assertEqual(plan.cols("first"), ["שם פרטי"])
            owners = []
            for rec in rows:
                ex, _ = idb.record_extraction(rec, plan)
                owners.append(sorted(k[1] for k in ex.ents if k[0] == "person"))
                if rec["שם האב"]:
                    self.assertTrue(any(k == "kinship:father" for (_a, _b, k) in ex.links))
            self.assertIn("יצחק כהנ", owners[0])                    # the person, under his own name
            self.assertEqual(len(owners), 3)                          # every row is a person, father or not


class Individuals(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "people.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז,טלפון,עיר,תאריך לידה,שם האב\n"
                    f"יצחק,כהן,{ID_A},,גן יבנה,02/04/1980,משה\n"         # A
                    f"יצחק,כהן,{ID_C},,גן יבנה,1965-07-11,אברהם\n"       # C: same town, another ID, born 1965
                    f"יצחק,כהן,{ID_D},,אילת,,\n"                         # D: another town
                    "יצחק,כהן,,052-6612309,חיפה,,\n")                     # E: another town, no ID
        import_db(self.eng, p, label="reg")
        q = os.path.join(tempfile.mkdtemp(), "contacts.csv")
        with open(q, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,עיר\nיצחק כהן,054-7718293,גן יבנה\n")   # B: one of the Gan Yavne men?
        import_db(self.eng, q, label="contacts")
        self.store.reindex_names(5000)

    def tearDown(self):
        self.srv.shutdown()

    def _ind(self, **fields):
        return multi_find(self.store, dict(name="יצחק כהן", **fields))

    def _by_status(self, res):
        out = {}
        for i in res["individuals"]:
            out.setdefault(i["status"], []).append(i)
        return out

    def test_town_separates_people_not_records(self):
        res = self._ind(city="גן יבנה")
        st = self._by_status(res)
        nids = lambda lst: {n for i in lst for n in i["facts"]["national_ids"]}
        self.assertEqual(nids(st.get("match", [])), {ID_A, ID_C})        # the two Gan Yavne men with an ID
        self.assertEqual(nids(st.get("conflict", [])), {ID_D})            # Eilat: another person with the name
        towns = {t for i in st.get("conflict", []) for t in i["facts"]["towns"]}
        self.assertIn("חיפה", towns)                                     # E is someone else too
        for i in res["individuals"]:                                     # one person = one card, never two IDs
            self.assertLessEqual(len(i["facts"]["national_ids"]), 1)

    def test_birth_year_picks_one_person(self):
        res = self._ind(city="גן יבנה", birth_year="1980")
        st = self._by_status(res)
        self.assertEqual([i["facts"]["national_ids"] for i in st["match"]], [[ID_A]])
        conflict_ids = {n for i in st.get("conflict", []) for n in i["facts"]["national_ids"]}
        self.assertIn(ID_C, conflict_ids)                                # born 1965: not the person asked about
        q = {q["field"]: q for q in st["match"][0]["qualifiers"]}
        self.assertEqual(q["birth_year"]["status"], "match")
        self.assertEqual(q["city"]["status"], "match")

    def test_age_is_a_birth_year_range(self):
        age = time.localtime().tm_year - 1980
        res = self._ind(city="גן יבנה", age=str(age))
        st = self._by_status(res)
        self.assertIn([ID_A], [i["facts"]["national_ids"] for i in st["match"]])

    def test_father_name(self):
        res = self._ind(father="משה")
        st = self._by_status(res)
        self.assertEqual([i["facts"]["national_ids"] for i in st["match"]], [[ID_A]])
        conflict_ids = {n for i in st.get("conflict", []) for n in i["facts"]["national_ids"]}
        self.assertIn(ID_C, conflict_ids)                                # his father is Avraham

    def test_unanchored_record_is_never_merged_into_two_people(self):
        res = self._ind(city="גן יבנה")
        b_cards = [i for i in res["individuals"] if "+972547718293" in i["facts"]["mobiles"]]
        attached = [(i, p) for i in res["individuals"] for p in i["possible"] if "+972547718293" in p["facts"]["mobiles"]]
        self.assertEqual(len(b_cards) + len(attached), 1)               # B appears exactly once
        for i, p in attached:                                           # if shown under someone: a probability,
            self.assertLess(p["probability"], 1.0)                      # not a merge, with what would decide it
            self.assertTrue(p["decide"])
        for i in b_cards:
            self.assertFalse(i["facts"]["national_ids"])

    def test_investigation_focuses_on_the_person_asked_about(self):
        em = self.svc.search("יצחק כהן גן יבנה 1980")["profile"]["exact_match"]
        clues = em["clues"]
        self.assertTrue(clues["all_matched"])
        self.assertEqual(len(clues["full_matches"]), 1)                  # one person, not every Yitzhak Cohen
        ind = {i["status"]: i for i in clues["individuals"]}
        self.assertIn("match", ind)
        self.assertIn("conflict", ind)                                   # the others are listed apart, with why
        why = {q["field"]: q for q in next(i for i in clues["individuals"] if i["status"] == "conflict")["qualifiers"]}
        self.assertEqual(why["birth_year"]["status"] if "birth_year" in why else why["city"]["status"], "conflict")

    def test_distinct_details_tell_them_apart(self):
        res = self._ind(city="גן יבנה")
        for i in res["individuals"]:
            if i["facts"]["national_ids"]:
                self.assertTrue(any(d.startswith('ת"ז') for d in i["distinct"]))


if __name__ == "__main__":
    unittest.main()
