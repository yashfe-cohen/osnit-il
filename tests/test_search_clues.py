"""Quick investigation with several clues in one box: 'name + phone', 'name + city', 'phone + city', a bare ID.
The person matching every clue becomes the investigation's focus; a clue that matches nobody is reported, never
silently dropped. Also: surname-only search through the per-word name index, and the Hebrew city list."""
import os
import tempfile
import unittest

from osnit.importdb import import_db
from osnit.query import parse_query
from osnit.semantic import is_city
from tests import helpers


class ClueParsing(unittest.TestCase):
    def _p(self, q):
        i = parse_query(q)
        return i.subject, i.clues, i.want

    def test_name_and_phone(self):
        self.assertEqual(self._p("דנה לוי 054-5566123"), ("דנה לוי", {"phone": ["054-5566123"]}, []))

    def test_name_and_city(self):
        self.assertEqual(self._p("דנה לוי תל אביב"), ("דנה לוי", {"city": ["תל אביב"]}, []))

    def test_name_street_and_city(self):
        s, c, _ = self._p("דנה לוי רחוב הרצל 5 חיפה")
        self.assertEqual((s, c), ("דנה לוי", {"address": ["רחוב הרצל 5"], "city": ["חיפה"]}))

    def test_phone_and_city_without_name(self):
        s, c, _ = self._p("054-5566123 חיפה")
        self.assertEqual(c, {"phone": ["054-5566123"], "city": ["חיפה"]})
        self.assertEqual(s, "054-5566123")              # the strongest clue becomes the subject

    def test_question_words_are_not_the_name(self):
        self.assertEqual(self._p("מה הטלפון של דנה לוי"), ("דנה לוי", {}, ["phone"]))
        self.assertEqual(self._p("איפה גרה דנה לוי"), ("דנה לוי", {}, ["address"]))

    def test_bare_digits_are_never_a_phone(self):
        _, c, _ = self._p("דנה לוי 12345678")           # 8 digits, invalid check digit: not a clue at all
        self.assertNotIn("phone", c)
        self.assertNotIn("national_id", c)

    def test_lone_city_word_stays_a_query(self):
        self.assertEqual(self._p("חיפה")[0], "חיפה")


class CityList(unittest.TestCase):
    def test_hebrew_cities_including_final_letters(self):
        for c in ("ירושלים", "תל אביב", "באר שבע", "חיפה", "ראשון לציון", "קריית גת"):
            self.assertTrue(is_city(c), c)

    def test_fragments_are_not_cities(self):
        for c in ("שבע", "תל", "אביב", "ראשון"):
            self.assertFalse(is_city(c), c)


class ClueInvestigation(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "people.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,טלפון,ת.ז,עיר\n"
                    "אסתר,כהן,054-5566123,123456782,חיפה\n"
                    "משה,כהן,052-7491835,,תל אביב\n"
                    "דוד,כהן,050-1112233,,ירושלים\n")
        import_db(self.eng, p, label="t")
        self.store.reindex_names(5000)

    def tearDown(self):
        self.srv.shutdown()

    def _em(self, q):
        return self.svc.search(q)["profile"]["exact_match"]

    def test_name_and_phone_pins_the_person(self):
        em = self._em("אסתר כהן 054-5566123")
        self.assertEqual(em["person_name"], "אסתר כהן")
        self.assertTrue(em["clues"]["all_matched"])

    def test_name_and_city(self):
        em = self._em("אסתר כהן חיפה")
        self.assertTrue(em["clues"]["all_matched"])
        self.assertEqual([m["name"] for m in em["clues"]["full_matches"]], ["אסתר כהן"])

    def test_wrong_city_is_reported(self):
        em = self._em("אסתר כהן ירושלים")
        self.assertFalse(em["clues"]["all_matched"])
        self.assertEqual(em["clues"]["partial"][0]["matched"], ["name"])

    def test_phone_and_city_without_name(self):
        em = self._em("052-7491835 תל אביב")
        self.assertTrue(em["clues"]["all_matched"])
        self.assertEqual(em["person_name"], "משה כהן")

    def test_landline_shaped_id_resolves_by_the_data(self):
        # 039337423 is both a valid landline shape (03-9337423) and a valid ID; the DB holds it as an ID
        p = os.path.join(tempfile.mkdtemp(), "ids.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,ת.ז\nרונית,אברמוביץ,039337423\n")
        import_db(self.eng, p, label="ids")
        em = self._em("039337423")
        self.assertEqual(em["kind"], "national_id")
        self.assertEqual(em["person_name"], "רונית אברמוביץ")
        self.assertTrue(self._em("רונית אברמוביץ 039337423")["clues"]["all_matched"])

    def test_name_and_street_without_city(self):
        p = os.path.join(tempfile.mkdtemp(), "addr.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,כתובת\nיואב,אברמוביץ,הרצל 12\nנעמה,ברק,יהודה הלוי 7\n")
        import_db(self.eng, p, label="addr")
        em = self._em("יואב אברמוביץ הרצל 12")
        self.assertTrue(em["clues"]["all_matched"])
        self.assertEqual(em["person_name"], "יואב אברמוביץ")
        em = self._em("נעמה ברק יהודה הלוי 7")              # a two-word street
        self.assertTrue(em["clues"]["all_matched"])
        self.assertEqual(em["person_name"], "נעמה ברק")

    def test_bare_national_id_is_an_identifier_search(self):
        em = self._em("123456782")
        self.assertEqual(em["kind"], "national_id")
        self.assertEqual(em["person_name"], "אסתר כהן")

    def test_repeated_search_replans(self):
        sid = self.svc.search("אסתר כהן 054-5566123")["subject_id"]
        with self.store.tx() as c:                       # an old investigation stored with stale parsing
            c.execute("UPDATE subjects SET kind='phone', canonical='x' WHERE id=?", (sid,))
        again = self.svc.search("אסתר כהן 054-5566123")
        self.assertEqual(again["subject_id"], sid)
        self.assertEqual(again["profile"]["subject"]["kind"], "person")
        self.assertEqual(again["profile"]["subject"]["canonical"], "אסתר כהן")

    def test_surname_finds_every_first_name(self):
        from osnit.contacts import contacts
        names = {r["name"] for r in contacts(self.store, "כהן")["rows"]}
        self.assertTrue({"אסתר כהן", "משה כהן", "דוד כהן"} <= names, names)

    def test_word_index_lookup(self):
        from osnit.store import name_tokens
        ids = self.store.persons_by_token(name_tokens("כהן"))
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(self.store.persons_by_token(name_tokens("משה כהן"))), 1)
        self.assertEqual(self.store.persons_by_token(name_tokens("אין כזה")), [])


class NothingDropped(unittest.TestCase):
    def test_implausible_identifier_is_kept_as_attribute(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            p = os.path.join(tempfile.mkdtemp(), "p.csv")
            with open(p, "w", encoding="utf-8") as f:
                f.write("שם פרטי,שם משפחה,טלפון,ת.ז\nמשה,כהן,052-3456789,123456780\n")
            import_db(eng, p, label="t")
            kinds = {(r["name"], r["value"], r["kind"]) for r in store.q("SELECT name, value, kind FROM attributes")}
            self.assertIn(("טלפון", "052-3456789", "unverified_phone"), kinds)       # sequential: not linkable, kept
            self.assertIn(("ת.ז", "123456780", "unverified_national_id"), kinds)     # bad check digit: kept
            self.assertFalse(store.q("SELECT 1 FROM entities WHERE type='phone'"))   # but never a linking identifier
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
