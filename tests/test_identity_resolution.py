"""People are identities, not names: tabular records join an existing person only through a shared personal
identifier (national ID > personal email > mobile) and a compatible name. A name alone never merges records, two
different national IDs never merge, and an identifier held by many people (an office line) is not personal."""
import os
import tempfile
import unittest

from osnit.importdb import import_db
from tests import helpers


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


ID_A, ID_B = _il_id(3933742), _il_id(30011221)


class IdentityResolution(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()

    def _import(self, text, name="p.csv"):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        import_db(self.eng, p, label=name)

    def _people(self, like="%"):
        return [dict(r) for r in self.store.q(
            "SELECT id, key, display FROM entities WHERE type='person' AND display LIKE ? ORDER BY id", (like,))]

    def _ids_of(self, pid, etype):
        return {r["key"] for r in self.store.q(
            "SELECT o.key FROM relations r JOIN entities o ON o.id = r.b_id WHERE r.a_id=? AND o.type=?", (pid, etype))}

    def test_shared_id_or_phone_joins_name_alone_does_not(self):
        self._import("שם פרטי,שם משפחה,ת.ז,טלפון,עיר\n"
                     f"יצחק,כהן,{ID_A},,גן יבנה\n"            # identity 1: the ID
                     "יצחק,כהן,,054-7718293,גן יבנה\n"         # identity 2: phone only (a POSSIBLE match of 1)
                     f"יצחק,כהן,{ID_A},054-7718293,\n"          # ID + phone -> joins identity 1
                     "יצחק,כהן,,,חיפה\n")                       # name only -> its own identity
        people = self._people("יצחק כהן")
        self.assertEqual(len(people), 3)
        by_anchor = {p["key"].split("|", 1)[1][0]: p for p in people}
        self.assertEqual(set(by_anchor), {"n", "p", "r"})
        self.assertEqual(self._ids_of(by_anchor["n"]["id"], "phone"), {"+972547718293"})   # the joined row's phone

    def test_two_national_ids_never_merge_even_with_a_shared_phone(self):
        self._import("שם פרטי,שם משפחה,ת.ז,טלפון\n"
                     f"דוד,לוי,{ID_A},054-7718293\n"
                     f"דוד,לוי,{ID_B},054-7718293\n")
        self.assertEqual(len(self._people("דוד לוי")), 2)

    def test_other_script_joins_through_the_id(self):
        self._import("שם פרטי,שם משפחה,ת.ז\n"
                     f"יצחק,כהן,{ID_A}\n"
                     f"Yitzhak,Cohen,{ID_A}\n")
        people = self._people()
        self.assertEqual(len(people), 1)
        aliases = {r["alias"] for r in self.store.q("SELECT alias FROM aliases WHERE entity_id=?", (people[0]["id"],))}
        self.assertIn("Yitzhak Cohen", aliases)

    def test_different_name_on_a_shared_phone_stays_a_different_person(self):
        self._import("שם פרטי,שם משפחה,טלפון\n"
                     "רונית,אברמוביץ,054-7718293\n"
                     "יואב,אברמוביץ,054-7718293\n")                # a family phone: two people
        self.assertEqual(len(self._people()), 2)

    def test_landline_is_not_personal(self):
        self._import("שם פרטי,שם משפחה,טלפון,עיר\n"
                     "משה,פרץ,03-6123456,חולון\n"
                     "משה,פרץ,03-6123456,בת ים\n")
        # same name + same landline: not proof of one person (a household / office) -> two record identities
        self.assertEqual(len(self._people()), 2)

    def test_an_identical_row_is_the_same_record(self):
        self._import("שם פרטי,שם משפחה,עיר\nמשה,פרץ,חולון\nמשה,פרץ,חולון\n")
        self.assertEqual(len(self._people()), 1)

    def test_generic_identifier_is_ignored(self):
        firsts = ("אבי דוד משה יוסי רון שרה רחל מיכל נועה יעל אורי עומר איתי תמר דנה גיל עידו ליאור שירה אדם "
                  "אסתר בתיה גלית הדס ורד זיו חנה טל ינון כרמל").split()
        rows = "".join(f"{f},גבאי,054-7000001,\n" for f in firsts)            # one office number, 30 people
        self._import("שם פרטי,שם משפחה,טלפון,הערה\n" + rows + "נועה,גבאי,054-7000001,לקוחה\n")
        # the office number is held by 30 people: the last row does not join "נועה גבאי" through it
        self.assertEqual(len(self._people("נועה גבאי")), 2)

    def test_reimporting_the_same_file_is_idempotent(self):
        text = "שם פרטי,שם משפחה,טלפון\nנועה,בר,054-7718293\nשירה,גל,\n"
        self._import(text, "a.csv")
        n = len(self._people())
        self._import(text, "a2.csv")
        self.assertEqual(len(self._people()), n)

    def test_foreign_key_child_keeps_the_parent_identity(self):
        sql = ("CREATE TABLE users (id INT, name VARCHAR(50), phone VARCHAR(20));\n"
               "INSERT INTO users VALUES (1,'אסתר כהן','054-5566123');\n"
               "CREATE TABLE orders (order_id INT, user_id INT, address VARCHAR(80));\n"
               "INSERT INTO orders VALUES (10,1,'הרצל 5 חיפה');\n")
        self._import(sql, "dump.sql")
        self.assertEqual(len(self._people("אסתר כהן")), 1)

    def test_investigation_finds_every_identity_of_the_name(self):
        self._import("שם פרטי,שם משפחה,ת.ז\n"
                     f"דוד,לוי,{ID_A}\n"
                     f"דוד,לוי,{ID_B}\n")
        prof = self.svc.search("דוד לוי")["profile"]
        self.assertEqual(len([c for c in prof["clusters"]]), 2)


if __name__ == "__main__":
    unittest.main()
