"""A relative known only by name (a 'שם האב' cell) matched to the person the data already has (kinresolve.py)."""
import os
import tempfile
import unittest

from osnit import kinresolve
from osnit.config import Config
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.network import ego_network
from osnit.possible import decide
from osnit.store import Store

ROWS = """שם מלא,טלפון נייד,כתובת,שם האב,תאריך לידה
משה פרידמן,0521112233,הרצל 5 גן יבנה,,1955-04-01
משה פרידמן,0541239876,ויצמן 3 חיפה,,1950-01-01
משה פרידמן,0547771234,הרצל 5 גן יבנה,,1986-06-06
דנה פרידמן,0534445566,הרצל 5 גן יבנה,משה,1984-02-02
"""


class KinResolveTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        self.st = Store(cfg.db_path)
        eng = Engine(self.st, cfg, providers={})
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write(ROWS)
        import_db(eng, p, label="a", crawl_urls=False)
        self.dana = self.st.q1("SELECT id FROM entities WHERE display='דנה פרידמן'")["id"]
        self.father_cell = self.st.q1("SELECT b_id FROM relations WHERE a_id=? AND kind='kinship:father'",
                                      (self.dana,))["b_id"]
        self.real = self.st.q1("SELECT entity_id FROM attributes WHERE value='1955-04-01'")["entity_id"]

    def test_only_the_family_member_of_the_right_generation_is_offered(self):
        self.assertTrue(kinresolve.name_only(self.st, self.father_cell))
        c = kinresolve.candidates(self.st, self.dana, self.father_cell, "father")
        # Haifa: nothing in common with the family; the 1986 Moshe at the address: too young to be her father
        self.assertEqual([x["id"] for x in c], [self.real])
        self.assertIn("כתובת משותפת", c[0]["reasons"])

    def test_on_the_map_and_after_the_operators_yes(self):
        people = {p["id"]: p for p in ego_network(self.st, self.dana)["people"]}
        self.assertEqual(people[self.father_cell]["identify"]["candidates"][0]["id"], self.real)
        decide(self.st, self.father_cell, self.real, "same")
        people = {p["id"]: p for p in ego_network(self.st, self.dana)["people"]}
        merged = [p for p in people.values() if p.get("merged")]
        self.assertEqual(len(merged), 1)                                  # the father is drawn once
        self.assertEqual(set(merged[0]["merged"]), {self.father_cell, self.real})
        self.assertNotIn("identify", merged[0])                           # nothing left to ask


if __name__ == "__main__":
    unittest.main()
