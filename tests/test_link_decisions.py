"""The operator's word on whether two people are related (osnit/linkdecide.py) overrides every computed link."""
import os
import tempfile
import unittest

from osnit import linkdecide
from osnit.config import Config
from osnit.connect import how_connected, resolve_person
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.network import ego_network
from osnit.store import Store

ROWS = """שם מלא,טלפון נייד,כתובת,מקום עבודה
דנה גל,0521112233,הרצל 5 גן יבנה,אלביט מערכות
רון כהן,0534445566,הרצל 5 גן יבנה,
שרה לוי,0534445566,,
נועה ברק,0549998877,,
"""


class LinkDecisionTest(unittest.TestCase):
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
        self.st.reindex_names(1000)
        self.id = {n: resolve_person(self.st, n)[0] for n in ("דנה גל", "רון כהן", "שרה לוי", "נועה ברק")}

    def names(self, who):
        return {p["name"]: p for p in ego_network(self.st, self.id[who])["people"]}

    def test_unrelated_leaves_the_map_both_ways_and_breaks_the_direct_step(self):
        self.assertIn("רון כהן", self.names("דנה גל"))
        linkdecide.decide(self.st, self.id["רון כהן"], self.id["דנה גל"], "unrelated", "שכנים, לא מכירים")
        self.assertNotIn("רון כהן", self.names("דנה גל"))
        self.assertNotIn("דנה גל", self.names("רון כהן"))
        r = ego_network(self.st, self.id["דנה גל"])
        self.assertEqual([u["note"] for u in r["unrelated"]], ["שכנים, לא מכירים"])
        self.assertEqual(how_connected(self.st, self.id["דנה גל"], self.id["רון כהן"])["paths"], [])

    def test_related_adds_a_tie_the_data_does_not_have(self):
        self.assertNotIn("נועה ברק", self.names("דנה גל"))
        linkdecide.decide(self.st, self.id["דנה גל"], self.id["נועה ברק"], "related", "חברות ילדות")
        p = self.names("דנה גל")["נועה ברק"]
        self.assertGreaterEqual(p["strength"], 0.95)
        self.assertEqual(p["decision"], "related")
        self.assertIn("חברות ילדות", p["via"][0]["label"])
        # and the chain search can now go through it
        chain = how_connected(self.st, self.id["נועה ברק"], self.id["רון כהן"])["paths"][0]
        self.assertEqual([n["display"] for n in chain["nodes"] if n["type"] == "person"],
                         ["נועה ברק", "דנה גל", "רון כהן"])

    def test_clear_and_validation_and_log(self):
        linkdecide.decide(self.st, self.id["דנה גל"], self.id["רון כהן"], "unrelated")
        linkdecide.decide(self.st, self.id["דנה גל"], self.id["רון כהן"], "clear")
        self.assertIn("רון כהן", self.names("דנה גל"))
        with self.assertRaises(ValueError):
            linkdecide.decide(self.st, self.id["דנה גל"], self.id["דנה גל"], "related")
        with self.assertRaises(ValueError):
            linkdecide.decide(self.st, self.id["דנה גל"], self.id["רון כהן"], "maybe")
        linkdecide.decide(self.st, self.id["דנה גל"], self.id["נועה ברק"], "related", "x")
        self.assertEqual(linkdecide.log(self.st)[0]["decision"], "related")

    def test_decisions_go_with_their_people(self):
        linkdecide.decide(self.st, self.id["דנה גל"], self.id["נועה ברק"], "related")
        self.st.reset("all")
        self.assertIsNone(self.st.q1("SELECT 1 x FROM link_decisions"))
        self.assertIsNone(self.st.q1("SELECT 1 x FROM identity_links"))


if __name__ == "__main__":
    unittest.main()
