"""How are two people connected (osnit/connect.py): strongest chains, exclusivity-weighted, explained in Hebrew."""
import os
import tempfile
import unittest

from osnit.config import Config
from osnit.connect import HUB, how_connected, resolve_person
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.store import Store


class ConnectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        cls.st = Store(cfg.db_path)
        eng = Engine(cls.st, cfg, providers={})
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,מייל,כתובת,מקום עבודה\n"
                    "דנה גל,0521112233,dana.gal@gmail.com,הרצל 5 גן יבנה,אלביט מערכות\n"
                    "רון כהן,0534445566,ron.k@gmail.com,הרצל 5 גן יבנה,אלביט מערכות\n"
                    "שרה לוי,0534445566,sara.l@walla.co.il,,\n"
                    "אבי מזרחי,0541231234,avi.m@gmail.com,,אלביט מערכות\n"
                    "נועה ברק,0549998877,noa.b@gmail.com,,\n")
        import_db(eng, p, label="a", crawl_urls=False)
        cls.st.reindex_names(1000)
        cls.id = {n: resolve_person(cls.st, n)[0] for n in ("דנה גל", "רון כהן", "שרה לוי", "אבי מזרחי", "נועה ברק")}

    def test_strongest_chain_goes_through_the_most_exclusive_link(self):
        r = how_connected(self.st, self.id["דנה גל"], self.id["שרה לוי"])
        self.assertTrue(r["paths"])
        best = r["paths"][0]
        self.assertEqual([n["display"] for n in best["nodes"] if n["type"] == "person"], ["דנה גל", "רון כהן", "שרה לוי"])
        # the shared address (2 people) beats the shared employer (3 people)
        self.assertEqual(best["nodes"][1]["type"], "address")
        self.assertIn("משותף ל-2", best["text"])
        self.assertGreater(len(r["paths"]), 1)                 # an alternative chain, through the employer
        self.assertLessEqual(r["paths"][0]["cost"], r["paths"][1]["cost"])

    def test_no_chain_no_invention(self):
        self.assertEqual(how_connected(self.st, self.id["דנה גל"], self.id["נועה ברק"])["paths"], [])

    def test_names_are_read_as_meant(self):
        pid, read = resolve_person(self.st, "Sara Levy")
        self.assertEqual(pid, self.id["שרה לוי"])
        self.assertEqual(resolve_person(self.st, str(self.id["רון כהן"]))[0], self.id["רון כהן"])

    def test_a_hub_value_is_not_walked(self):
        from osnit import connect
        g = connect._Graph(self.st)
        org = next(e for e, _k in g.neighbours(self.id["אבי מזרחי"]) if g.ent(e)["type"] == "org")
        g._deg[org] = HUB + 1
        self.assertIsNone(g.step_cost(org, "affiliated_with"))


if __name__ == "__main__":
    unittest.main()
