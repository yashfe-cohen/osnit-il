"""The network around one person (osnit/network.py): exclusivity-weighted ties, noisy-or, groups, ring 2."""
import os
import tempfile
import unittest

from osnit import network
from osnit.config import Config
from osnit.connect import resolve_person
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.store import Store

ROWS = """שם מלא,טלפון נייד,מייל,כתובת,מקום עבודה,שם האב
דנה גל,0521112233,dana.gal@gmail.com,הרצל 5 גן יבנה,אלביט מערכות,משה
רון כהן,0534445566,ron.k@gmail.com,הרצל 5 גן יבנה,אלביט מערכות,
שרה לוי,0534445566,sara.l@walla.co.il,,,
אבי מזרחי,0541231234,avi.m@gmail.com,,אלביט מערכות,
מאיה גל,0541231299,maya.gal@gmail.com,הרצל 5 גן יבנה,,
נועה ברק,0549998877,noa.b@gmail.com,,,
"""


class NetworkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        cls.st = Store(cfg.db_path)
        eng = Engine(cls.st, cfg, providers={})
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write(ROWS)
        import_db(eng, p, label="a", crawl_urls=False)
        cls.st.reindex_names(1000)
        cls.dana = resolve_person(cls.st, "דנה גל")[0]

    def by_name(self, r):
        return {p["name"]: p for p in r["people"]}

    def test_ring_one_strengths_follow_exclusivity_and_add_up(self):
        r = network.ego_network(self.st, self.dana)
        p = self.by_name(r)
        self.assertEqual(set(p), {"משה גל", "רון כהן", "מאיה גל", "אבי מזרחי"})     # nobody unrelated (נועה)
        self.assertGreater(p["רון כהן"]["strength"], p["מאיה גל"]["strength"])     # address + employer > address
        self.assertGreater(p["מאיה גל"]["strength"], p["אבי מזרחי"]["strength"])   # address (0.7) > org (0.45)
        self.assertEqual(p["משה גל"]["group"], "family")
        self.assertNotIn("שרה לוי", p)                                            # ring 2 only on request

    def test_groups_are_explained(self):
        r = network.ego_network(self.st, self.dana)
        labels = {g["label"]: len(g["people"]) for g in r["groups"]}
        self.assertEqual(labels.get("משפחה"), 1)
        self.assertEqual(labels.get("כתובת הרצל 5 גן יבנה"), 2)

    def test_ring_two_goes_through_a_bridge(self):
        p = self.by_name(network.ego_network(self.st, self.dana, depth=2))
        sara = p["שרה לוי"]
        self.assertEqual(sara["depth"], 2)
        self.assertEqual(self.st.q1("SELECT display FROM entities WHERE id=?", (sara["through"],))["display"], "רון כהן")
        self.assertLess(sara["strength"], p["רון כהן"]["strength"])

    def test_confirmed_same_person_is_one_centre(self):
        noa = resolve_person(self.st, "נועה ברק")[0]
        with self.st.tx() as c:
            c.execute("INSERT OR REPLACE INTO identity_links(a, b, decision, score, reasons, at) VALUES(?,?,?,?,?,?)",
                      (min(self.dana, noa), max(self.dana, noa), "same", 1.0, "", 0))
        try:
            r = network.ego_network(self.st, noa)
            self.assertIn(self.dana, r["center"]["identities"])
            self.assertIn("רון כהן", self.by_name(r))           # Dana's ties are Noa's when they are one person
        finally:
            with self.st.tx() as c:
                c.execute("DELETE FROM identity_links")

    def test_weights(self):
        self.assertAlmostEqual(network.value_weight("phone", 2), 0.9)
        self.assertLess(network.value_weight("org", 400), 0.08)
        self.assertEqual(network.value_weight("org", network.HUB + 1), 0.0)
        self.assertAlmostEqual(network.noisy_or([0.5, 0.5]), 0.75)

    def test_drawing_has_the_shared_address_as_a_hub(self):
        g = network.ego_network(self.st, self.dana)["graph"]
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertIn("address", kinds)
        self.assertTrue(all(e["a"] in {n["key"] for n in g["nodes"]} and e["b"] in {n["key"] for n in g["nodes"]}
                            for e in g["edges"]))


if __name__ == "__main__":
    unittest.main()
