"""Ties of an identity that may be the same person join the map, weighted and marked (network.py + possible.py)."""
import os
import tempfile
import unittest

from osnit.config import Config
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.network import ego_network
from osnit.possible import decide, possible_matches
from osnit.store import Store


class PossibleSelvesOnTheMapTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        self.st = Store(cfg.db_path)
        eng = Engine(self.st, cfg, providers={})
        # the same rare name, the same address and birth date in two files, different phones: possibly one person
        a = os.path.join(d, "a.csv")
        with open(a, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,כתובת,תאריך לידה\n"
                    "יוחאי בוקובזה,0521112233,הרצל 5 גן יבנה,1980-02-02\n"
                    "רון כהן,0534445566,הרצל 5 גן יבנה,1979-01-01\n")
        import_db(eng, a, label="a", crawl_urls=False)
        b = os.path.join(d, "b.csv")
        with open(b, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,כתובת,מקום עבודה,תאריך לידה\n"
                    "יוחאי בוקובזה,0549990000,הרצל 5 גן יבנה,קרן אור בע\"מ,1980-02-02\n"
                    "עדי צור,0547776655,,קרן אור בע\"מ,1990-01-01\n")
        import_db(eng, b, label="b", crawl_urls=False)
        ids = [r["id"] for r in self.st.q("SELECT id FROM entities WHERE display='יוחאי בוקובזה' ORDER BY id")]
        self.a, self.b = ids[0], ids[1]

    def test_the_possible_identitys_colleague_appears_marked(self):
        cands = possible_matches(self.st, self.a)["candidates"]
        self.assertTrue(any(c["id"] == self.b and c["probability"] >= 0.5 for c in cands), cands)
        r = ego_network(self.st, self.a)
        self.assertEqual([m["id"] for m in r["possible_selves"]], [self.b])
        people = {p["name"]: p for p in r["people"]}
        adi = people["עדי צור"]                                  # only through the other file's identity
        self.assertTrue(adi["maybe"])
        self.assertIn("דרך זהות אפשרית", adi["via"][0]["label"])
        self.assertLess(adi["strength"], 0.9)

    def test_a_no_takes_them_off_and_a_yes_makes_them_one(self):
        decide(self.st, self.a, self.b, "different")
        r = ego_network(self.st, self.a)
        self.assertEqual(r["possible_selves"], [])
        self.assertNotIn("עדי צור", {p["name"] for p in r["people"]})
        decide(self.st, self.a, self.b, "same")
        r = ego_network(self.st, self.a)
        adi = {p["name"]: p for p in r["people"]}["עדי צור"]
        self.assertFalse(adi.get("maybe"))                       # a confirmed identity: an ordinary tie now


if __name__ == "__main__":
    unittest.main()


class CoupleOnOneMobileTest(unittest.TestCase):
    """Two different names on one mobile are a couple, not one person (rule 5) — found by the network benchmark:
    the shared identifier was taken as certainty (95-100%) whatever the names."""

    def test_not_offered_as_the_same_person(self):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        st = Store(cfg.db_path)
        eng = Engine(st, cfg, providers={})
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,עיר\nחיים וקנין,0524141592,חיפה\nמשה שושן,0535107690,חיפה\n")
        import_db(eng, p, label="a", crawl_urls=False)
        q = os.path.join(d, "b.csv")
        with open(q, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,טלפון נוסף\nמשה שושן,0535107690,0524141592\n")
        import_db(eng, q, label="b", crawl_urls=False)
        haim = st.q1("SELECT id FROM entities WHERE display='חיים וקנין'")["id"]
        res = possible_matches(st, haim) or {"candidates": []}
        moshe = [c for c in res["candidates"] if c["name"] == "משה שושן"]
        self.assertTrue(all(c["probability"] < 0.5 for c in moshe), moshe)
        self.assertEqual(ego_network(st, haim)["possible_selves"], [])
