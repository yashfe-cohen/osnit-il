"""Relations stated in free text (osnit/textrel.py): precise, directed where it matters, and in the graph."""
import os
import tempfile
import unittest

from osnit import textrel
from osnit.config import Config
from osnit.connect import how_connected, resolve_person
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.ingest import import_path
from osnit.network import ego_network
from osnit.store import Store


def _env():
    d = tempfile.mkdtemp()
    cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
    cfg.providers = []
    st = Store(cfg.db_path)
    return d, st, Engine(st, cfg, providers={})


class CorpusTest(unittest.TestCase):
    def test_labelled_corpora(self):
        here = os.path.dirname(__file__)
        for folder, min_recall in (("relcorpus", 1.0), ("relcorpus_holdout", 0.8)):
            r = textrel.evaluate(os.path.join(here, folder))
            self.assertEqual(r["precision"], 1.0, r["errors"])
            self.assertGreaterEqual(r["recall"], min_recall, r["errors"])

    def test_negation_and_two_sentences(self):
        p = ["רחל אזולאי", "אבי מזרחי"]
        self.assertEqual(textrel.find_relations("רחל אזולאי לא עבדה עם אבי מזרחי.", p), [])
        self.assertEqual(textrel.find_relations("רחל אזולאי עבדה. עם אבי מזרחי נפגשה.", p), [])

    def test_direction(self):
        r = textrel.find_relations("עומר דהן כפוף לאבי מזרחי.", ["עומר דהן", "אבי מזרחי"])
        self.assertEqual([(a, b, k) for a, b, k, _c, _s in r], [("אבי מזרחי", "עומר דהן", "text:manages")])


class InTheSystemTest(unittest.TestCase):
    def test_an_article_becomes_a_relation_on_the_map(self):
        d, st, eng = _env()
        art = os.path.join(d, "article.txt")
        with open(art, "w", encoding="utf-8") as f:
            f.write("כתבה מקומית\n\nלפי הפרוטוקול, ד\"ר מיכל סויסה עבדה עם אורי בן שושן במעבדה במשך חמש שנים. "
                    "עומר דהן כפוף למיכל סויסה מאז 2019.\n")
        import_path(eng, art)
        st.reindex_names(1000)
        kinds = {r["kind"] for r in st.q("SELECT kind FROM relations")}
        self.assertIn("text:colleague", kinds)
        self.assertIn("text:manages", kinds)
        ev = st.q1("SELECT e.snippet FROM rel_evidence e JOIN relations r ON r.id=e.relation_id "
                   "WHERE r.kind='text:colleague'")
        self.assertIn("עבדה עם", ev["snippet"])                          # the sentence is the evidence
        michal = resolve_person(st, "מיכל סויסה")[0]
        people = {p["name"]: p for p in ego_network(st, michal)["people"]}
        self.assertIn("עמית/ה", people["אורי בן שושן"]["via"][0]["label"])
        self.assertIn("כפוף/ה", people["עומר דהן"]["via"][0]["label"])    # read from Michal's side
        omer = resolve_person(st, "עומר דהן")[0]
        back = {p["name"]: p for p in ego_network(st, omer)["people"]}
        self.assertIn("מנהל/ת", back["מיכל סויסה"]["via"][0]["label"])  # and from Omer's
        chain = how_connected(st, omer, resolve_person(st, "אורי בן שושן")[0])
        self.assertEqual([n["display"] for n in chain["paths"][0]["nodes"]], ["עומר דהן", "מיכל סויסה", "אורי בן שושן"])

    def test_a_note_ties_the_records_owner(self):
        d, st, eng = _env()
        p = os.path.join(d, "crm.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,הערות\nמשה לוי,0521112233,שותפו העסקי של יעקב שטרנברג מאז 2015\n")
        import_db(eng, p, label="crm", crawl_urls=False)
        row = st.q1("SELECT ea.display a, eb.display b, r.kind FROM relations r JOIN entities ea ON ea.id=r.a_id "
                    "JOIN entities eb ON eb.id=r.b_id WHERE r.kind LIKE 'text:%'")
        self.assertIsNotNone(row)
        self.assertEqual(row["kind"], "text:partner")
        self.assertEqual({row["a"], row["b"]}, {"משה לוי", "יעקב שטרנברג"})


if __name__ == "__main__":
    unittest.main()
