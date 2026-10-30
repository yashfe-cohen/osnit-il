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
        for folder, min_recall in (("relcorpus", 1.0), ("relcorpus_holdout", 1.0), ("relcorpus_holdout2", 1.0)):
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


class NewFormsTest(unittest.TestCase):
    def rels(self, text, persons, **kw):
        return sorted((a, b, k) for a, b, k, _c, _s in textrel.find_relations(text, persons, **kw))

    def test_relative_clause_list_and_pronoun(self):
        self.assertEqual(self.rels("Adi Zur, who reports to Gil Amir, resigned.", ["Adi Zur", "Gil Amir"]),
                         [("Gil Amir", "Adi Zur", "text:manages")])
        self.assertEqual(len(self.rels("יגאל נוי עבד עם מירב סלע ועם עדי צור.", ["יגאל נוי", "מירב סלע", "עדי צור"])), 2)
        r = self.rels("Gil Amir spoke. He worked with Adi Zur.", ["Gil Amir", "Adi Zur"])
        self.assertEqual([({a, b}, k) for a, b, k in r], [({"Gil Amir", "Adi Zur"}, "text:colleague")])
        # a pronoun with two candidates in the previous sentence is not resolved
        self.assertEqual(self.rels("A Bb and Cc Dd came. She worked with Ee Ff.", ["A Bb", "Cc Dd", "Ee Ff"]), [])

    def test_period_in(self):
        self.assertEqual(textrel.period_in("עבדו יחד בין 2012 ל-2016"), ("2012-01", "2016-12", "text"))
        self.assertEqual(textrel.period_in("partners since 2019"), ("2019-01", None, "text"))
        self.assertEqual(textrel.period_in("נפגשו ב-2014 בכנס"), ("2014-01", "2014-12", "text"))
        self.assertIsNone(textrel.period_in("עבדו יחד שנים"))
        self.assertIsNone(textrel.period_in("ברחוב הרצל 2015"))   # a house number glued to a word is not a year


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

    def test_years_stated_in_the_text_go_with_the_relation(self):
        d, st, eng = _env()
        art = os.path.join(d, "article.txt")
        with open(art, "w", encoding="utf-8") as f:
            f.write("כתבה\n\nמיכל סויסה עבדה עם אורי בן שושן בין 2012 ל-2016 במעבדה.\n")
        import_path(eng, art)
        st.reindex_names(1000)
        row = st.q1("SELECT p.lo, p.hi, p.basis FROM rel_period p JOIN relations r ON r.id=p.relation_id "
                    "WHERE r.kind='text:colleague'")
        self.assertEqual((row["lo"], row["hi"], row["basis"]), ("2012-01", "2016-12", "text"))
        michal = resolve_person(st, "מיכל סויסה")[0]
        p = {x["name"]: x for x in ego_network(st, michal)["people"]}["אורי בן שושן"]
        self.assertIn("2012–2016", p["via"][0]["label"])
        self.assertNotIn("אורי בן שושן", {x["name"] for x in ego_network(st, michal, at=2020)["people"]
                                         if any(l["kind"] == "text:colleague" for l in x["via"])})

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
