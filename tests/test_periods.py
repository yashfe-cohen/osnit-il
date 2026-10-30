"""Time on links (osnit/periods.py): when a link was true, and whether two people's links overlap."""
import os
import tempfile
import unittest

from osnit import periods
from osnit.config import Config
from osnit.connect import how_connected, resolve_person
from osnit.engine import Engine
from osnit.importdb import import_db
from osnit.network import ego_network
from osnit.store import Store


class PeriodRulesTest(unittest.TestCase):
    def test_header_roles(self):
        for h in ("מתאריך", "תאריך כניסה", "from", "Start date", "since"):
            self.assertEqual(periods.header_role(h), "start", h)
        for h in ("עד תאריך", "עד", "תאריך עזיבה", "until", "end_date"):
            self.assertEqual(periods.header_role(h), "end", h)
        for h in ("תאריך עדכון", "שנה", "updated", "date"):
            self.assertEqual(periods.header_role(h), "point", h)
        for h in ("תאריך לידה", "birth date", "dob", "כתובת"):
            self.assertIsNone(periods.header_role(h), h)

    def test_parse_and_row_period(self):
        self.assertEqual(periods.parse_when("2014"), ("2014-01", "2014-12"))
        self.assertEqual(periods.parse_when("01/03/2012"), ("2012-03", "2012-03"))
        self.assertEqual(periods.parse_when("2012-2016"), ("2012-01", "2016-12"))
        self.assertIsNone(periods.parse_when("הרצל 5"))
        self.assertEqual(periods.row_period([("מתאריך", "2012"), ("עד", "2016"), ("תאריך לידה", "1980")]),
                         ("2012-01", "2016-12", "row"))
        self.assertEqual(periods.row_period([("from", "2019")]), ("2019-01", None, "row"))   # still there
        self.assertIsNone(periods.row_period([("תאריך לידה", "1980-02-02")]))

    def test_file_year(self):
        self.assertEqual(periods.file_year("פנקס בוחרים 2015.csv")[:2], ("2015-01", "2015-12"))
        self.assertIsNone(periods.file_year("people.csv"))
        self.assertIsNone(periods.file_year("2015 vs 2019.csv"))      # two years: not dependable

    def test_overlap(self):
        a, b = ("2012-03", "2016-08", "row"), ("2014-01", "2018-12", "row")
        self.assertEqual(periods.overlap(a, b)[:2], ("overlap", 1.0))
        self.assertEqual(periods.overlap(a, ("2017-03", "2018-01", "row"))[0], "near")
        self.assertEqual(periods.overlap(("2001-01", "2003-12", "row"), ("2019-01", None, "row"))[:2], ("apart", 0.15))
        self.assertEqual(periods.overlap(a, None)[:2], ("unknown", 1.0))   # missing time is never a penalty


class PeriodsInTheGraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cfg = Config(db_path=os.path.join(d, "x.db"), request_delay=0, workers=1)
        cfg.providers = []
        cls.st = Store(cfg.db_path)
        eng = Engine(cls.st, cfg, providers={})
        p = os.path.join(d, "a.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,כתובת,מתאריך,עד תאריך,תאריך לידה\n"
                    "דנה גל,0521112233,הרצל 5 גן יבנה,01/03/2012,2016-08-31,1980-02-02\n"
                    "רון כהן,0534445566,הרצל 5 גן יבנה,2014,2018,1979-01-01\n"
                    "עומר דהן,0541231299,הרצל 5 גן יבנה,2021,,1990-01-01\n")
        import_db(eng, p, label="a", crawl_urls=False)
        q = os.path.join(d, "b.csv")
        with open(q, "w", encoding="utf-8") as f:
            f.write("שם מלא,טלפון נייד,כתובת\nאבי מזרחי,0549998877,הרצל 5 גן יבנה\n")
        import_db(eng, q, label="פנקס בוחרים 2015", crawl_urls=False)
        cls.st.reindex_names(1000)
        cls.id = {n: resolve_person(cls.st, n)[0] for n in ("דנה גל", "רון כהן", "עומר דהן", "אבי מזרחי")}

    def people(self, **kw):
        return {p["name"]: p for p in ego_network(self.st, self.id["דנה גל"], **kw)["people"]}

    def test_the_same_years_tie_closely_other_years_barely(self):
        p = self.people()
        self.assertGreater(p["רון כהן"]["strength"], 3 * p["עומר דהן"]["strength"])
        self.assertIn("באותה תקופה", p["רון כהן"]["via"][0]["when"])
        self.assertIn("לא באותה תקופה", p["עומר דהן"]["via"][0]["when"])
        self.assertIn("2015", p["אבי מזרחי"]["via"][0]["when"])            # the file's year counts, weakly

    def test_who_was_around_in_a_year(self):
        self.assertEqual(set(self.people(at=2015)), {"רון כהן", "אבי מזרחי"})
        self.assertEqual(set(self.people(at=2022)), set())                # Dana had left by then

    def test_the_chain_reports_the_years(self):
        r = how_connected(self.st, self.id["דנה גל"], self.id["רון כהן"])
        self.assertIn("באותה תקופה", r["paths"][0]["text"])

    def test_purge_removes_the_periods(self):
        n = self.st.q1("SELECT COUNT(*) n FROM rel_period")["n"]
        self.assertGreater(n, 0)
        sid = self.st.q1("SELECT source_id FROM rel_period LIMIT 1")["source_id"]
        self.st.purge_sources(f"id = {int(sid)}")
        self.assertIsNone(self.st.q1("SELECT 1 x FROM rel_period WHERE source_id=?", (sid,)))
        type(self).setUpClass()                                           # the other tests need the data back


if __name__ == "__main__":
    unittest.main()
