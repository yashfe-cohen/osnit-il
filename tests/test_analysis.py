"""Deep file analysis: semantic column types, structure finding, learning, custom types, cross-file links,
deletion per file and reset."""
import json
import os
import tempfile
import unittest
import urllib.request

from osnit.analyze import analyze_file
from osnit.catalog import plan_columns
from osnit.importqueue import ImportQueue
from osnit.semantic import CustomType, Registry, address_key, pattern_from_examples, value_kind
from osnit.server import make_server, serve_in_thread
from osnit.structure import delimited, html_tables, json_tables, kv_blocks, typed_lines
from tests import helpers

CSV = """id,שם,JJDBD,mail,pw,x7,notes,usr,tz,לינקדאין
1,יונתן חייט,"הרצל 5, תל אביב",yon@gmail.com,5f4dcc3b5aa765d61d8327deb882cf99,חיפה,לקוח ותיק,yoni_h1,123456782,linkedin.com/in/yonatan-h
2,דנה לוי,ביאליק 12 רמת גן,dana@walla.co.il,5f4dcc3b5aa765d61d8327deb882cf99,ירושלים,,dana.l,123456782,
3,אבי כהן,"רח' יפו 30, ירושלים",avi@x.co.il,5f4dcc3b5aa765d61d8327deb882cf99,תל אביב,חדש,avic_2,123456782,
"""
LEADS = """רשימת פניות — מרץ

שם: Yonatan Hayat
מייל: yon@gmail.com
נייד: 052-4471893
כתובת: רח' הרצל 5, תל אביב
מספר עובד: EMP-10023

שם: רונית לוי
מייל: ronit.levy@bgu.ac.il
נייד: 054-1234598
מספר עובד: EMP-88123
"""


class Values(unittest.TestCase):
    def test_value_kinds(self):
        cases = {"yon@gmail.com": "email", "050-8317945": "phone", "הרצל 5, תל אביב": "address",
                 "ביאליק 12 רמת גן": "address", "שד' רוטשילד 22": "address", "Herzl St 5, Tel Aviv": "address",
                 "תל אביב": "city", "יונתן חייט": "name", "192.168.1.1": "ip", "2020-01-04": "date",
                 "5f4dcc3b5aa765d61d8327deb882cf99": "hash", "123456782": "il_id", "@yoni_h": "username",
                 "linkedin.com/in/x": "profile", "₪1,200": "money", "נקבה": "gender", "בנק הפועלים בע\"מ": "org"}
        for v, k in cases.items():
            self.assertEqual(value_kind(v), k, v)
        for v in ("מנכ\"ל 2", "קומה 3", "שירות לקוחות 24"):
            self.assertNotEqual(value_kind(v), "address", v)       # a word and a number is not an address

    def test_address_key_ignores_street_word_and_hyphen(self):
        self.assertEqual(address_key("רח' הרצל 5, תל-אביב יפו"), address_key("הרצל 5 תל אביב"))

    def test_pattern_from_examples(self):
        rx = pattern_from_examples(["AB-12345", "XY-9981"])
        ct = CustomType("u_x", "x", (), rx)
        self.assertTrue(ct.matches("QQ-1234") and ct.matches("ZZ-55555"))
        self.assertFalse(ct.matches("Q-1234") or ct.matches("AB12345"))


class Columns(unittest.TestCase):
    def rows(self):
        import csv
        import io
        return list(csv.DictReader(io.StringIO(CSV)))

    def test_unknown_header_typed_by_content_and_secrets_dropped(self):
        rows = self.rows()
        p = plan_columns(list(rows[0]), rows)
        by = {c.name: c for c in p.columns}
        self.assertEqual((by["JJDBD"].type, by["JJDBD"].status, by["JJDBD"].how), ("address", "entity", "content"))
        self.assertEqual(by["usr"].type, "username")
        self.assertEqual(by["x7"].type, "city")
        self.assertEqual(by["לינקדאין"].type, "profile")
        self.assertEqual((by["notes"].status, by["notes"].label), ("attribute", "הערות"))   # unknown, named itself
        for col in ("pw", "tz"):
            self.assertEqual(by[col].status, "sensitive")
            self.assertEqual(by[col].samples, [])                  # secrets never even shown
        self.assertEqual(by["id"].status, "internal")

    def test_learned_header_is_used_when_content_is_ambiguous(self):
        mem = {"jjdbd": {"type": "address", "source": "auto"}}
        p = plan_columns(["שם", "JJDBD"], [{"שם": "דנה לוי", "JJDBD": "ליד הים"}], memory=mem)
        self.assertEqual(p.columns[1].type, "address")
        self.assertEqual(p.columns[1].how, "learned")

    def test_user_override_and_custom_type(self):
        reg = Registry([CustomType("u_emp", "מספר עובד", ("emp_no",), r"EMP-\d{5}")])
        rows = [{"name": "דנה לוי", "emp_no": "EMP-10023", "code": "EMP-88123"}]
        p = plan_columns(list(rows[0]), rows, registry=reg)
        self.assertEqual(p.columns[1].type, "u_emp")               # by header
        self.assertEqual(p.columns[2].type, "u_emp")               # by how the value looks
        p = plan_columns(list(rows[0]), rows, registry=reg, overrides={"code": "skip"})
        self.assertEqual(p.columns[2].status, "sensitive")


class Structure(unittest.TestCase):
    def test_finders(self):
        name, cols, recs = kv_blocks(LEADS)
        self.assertEqual(cols, ["שם", "מייל", "נייד", "כתובת", "מספר עובד"])   # the title line is not a field
        self.assertEqual(len(recs), 2)
        _, cols, recs = delimited("name|phone\nדנה לוי|054-6613972\nאבי כהן|052-1112233\nרון בר|050-7654321")
        self.assertEqual((cols, len(recs)), (["name", "phone"], 3))
        _, cols, recs = typed_lines("דנה לוי 054-6613972 dana@walla.co.il\nאבי כהן, 052-1112233, avi@x.co.il\n"
                                    "רון בר - 050-7654321 - ron@y.co.il\nסתם שורה")
        self.assertEqual(len(recs), 3)
        self.assertIn("מייל", cols)
        t = html_tables("<table><tr><th>שם</th><th>טלפון</th></tr><tr><td>א ב</td><td>050-8317945</td></tr>"
                        "<tr><td>ג ד</td><td>054-6613972</td></tr></table>")
        self.assertEqual(t[0][1], ["שם", "טלפון"])
        j = json_tables({"data": {"users": [{"name": "a b", "contact": {"email": "a@b.co"}}, {"name": "c d"}]}})
        self.assertEqual(j[0][0], "data.users")
        self.assertIn("contact.email", j[0][1])


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def _file(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_two_files_connect_through_shared_identifiers(self):
        self.store.save_custom_type("u_emp", "מספר עובד", ["מספר עובד"], r"EMP-\d{5}")
        j1 = self.q.add_file(self._file("customers.csv", CSV), delete_raw=True)["id"]
        self.q.run_pending()
        self.assertTrue(self.store.q1("SELECT 1 FROM field_memory WHERE header_key='jjdbd' AND type='address'"))
        # stage 1 of the second file already sees the overlap with the first
        a = analyze_file(self.store, self._file("leads.txt", LEADS))
        self.assertGreaterEqual(a["known"]["count"], 2)
        owners = {o["name"] for k in a["known"]["examples"] for o in k["owners"]}
        self.assertIn("יונתן חייט", owners)
        j2 = self.q.add_file(self._file("leads.txt", LEADS), delete_raw=True)["id"]
        self.q.run_pending()
        d = self.q.detail(j2)
        self.assertEqual(d["state"], "done")
        self.assertGreaterEqual(d["summary"]["linked"].get("email", 0), 1)
        self.assertGreaterEqual(d["summary"]["linked"].get("address", 0), 1)    # "רח' הרצל 5" == "הרצל 5"
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='u_emp' AND key='EMP-10023'"))
        # the gmail belongs to both people, from both files
        from osnit.linking import connections
        gm = self.store.q1("SELECT id FROM entities WHERE type='email' AND key='yon@gmail.com'")["id"]
        names = {o["name"] for o in connections(self.store, gm)["owners"]}
        self.assertEqual(names, {"יונתן חייט", "Yonatan Hayat"})
        # unknown columns are kept on the person under their original header; secrets are not stored
        keep = {r["name"] for r in self.store.q("SELECT name FROM attributes")}
        self.assertIn("notes", keep)
        self.assertFalse(keep & {"pw", "tz"})
        self.assertFalse(self.store.q1("SELECT 1 FROM evidence WHERE snippet LIKE '%5f4dcc3b%'"))
        # delete one file's data: shared facts survive with the other file's evidence
        self.q.purge(j2)
        self.assertEqual(self.q.detail(j2)["state"], "purged")
        self.assertFalse(self.store.q1("SELECT 1 FROM entities WHERE key='ronit.levy@bgu.ac.il'"))
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='yon@gmail.com'"))
        self.assertTrue(self.store.q1("SELECT 1 FROM sources WHERE import_id=?", (j1,)))

    def test_review_stops_before_import_and_overrides_apply(self):
        jid = self.q.add_bytes(CSV.encode(), "c.csv", delete_raw=False, review=True)["id"]
        self.q.run_pending()
        d = self.q.detail(jid)
        self.assertEqual(d["state"], "review")
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM entities")["n"], 0)     # nothing written yet
        self.assertTrue(d["preview"]["tables"][0]["samples"])
        self.assertTrue(self.q.approve(jid, {"c.csv": {"usr": "skip"}}, teach=True))
        self.q.run_pending()
        self.assertEqual(self.q.detail(jid)["state"], "done")
        self.assertFalse(self.store.q1("SELECT 1 FROM entities WHERE type='username'"))
        self.assertEqual(self.store.q1("SELECT source FROM field_memory WHERE header_key='usr'")["source"], "user")

    def test_reset_scopes(self):
        self.q.add_bytes(CSV.encode(), "c.csv")
        self.q.run_pending()
        self.store.add_source("https://example.org/a", origin="seed")
        self.store.reset("files")
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM entities")["n"], 0)
        self.assertTrue(self.store.q1("SELECT 1 FROM sources WHERE url='https://example.org/a'"))
        self.store.reset("all")
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM sources")["n"], 0)


class Api(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))
        self.api = make_server(self.svc, "127.0.0.1", 0, queue=self.q)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def call(self, path, body=None):
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_types_fields_imports_reset(self):
        code, r = self.call("/api/types", {"label": "מספר רכב", "examples": ["12-345-67", "123-45-678"]})
        self.assertEqual(code, 200)
        self.assertTrue(all(x["matches"] for x in r["examples"]))
        self.assertTrue(any(c["key"] == r["key"] for c in self.call("/api/types")[1]["custom"]))
        self.assertEqual(self.call("/api/fields", {"header": "JJDBD", "type": "address"})[0], 200)
        self.assertEqual(self.call("/api/fields")[1]["memory"][0]["source"], "user")
        jid = self.q.add_bytes(CSV.encode(), "c.csv", review=True)["id"]
        self.q.run_pending()
        code, d = self.call(f"/api/imports/{jid}")
        self.assertEqual((code, d["state"]), (200, "review"))
        self.assertEqual(self.call(f"/api/imports/{jid}/approve", {"overrides": {"c.csv": {"notes": "skip"}}})[0], 200)
        self.q.run_pending()
        self.assertEqual(self.call(f"/api/imports/{jid}")[1]["state"], "done")
        self.assertEqual(self.call("/api/reset", {"scope": "all"})[0], 400)            # needs explicit confirmation
        code, r = self.call("/api/reset", {"scope": "all", "confirm": "RESET"})
        self.assertEqual(code, 200)
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM entities")["n"], 0)


if __name__ == "__main__":
    unittest.main()
