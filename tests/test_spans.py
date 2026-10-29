"""Marker tagging (***…***), heavy-file streaming, and file-list management."""
import json
import os
import tempfile
import unittest

from osnit.importdb import _csv_rows, count_sql_tuples
from osnit.importqueue import ImportQueue
from osnit.spans import apply, augment, learn, parse_marked, virtual_name
from osnit.sqldump import stream_sql_dump
from tests import helpers


def ex(marked):
    clean, spans = parse_marked(marked)
    a, z, _ = spans[0]
    return dict(text=clean, start=a, end=z)


class Spans(unittest.TestCase):
    def test_parse_marked(self):
        clean, spans = parse_marked("***יונתן חייט***, 0508317945, ת.ז: ***123456782***")
        self.assertEqual(clean, "יונתן חייט, 0508317945, ת.ז: 123456782")
        self.assertEqual([p for _, _, p in spans], ["יונתן חייט", "123456782"])
        self.assertEqual(clean[spans[1][0]:spans[1][1]], "123456782")

    def test_field_context_and_shape_rules(self):
        rows = ["דנה לוי, 0546613972, ת.ז: 987654321", "אבי כהן, 0528841796, ת.ז: 111222333"]
        name = learn([ex("***יונתן חייט***, 0508317945, ת.ז: 123456782")])
        ident = learn([ex("יונתן חייט, 0508317945, ת.ז: ***123456782***")])
        phone = learn([ex("יונתן חייט, ***0508317945***, ת.ז: 123456782")])
        self.assertEqual([(apply(name, r) or [None])[0] for r in rows], ["דנה לוי", "אבי כהן"])
        self.assertEqual([(apply(ident, r) or [None])[0] for r in rows], ["987654321", "111222333"])
        self.assertEqual([(apply(phone, r) or [None])[0] for r in rows], ["0546613972", "0528841796"])
        self.assertFalse(apply(ident, "ללא פרטים"))

    def test_augment_adds_virtual_columns(self):
        rule = learn([ex("ת.ז: ***123456782*** טל 050")])
        row = augment({"details": "ת.ז: 555666777 טל 052"}, [dict(col="details", label="ת\"ז", rule=rule)])
        self.assertEqual(row[virtual_name("details", "ת\"ז")], "555666777")


class Streaming(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_csv_is_streamed_with_detected_encoding(self):
        p = os.path.join(self.dir, "x.csv")
        with open(p, "w", encoding="windows-1255", newline="") as f:
            f.write("שם;טלפון\n" + "".join(f"אדם {i};05412345{i:02d}\n" for i in range(50)))
        cols, rows = _csv_rows(p, ".csv")
        self.assertEqual(cols, ["שם", "טלפון"])
        first = next(rows)
        self.assertEqual(first["שם"], "אדם 0")
        self.assertEqual(sum(1 for _ in rows), 49)

    def test_sql_dump_streams_tables_and_counts(self):
        p = os.path.join(self.dir, "d.sql")
        with open(p, "w", encoding="utf-8") as f:
            f.write("-- dump\nCREATE TABLE `a` (`id` int, `note` text);\n"
                    "INSERT INTO `a` (`id`,`note`) VALUES (1,'x; y'),\n(2,'z');\n"
                    "INSERT INTO `b` (`k`) VALUES (7);\n")
        got = {t: (cols, list(rows)) for t, cols, rows in stream_sql_dump(p, "utf-8")}
        self.assertEqual(got["a"][0], ["id", "note"])
        self.assertEqual([r["note"] for r in got["a"][1]], ["x; y", "z"])
        self.assertEqual(len(got["b"][1]), 1)
        self.assertEqual(count_sql_tuples(p), 3)

    def test_partially_read_table_does_not_leak_into_next(self):
        p = os.path.join(self.dir, "d.sql")
        with open(p, "w", encoding="utf-8") as f:
            f.write("INSERT INTO `a` (`id`) VALUES (1),(2),(3);\nINSERT INTO `b` (`id`) VALUES (9);\n")
        out = []
        for t, cols, rows in stream_sql_dump(p, "utf-8"):
            out.append((t, next(rows)["id"]))         # read one row, skip the rest
        self.assertEqual([t for t, _ in out], ["a", "b"])
        self.assertEqual(str(out[1][1]), "9")


class Studio(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    CSV = ("id,details\n1,\"יונתן חייט, 0508317945, ת.ז: 123456782\"\n"
           "2,\"דנה לוי, 0546613972, ת.ז: 987654321\"\n3,\"אבי כהן, 0528841796, ת.ז: 111222333\"\n")

    def _review(self, body, name):
        job = self.q.add_bytes(body.encode(), name, delete_raw=False, review=True)
        self.q.run_pending()
        return self.store.q1("SELECT * FROM imports WHERE id=?", (job["id"],))

    def _items(self, marked, typ, label):
        clean, spans = parse_marked(marked)
        a, z, _ = spans[0]
        return dict(col="details", text=clean, start=a, end=z, type=typ, label=label)

    def test_marked_pieces_split_column_and_teach_next_file(self):
        job = self._review(self.CSV, "a.csv")
        self.assertEqual(job["state"], "review")
        table = json.loads(job["preview"])["tables"][0]
        self.assertEqual(len(table["raw"]), 3)
        items = [self._items("***יונתן חייט***, 0508317945, ת.ז: 123456782", "name", "שם"),
                 self._items("יונתן חייט, ***0508317945***, ת.ז: 123456782", "phone", "טלפון"),
                 self._items("יונתן חייט, 0508317945, ת.ז: ***123456782***", "national_id", "ת\"ז")]
        res = self.q.teach_spans(job["id"], table["table"], items, teach=True)
        cols = {c["name"]: c for c in res["tables"][0]["columns"]}
        self.assertEqual(cols["details ▸ טלפון"]["type"], "phone")
        self.assertEqual(cols["details ▸ ת\"ז"]["type"], "national_id")
        self.assertTrue(self.q.approve(job["id"]))
        self.q.run_pending()
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='phone' AND key LIKE '%546613972'"))
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='person' AND display='אבי כהן'"))

        # a second file with the same column header gets the learned pieces with no marking at all
        job2 = self._review(self.CSV.replace("יונתן חייט", "רונית לוי"), "b.csv")
        names = [c["name"] for c in json.loads(job2["preview"])["tables"][0]["columns"]]
        self.assertIn("details ▸ טלפון", names)

        # removing a rule in a job keeps the learned twin off there
        t2 = json.loads(job2["preview"])["tables"][0]["table"]
        res = self.q.teach_spans(job2["id"], t2, [], remove=[("details", "טלפון")])
        names = [c["name"] for c in res["tables"][0]["columns"]]
        self.assertNotIn("details ▸ טלפון", names)
        self.assertIn("details ▸ ת\"ז", names)

    def test_suggest_types(self):
        s = {x["piece"]: x["type"] for x in self.q.suggest_types(["יונתן חייט", "123456782", "0508317945", "a@b.co.il"])}
        self.assertEqual(s["יונתן חייט"], "name")
        self.assertEqual(s["123456782"], "national_id")
        self.assertEqual(s["0508317945"], "phone")
        self.assertEqual(s["a@b.co.il"], "email")

    def test_remove_and_clear_file_list(self):
        self.q.add_bytes("name,email\nאבי כהן,avi@x.co.il\n".encode(), "one.csv")
        self.q.add_bytes("name,email\nדנה לוי,dana@x.co.il\n".encode(), "two.csv")
        self.q.run_pending()
        ids = [r["id"] for r in self.q.list()]
        r = self.q.remove([ids[0]], purge_data=True)
        self.assertEqual(r["removed"], 1)
        self.assertEqual(len(self.q.list()), 1)
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='dana@x.co.il'") or
                        self.store.q1("SELECT 1 FROM entities WHERE key='avi@x.co.il'"))
        self.q.clear("all")
        self.assertEqual(self.q.list(), [])
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='email'"))   # data kept without purge


if __name__ == "__main__":
    unittest.main()
