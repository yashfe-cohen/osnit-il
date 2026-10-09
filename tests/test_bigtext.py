"""Huge text files are streamed, never read whole; detection never fails an upload."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

import osnit.structure as structure
from osnit.detect import detect
from osnit.importdb import big_text, cheap_count, raw_tables
from osnit.ingest import import_text_chunks
from tests import helpers


class BigText(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.small = mock.patch.object(structure, "BIG_TEXT", 1024)     # treat these test files as "huge"
        self.small.start()

    def tearDown(self):
        self.small.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, text, newline="\n"):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text.replace("\n", newline))
        return p

    def test_delimited_rows_are_streamed_and_nothing_is_lost(self):
        lines = ["ייצוא מערכת לקוחות", "שם|טלפון|מייל|עיר"]
        lines += [f"אדם {i}|05{i % 10}-{1000000 + i}|u{i}@x.co.il|חיפה" for i in range(400)]
        lines += ["דנה לוי|0541234567|dana@x.co.il|תל אביב|רחוב הרצל 5", "קצר|0529999999"]
        p = self.write("dump.txt", "\n".join(lines) + "\n", newline="\r")        # old-Mac line endings
        self.assertTrue(big_text(p))
        (table, cols, rows), = list(raw_tables(p))
        rows = list(rows)
        self.assertEqual(cols, ["שם", "טלפון", "מייל", "עיר"])
        self.assertEqual(len(rows), 402)
        self.assertEqual(rows[-2]["עיר"], "תל אביב|רחוב הרצל 5")           # extra separator kept in the last field
        self.assertEqual(rows[-1], {"שם": "קצר", "טלפון": "0529999999", "מייל": None, "עיר": None})
        n, exact = cheap_count(p)[table]
        self.assertFalse(exact)
        self.assertLess(abs(n - 402), 10)

    def test_key_value_blocks_across_chunks(self):
        blocks = [f"שם: אדם {i}\nטלפון: 05{i % 10}{1000000 + i}\nמייל: a{i}@x.co.il\n" for i in range(300)]
        p = self.write("blocks.txt", "\n".join(blocks))
        with mock.patch.object(structure, "CHUNK_LINES", 50):
            (_, cols, rows), = list(raw_tables(p))
            rows = list(rows)
        self.assertEqual(len(rows), 300)
        self.assertEqual(rows[299]["מייל"], "a299@x.co.il")

    def test_free_text_is_extracted_piece_by_piece(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            text = "".join(f"יומן {i}: פגישה עם הספק בנושא הזמנה {i * 7}.\n" for i in range(1500))
            text += "פגישה עם הצוות. ליצירת קשר: dana.levi@walla.co.il או 054-6613972.\n"
            p = self.write("notes.txt", text)
            r = import_text_chunks(eng, p, chunk_chars=20_000)
            self.assertGreaterEqual(r["imported"], 3)
            self.assertTrue(store.q1("SELECT 1 FROM entities WHERE type='email' AND key='dana.levi@walla.co.il'"))
        finally:
            srv.shutdown()


class DetectNeverCrashes(unittest.TestCase):
    def test_head_cut_inside_a_quoted_field(self):
        body = b'name,notes,phone\r' + b'"a","multi\rline,0541234567\r' * 400 + b'"b","open quote'
        d = detect(body[:16384], "x.csv")
        self.assertEqual(d["kind"], "csv")


if __name__ == "__main__":
    unittest.main()
