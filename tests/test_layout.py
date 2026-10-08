"""Row layout: the operator sees sample rows (from row 4 on) as the file holds them, and removing a separator joins
the two neighbouring fields into one new column — the file is then catalogued and imported by that layout."""
import json
import os
import tempfile
import unittest

from osnit.importdb import apply_merges, merge_layout, merged_name
from osnit.importqueue import ImportQueue
from tests import helpers


class Merge(unittest.TestCase):
    def test_adjacent_fields_join_into_one_column(self):
        cols, rows = apply_merges(["a", "b", "c", "d"], iter([{"a": "1", "b": "054", "c": "5566123", "d": "x"},
                                                             {"a": "2", "b": None, "c": "7", "d": "y"}]), [["b", "c"]])
        rows = list(rows)
        self.assertEqual(cols, ["a", "b + c", "d"])
        self.assertEqual(rows[0], {"a": "1", "b + c": "054 5566123", "d": "x"})
        self.assertEqual(rows[1]["b + c"], "7")                    # a blank field adds nothing, nothing is lost

    def test_only_adjacent_non_overlapping_runs(self):
        cols = ["a", "b", "c", "d"]
        self.assertEqual(merge_layout(cols, [["a", "c"], ["b", "c", "d"], ["c", "d"], ["zz", "a"], ["a"]]),
                         [["b", "c", "d"]])
        self.assertEqual(apply_merges(cols, [], None)[0], cols)


class LayoutFlow(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    # a phone that the export split in two at its separator: prefix | number
    CSV = "שם|קידומת|מספר|עיר\n" + "".join(f"{n}|05{i}|{5566120 + i}|חיפה\n" for i, n in enumerate(
        ["דוד לוי", "שרה כהן", "יוסי מזרחי", "רחל אברהם", "משה פרץ", "נועה ביטון", "אורי גולן"]))

    def test_samples_from_row_four_and_merged_phone_imports(self):
        job = self.q.add_bytes(self.CSV.encode(), "split.csv", delete_raw=False, review=True)
        self.q.run_pending()
        t = json.loads(self.store.q1("SELECT preview FROM imports WHERE id=?", (job["id"],))["preview"])["tables"][0]
        self.assertEqual(t["raw_rows"][:3], [4, 5, 6])              # not the first rows of the file
        self.assertEqual(t["raw"][0]["שם"], "רחל אברהם")
        self.assertEqual(t["delim"], "|")
        self.assertNotIn("phone", {c["type"] for c in t["columns"]})

        merged = merged_name(["קידומת", "מספר"])
        res = self.q.repreview(job["id"], {t["table"]: {"__merge__": [["קידומת", "מספר"]]}})
        rt = res["tables"][0]
        self.assertEqual(rt["layout_cols"], ["שם", merged, "עיר"])
        self.assertEqual(rt["cols"], ["שם", "קידומת", "מספר", "עיר"])   # the raw row keeps the file's own fields
        self.assertEqual({c["name"]: c["type"] for c in rt["columns"]}[merged], "phone")

        # approving with type choices only keeps the layout the operator set
        self.assertTrue(self.q.approve(job["id"], {t["table"]: {"עיר": "city"}}))
        self.q.run_pending()
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='phone' AND key='+972505566120'"))
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='phone' AND key='+972565566126'"))

        # putting the separator back restores the file's own columns
        res = self.q.repreview(job["id"], {t["table"]: {"__merge__": []}})
        self.assertEqual(res["tables"][0]["layout_cols"], ["שם", "קידומת", "מספר", "עיר"])


if __name__ == "__main__":
    unittest.main()
