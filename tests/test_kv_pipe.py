"""Key:value blocks: several "key: value" pairs on one line separated by " | " (common in OCR of ID cards and
forms) are separate fields, so the ID and phone become identifiers; a value that merely contains " | " stays whole."""
import unittest

from osnit.structure import kv_blocks


class KvPipe(unittest.TestCase):
    def test_pipe_separated_pairs_are_separate_fields(self):
        t = ("Name: Yonatan Hayat\nID: 000000018 | Phone: 052-3344556\nEmail: y@alpha.co.il\n\n"
             "Name: Dana Levi\nID: 000000026 | Phone: 054-7718293\nEmail: d@alpha.co.il\n")
        _, cols, recs = kv_blocks(t)
        self.assertEqual(cols, ["Name", "ID", "Phone", "Email"])
        self.assertEqual(recs[0]["ID"], "000000018")
        self.assertEqual(recs[1]["Phone"], "054-7718293")

    def test_value_with_a_pipe_but_no_second_key_stays_whole(self):
        t = ("שם: רונית ברק\nתפקיד: מנהלת | רכש\nטלפון: 054-7718293\n\n"
             "שם: יואב שגיא\nתפקיד: מהנדס | פיתוח\nטלפון: 052-6612309\n")
        _, _, recs = kv_blocks(t)
        self.assertEqual(recs[0]["תפקיד"], "מנהלת | רכש")


if __name__ == "__main__":
    unittest.main()
