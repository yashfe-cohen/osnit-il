"""Reconstructing a full ת"ז split across a 7-digit column and a 2-digit 'Family Tz' column: the correct assembly
is found by maximising the check-digit validity rate, and a coincidence never passes."""
import unittest

from osnit.idrecon import assemble, detect_id_join
from osnit.semantic import il_id_ok


def valid_ids(n):
    out, x = [], 100000000
    while len(out) < n and x < 500000000:
        s = str(x)
        if il_id_ok(s):
            out.append(s)
        x += 7
    return out


class IdRecon(unittest.TestCase):
    def test_family_leading(self):
        ids = valid_ids(40)
        pairs = [(i[2:], i[:2]) for i in ids]            # tz = last 7 digits, family = first 2  -> pattern bb+a
        d = detect_id_join(pairs)
        self.assertIsNotNone(d)
        self.assertEqual(d["pattern"], "bb+a")
        self.assertGreaterEqual(d["valid_rate"], 0.99)
        for i in ids[:5]:
            self.assertEqual(assemble(i[2:], i[:2], d["pattern"]), i)   # reconstructs the original exactly

    def test_family_trailing(self):
        ids = valid_ids(40)
        pairs = [(i[:7], i[7:]) for i in ids]            # tz = first 7, family = last 2 -> a+bb
        self.assertEqual(detect_id_join(pairs)["pattern"], "a+bb")

    def test_one_each_end(self):
        ids = valid_ids(40)
        pairs = [(i[1:8], i[0] + i[8]) for i in ids]     # one digit each end -> b.a.b
        self.assertEqual(detect_id_join(pairs)["pattern"], "b.a.b")

    def test_no_false_positive_on_unrelated_columns(self):
        pairs = [(str(1000000 + k * 3), str(10 + (k % 80))) for k in range(50)]
        self.assertIsNone(detect_id_join(pairs))         # not a real split -> nothing convincing -> no reconstruction


if __name__ == "__main__":
    unittest.main()
