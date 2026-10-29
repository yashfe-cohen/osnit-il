"""The coherent block resolver (resolve.py): three different-ID namesakes can't all be the same person, must-links
join, and a pair with no competition keeps its pairwise probability."""
import math
import unittest

from osnit import resolve


def _f(nids=(), mobiles=(), emails=()):
    return dict(ids={("phone", m) for m in mobiles}, nids=set(nids), emails=set(emails),
                addresses=set(), cities=set(), orgs=set(), birth=set(), files=set(), srcs=set())


def _lo(p):
    return math.log2(p / (1 - p))


class Resolve(unittest.TestCase):
    def test_three_different_id_namesakes_are_kept_apart(self):
        # A, B, C: same name, three different national IDs, each looks ~0.8 like the others pairwise
        feats = {1: _f(nids={"a"}), 2: _f(nids={"b"}), 3: _f(nids={"c"})}
        hi = _lo(0.8)
        pair = {(1, 2): hi, (1, 3): hi, (2, 3): hi}
        out = resolve.resolve_block([1, 2, 3], feats, pair, {})
        # every pair is between provably different people: each coherent probability must be low, none inflated
        for k, p in out.items():
            self.assertLessEqual(p, 0.5, (k, p))

    def test_a_shared_identifier_forms_one_core(self):
        feats = {1: _f(mobiles={"+972501111111"}), 2: _f(mobiles={"+972501111111"}), 3: _f(nids={"x"})}
        out = resolve.resolve_block([1, 2, 3], feats, {(1, 2): _lo(0.9), (1, 3): _lo(0.6), (2, 3): _lo(0.6)}, {})
        self.assertEqual(out[frozenset((1, 2))], 1.0)              # a shared mobile: one person, certainty

    def test_an_uncontested_pair_keeps_its_pairwise_value(self):
        feats = {1: _f(), 2: _f()}                                 # two unanchored records, no competitors
        out = resolve.resolve_block([1, 2], feats, {(1, 2): _lo(0.8)}, {})
        self.assertAlmostEqual(out[frozenset((1, 2))], 0.8, places=2)

    def test_operator_cannot_link_is_honoured(self):
        feats = {1: _f(), 2: _f(), 3: _f()}
        hi = _lo(0.8)
        out = resolve.resolve_block([1, 2, 3], feats, {(1, 2): hi, (1, 3): hi, (2, 3): hi},
                                    {(1, 2): "different", (2, 1): "different"})
        self.assertEqual(out.get(frozenset((1, 2)), 0.0), 0.0)     # the operator said different: never offered


if __name__ == "__main__":
    unittest.main()
