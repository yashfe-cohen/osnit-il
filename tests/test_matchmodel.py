"""The match model (matchmodel.py): date normalisation, the namesake prior that reasons about how common a name is,
and the Poisson fit that separates duplicates from namesakes."""
import unittest

from osnit import matchmodel as mm


class DatesAndFamilies(unittest.TestCase):
    def test_iso_date_normalises_both_formats(self):
        self.assertEqual(mm.iso_date("15/03/1979"), "1979-03-15")
        self.assertEqual(mm.iso_date("15.03.1979"), "1979-03-15")
        self.assertEqual(mm.iso_date("1979-03-15"), "1979-03-15")
        self.assertEqual(mm.iso_date("1979"), "1979")
        self.assertIsNone(mm.iso_date("not a date"))
        self.assertIsNone(mm.iso_date("40/40/1979"))

    def test_same_date_either_format_agrees(self):
        self.assertEqual(mm._birth_level({"1979-03-15"}, {"1979-03-15"}), "same")
        self.assertEqual(mm._birth_level({"1979-03-15"}, {"1979-11-02"}), "different")
        self.assertEqual(mm._birth_level({"1979"}, {"1979-03-15"}), "year")

    def test_token_family_links_scripts_and_nicknames(self):
        fam = set(mm.token_family("יצחק"))
        self.assertIn("yitzhak", {f.lower() for f in fam})          # Hebrew pulls in its Latin spellings
        self.assertIn("איציק", fam)                                 # and its nicknames


class NamesakePrior(unittest.TestCase):
    def test_a_common_name_predicts_more_namesakes_than_a_rare_one(self):
        self.assertGreater(mm.token_population_share("כהן"), mm.token_population_share("רוזנצוייג"))
        self.assertGreater(mm.token_population_share("יצחק"), mm.token_population_share("זבולון"))

    def test_name_prior_is_higher_for_a_rare_name(self):
        mod = mm.Model()
        rare = mod.name_prior_bits(mu=0.1, same_file=False, pi=0.3)
        common = mod.name_prior_bits(mu=8.0, same_file=False, pi=0.3)
        self.assertGreater(rare, common)                            # fewer namesakes -> a same name says more

    def test_same_file_pair_starts_below_a_cross_file_pair(self):
        mod = mm.Model()
        self.assertLess(mod.name_prior_bits(2.0, same_file=True, pi=0.5),
                        mod.name_prior_bits(2.0, same_file=False, pi=0.5))

    def test_poisson_fit_separates_duplicates_from_namesakes(self):
        # rare names (x≈0): ~0.5 duplicates in other files; common names (x large): namesakes grow with x
        import random
        rng = random.Random(0)
        obs = []
        for _ in range(400):
            x = rng.choice([0.0, 0.0, 0.0, 2.0, 5.0])
            same = sum(rng.random() < 0.05 for _ in range(3))
            other = (1 if rng.random() < 0.5 else 0) + sum(rng.random() < x * 0.3 for _ in range(10))
            obs.append((same, other, x, 0.3))
        ds, do, beta = mm.fit_duplicates(obs)
        self.assertLess(ds, do)                                     # same-file duplicates are rarer than cross-file
        self.assertGreater(beta, 0.05)                             # namesakes scale with the name's commonness
        self.assertLess(do, 2.0)


if __name__ == "__main__":
    unittest.main()
