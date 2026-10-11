"""Latin -> Hebrew name transliteration feeds the search: an English spelling now generates Hebrew query variants
even for names not in the gazetteer, so a search for 'Barkat Cohen' also looks for 'ברקת כהן'."""
import unittest

from osnit.textnorm import fold
from osnit.translit import latin_to_hebrew
from osnit.variants import name_variants


class Translit(unittest.TestCase):
    def test_latin_to_hebrew_common_names(self):
        self.assertIn("ברקת", latin_to_hebrew("barkat"))
        self.assertIn("ברקת", latin_to_hebrew("bareket"))
        self.assertIn("כהן", latin_to_hebrew("cohen"))
        self.assertIn("דוד", latin_to_hebrew("david"))
        self.assertIn("לוי", latin_to_hebrew("levy"))

    def test_hebrew_input_yields_nothing(self):
        self.assertEqual(latin_to_hebrew("ברקת"), [])

    def test_name_variants_bridges_english_to_hebrew(self):
        folded = [[fold(w) for w in v] for v in name_variants("Barkat Cohen")]
        self.assertIn([fold("ברקת"), fold("כהן")], folded)       # the full Hebrew spelling is now a search variant


if __name__ == "__main__":
    unittest.main()
