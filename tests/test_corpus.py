"""Regression guard on the labelled corpora (see `python -m osnit eval <folder>`)."""
import os
import unittest

from osnit.evaluate import evaluate

HERE = os.path.dirname(__file__)


class Corpus(unittest.TestCase):
    def check(self, folder, p, r, link):
        summary, docs = evaluate(os.path.join(HERE, folder))
        self.assertGreaterEqual(summary["person_precision"], p, docs)
        self.assertGreaterEqual(summary["person_recall"], r, docs)
        self.assertGreaterEqual(summary["link_recall"], link, docs)
        self.assertEqual(summary["violations"], 0, [d["violations"] for d in docs if d["violations"]])
        self.assertEqual(summary["page_type_errors"], 0)

    def test_tuning_corpus(self):
        self.check("corpus", 1.0, 1.0, 1.0)

    def test_holdout_corpus(self):
        self.check("corpus_holdout", 0.9, 0.9, 0.8)


if __name__ == "__main__":
    unittest.main()
