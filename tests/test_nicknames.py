"""Nicknames / diminutives across Hebrew and English (אסתר ≈ אתי ≈ Esther ≈ Etti) are a SUGGESTION signal only:
they surface a possible same-person link for the operator to confirm, never an automatic merge and never in the
extraction/eval path (a nickname is ambiguous). Here: the gazetteer itself, the dossier suggestion, and the
cross-source correlation reason."""
import os
import tempfile
import unittest

from osnit.identity import dossier, suggest_same_person
from osnit.importqueue import ImportQueue
from osnit.nicknames import names_nick_match, nick_equiv
from tests import helpers


class NicknameGazetteer(unittest.TestCase):
    def test_equivalences(self):
        self.assertTrue(nick_equiv("אסתר", "אתי"))          # formal <-> nickname (Hebrew)
        self.assertTrue(nick_equiv("אסתר", "etti"))         # Hebrew formal <-> English nickname
        self.assertTrue(nick_equiv("יצחק", "איציק"))
        self.assertFalse(nick_equiv("אסתר", "שרה"))         # two distinct names never equate
        self.assertFalse(nick_equiv("כהן", "לוי"))          # surnames are not in the gazetteer

    def test_full_name_match_needs_a_nickname(self):
        self.assertTrue(names_nick_match("אסתר כהן", "אתי כהן"))       # given-name nickname, same surname
        self.assertTrue(names_nick_match("אסתר כהן", "Etti Cohen"))    # Hebrew <-> English nickname + translit
        self.assertFalse(names_nick_match("ברקת כהן", "ברקת כהן"))     # plain same name is NOT a nickname match
        self.assertFalse(names_nick_match("אסתר כהן", "אתי לוי"))      # different surname
        self.assertFalse(names_nick_match("אסתר", "אתי"))             # a single token is never enough


class NicknameSuggestion(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def _all_candidates(self, d):
        return {s["name"]: s for c in d["clusters"] for s in c.get("same_identity", [])}

    def test_nickname_variant_suggested_but_not_merged(self):
        # same surname, nickname of the given name, no shared identifier -> surfaced as a possibility, never merged
        self.q.add_bytes("name\nאסתר כהן\nאתי כהן\nדליה לוי\n".encode(), "p.csv")
        self.q.run_pending()
        d = dossier(self.store, name="אסתר כהן")
        sug = {s["name"]: s["reason"] for s in d["suggested"]}
        self.assertIn("אתי כהן", sug)                            # nickname -> suggested
        self.assertIn("כינוי", sug["אתי כהן"])                   # the reason says it is a nickname
        self.assertNotIn("דליה לוי", sug)                        # an unrelated name is not suggested
        # precision: the nickname record is NOT pulled into אסתר כהן's own identity cluster
        clustered = {r.get("name") for c in d["clusters"] for r in c.get("records", [])}
        self.assertNotIn("אתי כהן", clustered)

    def test_shared_detail_plus_nickname_is_same_person(self):
        # a shared exclusive mobile between a Hebrew formal name and its English nickname -> same person, and the
        # reason records that the names match via a nickname
        self.q.add_bytes("name,phone\nאסתר כהן,0545566123\nEtti Cohen,0545566123\n".encode(), "x.csv")
        self.q.run_pending()
        d = dossier(self.store, name="אסתר כהן")
        c = self._all_candidates(d).get("Etti Cohen")
        self.assertIsNotNone(c)
        self.assertEqual(c["relation"], "same_person")
        self.assertTrue(any("כינוי" in r for r in c["reasons"]))   # explained as a nickname match


if __name__ == "__main__":
    unittest.main()
