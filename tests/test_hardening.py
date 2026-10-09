"""Robustness fixes: no double extraction of a document that also has a table, a missing link endpoint never loses
the page, bidi-isolated Hebrew names tokenise whole, short Hebrew names are found, and malformed Access metadata
does not fail a whole database."""
import os
import tempfile
import unittest

from osnit import identity
from osnit.importqueue import ImportQueue
from osnit.textnorm import name_key, tokens
from tests import helpers


class Textnorm(unittest.TestCase):
    def test_bidi_isolates_do_not_split_a_name(self):
        bare = "יונתן חייט"
        wrapped = "⁦יונתן⁩ ⁧חייט⁩"           # FSI/PDI, RLI/PDI around the tokens
        self.assertEqual(tokens(wrapped), tokens(bare))
        self.assertEqual(name_key(wrapped), name_key(bare))


class Dossier(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def imp(self, body, name):
        self.q.add_bytes(body.encode("utf-8"), name, delete_raw=False, review=False)
        self.q.run_pending()

    def test_short_hebrew_name_is_found(self):
        self.imp("שם,טלפון\nבר לב,0545566123\n", "s.csv")          # every token < 3 chars, no transliteration probe
        d = identity.dossier(self.store, name="בר לב")
        self.assertTrue(d["clusters"])
        self.assertIn("בר לב", {n for c in d["clusters"] for n in c["names"]})

    def test_document_with_a_table_is_one_source(self):
        vcard = ("BEGIN:VCARD\nFN:דוד לוי\nTEL:054-5566123\nEMAIL:david@gmail.com\nEND:VCARD\n"
                 "BEGIN:VCARD\nFN:שרה כהן\nTEL:052-7788990\nEMAIL:sara@walla.co.il\nEND:VCARD\n")
        self.imp(vcard, "cards.vcf")
        n = self.store.q1("SELECT COUNT(*) c FROM sources WHERE import_id IS NOT NULL")["c"]
        self.assertEqual(n, 1)                                      # not two (records pass + text sweep)


class EngineGuard(unittest.TestCase):
    def test_link_with_unresolved_endpoint_keeps_the_page(self):
        from osnit.extract import Ent, Extraction
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            ex = Extraction()
            a = Ent("person", "pp", "Person P", 0, 0, 0.8)
            b = Ent("email", "e@x.com", "e@x.com", 0, 0, 0.8)
            ex.add_ent(a, "snippet")                                # only the person is added as an entity...
            ex.add_link(a, b, "contact", 0.8, "snip")              # ...but a link references the never-added email
            sid, _ = store.add_source("import://t/x", origin="t")
            nf = eng.persist(ex, sid, 1.0, [], bulk=True)          # must not raise, and must persist the person
            self.assertTrue(store.q1("SELECT 1 FROM entities WHERE type='person' AND key='pp'"))
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
