import unittest

from osnit.query import parse_query
from tests import helpers
from tests.helpers import PAGES
from tests.test_pipeline import DOC, TEAM, docx


class Intent(unittest.TestCase):
    def test_parse(self):
        q = parse_query("יונתן חייט נקודה PDF")
        self.assertEqual((q.subject, q.filetypes), ("יונתן חייט", ["pdf"]))
        q = parse_query("יונתן חייט מספר טלפון")
        self.assertEqual((q.subject, q.want), ("יונתן חייט", ["phone"]))
        self.assertEqual(parse_query('בנק הפועלים בע"מ').subject, 'בנק הפועלים בע"מ')

    def setUp(self):
        PAGES.clear()
        PAGES.update({"/team": (TEAM, "text/html; charset=utf-8"), "/doc.txt": (DOC, "text/plain; charset=utf-8"),
                      "/cv.docx": (docx(DOC), "application/octet-stream")})
        self.srv, self.base, self.store, self.eng, self.svc, self.prov = helpers.make(["/team", "/doc.txt", "/cv.docx"])

    def tearDown(self):
        self.srv.shutdown()

    def test_phone_answer_and_query_plan(self):
        sid = self.svc.search("יונתן חייט מספר טלפון")["subject_id"]
        self.eng.drain()
        prof = self.svc.profile(sid)
        self.assertEqual(prof["subject"]["canonical"], "יונתן חייט")
        self.assertEqual(prof["answer"]["phones"][0]["value"], "+972508317945")
        self.assertNotIn("emails", prof["answer"])
        self.assertTrue(any("טלפון" in q for q in self.prov.calls[:3]))   # the asked-for query is planned first

    def test_pdf_intent_filters_documents(self):
        sid = self.svc.search("יונתן חייט docx")["subject_id"]
        self.eng.drain()
        docs = self.svc.profile(sid)["answer"]["documents"]
        self.assertTrue(docs and all(d["kind"] == "docx" for d in docs))
        self.assertTrue(any("filetype:docx" in q for q in self.prov.calls))


if __name__ == "__main__":
    unittest.main()
