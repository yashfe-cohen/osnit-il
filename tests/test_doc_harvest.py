"""Web file harvesting: a document hit (PDF/CSV/…) is fetched and run through osnit's own parser, and the
target's details (names/emails/phones) are pulled from the file itself — with a link to it. Precision-first:
a file's contents are surfaced only when the file actually mentions the target."""
import asyncio
import unittest

from osnit.web_osint import (SearchTargetProfile, document_type_of, focus_excerpt, harvest_document_text,
                             run_layer5_dork_search)


def _run(coro):
    return asyncio.run(coro)


def _csv_bytes(text):
    return text.encode("utf-8")


class DocDetect(unittest.TestCase):
    def test_document_type_of(self):
        self.assertEqual(document_type_of("https://x.gov.il/a/report.PDF?y=1"), "pdf")
        self.assertEqual(document_type_of("https://x/list.xlsx"), "xlsx")
        self.assertEqual(document_type_of("https://x/profile"), "")

    def test_focus_excerpt_only_around_the_target(self):
        text = "foo bar " * 50 + " Contact: Dana Levi dana@corp.com " + "baz " * 50
        ex = focus_excerpt(text, ["Dana Levi"])
        self.assertIn("Dana Levi", ex)
        self.assertIn("dana@corp.com", ex)
        self.assertEqual(focus_excerpt(text, ["Someone Else"]), "")


class DocHarvest(unittest.TestCase):
    def setUp(self):
        self.profile = SearchTargetProfile.from_raw(name="Dana Levi", phones=["054-7718293"])

    def test_harvest_reads_a_csv_through_the_parser(self):
        csv = "name,email,phone\nDana Levi,dana.levi@corp.com,054-7718293\n"

        def fetch(url, headers):
            return (200, _csv_bytes(csv), {"Content-Type": "text/csv"})
        text = _run(harvest_document_text("https://x.org/people.csv", http_fetcher=fetch))
        self.assertIn("dana.levi@corp.com", text)

    def test_layer5_surfaces_the_file_link_and_details_from_the_file(self):
        csv = "full name,email,mobile\nDana Levi,dana.levi@corp.com,054-7718293\nYossi Cohen,y@corp.com,054-1112233\n"
        file_url = "https://registry.example.gov.il/members.csv"

        def search(q):
            return [{"url": file_url, "title": "members list", "snippet": "Dana Levi"}]

        def fetch(url, headers):
            return (200, _csv_bytes(csv), {"Content-Type": "text/csv"}) if url == file_url else (0, b"", {})

        findings, leads = _run(run_layer5_dork_search(self.profile, search_fn=search, http_fetcher=fetch))
        docs = [f for f in findings if f["url"] == file_url]
        self.assertTrue(docs, "the document hit was not surfaced")
        d = docs[0]
        self.assertEqual(d["extracted_data"].get("file_type"), "csv")
        self.assertTrue(d["extracted_data"].get("from_file"))
        self.assertIn("dana.levi@corp.com", d["extracted_data"].get("emails") or [])


if __name__ == "__main__":
    unittest.main()
