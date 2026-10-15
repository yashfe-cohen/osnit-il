"""
Regression tests verifying all supported document and tabular formats:
- SQL dump files
- CSV files
- HTML web pages
- Plain text / Markdown
- JSON / JSONL files
- DOCX files
- SQLite Database store & records creation
"""
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile

from osnit.extract import Extractor
from osnit.parse import parse, Parsed
from osnit.sql_parser import read_sql_dump
from osnit.store import Store


def create_docx(text: str) -> bytes:
    """Creates an in-memory valid DOCX binary containing given text."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        paragraphs = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in text.split("\n"))
        z.writestr(
            "word/document.xml",
            f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{paragraphs}</w:body></w:document>'
        )
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        )
    return bio.getvalue()


class TestFileTypesRegression(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_file_reg_")
        self.db_path = os.path.join(self.tmp_dir, "test.db")
        self.store = Store(self.db_path)
        self.extractor = Extractor()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. SQL Dumps
    def test_sql_dump_parsing(self):
        sql_content = """
        CREATE TABLE users (
            id INT,
            full_name VARCHAR(100),
            id_num VARCHAR(20),
            phone_num VARCHAR(30),
            email_addr VARCHAR(100)
        );
        INSERT INTO users (id, full_name, id_num, phone_num, email_addr) VALUES
        (1, 'ישראל כהן', '216958868', '054-7681313', 'israel.cohen@example.com'),
        (2, 'רונית לוי', '012345674', '050-1234567', 'ronit.levi@alpha.org');
        """
        tables = list(read_sql_dump(sql_content))
        self.assertEqual(len(tables), 1)
        tbl_name, cols, rows = tables[0]
        self.assertEqual(tbl_name, "users")
        self.assertGreaterEqual(len(rows), 2)
        first_row = rows[0]
        self.assertIn("ישראל כהן", str(first_row.values()))
        self.assertIn("216958868", str(first_row.values()))

    # 2. CSV Files
    def test_csv_parsing(self):
        csv_data = b"id,name,phone,email,tz\n101,Dan Ben-David,052-5248353,dan@tech.co.il,216958868\n102,Maya Sharon,054-7681313,maya@tech.co.il,012345674\n"
        parsed = parse(csv_data, url="employees.csv")
        self.assertEqual(parsed.kind, "csv")
        self.assertIn("Dan Ben-David", parsed.text)
        self.assertIn("dan@tech.co.il", parsed.text)

        ex = self.extractor.extract(parsed.text, title=parsed.title)
        self.assertIn(("email", "dan@tech.co.il"), ex.ents)
        self.assertIn(("phone", "+972525248353"), ex.ents)
        self.assertIn(("national_id", "216958868"), ex.ents)

    # 3. HTML Pages
    def test_html_parsing(self):
        html_data = b"""<!DOCTYPE html>
        <html>
        <head><title>Company Directory</title></head>
        <body>
            <h1>Management</h1>
            <p>Contact <strong>David Levi</strong> at <a href="mailto:david@levi.co.il">david@levi.co.il</a> or call 052-5248353.</p>
        </body>
        </html>"""
        parsed = parse(html_data, url="directory.html")
        self.assertEqual(parsed.kind, "html")
        self.assertIn("David Levi", parsed.text)
        self.assertIn("david@levi.co.il", parsed.text)

        ex = self.extractor.extract(parsed.text, title=parsed.title)
        self.assertIn(("email", "david@levi.co.il"), ex.ents)
        self.assertIn(("phone", "+972525248353"), ex.ents)

    # 4. Plain Text & Markdown
    def test_plain_text_and_markdown(self):
        txt_data = "פרטי התקשרות:\nשם: אברהם לוי\nת.ז.: 216958868\nטלפון: 054-7681313\nדוא\"ל: avi@levi.com".encode("utf-8")
        parsed = parse(txt_data, url="notes.txt")
        self.assertEqual(parsed.kind, "txt")

        ex = self.extractor.extract(parsed.text, title=parsed.title)
        self.assertIn(("email", "avi@levi.com"), ex.ents)
        self.assertIn(("phone", "+972547681313"), ex.ents)
        self.assertIn(("national_id", "216958868"), ex.ents)

    # 5. JSON Files
    def test_json_parsing(self):
        payload = [
            {"name": "Noa Cohen", "email": "noa.cohen@cyber.org", "phone": "052-5248353"},
            {"name": "Yaron Tal", "email": "yaron@cyber.org", "phone": "054-7681313"}
        ]
        json_bytes = json.dumps(payload).encode("utf-8")
        parsed = parse(json_bytes, url="records.json")
        self.assertEqual(parsed.kind, "json")
        self.assertIn("Noa Cohen", parsed.text)
        self.assertIn("noa.cohen@cyber.org", parsed.text)

        ex = self.extractor.extract(parsed.text, title=parsed.title)
        self.assertIn(("email", "noa.cohen@cyber.org"), ex.ents)
        self.assertIn(("phone", "+972525248353"), ex.ents)

    # 6. DOCX Documents
    def test_docx_parsing(self):
        doc_text = "קורות חיים\nשם: רון כהן\nטלפון: 054-7681313\nדוא\"ל: ron.c@company.il"
        docx_bytes = create_docx(doc_text)
        parsed = parse(docx_bytes, url="resume.docx")
        self.assertEqual(parsed.kind, "docx")
        self.assertIn("רון כהן", parsed.text)
        self.assertIn("ron.c@company.il", parsed.text)

        ex = self.extractor.extract(parsed.text, title=parsed.title)
        self.assertIn(("email", "ron.c@company.il"), ex.ents)
        self.assertIn(("phone", "+972547681313"), ex.ents)

    # 7. SQLite Store Record Persistence
    def test_store_records_and_query(self):
        source_id, _ = self.store.add_source("file:///data/inbox/test_records.csv")
        self.assertGreater(source_id, 0)

        self.store.index_document_fts(
            source_id=source_id,
            file_path="data/inbox/test_records.csv",
            location_ref="row=1",
            raw_text="שם: ישראל כהן | תז: 216958868 | טלפון: 054-7681313 | מייל: israel@example.com"
        )

        res = self.store.search_fts("216958868")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["source_id"], source_id)
        self.assertIn("<b>216958868</b>", res[0]["snippet"])

        res_name = self.store.search_fts("ישראל")
        self.assertEqual(len(res_name), 1)
        self.assertIn("<b>ישראל</b>", res_name[0]["snippet"])


if __name__ == "__main__":
    unittest.main()
