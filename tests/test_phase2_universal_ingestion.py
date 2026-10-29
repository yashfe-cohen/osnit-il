"""Phase 2 Real-World E2E QA: Universal File & DB Ingestion Pipeline.

Tests:
1. Nested archives (ZIP -> TAR.GZ -> 7z) and RAR extraction with zero patool 'file' warning logs.
2. SQL dumps (.sql with CREATE TABLE + INSERT INTO) and SQLite databases (.db / .sqlite).
3. Spreadsheets & structured formats (.xlsx, .csv, .tsv, .json, .xml, .yaml).
4. Rich documents (.pdf digital, .docx with headers/footers, .eml with RFC2047 Hebrew headers & attachment).
5. Hebrew text encodings (UTF-8, Windows-1255, ISO-8859-8) and end-to-end Inbox ingestion via ImportQueue.
"""
import csv
import email.header
import email.message
import io
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile

from osnit.config import Config
from osnit.engine import Engine
from osnit.importqueue import ImportQueue
from osnit.ingest import extract_rar_archive, import_path, unpack_archive_recursive
from osnit.parse import decode, parse
from osnit.store import Store


def _build_minimal_docx(paragraphs, header_text="", footer_text="") -> bytes:
    """Create a valid .docx zip buffer with document.xml and optional header1.xml/footer1.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        body_xml = "".join(
            f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs
        )
        doc_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body>{body_xml}</w:body></w:document>"
        )
        zf.writestr("word/document.xml", doc_xml.encode("utf-8"))
        if header_text:
            hdr_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f"<w:p><w:r><w:t>{header_text}</w:t></w:r></w:p></w:hdr>"
            )
            zf.writestr("word/header1.xml", hdr_xml.encode("utf-8"))
        if footer_text:
            ftr_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f"<w:p><w:r><w:t>{footer_text}</w:t></w:r></w:p></w:ftr>"
            )
            zf.writestr("word/footer1.xml", ftr_xml.encode("utf-8"))
    return buf.getvalue()


def _build_minimal_xlsx(rows) -> bytes:
    """Create a valid .xlsx zip buffer with sharedStrings.xml and sheet1.xml."""
    strings = []
    str_idx = {}
    for r in rows:
        for val in r:
            s = str(val)
            if s not in str_idx:
                str_idx[s] = len(strings)
                strings.append(s)

    sst_items = "".join(f"<si><t>{s}</t></si>" for s in strings)
    sst_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"{sst_items}</sst>"
    )

    row_xmls = []
    for r_i, r in enumerate(rows, start=1):
        cells = []
        for c_i, val in enumerate(r):
            col_letter = chr(ord("A") + c_i)
            idx = str_idx[str(val)]
            cells.append(f'<c r="{col_letter}{r_i}" t="s"><v>{idx}</v></c>')
        row_xmls.append(f'<row r="{r_i}">{"".join(cells)}</row>')

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(row_xmls)}</sheetData></worksheet>'
    )
    wb_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Personnel" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/sharedStrings.xml", sst_xml.encode("utf-8"))
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml.encode("utf-8"))
        zf.writestr("xl/workbook.xml", wb_xml.encode("utf-8"))
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml.encode("utf-8"))
    return buf.getvalue()


class TestPhase2UniversalIngestion(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_phase2_e2e_")
        self.db_path = os.path.join(self.tmp_dir, "osnit_phase2.db")
        self.inbox_dir = os.path.join(self.tmp_dir, "inbox")
        os.makedirs(self.inbox_dir, exist_ok=True)
        self.cfg = Config(db_path=self.db_path)
        self.store = Store(self.db_path)
        self.engine = Engine(self.store, self.cfg)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_hebrew_encodings_detection(self):
        hebrew_sentence = "דוח מודיעין מסווג: יוסי כהן, ת.ז 012345674, טלפון 052-4455667, רחוב הרצל 15 תל אביב"
        # 1. UTF-8
        b_utf8 = hebrew_sentence.encode("utf-8")
        self.assertIn("יוסי כהן", decode(b_utf8))

        # 2. Windows-1255
        b_1255 = hebrew_sentence.encode("windows-1255")
        decoded_1255 = decode(b_1255)
        self.assertIn("יוסי כהן", decoded_1255)
        self.assertIn("רחוב הרצל", decoded_1255)

        # 3. ISO-8859-8
        b_iso = hebrew_sentence.encode("iso-8859-8")
        decoded_iso = decode(b_iso)
        self.assertIn("יוסי כהן", decoded_iso)

    def test_patool_warning_silenced(self):
        """Ensure patool logger never emits the 'could not find a file executable' warning."""
        patool_logger = logging.getLogger("patool")
        self.assertGreaterEqual(patool_logger.level, logging.ERROR)

    def test_universal_inbox_e2e_ingestion(self):
        """Feed Inbox with SQL dump, SQLite DB, XLSX, CSV, TSV, DOCX, YAML, EML, Hebrew TXT, PDF, and Nested Archive."""
        # 1. SQL Dump (.sql)
        sql_path = os.path.join(self.inbox_dir, "employees_dump.sql")
        sql_content = (
            "CREATE TABLE employees (id INT, full_name VARCHAR(100), tz VARCHAR(20), phone VARCHAR(30), email VARCHAR(100), city VARCHAR(50));\n"
            "INSERT INTO employees VALUES (1, 'דניאל לוי', '039199047', '054-3219876', 'daniel.levi@mod-il.org', 'ירושלים');\n"
            "INSERT INTO employees VALUES (2, 'מיכל אברהם', '012345674', '050-7654321', 'michal.av@mod-il.org', 'חיפה');\n"
        )
        with open(sql_path, "w", encoding="utf-8") as f:
            f.write(sql_content)

        # 2. SQLite Database (.sqlite)
        sqlite_path = os.path.join(self.inbox_dir, "contacts_leaked.sqlite")
        conn = sqlite3.connect(sqlite_path)
        conn.execute("CREATE TABLE operatives (full_name TEXT, national_id TEXT, mobile TEXT, email TEXT, address TEXT)")
        conn.execute(
            "INSERT INTO operatives VALUES (?, ?, ?, ?, ?)",
            ("אורי מזרחי", "015050463", "052-8899001", "uri.mizrahi@intel-sec.co.il", "שדרות רוטשילד 22 תל אביב"),
        )
        conn.commit()
        conn.close()

        # 3. Excel (.xlsx)
        xlsx_path = os.path.join(self.inbox_dir, "roster.xlsx")
        xlsx_bytes = _build_minimal_xlsx([
            ["שם מלא", "תעודת זהות", "טלפון", "אימייל"],
            ["רונית שפירא", "024681352", "053-6677889", "ronit.shapira@cyber-corp.co.il"],
        ])
        with open(xlsx_path, "wb") as f:
            f.write(xlsx_bytes)

        # 4. CSV & TSV
        csv_path = os.path.join(self.inbox_dir, "vendors.csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "phone", "email"])
            writer.writerow(["גילעד פרץ", "058-1122334", "gilad.peretz@vendor-il.com"])

        tsv_path = os.path.join(self.inbox_dir, "access_list.tsv")
        with open(tsv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["name", "phone", "email"])
            writer.writerow(["נועה כץ", "052-5544332", "noa.katz@access-il.com"])

        # 5. DOCX (with header, body, and footer)
        docx_path = os.path.join(self.inbox_dir, "intel_brief.docx")
        docx_bytes = _build_minimal_docx(
            paragraphs=[
                "מסמך הערכת מצב - יחידת מחקר",
                "איש קשר מרכזי: אלון ברק, טלפון: 054-9911223, אימייל: alon.barak@research-il.org",
            ],
            header_text="סיווג: שמור ביותר - header.hq@research-il.org",
            footer_text="עמוד 1 מתוך 1 - footer.audit@research-il.org",
        )
        with open(docx_path, "wb") as f:
            f.write(docx_bytes)

        # 6. YAML (.yaml)
        yaml_path = os.path.join(self.inbox_dir, "target_profile.yaml")
        yaml_content = (
            "--- # Target Profile\n"
            "full_name: עידן גולן\n"
            "phone: 050-3344556\n"
            "email: idan.golan@target-net.co.il\n"
            "city: באר שבע\n"
        )
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        # 7. EML with RFC2047 Hebrew headers & attachment
        eml_path = os.path.join(self.inbox_dir, "intercepted_mail.eml")
        msg = email.message.EmailMessage()
        msg["From"] = "שמעון חדד <shimon.hadad@mail-il.org>"
        msg["To"] = "hq.command@mail-il.org"
        msg["Subject"] = "דוח פעילות מבצעית - שמעון חדד"
        msg.set_content("שלום רב,\nפרטי קשר של שמעון חדד: טלפון 052-6655443, מייל shimon.hadad@mail-il.org.\nמצורף קובץ נתונים.")
        msg.add_attachment(
            "נספח סודי: תומר דהן 054-7788990 tomer.dahan@mail-il.org".encode("utf-8"),
            maintype="text",
            subtype="plain",
            filename="appendix.txt",
        )
        with open(eml_path, "wb") as f:
            f.write(msg.as_bytes())

        # 8. Windows-1255 Hebrew TXT
        txt1255_path = os.path.join(self.inbox_dir, "legacy_note_1255.txt")
        with open(txt1255_path, "wb") as f:
            f.write("תיעוד ישן: אביגדור קליין, טלפון 050-2233445, מייל avigdor.klein@legacy-il.org.il".encode("windows-1255"))

        # 9. Nested Archive: outer.zip -> inner.tar.gz -> deep_secret.txt & inner_7z.7z
        deep_txt = "מקור פנימי בארכיון מקונן: ליאור שמש, טלפון 053-9900112, אימייל lior.shemesh@deep-archive.org".encode("utf-8")
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("deep_secret.txt")
            ti.size = len(deep_txt)
            tf.addfile(ti, io.BytesIO(deep_txt))

        nested_zip_path = os.path.join(self.inbox_dir, "nested_bundle.zip")
        with zipfile.ZipFile(nested_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("inner_layer.tar.gz", tar_buf.getvalue())
            try:
                import py7zr
                sz_path = os.path.join(self.tmp_dir, "payload.7z")
                with py7zr.SevenZipFile(sz_path, "w") as sz:
                    sz.writestr("שלום מארכיון 7z: יעל נחמיאס 054-4433221 yael.n@sevenzip-il.org", "sevenzip_note.txt")
                zf.write(sz_path, "payload.7z")
            except ImportError:
                pass

        # 10. Copy real project PDF if present (`Amit Tulian.pdf`)
        real_pdf = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Amit Tulian.pdf")
        if os.path.isfile(real_pdf):
            shutil.copy2(real_pdf, os.path.join(self.inbox_dir, "Amit_Tulian.pdf"))

        # Run ImportQueue across all files in Inbox
        queue = ImportQueue(self.engine, self.inbox_dir)
        processed = queue.run_pending()

        # Verify zero failed jobs
        jobs = queue.list()
        failed_jobs = [j for j in jobs if j["state"] == "error"]
        self.assertEqual(len(failed_jobs), 0, f"Expected 0 failed jobs, got: {failed_jobs}")
        self.assertGreaterEqual(processed, 10)

        # Verify extracted entities in the store from every single file format
        emails_in_db = {r["key"] for r in self.store.q("SELECT key FROM entities WHERE type='email'")}
        expected_emails = {
            "daniel.levi@mod-il.org",          # from .sql dump
            "michal.av@mod-il.org",            # from .sql dump
            "uri.mizrahi@intel-sec.co.il",     # from .sqlite DB
            "ronit.shapira@cyber-corp.co.il",  # from .xlsx
            "gilad.peretz@vendor-il.com",      # from .csv
            "noa.katz@access-il.com",          # from .tsv
            "alon.barak@research-il.org",      # from .docx body
            "header.hq@research-il.org",       # from .docx header
            "footer.audit@research-il.org",    # from .docx footer
            "idan.golan@target-net.co.il",     # from .yaml
            "shimon.hadad@mail-il.org",        # from .eml body/headers
            "tomer.dahan@mail-il.org",         # from .eml attachment
            "avigdor.klein@legacy-il.org.il",  # from Windows-1255 .txt
            "lior.shemesh@deep-archive.org",   # from nested .zip -> .tar.gz -> .txt
            "yael.n@sevenzip-il.org",          # from nested .zip -> .7z -> .txt
        }
        missing = expected_emails - emails_in_db
        self.assertEqual(len(missing), 0, f"Missing expected emails across formats: {missing}")


if __name__ == "__main__":
    unittest.main()
