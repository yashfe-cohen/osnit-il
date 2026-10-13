import email.message
import gzip
import io
import mailbox
import os
import shutil
import tempfile
import unittest
import zipfile
import tarfile
from unittest.mock import patch, MagicMock

from osnit.detect import sniff_magic_route
from osnit.ingest import (
    is_archive,
    unpack_archive_recursive,
    ZipBombError,
    _safe_dest_path,
    import_path,
    configure_unrar_tool,
)
from osnit.engine import Engine
from osnit.store import Store


class TestDeepUnpacker(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_test_unpacker_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_magic_byte_sniffing(self):
        # ZIP magic bytes PK\x03\x04
        zip_head = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        route = sniff_magic_route(zip_head, "unknown_ext")
        self.assertEqual(route["category"], "archive")
        self.assertEqual(route["kind"], "zip")

        # 7z magic bytes 7z\xbc\xaf\x27\x1c
        sz_head = b"7z\xbc\xaf\x27\x1c\x00\x04"
        route = sniff_magic_route(sz_head, "file.bin")
        self.assertEqual(route["category"], "archive")
        self.assertEqual(route["kind"], "7z")

        # Gzip magic bytes \x1f\x8b
        gz_head = b"\x1f\x8b\x08\x00\x00\x00\x00\x00"
        route = sniff_magic_route(gz_head, "something")
        self.assertEqual(route["category"], "archive")
        self.assertEqual(route["kind"], "gz")

        # Zstandard magic bytes \x28\xb5\x2f\xfd
        zst_head = b"\x28\xb5\x2f\xfd\x00\x00"
        route = sniff_magic_route(zst_head, "leak.bin")
        self.assertEqual(route["category"], "archive")
        self.assertEqual(route["kind"], "zst")

        # Visual PNG
        png_head = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        route = sniff_magic_route(png_head, "no_ext")
        self.assertEqual(route["category"], "visual")
        self.assertEqual(route["kind"], "png")

        # Structured SQLite
        sqlite_head = b"SQLite format 3\x00\x10\x00\x01\x01"
        route = sniff_magic_route(sqlite_head, "dump.dat")
        self.assertEqual(route["category"], "structured")
        self.assertEqual(route["kind"], "sqlite")

    def test_zip_slip_protection(self):
        dest = os.path.join(self.tmp_dir, "dest")
        os.makedirs(dest, exist_ok=True)
        # Normal safe path
        safe = _safe_dest_path(dest, "sub/file.txt")
        self.assertTrue(safe.startswith(os.path.abspath(dest)))

        # Directory traversal attempts must raise ValueError
        with self.assertRaises(ValueError):
            _safe_dest_path(dest, "../evil.exe")

        with self.assertRaises(ValueError):
            _safe_dest_path(dest, "sub/../../evil.exe")

    def test_zip_bomb_protection(self):
        # Create a zip with 10KB of uncompressed data
        zip_path = os.path.join(self.tmp_dir, "bomb.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("large.txt", "A" * 20000)

        dest = os.path.join(self.tmp_dir, "bomb_dest")
        # Set max_bytes cap to 5000 bytes (< 20000)
        with self.assertRaises(ZipBombError):
            unpack_archive_recursive(zip_path, dest, max_bytes=5000)

    def test_nested_recursive_unpacking_and_lineage(self):
        # Inner-most file: doc.txt
        inner_txt_content = "ישראל כהן 052-1234567 israel@test.co.il"
        
        # Inner archive: inner.tar.gz containing doc.txt
        inner_tar_path = os.path.join(self.tmp_dir, "inner.tar.gz")
        with tarfile.open(inner_tar_path, "w:gz") as tf:
            ti = tarfile.TarInfo("doc.txt")
            encoded = inner_txt_content.encode("utf-8")
            ti.size = len(encoded)
            tf.addfile(ti, io.BytesIO(encoded))

        # Mid archive: mid.zip containing inner.tar.gz
        mid_zip_path = os.path.join(self.tmp_dir, "mid.zip")
        with zipfile.ZipFile(mid_zip_path, "w") as zf:
            zf.write(inner_tar_path, "inner.tar.gz")

        # Outer archive: outer.zip containing mid.zip
        outer_zip_path = os.path.join(self.tmp_dir, "outer.zip")
        with zipfile.ZipFile(outer_zip_path, "w") as zf:
            zf.write(mid_zip_path, "mid.zip")

        # Unpack recursively
        dest = os.path.join(self.tmp_dir, "unpack_dest")
        results = unpack_archive_recursive(outer_zip_path, dest, max_depth=5)

        self.assertEqual(len(results), 1)
        leaf = results[0]
        self.assertTrue(leaf["is_leaf"])
        self.assertTrue(leaf["path"].endswith("doc.txt"))
        self.assertIn("outer.zip::mid.zip::inner.tar.gz::doc.txt", leaf["lineage"])

        with open(leaf["path"], "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), inner_txt_content)

    def test_standalone_gzip_unpacking(self):
        gz_path = os.path.join(self.tmp_dir, "data.sql.gz")
        sql_content = b"CREATE TABLE users (id int, name text);\nINSERT INTO users VALUES (1, 'David');\n"
        with gzip.open(gz_path, "wb") as f:
            f.write(sql_content)

        dest = os.path.join(self.tmp_dir, "gz_dest")
        results = unpack_archive_recursive(gz_path, dest)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["path"].endswith("data.sql"))
        with open(results[0]["path"], "rb") as f:
            self.assertEqual(f.read(), sql_content)

    def test_mbox_and_eml_attachment_extraction(self):
        mbox_path = os.path.join(self.tmp_dir, "test.mbox")
        mb = mailbox.mbox(mbox_path)
        
        # Build an email with an attachment
        msg = email.message.EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "receiver@example.com"
        msg["Subject"] = "Important Documents"
        msg.set_content("Please find attached contract.")
        msg.add_attachment(b"PDF Content Here", maintype="application", subtype="pdf", filename="contract.pdf")

        mb.add(msg)
        mb.close()

        dest = os.path.join(self.tmp_dir, "mbox_dest")
        results = unpack_archive_recursive(mbox_path, dest)

        # Should extract the .eml and the attachment contract.pdf
        filenames = [os.path.basename(r["path"]) for r in results]
        self.assertTrue(any(f.endswith(".eml") for f in filenames))
        self.assertTrue(any("contract.pdf" in f for f in filenames))

    def test_import_path_with_archive(self):
        # Test full pipeline: import_path unpacking an archive and indexing documents into Engine
        store_path = os.path.join(self.tmp_dir, "test_store.db")
        store = Store(store_path)
        engine = Engine(store)

        # Create a leak archive with a text document
        leak_zip = os.path.join(self.tmp_dir, "leak_archive.zip")
        with zipfile.ZipFile(leak_zip, "w") as zf:
            zf.writestr("confidential_memo.txt", "שם: אברהם לוי, טלפון: 054-9988776, תז: 012345674")

        res = import_path(engine, leak_zip)
        self.assertEqual(res["imported"], 1)

        # Check that the source has recorded lineage
        sources = store.q("SELECT * FROM sources WHERE lineage LIKE '%confidential_memo.txt%'")
        self.assertTrue(len(sources) >= 1)
        self.assertIn("leak_archive.zip::confidential_memo.txt", sources[0]["lineage"])

    def test_configure_unrar_tool(self):
        fake_unrar = os.path.join(self.tmp_dir, "fake_WinRAR.exe")
        with open(fake_unrar, "wb") as f:
            f.write(b"fake_binary")

        mock_rarfile = MagicMock()
        # 1. Test passing an explicit valid file path
        with patch("osnit.ingest.HAS_RARFILE", True), \
             patch("osnit.ingest.rarfile", mock_rarfile):
            configured = configure_unrar_tool(fake_unrar)
            self.assertEqual(configured, fake_unrar)
            self.assertEqual(mock_rarfile.UNRAR_TOOL, fake_unrar)

        # 2. Test via OSNIT_UNRAR_TOOL environment variable
        with patch("osnit.ingest.HAS_RARFILE", True), \
             patch("osnit.ingest.rarfile", mock_rarfile), \
             patch.dict(os.environ, {"OSNIT_UNRAR_TOOL": fake_unrar}):
            configured = configure_unrar_tool()
            self.assertEqual(configured, fake_unrar)
            self.assertEqual(mock_rarfile.UNRAR_TOOL, fake_unrar)
