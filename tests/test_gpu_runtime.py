import os
import shutil
import tempfile
import unittest

from unittest.mock import patch, MagicMock

from osnit import gpu_runtime
from osnit.cli import main


class TestGpuRuntime(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_device_detection(self):
        device = gpu_runtime.get_device()
        self.assertIn(device, ("cuda", "mps", "cpu"))

    def test_device_info_keys(self):
        info = gpu_runtime.get_device_info()
        self.assertIn("torch_available", info)
        self.assertIn("gpu_available", info)
        self.assertIn("device", info)
        self.assertIn("name", info)
        self.assertIsInstance(info["gpu_available"], bool)

    def test_log_gpu_status(self):
        status_line = gpu_runtime.log_gpu_status()
        self.assertIsInstance(status_line, str)
        self.assertTrue(status_line.startswith("GPU Active:") or status_line.startswith("GPU Inactive:"))

    def test_clear_vram_cache_safe(self):
        # Must not raise in any environment
        gpu_runtime.clear_vram_cache()

    def test_warmup_fallback(self):
        models_dir = os.path.join(self.tmpdir, "models")
        with patch.dict("sys.modules", {"transformers": None}):
            res = gpu_runtime.warmup(models_dir=models_dir)
        self.assertTrue(os.path.isdir(models_dir))
        self.assertIn("device", res)
        self.assertIn("gpu_available", res)
        self.assertIn("ocr", res)
        self.assertIn("dictabert_ner", res)

    def test_warmup_tesseract_ocr(self):
        models_dir = os.path.join(self.tmpdir, "models_tesseract")
        with patch("osnit.ocr_engine.is_ocr_available", return_value=True), \
             patch("osnit.ocr_engine._HAS_HEB_DATA", True), \
             patch("osnit.ocr_engine._HAS_ENG_DATA", True), \
             patch.dict("sys.modules", {"transformers": None}):
            res = gpu_runtime.warmup(models_dir=models_dir)
            self.assertIn("ready (tesseract", res["ocr"])
            self.assertIn("heb+eng", res["ocr"])

    def test_cli_warmup_subcommand(self):
        models_dir = os.path.join(self.tmpdir, "cli_models")
        # Should not raise exception or perform network downloads during unit tests
        with patch.dict("sys.modules", {"transformers": None}):
            main(["warmup", "--models-dir", models_dir])
        self.assertTrue(os.path.isdir(models_dir))

    def test_turnkey_install_and_run_scripts(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for script_name in ("install.bat", "install.sh", "run.bat", "run.sh", "requirements.txt", "osnit.env.example"):
            script_path = os.path.join(root, script_name)
            self.assertTrue(os.path.isfile(script_path), f"Missing setup file: {script_name}")

        with open(os.path.join(root, "install.bat"), encoding="utf-8") as f:
            install_bat = f.read()
        self.assertIn("-m venv .venv", install_bat)
        self.assertIn("-m playwright install chromium", install_bat)
        self.assertIn("-r requirements.txt", install_bat)
        self.assertIn("-m osnit warmup", install_bat)
        for sub in ("data\\archive", "data\\models", "data\\inbox", "data\\avatars", "data\\browser_profile", "data\\exports"):
            self.assertIn(sub, install_bat)

        with open(os.path.join(root, "install.sh"), encoding="utf-8") as f:
            install_sh = f.read()
        self.assertIn("-m venv .venv", install_sh)
        self.assertIn("-m playwright install chromium", install_sh)
        self.assertIn("-r requirements.txt", install_sh)
        self.assertIn("-m osnit warmup", install_sh)

        with open(os.path.join(root, "run.bat"), encoding="utf-8") as f:
            run_bat = f.read()
        self.assertIn("install.bat", run_bat)
        self.assertIn("-m osnit serve", run_bat)

    def test_requirements_completeness(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "requirements.txt"), encoding="utf-8") as f:
            reqs = f.read().lower()
        expected_packages = [
            "pypdf", "pymupdf", "pypdfium2", "xlrd", "openpyxl", "python-docx", "extract-msg", "pyyaml",
            "zstandard", "py7zr", "patool",
            "pytesseract", "pillow", "python-bidi", "opencv-python-headless", "numpy",
            "transformers",
            "httpx", "aiohttp", "playwright", "playwright-stealth", "phonenumbers", "holehe", "ignorant",
        ]
        for pkg in expected_packages:
            self.assertIn(pkg, reqs, f"Package {pkg} missing from requirements.txt")

    def test_batch_files_pure_ascii(self):
        """Windows cmd.exe shifts byte offsets after chcp 65001 if .bat files contain multi-byte UTF-8 chars."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for fn in ("run.bat", "install.bat", "run.sh", "install.sh"):
            with open(os.path.join(root, fn), "rb") as f:
                raw = f.read()
            non_ascii = [b for b in raw if b >= 128]
            self.assertEqual(non_ascii, [], f"{fn} contains non-ASCII bytes that break cmd.exe parsing")

    def test_missing_indexes_rebuilt_with_progress(self):
        import io
        import sqlite3
        from contextlib import redirect_stderr
        from osnit.store import Store

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "test_scale.db")
            with Store(db_path) as s:
                s.resolve_entity("person", "ישראל ישראלי", "ישראל ישראלי", 1.0, fuzzy=False)
            # Simulate an older DB missing entities_key and evidence_entity indexes
            con = sqlite3.connect(db_path)
            con.execute("DROP INDEX IF EXISTS entities_key")
            con.execute("DROP INDEX IF EXISTS evidence_entity")
            con.commit()
            con.close()

            buf = io.StringIO()
            with redirect_stderr(buf):
                with Store(db_path) as s2:
                    idx_names = {
                        r[0] for r in s2.conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
                    }
            self.assertIn("entities_key", idx_names)
            self.assertIn("evidence_entity", idx_names)
            out = buf.getvalue()
            self.assertIn("Building index 'entities_key'", out)
            self.assertIn("Building index 'evidence_entity'", out)


if __name__ == "__main__":
    unittest.main()

