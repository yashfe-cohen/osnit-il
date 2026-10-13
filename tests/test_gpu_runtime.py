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
        res = gpu_runtime.warmup(models_dir=models_dir)
        self.assertTrue(os.path.isdir(models_dir))
        self.assertIn("device", res)
        self.assertIn("gpu_available", res)
        self.assertIn("easyocr", res)
        self.assertIn("dictabert_ner", res)

    def test_warmup_easyocr_valueerror_fallback(self):
        models_dir = os.path.join(self.tmpdir, "models_fallback")
        mock_easyocr = MagicMock()
        def fake_reader(langs, **kwargs):
            if "he" in langs:
                raise ValueError("({'he'}, 'is not supported')")
            return MagicMock()
        mock_easyocr.Reader.side_effect = fake_reader

        with patch.dict("sys.modules", {"easyocr": mock_easyocr}):
            res = gpu_runtime.warmup(models_dir=models_dir)
            self.assertIn("fallback=['en']", res["easyocr"])
            self.assertEqual(mock_easyocr.Reader.call_count, 2)
            first_call_langs = mock_easyocr.Reader.call_args_list[0][0][0]
            second_call_langs = mock_easyocr.Reader.call_args_list[1][0][0]
            self.assertEqual(first_call_langs, ["he", "en"])
            self.assertEqual(second_call_langs, ["en"])

    def test_cli_warmup_subcommand(self):
        models_dir = os.path.join(self.tmpdir, "cli_models")
        # Should not raise exception
        main(["warmup", "--models-dir", models_dir])
        self.assertTrue(os.path.isdir(models_dir))


if __name__ == "__main__":
    unittest.main()
