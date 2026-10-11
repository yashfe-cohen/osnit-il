"""UI-managed runtime settings (osnit.settings): the opt-in AI key/url/model + toggles are stored in the DB,
applied onto the live Config without a restart, masked for display, env values kept as the fallback."""
import tempfile
import os
import unittest

from osnit import ai, settings
from osnit.config import Config
from osnit.store import Store


class Settings(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "t.db")
        self.store = Store(self.db)
        self.cfg = Config(db_path=self.db)

    def test_save_apply_enables_ai(self):
        settings.save(self.store, {"ai_key": "k-123456", "ai_url": settings.GEMINI_URL,
                                   "ai_model": "gemini-2.5-flash", "ai_names": True})
        settings.apply(self.cfg, self.store)
        self.assertTrue(ai.names_enabled(self.cfg))
        self.assertEqual(self.cfg.ai_model, "gemini-2.5-flash")

    def test_public_masks_the_key(self):
        settings.save(self.store, {"ai_key": "abcd1234efgh"})
        settings.apply(self.cfg, self.store)
        p = settings.public(self.cfg, self.store)
        self.assertTrue(p["ai_key_set"])
        self.assertEqual(p["ai_key_mask"], "•" * 8 + "efgh")       # only the last 4 ever leave the server
        self.assertNotIn("abcd", p["ai_key_mask"])

    def test_blank_key_kept_explicit_clear_resets(self):
        settings.save(self.store, {"ai_key": "secret-key"})
        settings.apply(self.cfg, self.store)
        settings.save(self.store, {"ai_names": True})              # a flag change with no key field -> key kept
        settings.apply(self.cfg, self.store)
        self.assertEqual(self.cfg.ai_key, "secret-key")
        settings.save(self.store, {"ai_key": "•••••"})             # the masked placeholder -> key kept
        settings.apply(self.cfg, self.store)
        self.assertEqual(self.cfg.ai_key, "secret-key")
        settings.save(self.store, {"ai_key": ""})                  # explicit clear
        settings.apply(self.cfg, self.store)
        self.assertEqual(self.cfg.ai_key, "")

    def test_env_key_is_the_fallback(self):
        self.cfg.ai_key = "from-env"                               # as if OSNIT_AI_KEY was set
        settings.save(self.store, {"ai_names": True})              # UI never touched the key
        settings.apply(self.cfg, self.store)
        self.assertEqual(self.cfg.ai_key, "from-env")
        self.assertTrue(settings.public(self.cfg, self.store)["from_env_key"])


if __name__ == "__main__":
    unittest.main()
