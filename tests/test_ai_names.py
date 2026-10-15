"""Opt-in AI name expansion + the always-on internal nickname gazetteer widen a person SEARCH (not extraction,
not the eval matcher): a search for 'אסתר כהן' also looks for 'אתי כהן' / 'Etti Cohen'. The AI layer is off by
default, cached, and degrades to the gazetteer on any failure."""
import os
import tempfile
import unittest
from unittest import mock

from osnit import ai
from osnit.nicknames import expanded_variants
from osnit.textnorm import fold
from tests import helpers


def _ai_on(cfg):
    cfg.ai_names, cfg.ai_key, cfg.ai_url, cfg.ai_model = True, "k", "https://api.example.com/v1/chat/completions", "m"
    return cfg


def _has(variants, *tokens):
    want = {fold(t) for t in tokens}
    return any(want <= {fold(t) for t in v} for v in variants)


class Gazetteer(unittest.TestCase):
    def test_expanded_variants_cross_nicknames_and_scripts(self):
        evs = expanded_variants("אסתר כהן")
        self.assertTrue(_has(evs, "אסתר", "כהן"))        # the original
        self.assertTrue(_has(evs, "אתי", "כהן"))         # a Hebrew nickname
        self.assertTrue(_has(evs, "esther", "cohen") or _has(evs, "etti", "cohen"))   # crossed to English
        self.assertTrue(any("כהן" in v for v in evs))    # surname kept in its real spelling, not final-folded

    def test_single_token_name_is_not_expanded(self):
        self.assertEqual(expanded_variants("אסתר"), [])


class AiLayer(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def test_names_enabled_requires_flag_and_model(self):
        self.assertFalse(ai.names_enabled(self.eng.cfg))
        self.assertTrue(ai.names_enabled(_ai_on(self.eng.cfg)))

    def test_disabled_returns_empty_and_never_calls(self):
        with mock.patch.object(ai, "_call", side_effect=AssertionError("must not call")):
            self.assertEqual(ai.name_expansions(self.eng.cfg, self.store, "אסתר כהן"), [])

    def test_expansion_parses_and_caches(self):
        _ai_on(self.eng.cfg)
        reply = '{"names": ["אתי כהן", "Etti Cohen", "Esti Cohen", "אתי כהן"]}'   # includes a duplicate
        with mock.patch.object(ai, "_call", return_value=reply) as m:
            got = ai.name_expansions(self.eng.cfg, self.store, "אסתר כהן")
            self.assertIn("אתי כהן", got)
            self.assertIn("Etti Cohen", got)
            self.assertEqual(len(got), len(set(n.lower() for n in got)))        # deduped
            self.assertEqual(m.call_count, 1)
            ai.name_expansions(self.eng.cfg, self.store, "אסתר כהן")            # second call served from cache
            self.assertEqual(m.call_count, 1)

    def test_bad_reply_degrades_to_empty(self):
        _ai_on(self.eng.cfg)
        with mock.patch.object(ai, "_call", return_value="not json"):
            self.assertEqual(ai.name_expansions(self.eng.cfg, self.store, "אסתר כהן"), [])


class SearchWidening(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])

    def tearDown(self):
        self.srv.shutdown()

    def test_gazetteer_widens_without_ai(self):
        base = [["אסתר", "כהן"]]
        wide = self.svc._widen_names("אסתר כהן", base)
        self.assertTrue(_has(wide, "אסתר", "כהן"))       # original kept
        self.assertTrue(_has(wide, "אתי", "כהן"))        # nickname added, no AI configured

    def test_ai_adds_its_forms_and_failure_is_harmless(self):
        _ai_on(self.eng.cfg)
        with mock.patch.object(ai, "_call", return_value='{"names": ["Ettie Kohn"]}'):
            wide = self.svc._widen_names("אסתר כהן", [["אסתר", "כהן"]])
            self.assertTrue(_has(wide, "ettie", "kohn"))  # the model's form is now a search variant
        # a model error must not break the search: the gazetteer forms still come through
        with self.store.tx() as c:                       # clear the cache so _call is reached again
            c.execute("DELETE FROM ai_cache")
        with mock.patch.object(ai, "_call", side_effect=TimeoutError("slow")):
            wide = self.svc._widen_names("אסתר כהן", [["אסתר", "כהן"]])
            self.assertTrue(_has(wide, "אתי", "כהן"))


if __name__ == "__main__":
    unittest.main()
