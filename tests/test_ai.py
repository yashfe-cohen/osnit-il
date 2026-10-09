"""The optional AI extraction-template layer (osnit.ai). All tests monkeypatch ai._call — no network. The layer is
off by default, only ever ADDS a validated mapping through the overrides channel, always forces operator review,
degrades on any failure, and never lets the model drop data or override the phone-vs-ID rule."""
import json
import os
import tempfile
import unittest
from unittest import mock

from osnit import ai
from osnit.importqueue import ImportQueue
from osnit.semantic import Registry
from tests import helpers

CSV = ('פרטים,סודי\n' +
       'דוד לוי;054-5566123;david@gmail.com,hunter2\n' * 3 +
       'שרה כהן;052-7788990;sara@walla.co.il,pw9\n' * 3)


def cfg_on(cfg):
    cfg.ai_template, cfg.ai_key, cfg.ai_url, cfg.ai_model = True, "k", "https://api.example.com/v1/chat/completions", "m"
    return cfg


class Unit(unittest.TestCase):
    def test_enabled_requires_all_four(self):
        c = helpers.Config() if hasattr(helpers, "Config") else __import__("osnit.config", fromlist=["Config"]).Config()
        self.assertFalse(ai.enabled(c))
        self.assertTrue(ai.enabled(cfg_on(c)))

    def test_parse_tolerates_fences_and_prose(self):
        self.assertEqual(ai.parse('```json\n{"columns": {"a": "name"}}\n```')["columns"], {"a": "name"})
        self.assertEqual(ai.parse('sure, here:\n{"columns": {"a": "email"}} done')["columns"], {"a": "email"})
        self.assertEqual(ai.parse("not json at all"), {})
        self.assertEqual(ai.parse('{"s": "a } b", "columns": {}}')["s"], "a } b")   # brace inside a string

    def test_to_overrides_validates_against_registry(self):
        reg = Registry(())
        table = {"table": "t", "cols": ["a", "b", "c"], "raw": [{"a": "x", "b": "y", "c": "z"}], "columns": []}
        tmpl = {"columns": {"a": "name", "b": "bogus_key", "c": "skip", "zz": "email"}}
        ov = ai.to_overrides(tmpl, reg, table)
        self.assertEqual(ov, {"a": "name"})                 # unknown key, 'skip', and a non-column are all dropped

    def test_to_overrides_merge_and_split(self):
        reg = Registry(())
        table = {"table": "t", "cols": ["street", "house", "city", "mix"],
                 "raw": [{"street": "הרצל", "house": "5", "city": "חיפה", "mix": "דוד לוי;0545566123"},
                         {"street": "ביאליק", "house": "2", "city": "חיפה", "mix": "שרה כהן;0527788990"}],
                 "columns": []}
        tmpl = {"merges": [{"columns": ["street", "house", "city"], "type": "address"}],
                "splits": [{"column": "mix", "delimiter": ";",
                            "fields": [{"label": "שם", "type": "name"}, {"label": "טלפון", "type": "phone"}]}]}
        ov = ai.to_overrides(tmpl, reg, table)
        self.assertEqual(ov["__merge__"], [["street", "house", "city"]])
        self.assertTrue(any(r["type"] == "phone" for r in ov["__spans__"]))


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        cfg_on(self.eng.cfg)
        self.q = ImportQueue(self.eng, inbox=os.path.join(tempfile.mkdtemp(), "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def run_with(self, reply, body=CSV, name="f.csv"):
        with mock.patch.object(ai, "_call", return_value=reply) as m:
            job = self.q.add_bytes(body.encode("utf-8"), name, delete_raw=False, review=False)
            self.q.run_pending()
            return job, m

    def test_template_forces_review_and_imports_on_approve(self):
        reply = json.dumps({"columns": {"פרטים": "name", "סודי": "password"}})
        job, m = self.run_with(reply)
        j = self.store.q1("SELECT * FROM imports WHERE id=?", (job["id"],))
        self.assertEqual(j["state"], "review")                      # AI template is always confirmed first
        self.assertTrue(m.called)
        self.assertEqual(json.loads(j["ai"])["status"], "applied")
        self.assertEqual(json.loads(j["overrides"])["f.csv"]["פרטים"], "name")
        self.assertTrue(self.q.approve(job["id"]))
        self.q.run_pending()
        self.assertEqual(self.store.q1("SELECT state FROM imports WHERE id=?", (job["id"],))["state"], "done")

    def test_off_by_default_is_byte_identical(self):
        self.eng.cfg.ai_template = False
        with mock.patch.object(ai, "_call", side_effect=AssertionError("must not call")) as m:
            job = self.q.add_bytes(CSV.encode("utf-8"), "g.csv", delete_raw=False, review=False)
            self.q.run_pending()
        self.assertFalse(m.called)
        self.assertEqual(self.store.q1("SELECT state FROM imports WHERE id=?", (job["id"],))["state"], "done")

    def test_degrades_on_failure(self):
        with mock.patch.object(ai, "_call", side_effect=TimeoutError("slow")):
            job = self.q.add_bytes(CSV.encode("utf-8"), "h.csv", delete_raw=False, review=False)
            self.q.run_pending()
        j = self.store.q1("SELECT * FROM imports WHERE id=?", (job["id"],))
        self.assertIn(j["state"], ("done", "review"))               # not 'error'
        self.assertEqual(json.loads(j["ai"])["status"], "error")

    def test_caches_by_signature(self):
        reply = json.dumps({"columns": {"פרטים": "name"}})
        _, m1 = self.run_with(reply, name="a.csv")
        self.assertEqual(m1.call_count, 1)
        _, m2 = self.run_with(reply, name="b.csv")                  # same header set + content kinds
        self.assertEqual(m2.call_count, 0)                          # served from the ai_cache, no second call

    def test_phone_vs_id_rule_survives_a_bad_ai_mapping(self):
        # the model mislabels a bare-8-digit column as phone; extraction still refuses to make it a phone
        body = "קוד\n" + "".join(f"1847005{i}\n" for i in range(4))
        reply = json.dumps({"columns": {"קוד": "phone"}})
        job, _ = self.run_with(reply, body=body, name="ids.csv")
        self.q.approve(job["id"]); self.q.run_pending()
        self.assertIsNone(self.store.q1("SELECT 1 FROM entities WHERE type='phone'"))


if __name__ == "__main__":
    unittest.main()
