"""Scale guards: query plans that stay page-sized on a big database, and the fast national-ID proximity check.

The plan test records every SQL statement the people/entity/dossier screens run and EXPLAINs it. A statement that
walks relations must never start from "every entity of a type" (the entities_type_seen index) — that plan scans all
phones/emails in the database for each page and was the cause of multi-minute page loads at 100k+ records."""
import random
import time
import unittest

from osnit.contacts import _aggregate, contacts
from osnit.identity import dossier
from osnit.kinship import _close_national_ids
from osnit.semantic import il_id_ok
from osnit.server import entity_detail
from osnit.store import Store


def _il_id(n):
    d = f"{n:08d}"
    s = sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d))
    return d + str((10 - s % 10) % 10)


def _brute_close(ids_a, ids_b):
    """The original quadratic definition, kept here as the reference."""
    hits = []
    for a in ids_a:
        da = a.zfill(9)
        if not il_id_ok(da):
            continue
        for b in ids_b:
            db = b.zfill(9)
            if da == db or not il_id_ok(db):
                continue
            if 0 < abs(int(da[:8]) - int(db[:8])) <= 25 or 0 < abs(int(da) - int(db)) <= 150:
                hits.append((da, db))
    return hits


class CloseNationalIdsTest(unittest.TestCase):
    def test_matches_reference_on_random_sets(self):
        rnd = random.Random(7)
        for _ in range(300):
            base = rnd.randint(10000000, 10002000)
            a = {_il_id(base + rnd.randint(0, 400)) for _ in range(rnd.randint(0, 6))}
            b = {_il_id(base + rnd.randint(0, 400)) for _ in range(rnd.randint(0, 6))}
            if rnd.random() < 0.3:
                b.add("123456789")            # invalid check digit: never counts
            ref = _brute_close(a, b)
            got = _close_national_ids(a, b)
            if not ref:
                self.assertIsNone(got, (a, b))
            else:
                self.assertIn(got, ref, (a, b))
                self.assertIn(got[0], a)    # first element always comes from the first argument
                self.assertIn(got[1], b)

    def test_identical_ids_are_not_relatives(self):
        x = _il_id(12345678)
        self.assertIsNone(_close_national_ids({x}, {x}))

    def test_thousands_of_ids_are_fast(self):
        a = {_il_id(10000000 + i * 1000) for i in range(3000)}
        b = {_il_id(10000500 + i * 1000) for i in range(3000)}
        t = time.time()
        self.assertIsNone(_close_national_ids(a, b))
        self.assertLess(time.time() - t, 1.0)


class PagePlansTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Store(":memory:")
        now = time.time()
        with cls.s.tx() as c:
            # enough identifiers that a type-index scan would be the planner's tempting choice
            for i in range(1, 3001):
                c.execute("INSERT INTO entities(id,type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                          (i, "person", f"p{i}", f"אדם {i}", now, now + i))
                c.execute("INSERT INTO entities(id,type,key,display,first_seen,last_seen) VALUES(?,'phone',?,?,?,?)",
                          (10000 + i, f"+97250{i:07d}", f"050{i:07d}", now, now))
                c.execute("INSERT INTO relations(a_id,b_id,kind,first_seen,last_seen) VALUES(?,?,'has',?,?)",
                          (i, 10000 + i, now, now))
            c.execute("ANALYZE")

    def _capture(self, fn):
        seen = []
        orig_q, orig_q1 = self.s.q, self.s.q1

        def q(sql, args=()):
            seen.append((sql, tuple(args)))
            return orig_q(sql, args)

        def q1(sql, args=()):
            seen.append((sql, tuple(args)))
            return orig_q1(sql, args)

        self.s.q, self.s.q1 = q, q1
        try:
            fn()
        finally:
            self.s.q, self.s.q1 = orig_q, orig_q1
        return seen

    def _assert_no_type_scan_into_relations(self, seen):
        conn = self.s.conn
        for sql, args in seen:
            if "relations" not in sql or sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                continue
            lines = [r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, args)]
            for cur, nxt in zip(lines, lines[1:]):
                bad = "entities_type_seen" in cur and ("relations" in nxt or "rel_a" in nxt or "rel_b" in nxt)
                self.assertFalse(bad, "type-index scan drives the relations probe:\n" + sql + "\n" + "\n".join(lines))

    def test_aggregate_plan(self):
        self._assert_no_type_scan_into_relations(self._capture(lambda: _aggregate(self.s, list(range(1, 501)))))

    def test_contacts_plans(self):
        self._assert_no_type_scan_into_relations(self._capture(lambda: contacts(self.s, "", True)))
        self._assert_no_type_scan_into_relations(self._capture(lambda: contacts(self.s, "0500000042")))

    def test_entity_and_dossier_plans(self):
        self._assert_no_type_scan_into_relations(self._capture(lambda: entity_detail(self.s, 42)))
        self._assert_no_type_scan_into_relations(self._capture(lambda: dossier(self.s, 42)))

    def test_phone_search_finds_owner(self):
        rows = contacts(self.s, "050-0000042")["rows"]
        self.assertEqual([r["name"] for r in rows], ["אדם 42"])

    def test_list_rows_are_capped_with_totals(self):
        now = time.time()
        with self.s.tx() as c:          # one person who owns 20 phones (a common name fusing many records)
            for k in range(20):
                c.execute("INSERT INTO entities(id,type,key,display,first_seen,last_seen) VALUES(?,'phone',?,?,?,?)",
                          (50000 + k, f"+97252{k:07d}", f"052{k:07d}", now, now))
                c.execute("INSERT INTO relations(a_id,b_id,kind,first_seen,last_seen) VALUES(7,?,'has',?,?)",
                          (50000 + k, now, now))
        row = next(r for r in contacts(self.s, "", cap=8, limit=3000)["rows"] if r["id"] == 7)
        self.assertEqual(len(row["phones"]), 8)
        self.assertEqual(row["phones_total"], 21)
        full = next(r for r in contacts(self.s, "", limit=3000)["rows"] if r["id"] == 7)
        self.assertEqual(len(full["phones"]), 21)            # the CSV export path keeps everything



class DeterministicKinship(unittest.TestCase):
    """The same dossier must list the same relatives in every process (a set's iteration order of strings changes
    with PYTHONHASHSEED; kinship used to truncate such sets, so relatives changed after every restart)."""

    def test_same_relatives_under_different_hash_seeds(self):
        import os
        import subprocess
        import sys
        import tempfile
        db = os.path.join(tempfile.mkdtemp(), "k.db")
        code = r'''
import json, sys, time
from osnit.store import Store
from osnit.identity import dossier
s = Store(sys.argv[1])
if sys.argv[2] == "build":
    now = time.time()
    with s.tx() as c:
        n = 0
        for i in range(40):                       # 40 "נועה X" people, each with relatives "Y X"
            sur = "משפחה" + chr(0x05d0 + i % 22) + chr(0x05d0 + i // 22)
            for first in ("נועה", "דוד", "שרה"):
                n += 1
                c.execute("INSERT INTO entities(id,type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                          (n, "person", first + " " + sur, first + " " + sur, now, now))
            n += 1
            c.execute("INSERT INTO entities(id,type,key,display,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                      (n, "address", "הרצל " + str(i), "הרצל " + str(i), now, now))
            for p in (n - 3, n - 2, n - 1):
                c.execute("INSERT INTO relations(a_id,b_id,kind,first_seen,last_seen) VALUES(?,?,'lives_at',?,?)", (p, n, now, now))
    s.reindex_names(10000)
else:
    s._force_scoped_kinship = True
    d = dossier(s, name="נועה")
    print(json.dumps(sorted((k.get("cluster"), k.get("name") or "") for k in d.get("kinship", [])), ensure_ascii=False))
'''
        env = dict(os.environ, PYTHONPATH=os.getcwd())
        subprocess.run([sys.executable, "-c", code, db, "build"], check=True, env=env)
        outs = set()
        for seed in ("1", "2", "3"):
            r = subprocess.run([sys.executable, "-c", code, db, "read"], capture_output=True, text=True,
                               env=dict(env, PYTHONHASHSEED=seed), check=True)
            outs.add(r.stdout.strip())
        self.assertEqual(len(outs), 1, outs)


if __name__ == "__main__":
    unittest.main()
