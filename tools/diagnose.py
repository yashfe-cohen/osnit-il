"""Where does the time go on THIS database? A read-mostly report to paste back when something is slow.

    python tools/diagnose.py                       # data/osnit.db, times the 3 most recent investigations
    python tools/diagnose.py --db D:\\osnit\\osnit.db --subject 12
    python tools/diagnose.py --query "דוד כהן"     # time a new investigation of this query

Stop the server first for a clean measurement (otherwise its background work competes for the disk).
Writes the report to the screen and to diagnose_report.txt next to the database. It contains counts, sizes,
settings and timings — no names or record contents."""
import argparse
import cProfile
import io
import os
import pstats
import sqlite3
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

EXPECTED_INDEXES = ("entities_key", "entities_type_seen", "aliases_key", "aliases_source", "evidence_source",
                    "evidence_entity", "rel_a", "rel_b", "relev_source", "attributes_source", "attributes_name",
                    "name_index_ent", "sources_subject", "sources_import", "subject_entities_ent")


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join(ROOT, "data", "osnit.db"))
    ap.add_argument("--subject", type=int, action="append", help="investigation id to time (repeatable)")
    ap.add_argument("--query", help="also time a NEW investigation of this query")
    a = ap.parse_args()
    out = io.StringIO()

    def say(*x):
        line = " ".join(str(v) for v in x)
        print(line, flush=True)
        out.write(line + "\n")

    if not os.path.exists(a.db):
        sys.exit(f"no database at {a.db}")
    say("== osnit diagnose", time.strftime("%Y-%m-%d %H:%M"), "| python", sys.version.split()[0],
        "| sqlite", sqlite3.sqlite_version, "|", sys.platform)
    wal = a.db + "-wal"
    say("db file:", fmt_bytes(os.path.getsize(a.db)), "| wal:", fmt_bytes(os.path.getsize(wal)) if os.path.exists(wal) else "none")
    try:
        import shutil
        du = shutil.disk_usage(os.path.dirname(os.path.abspath(a.db)))
        say("disk free:", fmt_bytes(du.free), "of", fmt_bytes(du.total))
    except OSError:
        pass

    raw = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    for p in ("page_size", "journal_mode", "cache_size", "mmap_size"):
        say(f"pragma {p}:", raw.execute(f"PRAGMA {p}").fetchone()[0])
    say("-- rows (max rowid, a cheap estimate):")
    for t in ("entities", "relations", "evidence", "rel_evidence", "attributes", "aliases", "sources", "name_index",
              "subjects", "subject_entities", "osint_findings", "imports"):
        try:
            t0 = time.time()
            n = raw.execute(f"SELECT MAX(rowid) FROM {t}").fetchone()[0] or 0
            say(f"   {t:18} ~{n:>13,}   ({time.time() - t0:.2f}s)")
        except sqlite3.OperationalError as e:
            say(f"   {t:18} n/a ({e})")
    try:
        t0 = time.time()
        n = raw.execute("SELECT MAX(rowid) FROM documents_fts").fetchone()[0] or 0
        say(f"   {'documents_fts':18} ~{n:>13,}   ({time.time() - t0:.2f}s)")
    except sqlite3.OperationalError:
        pass
    have = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    missing = [i for i in EXPECTED_INDEXES if i not in have]
    say("indexes missing:", ", ".join(missing) if missing else "none")
    say("query planner stats (ANALYZE):", "present" if raw.execute(
        "SELECT 1 FROM sqlite_master WHERE name='sqlite_stat1'").fetchone() else "absent")
    try:
        say("name index progress:", raw.execute("SELECT key, value FROM meta WHERE key LIKE 'name_index%'").fetchall(),
            "| max person id:", raw.execute("SELECT MAX(id) FROM entities WHERE type='person'").fetchone()[0])
    except sqlite3.OperationalError:
        pass
    states = raw.execute("SELECT state, COUNT(*) FROM imports GROUP BY state").fetchall()
    say("imports by state:", states)
    raw.close()

    # ---- time real investigations, logging every query slower than 0.3 s
    os.environ["OSNIT_SLOW_SQL"] = "0.3"
    import osnit.store as store_mod
    store_mod._SLOW_SQL = 0.3
    slow = []

    def log_slow(sql, dt):
        if dt >= 0.3:
            slow.append((dt, " ".join(sql.split())[:160]))
    store_mod._log_slow = log_slow
    from osnit.profile import build_profile
    store = store_mod.Store(a.db)
    sids = a.subject or [r["id"] for r in store.q("SELECT id FROM subjects ORDER BY id DESC LIMIT 3")]
    if a.query:
        from osnit.engine import Engine
        from osnit.search import SearchService
        svc = SearchService(Engine(store, providers={}))
        t0 = time.time()
        res = svc.search(a.query)
        say(f"-- new investigation of the given query: {time.time() - t0:.1f}s (subject {res['subject_id']})")
        sids = [res["subject_id"]] + sids
    for sid in sids:
        subj = store.q1("SELECT id, kind FROM subjects WHERE id=?", (sid,))
        if not subj:
            say(f"-- investigation {sid}: not found")
            continue
        n_ent = store.q1("SELECT COUNT(*) n FROM subject_entities WHERE subject_id=?", (sid,))["n"]
        slow.clear()
        prof = cProfile.Profile()
        t0 = time.time()
        prof.enable()
        try:
            p = build_profile(store, sid)
        finally:
            prof.disable()
        dt = time.time() - t0
        say(f"-- investigation {sid} (kind={subj['kind']}, attached records={n_ent}): built in {dt:.1f}s; "
            f"clusters={len((p or {}).get('clusters', []))}")
        for d, q in sorted(slow, reverse=True)[:8]:
            say(f"   slow sql {d:6.2f}s  {q}")
        s = io.StringIO()
        pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(r"osnit", 14)
        for line in s.getvalue().splitlines():
            if "osnit" in line and "{" not in line:
                say("   ", line.strip()[:150])
    rep = os.path.join(os.path.dirname(os.path.abspath(a.db)), "diagnose_report.txt")
    with open(rep, "w", encoding="utf-8") as f:
        f.write(out.getvalue())
    print("\nreport saved to", rep)


if __name__ == "__main__":
    main()
