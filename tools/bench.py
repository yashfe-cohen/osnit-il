"""Scale benchmark: build a synthetic people database and time every screen the UI loads.

    python tools/bench.py                      # 50,000 people into a temp DB, then time the endpoints
    python tools/bench.py --people 1000000     # bigger
    python tools/bench.py --db data/big.db     # re-time an existing DB (no generation / import)
    python tools/bench.py --budget 2           # exit non-zero if any endpoint is slower than 2 s

The synthetic file mixes many distinct names with a few very common ones (the realistic hard case: one
common name owns thousands of records), valid national IDs, Israeli mobiles and emails. Every record is
fictional. Nothing touches the network (OSNIT_PROVIDERS is emptied for the server)."""
import argparse
import csv
import itertools
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FIRST = "דוד משה יוסי אבי רון שרה רחל מיכל נועה יעל אורי עומר איתי תמר דנה גיל עידו ליאור שירה אדם".split()
COMMON_LAST = "כהן לוי מזרחי פרץ ביטון".split()
CITIES = "תל אביב|ירושלים|חיפה|באר שבע|נתניה|אשדוד|רמת גן|חולון".split("|")
ORGS = "אלביט|בנק הפועלים|תדיראן|אינטל|עיריית חיפה|טבע".split("|")


def il_id(n):
    d = [int(x) for x in f"{n:08d}"]
    s = sum((y // 10 + y % 10) for y in (x * (1 if i % 2 == 0 else 2) for i, x in enumerate(d)))
    return f"{n:08d}{(10 - s % 10) % 10}"


def generate(path, n, seed=1):
    rnd = random.Random(seed)
    letters = "אבגדהוזחטיכלמנסעפצקרשת"
    rare_last = [a + b + c + "י" for a, b, c in itertools.product(letters, repeat=3)]
    probes = {}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["שם פרטי", "שם משפחה", "טלפון", "אימייל", "ת.ז", "עיר", "מקום עבודה"])
        for i in range(n):
            last = rnd.choice(COMMON_LAST) if rnd.random() < 0.2 else rnd.choice(rare_last)
            first = rnd.choice(FIRST)
            phone = "05%d%07d" % (rnd.randint(0, 8), rnd.randint(0, 9999999))
            nid = il_id(10000000 + i * 7)
            w.writerow([first, last, phone, f"user{i}@example.co.il", nid, rnd.choice(CITIES), rnd.choice(ORGS)])
            if i == n // 2:
                probes = dict(phone=phone, nid=nid, name=f"{first} {last}", email=f"user{i}@example.co.il")
    return probes


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def timed_get(url, timeout):
    t = time.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read()
            status = r.status
    except Exception as e:  # report, keep going
        body, status = str(e).encode(), "ERR"
    return time.time() - t, status, len(body), body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--people", type=int, default=50000)
    ap.add_argument("--db")
    ap.add_argument("--budget", type=float, default=0, help="fail if any endpoint exceeds this many seconds")
    ap.add_argument("--timeout", type=float, default=600)
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="osnit-bench-")
    db = a.db
    probes = {}
    probe_file = (db + ".probes.json") if db else None
    if not db:
        db = os.path.join(work, "bench.db")
        csv_path = os.path.join(work, "people.csv")
        probes = generate(csv_path, a.people)
        t = time.time()
        r = subprocess.run([sys.executable, "-m", "osnit", "--db", db, "import-db", csv_path],
                           cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode:
            print(r.stderr[-3000:])
            sys.exit("import failed")
        dt = time.time() - t
        print(f"import: {a.people} records in {dt:.1f}s ({a.people / max(dt, 1e-9):.0f} rows/s)")
        with open(db + ".probes.json", "w", encoding="utf-8") as f:
            json.dump(probes, f, ensure_ascii=False)
    elif probe_file and os.path.exists(probe_file):
        probes = json.load(open(probe_file, encoding="utf-8"))

    port = free_port()
    env = dict(os.environ, OSNIT_PROVIDERS="")
    srv = subprocess.Popen([sys.executable, "-m", "osnit", "--db", db, "serve", "--port", str(port)],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(300):
            try:
                urllib.request.urlopen(base + "/api/stats", timeout=2).read()
                break
            except Exception:
                time.sleep(0.2)
        Q = urllib.parse.quote
        name = probes.get("name") or "דוד כהן"
        paths = ["/api/stats", "/api/dashboard", "/api/overview", "/api/entities", "/api/entities?type=person",
                 "/api/entities?q=" + Q("דוד"), "/api/entities?q=" + Q(name),
                 "/api/contacts", "/api/contacts?q=" + Q("כהן"), "/api/contacts?q=" + Q(name),
                 "/api/dossier?q=" + Q(name), "/api/dossier?q=" + Q("דוד כהן"), "/api/subjects"]
        for k in ("phone", "nid", "email"):
            if probes.get(k):
                paths += ["/api/contacts?q=" + Q(probes[k]), "/api/entities?q=" + Q(probes[k])]
        if probes.get("phone"):
            p = probes["phone"]
            paths += ["/api/contacts?q=" + Q(p[:3] + "-" + p[3:]), "/api/contacts?q=" + Q("+972" + p[1:])]
        paths += ["/api/entities/1", "/api/entities/2"]
        worst = 0.0
        for p in paths:
            dt, st, n, body = timed_get(base + p, a.timeout)
            hits = ""
            if probes and ("contacts?q=" in p) and st == 200:
                try:
                    hits = f"  rows={len(json.loads(body)['rows'])}"
                except Exception:
                    pass
            worst = max(worst, dt)
            print(f"{dt:8.2f}s {st} {n:>9}B  {urllib.parse.unquote(p)}{hits}", flush=True)
        print(f"slowest: {worst:.2f}s   db: {db}")
        if a.budget and worst > a.budget:
            sys.exit(f"over budget ({worst:.2f}s > {a.budget}s)")
    finally:
        srv.terminate()
        try:
            srv.wait(10)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    main()
