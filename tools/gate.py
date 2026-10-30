"""The project's quality gate, as one cross-platform command (also what CI runs):

    python tools/gate.py

1. the whole unit-test suite;
2. the labelled extraction evals (tests/corpus_holdout, tests/corpus) — must stay at precision / recall /
   link_recall = 1.0 with 0 violations and 0 page-type errors;
3. the identity-resolution benchmark (`python -m osnit ereval`) — the importer never joins two different people,
   and the possible-match layer stays within ER_EXACT / ER_MAX / ER_MIN;
4. the messy-query search benchmark (`python -m osnit qeval`) — a name typed with slips, by ear, on the wrong
   keyboard, joined, in Cyrillic or half in English still finds the person, and a name not in the data finds nobody;
5. a syntax check of the inline script in osnit/ui.html (skipped with a note when Node.js is not installed).

Exits non-zero on the first failure, so it can guard a push or a CI job."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PERFECT = {"person_precision": 1.0, "person_recall": 1.0, "link_recall": 1.0, "violations": 0, "page_type_errors": 0}

# Identity resolution (`python -m osnit ereval`, a synthetic population with known truth). The importer must NEVER
# join two different people (rule 5). The possible-match layer must not get worse than these limits — they are
# tightened as the resolver improves, never loosened.
ER_EXACT = {("auto", "false_merges"): 0, ("auto", "namesake_false_merges"): 0}
ER_MAX = {("suggest", "brier"): 0.19, ("suggest", "incoherent"): 1, ("suggest", "worst_claim_sum"): 1.05,
          ("unlinked_rows",): 1}
# recall_at_05 counts every true pair; since the operator's rule (a name alone is never offered — only a pair with a
# concrete detail in common), about a third of them are not eligible by design, so the gate holds the recall over the
# ELIGIBLE pairs, and the overall figure at the level that rule implies
ER_MIN = {("suggest", "recall_at_05"): 0.40, ("suggest", "recall_eligible_at_05"): 0.58,
          ("suggest", "precision_at_05"): 0.90}
# Messy-query search (`python -m osnit qeval`): tightened as search improves, never loosened. A name that is not in
# the data must never bring anybody up (fuzzy search must not buy recall with false hits).
Q_MIN = {"found_at_5": 0.97, "found_at_1": 0.96}
Q_EXACT = {"false_hit_rate": 0.0}


def q_problems(got):
    out = [f"{k}={got.get(k)} (min {v})" for k, v in Q_MIN.items() if got.get(k) is None or got.get(k) < v]
    out += [f"{k}={got.get(k)} (must be {v})" for k, v in Q_EXACT.items() if got.get(k) != v]
    return out


def er_problems(got):
    """The identity-benchmark limits this summary breaks (empty list = pass)."""
    def val(path):
        v = got
        for k in path:
            v = (v or {}).get(k)
        return v
    out = [f"{'.'.join(k)}={val(k)} (must be {v})" for k, v in ER_EXACT.items() if val(k) != v]
    out += [f"{'.'.join(k)}={val(k)} (max {v})" for k, v in ER_MAX.items() if val(k) is None or val(k) > v]
    out += [f"{'.'.join(k)}={val(k)} (min {v})" for k, v in ER_MIN.items() if val(k) is None or val(k) < v]
    return out


def run(cmd):
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, encoding="utf-8", errors="replace")


def main():
    r = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."])
    print("\n".join((r.stderr or "").strip().splitlines()[-3:]))
    if r.returncode:
        print(r.stdout[-4000:], r.stderr[-12000:])
        sys.exit("unit tests failed")
    for corpus in ("tests/corpus_holdout", "tests/corpus"):
        r = run([sys.executable, "-m", "osnit", "eval", corpus])
        line = next((ln for ln in reversed(r.stdout.splitlines()) if ln.startswith("{")), "{}")
        got = json.loads(line)
        print(corpus, got)
        bad = {k: got.get(k) for k, v in PERFECT.items() if got.get(k) != v}
        if r.returncode or bad:
            print(r.stdout[-4000:], r.stderr[-4000:])
            sys.exit(f"eval {corpus} regressed: {bad}")
    r = run([sys.executable, "-m", "osnit", "ereval"])
    line = next((ln for ln in reversed(r.stdout.splitlines()) if ln.startswith("{")), "{}")
    got = json.loads(line)
    print("identity", {k: got.get(k) for k in ("auto", "suggest", "unlinked_rows")})
    bad = er_problems(got)
    if r.returncode or bad:
        print(r.stdout[-4000:], r.stderr[-4000:])
        sys.exit(f"identity resolution regressed: {bad}")
    r = run([sys.executable, "-m", "osnit", "qeval"])
    line = next((ln for ln in reversed(r.stdout.splitlines()) if ln.startswith("{")), "{}")
    got = json.loads(line)
    print("messy queries", {k: got.get(k) for k in ("found_at_5", "found_at_1", "false_hit_rate", "by_kind")})
    bad = q_problems(got)
    if r.returncode or bad:
        print(r.stdout[-4000:], r.stderr[-4000:])
        sys.exit(f"messy-query search regressed: {bad}")
    node = shutil.which("node")
    if not node:
        print("node not found - skipping the ui.html script check")
        return
    s = open(os.path.join(ROOT, "osnit", "ui.html"), encoding="utf-8").read()
    js = s[s.index("<script>") + 8:s.rindex("</script>")]
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js)
    try:
        r = run([node, "--check", f.name])
    finally:
        os.unlink(f.name)
    if r.returncode:
        print(r.stderr)
        sys.exit("ui.html script has a syntax error")
    print("gate: all green")


if __name__ == "__main__":
    main()
