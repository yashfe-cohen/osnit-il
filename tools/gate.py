"""The project's quality gate, as one cross-platform command (also what CI runs):

    python tools/gate.py

1. the whole unit-test suite;
2. the labelled extraction evals (tests/corpus_holdout, tests/corpus) — must stay at precision / recall /
   link_recall = 1.0 with 0 violations and 0 page-type errors;
3. a syntax check of the inline script in osnit/ui.html (skipped with a note when Node.js is not installed).

Exits non-zero on the first failure, so it can guard a push or a CI job."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PERFECT = {"person_precision": 1.0, "person_recall": 1.0, "link_recall": 1.0, "violations": 0, "page_type_errors": 0}


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
