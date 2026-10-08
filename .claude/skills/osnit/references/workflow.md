# Workflow templates

## The pre-push gate (copy/paste)

```bash
cd /path/to/osnit-il
python -m unittest discover -s tests -t . 2>&1 | tail -3
python -m osnit eval tests/corpus_holdout | tail -1
python -m osnit eval tests/corpus | tail -1
```

Expect `OK` and, from both evals, `"person_precision": 1.0, "person_recall": 1.0, "link_recall": 1.0,
"violations": 0, "page_type_errors": 0`.

## Add a test for new behaviour

Tests live in `tests/test_*.py` (plain `unittest`). `tests/helpers.py` `make()` builds a store+engine+server
with a fake web server; `ImportQueue(engine, inbox=…)` + `run_pending()` drives imports synchronously. Column
cataloguing is tested directly via `catalog.plan_columns(cols, rows[, overrides=…])`; identity via
`identity.dossier(store, name=…)`. Extraction quality lives in `tests/corpus*` as `<name>.html/.txt` +
`<name>.gold.json`; add real pages there and run `python -m osnit eval <folder>`.

## Drive the UI in a real browser (Playwright/Node)

```bash
S=/tmp/scratch; mkdir -p "$S"; rm -rf "$S"/x.db* "$S"/inbox
OSNIT_PROVIDERS= nohup python -m osnit --db "$S/x.db" serve --port 8766 > "$S/serve.log" 2>&1 & echo $! > "$S/pid"
sleep 3
# write a demo CSV to "$S/demo.csv", then:
node - <<'EOF'
const {chromium}=require('playwright');            // npm i playwright@1.56.1 in the scratch dir if needed
(async()=>{
 const br=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const p=await br.newPage({viewport:{width:1360,height:1200}});
 await p.goto('http://localhost:8766/#uploads'); await p.waitForSelector('#drop');
 if(!await p.isChecked('#review')) await p.check('#review');
 await p.setInputFiles('#file','/tmp/scratch/demo.csv');
 await p.waitForSelector('#jApprove',{timeout:20000}); await p.waitForTimeout(600);
 await p.screenshot({path:'/tmp/scratch/review.png',fullPage:true});
 await br.close();
})();
EOF
kill $(cat "$S/pid")
```

The 404 for the favicon in console output is harmless. Chromium's exact dir is `/opt/pw-browsers/chromium-*`;
adjust the version in the path if the glob differs.

## Git / PR

```bash
git push -u origin <feature-branch>
# merged PR already? advance safely, then push follow-up as a NEW PR (only if asked):
git fetch origin main && git merge --ff-only origin/main
```

Commit messages end with the attribution footer the session specifies. Never open a PR unless the user asks.
