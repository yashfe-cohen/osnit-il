# CLAUDE.md — osnit-il

A continuous public-source OSINT engine (Hebrew/English), stdlib-only Python 3.10+ (`pypdf` optional).
It imports files and public web sources, extracts people/orgs/contacts/identifiers with evidence and
confidence, resolves identities, and correlates across sources. UI/comments are Hebrew/RTL; code is English.

**When working here, use the `osnit` skill** (`.claude/skills/osnit/`) — it holds the architecture map, the
non-negotiable data rules, the gotchas, and the exact commands. Load it before changing extraction,
cataloguing, identity/linking, the engine, the store, the import pipeline, the UI, or the CLI.

## Golden rules (short form — full detail in the skill)

- **Gate before every push:** `python -m unittest discover -s tests -t .` **and** `python -m osnit eval
  tests/corpus_holdout` **and** `python -m osnit eval tests/corpus`. Both evals must stay at precision/recall/
  link_recall = 1.0, violations = 0. Add a test for new behaviour. `node --check` the `ui.html` script.
- **Precision-first extraction.** A false person/fact is worse than a miss. No statistical NER.
- **Nothing is auto-dropped** — it's the operator's own data. Credentials are stored under labelled security
  types; a national ID is a linking identifier; only an explicit user `skip` withholds a column.
- **Phone needs `0` or `972`/`+972`.** A bare 8–9-digit number is never a phone (collides with a national ID).
- **Link the same thing written differently:** `email_key`, `social_profile`, Hebrew org-word stripping; two
  different national IDs never merge into one identity.
- **No hard cap on records per file;** imports stream, counting is cheap.
- Never open a PR unless asked. Develop on the designated branch.

## Run / layout

- Run: `./run.sh` or `python -m osnit serve --port 8080`. CLI: `python -m osnit <serve|search|import|import-db|
  analyze|add-type|reset|stats|forget|eval|show>`.
- Code in `osnit/` (one responsibility per module — see the skill's map); tests in `tests/`; labelled
  extraction corpora in `tests/corpus*`; the whole web app is the single file `osnit/ui.html`.
