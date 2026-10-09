---
name: osnit
description: >-
  Working guide for the osnit-il repository — a continuous public-source OSINT engine (Hebrew/English) that
  ingests files, extracts and catalogues entities, resolves identities and correlates across sources. USE THIS
  SKILL whenever you touch this repo: adding or changing extraction, column cataloguing, the semantic type
  system, identity/dossier clustering, cross-file linking, the crawl/discovery engine, the SQLite store, the
  import pipeline, the local web UI (ui.html), or the CLI — and before running tests, the quality eval, or
  pushing. It encodes the architecture, the non-negotiable data rules (precision-first names, nothing dropped,
  phone-vs-ID, email canonicalization), the test+eval gate, and the known gotchas, so you don't re-derive them.
---

# osnit-il — engineering guide

A local, dependency-free (Python 3.10+, stdlib only; `pypdf` optional) OSINT engine. It starts from imported
files and public web sources, extracts people/orgs/contacts/identifiers, keeps **evidence + confidence** for
every fact, resolves identities and draws the connections between them. UI and comments are **Hebrew/RTL**;
code and identifiers are English.

Run the app: `./run.sh` (or `python -m osnit serve --port 8080`). CLI entry: `python -m osnit …`.

## The one gate you never skip

Before **every** push, all three must pass — they are fast and offline:

```bash
python -m unittest discover -s tests -t .      # the whole suite must be OK
python -m osnit eval tests/corpus_holdout      # person_precision/recall, link_recall, violations
python -m osnit eval tests/corpus
```

The two evals must stay at **precision 1.0, recall 1.0, link_recall 1.0, violations 0, page_type_errors 0**.
If a change drops any of them, it regressed extraction quality — fix it or reconsider, don't lower the bar.
When you touch `osnit/ui.html`, also syntax-check the inline script before pushing:

```bash
python - <<'EOF'
s=open("osnit/ui.html",encoding="utf-8").read()
js=s[s.index("<script>")+8:s.rindex("</script>")]
open("/tmp/ui.js","w").write(js); import subprocess
print(subprocess.run(["node","--check","/tmp/ui.js"],capture_output=True,text=True).stderr or "ui js ok")
EOF
```

Add a focused test in `tests/` for any new behavior. The suite is the contract; a feature without a test will
silently rot.

## Architecture — module map

The import/analysis path (the heart of the project — recognising columns, names, and building connections):

- `semantic.py` — the **type system**. ~30 built-in `SType`s + user `CustomType`s in a `Registry`. `value_kind()`
  classifies one value by content; `header_type()` by header; `KIND_TO_TYPES`/`DECISIVE` map content→type.
  Normalisers that make linking work: `email_key` (gmail dots/+tag/googlemail), `address_key`, `username_key`,
  `profile_url`, `social_profile`, `il_id_ok`, `pattern_from_examples`.
- `catalog.py` — decides, per column, **what it is and what happens to it**: status `entity` (linkable),
  `attribute` (kept under its original header), `doc` (full-text extraction), `internal`, `empty`, or `skip`
  (user chose not to store). Decision order of trust: user override → taught header → exact synonym → **content**
  → learned-from-earlier-files → fuzzy header. `plan_columns()` returns a `Plan`.
- `structure.py` — finds record tables **inside non-tabular files**: `key: value` blocks and vCard, delimited
  lines, typed lines, HTML tables, nested JSON (flattened), XML.
- `importdb.py` — `raw_tables()` yields (table, cols, rows) for every format; `read_tables()` plans them;
  `record_extraction()` turns one row into an `Extraction` (owner + linked entities + attributes); `import_db()`
  streams rows into the store; `cheap_count()` counts rows without a full pass (no cap on big files).
- `ai.py` — **optional, opt-in AI extraction-template layer** (off and inert unless OSNIT_AI_TEMPLATE/KEY/URL/MODEL
  are all set). Between analyse and import it shows an LLM the headers + 5 middle rows and gets a column→type
  template, validated against the live Registry and applied through the SAME overrides channel (never drops data,
  never overrides the phone-vs-ID rule, always forces operator review, caches by header+kind signature, degrades
  to today's deterministic path on any failure). `_call` is the single network seam tests monkeypatch.
- `mdb.py` — stdlib **Microsoft Access** reader (.mdb Jet 3/4, .accdb ACE 2007–2016+): page-by-page, never the
  whole file. `access_tables()` also does the deep join: a fact table with no personal identity of its own
  (orders, calls…) gets its parent's identity columns (`<parent>.<col>`) via MSysRelationships or a column named
  like the parent's non-generic key — only when ≥50% of its sampled keys hit the parent. Verified value-by-value
  against Jackcess dumps (`tests/access/samples.zip`; regenerate with Jackcess if you change the reader).
- `analyze.py` — stage-1 read-only analysis: `analyze_file()` (tables, column plans, sample records, overlap
  with the DB, stored raw sample rows) and `repreview()` (re-catalogue/re-extract the stored sample rows with
  the user's overrides, no file read — powers live editing). `import_summary()` describes what an import added.
- `importqueue.py` — background queue: analyse → (review/approve) → import; `repreview`, `reanalyze`, `approve`,
  `purge`, per-file deletion. `detect.py` guesses a file's kind for the queue.

Extraction from free text / web pages:

- `extract.py` — the `Extractor`: names (precision-first), orgs, roles, emails, phones, domains, URLs, social
  handles, and the relations between them. `norm_phone_il`, `phone_variants`, `org_key`, the `Extraction` type.
- `sensitive.py` — **context-aware DLP engine** (a separate read-only pass over free text; does NOT touch the
  entity extractor, so the eval is unaffected). A deterministic detector layer (national_id/card/phone/email/iban
  checksums) + an anchor layer that boosts/dampens confidence by nearby cues (Presidio-style) + lightweight person
  coreference + subject/object-aware attribution + a hierarchical sensitivity taxonomy, every finding explained.
  `analyze_text(text) -> Report`; CLI `python -m osnit sensitive <file>`.
- `quality.py` — plausibility gates: `valid_email`/`valid_phone`, `is_role_mailbox`, page `classify`
  (normal/directory/spam), `is_reference_text` (scripture/encyclopaedia — its names are not real contacts),
  `prune_shared`.
- `parse.py` — bytes→`Parsed` for html/pdf/docx/xlsx/csv/json/vcf/xml/txt; `names.py`/`variants.py`/`xling.py`
  — first-name gazetteers, spelling variants, Hebrew↔Latin matching; `textnorm.py` — folding/`name_key`.

Correlation, storage, serving:

- `store.py` — SQLite schema and all DB ops: entities, aliases, evidence, relations, rel_evidence, attributes,
  sources, subjects, jobs, events, imports, field_memory, custom_types. `resolve_entity` fuses persons by
  `name_key` (+ typo). `reset()`/`purge_sources()`/`purge_import()`.
- `profile.py` — builds a subject's picture: identity clustering by shared anchors, facets, noisy-or confidence
  over independent domains (`combine`).
- `identity.py` — the **dossier** (`dossier()`): gather every record of a name (any spelling), cluster records
  that share a strong personal identifier, grade each detail by exclusivity, draw the "threads" graph.
- `linking.py` — connections across files/web: `connections`, `attributes_of`, `origins_of`, `link_stats`.
- `engine.py` — the crawl/scan engine (claim→fetch→parse→extract→persist→follow). `_focus_filter` keeps only
  the searched subject and what links to it. `fetch.py` — polite fetch (robots, SSRF guard).
- `providers.py` — discovery providers (google/serpapi/brave/searxng/wikipedia(opt-in)/archive/ddg,
  and **`browser`** — opt-in no-API discovery through the pre-installed headless Chromium via `browser_search.cjs`;
  degrades to [] when Node/Playwright/Chromium is absent or the engine blocks the visit; downloads result-page
  documents through the Fetcher's robots/SSRF/size posture).
  `clean_results` drops generic sites. `search.py` — query planning; `query.py` — intent parsing.
- `server.py` — stdlib HTTP API + serves `ui.html`. `analytics.py` — dashboard. `ui.html` — the entire
  single-page Hebrew UI (vanilla JS, inline `<script>`).

## Non-negotiable data rules (the project's identity)

Read `references/rules.md` for the full list with rationale. The essentials:

1. **Precision-first names.** A person is recognised only with real evidence (subject match, a title incl.
   `ד"ר`, adjacency to a role, a `שם:`/label line, or a known first name + surname). No statistical NER. Reject
   prose/scripture tokens as surnames and two-first-name gazetteer hits unless the pair repeats. Never trade a
   recall point for a precision point — the eval encodes this.
2. **Nothing is dropped automatically.** It is the operator's own data. Credential-type columns (passwords,
   hashes, cards, national IDs) are stored under their own `security` types and labelled; the user can mark any
   column `skip` by hand. A **national ID is a linking identifier**. Do not add automatic restrictions on what
   becomes an identifier.
3. **Phone vs. ID.** A phone needs a trunk `0` (10 digits, `0545566123`) or a `972`/`+972` country code. A bare
   8–9-digit number is **never** a phone (it collides with a national ID). `norm_phone_il` enforces this.
4. **Linking normalisation.** Emails canonicalise via `email_key`; social links via `social_profile`→profile+
   handle; Hebrew org names drop leading `חברת`/`עמותת`. The same value written differently must link.
5. **Identity clustering.** Merge records across spellings on a shared *personal* identifier; same-name records
   may merge on a weak anchor (org/address/city) but two different national IDs **never** merge.
6. **Focused web search.** Generic-knowledge sites (Wikipedia, scripture, dictionaries, lyrics, genealogy) are
   not read; person queries target profiles, `*.gov/ac/org.il`, Israeli news, documents.
7. **Evidence & confidence** on every fact; confidence is noisy-or over *independent domains*. Raw bodies are
   never persisted. Bulk deletion needs the reset code (`OSNIT_RESET_CODE`, default 1212).

## Gotchas that have bitten us

- `analyze._peeked()` returns `(head, chain(head, remainder))` — the second element **replays head**. To count
  rows do `sum(1 for _ in rest)`, never `len(head) + sum(...)`.
- `catalog.LEGACY` (`text→doc`, `domain→website`) applies to **mapping files only**, never to user overrides
  from the UI (the UI sends real type keys).
- `store.resolve_entity` fuses same-`name_key` persons into one entity, so two identically-named people can't be
  split at the entity level — the dossier splits by shared identifiers across *different-spelling* entities.
- Client disconnects (`ConnectionAbortedError`/`BrokenPipe`, WinError 10053) on the SSE stream and dashboard
  poll are normal; `server.py` already swallows them — don't reintroduce tracebacks.
- UI is one file, vanilla JS, inline script, RTL Hebrew. Keep the token helpers (`tl`, `esc`, `ORG`, `pct`) and
  the `#hash` router pattern; `node --check` the script before pushing.

## Verifying the UI in a real browser

Chromium is pre-installed. Drive it with Playwright (Node) at `/opt/pw-browsers/chromium-*/chrome-linux/chrome`.
Start a scratch server on a spare port with its own DB (`--db <scratch>/x.db`, `OSNIT_PROVIDERS=` to avoid net),
upload a demo file, and screenshot the analysis / dossier screens. See `references/workflow.md` for a template.

## Git / PR workflow

Develop on the designated feature branch; run the gate above; commit with a clear message and the required
attribution footer; push with `git push -u origin <branch>`. A merged PR is finished — for follow-up work
advance the branch from latest `main` (a non-destructive `git merge --ff-only origin/main` when it's already an
ancestor) and open a fresh PR. Never create a PR unless asked.
