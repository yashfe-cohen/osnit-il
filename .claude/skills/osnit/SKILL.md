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
  records (each tabular row stored ONCE; evidence points at it via `record_id`; `records_fts` indexes it),
  sources, subjects, jobs, events, imports, field_memory, custom_types, identity_links, subject_cache.
  `resolve_person_record` resolves a tabular record's person to an IDENTITY (see rule 5); `resolve_entity` is the
  free-text/web path (fuses by `name_key` + typo). `reset()`/`purge_sources()` (batched)/`purge_import()`.
- `possible.py` — "possible same person": indexed blocking (`block()` — name in any spelling, nicknames, identifier
  holders ≤25), then the learned model (`matchmodel`) scores every pair and the resolver (`resolve`) makes the whole
  name block coherent; operator decisions (`identity_links`, honoured by the dossier) always win. `_features()`
  gathers each identity's ids/nids/emails/addresses/cities/orgs/birth (ISO-normalised) and **srcs** (its files).
- `matchmodel.py` — the identity model, **measured on the operator's own data** (cached in `meta`, refit when the
  data or decisions change). A same-name pair's odds are `duplicates / (namesakes × where-B-is)`: a Poisson EM over
  the sampled blocks splits constant duplicates from namesakes that grow with how common the name's words are (the
  data's own word frequencies, smoothed toward `data/population_il.json`); same-file vs other-file is part of the
  prior (one file rarely lists a person twice). Every further field is a likelihood ratio with m/u learned from known
  namesakes (two different IDs) and operator decisions; towns carry a learned clustering factor. `Scorer` scores a
  block; `iso_date`, `token_population_share`, `town_population_share` are the pieces.
- `resolve.py` — **coherent block resolution**: cores are the must-linked components (shared identifier / operator
  "same"), kept apart by cannot-links (two different IDs / operator "different"); a per-core + per-identity budget
  (Sinkhorn-style cap) brings only the incoherent sums down to 1, so three different-ID namesakes can't each be the
  same person, while an uncontested duplicate keeps its pairwise probability. A shared identifier or a decision stays
  an exact certainty. Guarded by `tests/test_matchmodel.py`, `tests/test_resolve.py`, and the `ereval` gate
  thresholds (`worst_claim_sum ≤ 1.05`, `incoherent ≤ 1`, `precision_at_05 ≥ 0.90`).
- `profile.py` — builds a subject's picture: identity clustering by shared anchors, facets, noisy-or confidence
  over independent domains (`combine`).
- `identity.py` — the **dossier** (`dossier()`): gather every record of a name (any spelling), cluster records
  that share a strong personal identifier, grade each detail by exclusivity, draw the "threads" graph.
- `linking.py` — connections across files/web: `connections`, `attributes_of`, `origins_of`, `link_stats`.
- `engine.py` — the crawl/scan engine (claim→fetch→parse→extract→persist→follow). `_focus_filter` keeps only
  the searched subject and what links to it. `fetch.py` — polite fetch (robots, SSRF guard).
  `run_jobs_once` **ranks** each discovered URL with `rank_source_priority` (SERP position + domain class —
  gov/ac/legal > social-profile paths > Israeli news — + document bonus + a subject-token-in-path boost) so
  the crawler reads the most promising pages first under budget/time; ranking only reorders, never fabricates.
  It also **harvests SERP snippet intel** (`_harvest_serp_intel`): identifiers (phone/email/national-id) that a
  provider surfaced in result titles/snippets (`prov.last_snippets`, via `harvest_snippet_intel`) — reaching data
  on pages that block the crawler — persisted as `serp_contact` osint_findings on the subject's entity. Precision
  gate: one full spelling of the subject's name (`_subject_name_forms`) must appear in the SAME snippet, so a stray
  number on an unrelated result is never attributed; `_subject_primary_entity` links a freshly created anchor into
  `subject_entities` so the finding surfaces in the profile — see `test_search_ranking_intel`.
- `providers.py` — discovery providers (google/serpapi/brave/searxng/wikipedia(opt-in)/archive/ddg,
  and **`browser`** — opt-in no-API discovery through the pre-installed headless Chromium via `browser_search.cjs`;
  degrades to [] when Node/Playwright/Chromium is absent or the engine blocks the visit; downloads result-page
  documents through the Fetcher's robots/SSRF/size posture).
  `clean_results` drops generic sites. `search.py` — query planning; `query.py` — intent parsing.
- `server.py` — stdlib HTTP API + serves `ui.html`. `analytics.py` — dashboard. `ui.html` — the entire
  single-page Hebrew UI (vanilla JS, inline `<script>`).
- `web_osint.py` — the 7-layer **Deep Recon** engine (keyless, public-source only, never bypasses a login):
  `SearchTargetProfile` (seed → permutations/transliteration), the layer runners, `UnifiedReconEngine` /
  `ReconJobManager` (background jobs the UI polls at `/api/recon/*`). Precision-first and network-honest:
  `_async_http_get[_bytes]` count request/search health into a per-run `_NET` context, and a run that got no
  answers (no net / blocked / CAPTCHA) says so (`network_summary`) instead of looking "done" — see
  `test_recon_network`. Empty tool answers cache only `Store.OSINT_EMPTY_TTL` (15 min), real findings 24h.
  - **Layer 3 username presence** scans the curated `SOCIAL_PLATFORMS` **and** keyless WhatsMyName/Sherlock
    JSON manifests via `osnit/manifests.py` through the SAME `check_username_on_platform` (which honours
    `exist_code`/`positive`/`negative`): a site is a hit only on an explicit exists-string, never a status code
    alone; curated names win over manifest duplicates. Bundled `osnit/data/username_sites.json` works offline;
    `tools/sync_manifests.py` expands it to `username_sites.synced.json` (git-ignored, preferred when present).
    Caps: `OSNIT_USERNAME_SITES_MAX`, `OSNIT_USERNAME_CONCURRENCY`.
  - **Layer 5 dorks**: `build_israeli_dorks` (`_IL_SOURCES` registries: legal/enforcement/gov/business/
    professional/academic/press/lifecycle/social/documents/paste) + `build_open_web_queries`; every query is
    anchored on a target identifier so `score_search_result` still gates precision. Budget `OSNIT_MAX_RECON_DORKS`.
    A document hit (pdf/xlsx/docx/csv/… — `document_type_of`) is fetched and run through osnit's own
    `parse()`; `focus_excerpt` keeps only windows that mention the target (so a file's PII is surfaced ONLY when
    it actually names the target), and the finding carries `file_url`/`file_type`/`from_file` plus the extracted
    names/emails/phones — see `test_doc_harvest`.
  - **Domain & infrastructure intel** (`check_certificate_transparency`/crt.sh, `check_rdap_domain`/RDAP,
    `run_layer_domain_intel`), folded into Layer 2 and seeded from the target's own email/URL domains
    (`SearchTargetProfile.domains` / `pivotable_domains()`). crt.sh gives subdomains; RDAP gives the public
    registrant (person/org/email) when not privacy-protected. Precision-first: `is_pivotable_domain` /
    `registrable_domain` never sweep free-mail or a big platform, only a domain the target owns/uses; a
    redacted WHOIS yields nothing — see `test_domain_intel`.
  - **Layer 6 visual recon** (`run_layer6_image_recon`): four image sources — A `direct_avatar` (avatars from
    L2–4), B `article_image` (from L5 pages), C `search_image` (Bing images), D `og_image` (og:image/
    twitter:image scraped from finding URLs via `_scrape_og_images`, name-token-gated). `verify_human_face_in_image`
    (OpenCV Haar frontal+profile, eye-cascade corroboration, large-image downscale) returns face boxes, a
    `portrait` flag (one dominant face ⇒ likely the target) and `largest_face_ratio`; non-avatar sources must
    face-verify. `_dhash`/`_hamming` drop perceptual near-duplicates (Hamming <8). `_extract_jpeg_exif` is a pure
    stdlib EXIF reader (JPEG APP1→TIFF IFD0→Exif SubIFD→GPS IFD): make/model/lens/iso/f_number/exposure/
    orientation/datetime + GPS lat/lon/alt/img_direction/datestamp; `_reverse_geocode_il` turns the GPS fix into
    a coarse Hebrew place hint (keyless, offline bounding boxes) as `gps_place`. All in `extracted_data.exif`,
    shown in the image inspector with a Maps link — see `test_layer6_improvements`.
  - **Recursive pivot expansion** (`recursive_pivot_expand`, Maltego "a result of a result"): high-confidence
    NEW identifiers (emails/usernames/domains, floor `OSNIT_PIVOT_CONF`) feed focused extra discovery rounds
    (email breach/Gravatar/GitHub, the L3 username sweep, crt.sh/RDAP) up to `max_depth` hops (`run_recon`'s
    `max_depth`, clamped ≤4, default 2 = one extra hop); each hop's findings are tagged `pivot_depth` and its
    identifiers folded back into the profile. Replaces the old ad-hoc "Hop 2" block.
  - `recon_entity_graph()` returns a Maltego-style `{nodes,edges}` (same shape as the dossier's `forceGraph`):
    target → seed identifiers (incl. `domain` nodes) → discovered profiles (edge = the transform/tool) → pivot
    leads → local-DB matches; `domain_intel` findings anchor to their domain node.

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
5. **People are identities, not names.** A tabular record joins an existing person ONLY through a shared personal
   identifier (national ID > personal email > mobile) with a compatible name; person keys are
   `<name_key>|<anchor>`. A name alone, a landline, or an identifier held by >25 people never merges; two different
   national IDs **never** merge. Same name + same city/org/address is a *possible match* (`possible.py`) the
   operator confirms — never automatic.
6. **Focused web search.** Generic-knowledge sites (Wikipedia, scripture, dictionaries, lyrics, genealogy) are
   not read; person queries target profiles, `*.gov/ac/org.il`, Israeli news, documents.
7. **Evidence & confidence** on every fact; confidence is noisy-or over *independent domains*. Raw bodies are
   never persisted. Bulk deletion needs the reset code (`OSNIT_RESET_CODE`, default 1212).

## Gotchas that have bitten us

- `analyze._peeked()` returns `(head, chain(head, remainder))` — the second element **replays head**. To count
  rows do `sum(1 for _ in rest)`, never `len(head) + sum(...)`.
- `catalog.LEGACY` (`text→doc`, `domain→website`) applies to **mapping files only**, never to user overrides
  from the UI (the UI sends real type keys).
- Person keys are `<name_key>|<anchor>` for imported records: match a name with the key prefix
  (`key >= nk+"|" AND key < nk+"|\uffff"`), and use `person_base_key()` / `_pkey()` before comparing keys.
- Investigation pages are served from `subject_cache` (rebuilt in the background); anything that removes data or
  changes identity decisions must clear it.
- Scale: always verify with `tools/bench.py` / `tools/diagnose.py`; join relations→entities with `CROSS JOIN`
  (relations first) — `tests/test_scale_plans.py` guards the plans.
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
