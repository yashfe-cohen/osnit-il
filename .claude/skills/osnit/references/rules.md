# Data rules — full list with rationale

These rules are what make osnit-il trustworthy. Each exists for a reason; keep the reason in mind before
changing the behaviour, and if you change a rule, change the test that encodes it and say why.

## Extraction / recognition

- **Precision-first names.** `extract._name_ok` + the detection patterns only accept a person with real
  evidence. The holdout eval demands precision 1.0 — a false name (a verse figure, two first names in prose, a
  verb mistaken for a surname) is worse than a miss, because the whole point is a believable picture.
  - Hebrew non-surnames live in `NOT_SURNAME_HE`; scripture/reference pages are caught by
    `quality.is_reference_text` and contribute no co-mention links.
  - A gazetteer match whose "surname" is itself a known first name is only trusted if the full pair repeats.
- **Org normalisation.** `extract.org_key` strips `ORG_SUFFIX` (בעמ/ltd/…) and leading `ORG_LEAD_HE`
  (חברת/עמותת/…), so `חברת אלפא` / `אלפא בע"מ` / `אלפא` share a key and link across files.
- **Phone vs. national ID.** `norm_phone_il` returns a number only with a trunk `0` or a `972`/`+972` code; a
  bare 8–9-digit string is `None` and `value_kind` classifies it as `il_id`/`number`. This is the single most
  important disambiguation for Israeli data — a 9-digit mobile national part and a 9-digit ID look identical.

## Storage / cataloguing

- **Nothing auto-dropped.** `catalog` never produces a "discard" status on its own. `semantic.SENSITIVE_KINDS`
  is empty by design; `SECURITY_KINDS` only *labels* credential columns (they are stored under `password`/
  `hash`/`card`/`national_id`). Only an explicit user `skip`/`internal`, or a user-defined `sensitive` custom
  type, withholds a column.
- **national_id is linkable.** It is a strong personal identifier; it creates an entity and links records.
- **Attributes keep the original header.** Unknown-but-useful columns are stored on the person/org under their
  own column name (with a suggested Hebrew label), never discarded, never renamed.

## Linking / identity

- **Canonical identifiers link across files.** `email_key` (dots/+tag/googlemail), `social_profile` (profile +
  handle), `address_key`, `username_key`. Same real thing, written differently → one entity.
- **Clustering (identity.dossier).** Records merge on a shared personal identifier even across name spellings,
  when the identifier ties ≤2 parties. Same-name records may merge on a weak anchor (org/address/city) and are
  labelled `merge: "weak"`. Two different `national_id` values are a hard conflict and never merge — this keeps
  two distinct people who happen to share a name apart.
- **Exclusivity weighting.** A detail held by several people (a switchboard number, a shared address) is weak
  evidence about any one of them; the dossier down-weights it and flags it as shared.
- **Confidence = noisy-or over independent domains** (`profile.combine`). Ten pages on one site ≠ corroboration.

## Collection / safety

- **Focused search.** `urls.GENERIC_DOMAINS` + `OSNIT_BLOCK_DOMAINS` are never read; Wikipedia is opt-in only.
  Person query templates in `search.py` target profiles, Israeli institutions, news, and documents.
- **Politeness & SSRF.** `fetch.py` honours robots.txt and Crawl-delay, caps size/time, blocks internal hosts
  (also through redirects). Google is only queried via its API, never scraped.
- **Raw bodies are never persisted** — parsed in memory and dropped. Imported files are deleted after a
  successful import when `--delete-raw`/`OSNIT_DELETE_IMPORTED`.
- **Bulk deletion is gated** by `OSNIT_RESET_CODE` (default 1212). A fact seen in another source survives a
  per-file/source delete, with that other source's evidence.
