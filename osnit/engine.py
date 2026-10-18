"""Crawl/scan engine: claims due sources, fetches, detects change, parses, extracts, persists, follows links."""
import hashlib
import json
import logging
import re
import threading
import time

from .config import Config
from .extract import Extractor, SubjectSpec
from .fetch import Fetcher
from .parse import ParseError, parse
from .providers import build_providers, clean_results
from .store import Store
from .urls import DOC_EXT, SKIP_EXT, ext_of, host_of, is_generic, normalize_url, registered_domain
from .variants import build_matcher

log = logging.getLogger("osnit")


def sha(b) -> str:
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode("utf-8", "replace")).hexdigest()


def load_specs(store: Store) -> list:
    specs = []
    for r in store.q("SELECT * FROM subjects WHERE status='active'"):
        matcher = build_matcher(json.loads(r["variants"])) if r["kind"] in ("person", "org") else None
        specs.append(SubjectSpec(r["id"], r["kind"], r["canonical"], r["entity_key"], matcher))
    return specs


# Domain classes that decide which discovered pages the crawler reads first under a budget/time limit.
# Ranking only reorders the crawl queue — it never fabricates a fact and never drops a result.
_HIGH_VALUE_HOST_HINTS = ("gov.il", "ac.il", "muni.il", "org.il", "court.gov.il", "nevo.co.il", "psakdin.co.il")
_NEWS_HOST_HINTS = ("ynet", "globes", "calcalist", "themarker", "haaretz", "maariv", "mako", "walla",
                    "bizportal", "israelhayom", "n12", "kan")
_SOCIAL_PROFILE_HINTS = ("linkedin.com/in/", "linkedin.com/pub/", "facebook.com/", "instagram.com/",
                         "t.me/", "github.com/", "x.com/", "twitter.com/", "tiktok.com/@")


def rank_source_priority(url: str, serp_rank: int, subject_tokens: set = ()) -> int:
    """Relevance score → crawl priority (higher = read sooner). Folds the SERP position (earlier results are more
    relevant), the domain class (gov/academic/legal > social profiles > Israeli news), whether the hit is a
    document (richest PII) and whether a subject name token appears in the URL path. Precision-safe: this only
    orders the crawl queue, so a low score delays a page, never invents or discards anything."""
    u = (url or "").lower()
    if not u:
        return 100
    host = host_of(u)
    score = 100
    score += max(0, 40 - serp_rank * 3)                      # SERP position 0 → +40, fades out by ~rank 13
    if any(h in host for h in _HIGH_VALUE_HOST_HINTS):
        score += 55
    elif any(sp in u for sp in _SOCIAL_PROFILE_HINTS):
        score += 45
    elif any(nh in host for nh in _NEWS_HOST_HINTS):
        score += 25
    if ext_of(u) in DOC_EXT:                                 # a PDF/DOCX/XLSX carries the richest contact data
        score += 35
    if subject_tokens:
        path = u.split("//", 1)[-1]
        if any(tok in path for tok in subject_tokens if len(tok) >= 3):
            score += 25
    return score


class Engine:
    def __init__(self, store: Store, cfg: Config = None, fetcher=None, providers=None):
        self.store, self.cfg = store, cfg or Config()
        self.fetcher = fetcher or Fetcher(self.cfg)
        self.providers = providers if providers is not None else build_providers(self.cfg, fetcher=self.fetcher)
        self.tickers = []
        self._stop = threading.Event()
        self._pause = threading.Event()   # set = web activity (crawl + discovery) suspended
        self._threads = []
        self._busy = set()
        self._dlock = threading.Lock()
        self._specs, self._specs_at = [], 0.0
        self.stats = {"scanned": 0, "unchanged": 0, "errors": 0, "skipped": 0}

    # ------------------------------------------------------------ subjects
    def specs(self, force=False):
        if force or time.time() - self._specs_at > 5:
            self._specs, self._specs_at = load_specs(self.store), time.time()
        return self._specs

    # ------------------------------------------------------------ one source
    def process(self, row):
        now = time.time()
        sid = row["id"]
        res = self.fetcher.fetch(row["url"], row["etag"], row["last_modified"])
        if res.skipped:
            self.stats["skipped"] += 1
            retry = 86400 if res.skipped == "robots" else 30 * 86400
            self.store.update_source(sid, state="blocked" if res.skipped == "robots" else "skipped",
                                     error=res.skipped, last_scanned=now, lease_until=0, next_scan_at=now + retry)
            return "skipped"
        if res.error:
            return self._fail(row, res.error, res.retry_after, now)
        if res.not_modified:
            return self._unchanged(row, now, res)
        raw_hash = sha(res.body)
        if raw_hash == row["raw_hash"]:
            return self._unchanged(row, now, res)
        try:
            parsed = parse(res.body, res.url or row["url"], res.content_type)
        except ParseError as e:
            self.stats["errors"] += 1
            self.store.update_source(sid, state="skipped", error=str(e)[:200], last_scanned=now, lease_until=0,
                                     next_scan_at=now + 30 * 86400, http_status=res.status)
            return "unparseable"
        size = len(res.body)
        del res.body   # raw bytes are never persisted; drop the reference as soon as parsing is done
        # web pages are read only because we searched a subject: keep that subject and what links to it,
        # not every stray name in the prose (which minted e.g. biblical names off Wikipedia articles)
        return self.ingest(row, parsed, now, raw_hash=raw_hash, http=res, size=size, focus=True)

    def _fail(self, row, err, retry_after, now):
        self.stats["errors"] += 1
        fails = row["fail_count"] + 1
        delay = max(retry_after, min(self.cfg.rescan_max, 600 * 2 ** min(fails, 10)))
        self.store.update_source(row["id"], state="error" if fails < 6 else "skipped", error=err[:200], fail_count=fails,
                                 last_scanned=now, lease_until=0, next_scan_at=now + (delay if fails < 6 else 30 * 86400))
        return "error"

    def _next_interval(self, row, changed):
        if changed:
            iv = self.cfg.rescan_min
        else:
            iv = min(max((row["scan_interval"] or self.cfg.rescan_min) * 2, self.cfg.rescan_min), self.cfg.rescan_max)
        if row["hit"]:
            iv = min(iv, 86400)
        return iv

    def _unchanged(self, row, now, res=None):
        self.stats["unchanged"] += 1
        iv = self._next_interval(row, False)
        self.store.touch_source_evidence(row["id"], now)
        kw = dict(state="scanned", last_scanned=now, last_seen=now, lease_until=0, scan_interval=iv,
                  next_scan_at=now + iv, scan_count=row["scan_count"] + 1, fail_count=0, error=None)
        if res is not None and res.status:
            kw["http_status"] = res.status
        self.store.update_source(row["id"], **kw)
        return "unchanged"

    def ingest(self, row, parsed, now=None, raw_hash=None, http=None, size=0, state="scanned", focus=False):
        """Parse result -> entities/evidence/relations. Shared by crawler and historical importers."""
        now = now or time.time()
        if row["last_scanned"] and now <= row["last_scanned"]:   # coarse clocks (Windows ~15ms) must not
            now = row["last_scanned"] + 0.001                    # stall a rescan, or change-detection misses
        sid, st = row["id"], self.store
        text_hash = sha(parsed.title + "\n" + parsed.text)
        if row["text_hash"] == text_hash and state == "scanned":   # same content under a different raw encoding
            st.update_source(sid, raw_hash=raw_hash)
            return self._unchanged(row, now, http)
        specs = self.specs(force=True)
        row_d = dict(row)
        title_ctx = parsed.title
        if not title_ctx or ("/" not in title_ctx and "\\" not in title_ctx and "::" not in title_ctx):
            title_ctx = row_d.get("lineage") or row_d.get("url") or parsed.title
        ex = Extractor(specs).extract(parsed.text, title_ctx)

        # 4.3 Document Co-occurrence (UPGRADE_PLAN v2.0):
        # In focused documents mentioning between 2 and 6 persons, link them with 'co_mentioned_in_doc'
        person_items = [(k, d) for (t, k), d in ex.ents.items() if t == "person"]
        if 2 <= len(person_items) <= 6:
            doc_ref = parsed.title or row["url"] or "document"
            snip = f"Co-mentioned in {doc_ref}"[:300]
            from .extract import Ent
            ents_list = [Ent("person", k, d["display"], 0, 0, 0.75, surface=d.get("display", k))
                         for k, d in person_items]
            for i in range(len(ents_list)):
                for j in range(i + 1, len(ents_list)):
                    ex.add_link(ents_list[i], ents_list[j], "co_mentioned_in_doc", 0.75, snip)

        if focus:
            self._focus_filter(ex, specs)   # web page: keep only the searched subject and what links to it
        with st.tx():
            new_findings = self.persist(ex, sid, now, specs)
            added, removed = st.count_new(sid, now), st.count_stale(sid, now)
            if row["last_scanned"] and removed:
                self._emit_gone(row, specs, now)
            first = row["scan_count"] == 0 and not row["text_hash"]
            if added or removed or first:
                st.add_change(sid, now, "new" if first else "changed", added, removed)
            hit = 1 if ex.subject_hits else 0
            iv = self._next_interval({**dict(row), "hit": hit}, True)
            st.update_source(
                sid, state=state, kind=parsed.kind, title=parsed.title[:300], raw_hash=raw_hash, text_hash=text_hash,
                etag=getattr(http, "etag", None), last_modified=getattr(http, "last_modified", None),
                http_status=getattr(http, "status", None), bytes=size, hit=hit, page_type=ex.page_type,
                quality={"normal": 1.0, "directory": 0.5, "spam": 0.0, "reference": 0.2}.get(ex.page_type, 1.0),
                last_scanned=now, last_seen=now,
                last_changed=now, lease_until=0, scan_interval=iv,
                next_scan_at=now + iv if state == "scanned" else 9e15, scan_count=row["scan_count"] + 1,
                fail_count=0, error=None)
            for subj_id in ex.subject_hits:
                st.add_event(subj_id, "source_hit", {"url": row["url"], "title": parsed.title[:120], "kind": parsed.kind,
                                                      "new": first, "added": added, "removed": removed}, now)
            self.emit_findings(ex, new_findings, row["url"], now)
            if parsed.text and parsed.text.strip():
                try:
                    st.index_document_fts(sid, row["url"], "", parsed.text)
                except Exception:
                    pass
        if getattr(self.cfg, "sensitive_scan", False):
            self._scan_sensitive(parsed, sid, now)
        self.stats["scanned"] += 1
        if state == "scanned":
            self._enqueue_links(row, parsed, bool(ex.subject_hits))
            if ex.subject_hits:
                self._enqueue_sitemaps(row)
        return "scanned"

    def _scan_sensitive(self, parsed, sid, now):
        """Context-aware sensitive-info pass over the page text: attach each finding to the individual it concerns
        (an EXISTING person entity, resolved by name key — never invents a person). Additive and best-effort."""
        try:
            from .sensitive import analyze_text
            rep = analyze_text(parsed.text)
            for f in rep.findings:
                if not f.subject_key:
                    continue
                e = self.store.q1("SELECT id FROM entities WHERE type='person' AND key=?", (f.subject_key,))
                if e:
                    self.store.add_sensitive(e["id"], sid, dict(
                        kind=f.kind, family=f.family, severity=f.severity, value=f.value, confidence=f.confidence,
                        link=f.link, link_confidence=f.link_confidence, reasoning=f.reasoning), now)
        except Exception as ex:
            log.debug("sensitive scan skipped: %s", ex)

    def _enqueue_sitemaps(self, row):
        """A site that mentions a subject is worth a structured look: its sitemaps list documents too."""
        if "web.archive.org" in row["url"]:
            return
        origin = re.match(r"^(https?://[^/]+)", row["url"]).group(1)
        maps = getattr(self.fetcher, "sitemaps", lambda o: [])(origin) or [origin + "/sitemap.xml"]
        for m in maps[:3]:
            u = normalize_url(m)
            if u and registered_domain(host_of(u)) == registered_domain(host_of(row["url"])):
                self.store.add_source(u, priority=max(row["priority"] - 10, 1), depth=row["depth"], origin=row["url"],
                                      subject_id=row["subject_id"])

    def _focus_filter(self, ex, specs):
        """Keep only the searched subjects and the entities directly linked to them; drop stray prose entities."""
        spec_keys = {(("person" if s.kind == "person" else s.kind), s.key) for s in specs}
        if not ex.subject_hits:
            ex.ents.clear()
            ex.links.clear()
            return
        keep = set(spec_keys)
        for (ka, kb, _kind) in ex.links:
            if ka in spec_keys:
                keep.add(kb)
            if kb in spec_keys:
                keep.add(ka)
        ex.ents = {k: v for k, v in ex.ents.items() if k in keep}
        ex.links = {key: v for key, v in ex.links.items() if key[0] in keep and key[1] in keep}

    def persist(self, ex, sid, now, specs, bulk=False):
        """Write one Extraction as evidence of source `sid` observed at `now`. Caller holds the transaction.
        Returns new subject findings [(subject_id, other_key, kind, conf, snippet)].
        bulk=True (file imports): exact-key entity resolution and single-statement evidence upserts — keeps
        multi-million-row files linear instead of quadratic."""
        st = self.store
        spec_keys = {s.id: (("person" if s.kind == "person" else s.kind), s.key) for s in specs}
        new_findings, ids = [], {}
        add_ev = st.add_evidence_fast if bulk else st.add_evidence
        record = bulk and getattr(ex, "record", False)
        rec_id = getattr(ex, "record_id", None) if record else None
        for (t, k), e in ex.ents.items():
            if record and t == "person":
                eid = self._resolve_record_person(ex, (t, k), e, sid, now)
                if eid and eid > 0:          # an open investigation of this name gets this identity live
                    for subj_id in ex.subject_hits:
                        if spec_keys.get(subj_id) == (t, k):
                            st.conn.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)",
                                            (subj_id, eid, "live", 1.0))
            else:
                eid = st.resolve_entity(t, k, e["display"], now, fuzzy=not bulk)
            if not eid or eid < 0:
                continue
            ids[(t, k)] = eid
            for alias in e["aliases"]:
                st.add_alias(eid, alias, sid, now)
            if rec_id:                      # a stored record: point at it instead of copying its text per entity
                st.add_evidence_record(eid, sid, rec_id, max((c for _, c in e["hits"]), default=0.8), now)
                continue
            for snip, conf in e["hits"]:
                add_ev(eid, sid, snip, conf, now)
        for ek, name, value, kind in getattr(ex, "attrs", ()):
            if ek in ids:
                st.add_attribute(ids[ek], sid, name, value, kind, now)
        for (ka, kb, kind), hits in ex.links.items():
            if ka not in ids or kb not in ids:        # an unresolved endpoint skips its link, never loses the page
                continue
            a, b = ids[ka], ids[kb]
            if a == b:
                continue
            rid = st.add_relation(a, b, kind, now)
            if rec_id:
                hits = [(getattr(ex, "record_text", "")[:300], max((c for _, c in hits), default=0.8))]
            for snip, conf in hits:
                added = (st.add_rel_evidence_record(rid, sid, rec_id, conf, now) if rec_id
                         else st.add_rel_evidence(rid, sid, snip, conf, now))
                if added:
                    for subj_id in ex.subject_hits:
                        sk = spec_keys.get(subj_id)
                        if sk in (ka, kb) and kind != "co_mentioned":
                            new_findings.append((subj_id, kb if sk == ka else ka, kind, conf, snip))
        return new_findings

    def _resolve_record_person(self, ex, pk, e, sid, now):
        """A tabular record's person -> the identity it belongs to (Store.resolve_person_record). A foreign-key parent
        reuses the identity its own row resolved to, so a child table never splits it off."""
        st = self.store
        parent = getattr(ex, "parent_ent", None)
        if parent is not None and (parent.type, parent.key) == pk and getattr(parent, "resolved_id", None):
            return parent.resolved_id
        from .name_validator import is_valid_person_name
        if not is_valid_person_name(e["display"] or pk[1]):
            return -1
        idents = [kb for (ka, kb, _kind) in ex.links if ka == pk and kb[0] != "person"]
        idents += [ka for (ka, kb, _kind) in ex.links if kb == pk and ka[0] != "person"]
        text = e["hits"][0][0] if e["hits"] else e["display"]
        eid, how = st.resolve_person_record(pk[1], e["display"], idents, text, now)
        if how == "joined":
            row = st.q1("SELECT display FROM entities WHERE id=?", (eid,))
            if row and row["display"] != e["display"]:
                st.add_alias(eid, e["display"], sid, now)      # the same person written another way
        owner = getattr(ex, "owner_ent", None)
        if owner is not None and (owner.type, owner.key) == pk:
            owner.resolved_id = eid
        return eid

    def _emit_gone(self, row, specs, now):
        """Facts about a subject that were on this page at the previous scan and are not anymore."""
        st = self.store
        # judged per relation, not per snippet: a fact whose surrounding text changed is still there
        gone = st.q("SELECT r.a_id, r.b_id, r.kind FROM rel_evidence re JOIN relations r ON r.id=re.relation_id "
                    "WHERE re.source_id=? GROUP BY r.id HAVING MAX(re.last_seen)>=? AND MAX(re.last_seen)<?",
                    (row["id"], row["last_scanned"] - 1e-6, now))
        if not gone:
            return
        for sp in specs:
            e = st.q1("SELECT id FROM entities WHERE type=? AND key=?", ("person" if sp.kind == "person" else sp.kind, sp.key))
            ids = {r["entity_id"] for r in st.q("SELECT entity_id FROM subject_entities WHERE subject_id=?", (sp.id,))}
            if e:
                ids.add(e["id"])
            for g in gone:
                if g["kind"] == "co_mentioned" or not ({g["a_id"], g["b_id"]} & ids):
                    continue
                other = st.q1("SELECT type, display FROM entities WHERE id=?", (g["b_id"] if g["a_id"] in ids else g["a_id"],))
                st.add_event(sp.id, "gone", {"type": other["type"], "value": other["display"], "kind": g["kind"],
                                             "url": row["url"]}, now)

    def emit_findings(self, ex, new_findings, url, now):
        seen = set()
        for subj_id, other, kind, conf, _snip in new_findings:
            if (subj_id, other, kind) in seen:
                continue
            seen.add((subj_id, other, kind))
            self.store.add_event(subj_id, "finding", {"type": other[0], "value": ex.ents[other]["display"], "kind": kind,
                                                       "confidence": round(conf, 2), "url": url}, now)

    def _enqueue_links(self, row, parsed, hit):
        """Follow links only from pages that mention the subject, and prefer documents (PDF/DOCX/XLSX).
        No broad web crawl: we are not here to read the whole site, only to pull the subject's own files."""
        cfg = self.cfg
        if not hit and parsed.kind != "xml":
            return
        if row["depth"] + 1 > cfg.max_depth + 1:
            return
        n = 0
        for u, _anchor in parsed.links:
            if n >= cfg.max_links_per_page:
                break
            if ext_of(u) not in DOC_EXT:   # only ever chase documents (PDF/DOCX/XLSX/CSV/…), never crawl more pages
                continue
            if is_generic(u, cfg.block_domains):   # a file hosted on a generic-knowledge/blocked site is not the subject's
                continue
            dom = registered_domain(host_of(u))
            if self.store.domain_count(dom) >= cfg.max_pages_per_domain:
                continue
            _, new = self.store.add_source(u, priority=max(row["priority"] - 2, 0), depth=row["depth"] + 1,
                                           origin=row["url"], subject_id=row["subject_id"])
            n += new

    # ------------------------------------------------------------ discovery jobs
    def _subject_name_forms(self, subject_id) -> list:
        """One folded-token set per spelling of the subject (canonical + each variant). Harvesting a SERP snippet
        requires ANY single spelling to be fully present (so a Hebrew-only snippet isn't rejected for lacking the
        Latin transliteration's tokens), while ranking uses the flat union below."""
        from .textnorm import fold
        if not subject_id:
            return []
        row = self.store.q1("SELECT canonical, variants, kind FROM subjects WHERE id=?", (subject_id,))
        if not row or row["kind"] not in ("person", "org"):
            return []
        forms = []
        seen = set()

        def _add(tokens):
            form = frozenset(f for f in (fold(t) for t in tokens) if len(f) >= 2)
            if form and form not in seen:
                seen.add(form)
                forms.append(set(form))

        _add((row["canonical"] or "").split())
        try:
            for v in json.loads(row["variants"] or "[]"):
                _add(v)
        except Exception:
            pass
        return forms

    def _subject_name_tokens(self, subject_id) -> set:
        """Flat union of the subject's folded name tokens — used only to boost crawl priority when a token appears
        in a discovered URL's path."""
        out = set()
        for form in self._subject_name_forms(subject_id):
            out |= form
        return out

    def _subject_primary_entity(self, subject_id, canonical):
        """The subject's strongest person entity (highest-score subject_entity), creating one from the canonical
        name when the DB holds nobody yet — the anchor SERP-snippet intel is attached to. A freshly created entity
        is linked into subject_entities (how='serp') so the finding actually surfaces in the subject's profile."""
        row = self.store.q1(
            "SELECT se.entity_id FROM subject_entities se JOIN entities e ON e.id=se.entity_id "
            "WHERE se.subject_id=? AND e.type='person' ORDER BY se.score DESC LIMIT 1", (subject_id,))
        if row:
            return row["entity_id"]
        if not canonical:
            return None
        from .textnorm import name_key
        eid = self.store.resolve_entity("person", name_key(canonical), canonical, time.time(), fuzzy=False)
        if eid:
            with self.store.tx() as c:
                c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (subject_id, eid, "serp", 0.6))
        return eid

    def _harvest_serp_intel(self, prov, subject_id, name_forms, canonical, query):
        """Capture identifiers that appear in SERP titles/snippets — reaching data on pages that block the crawler
        (LinkedIn, Facebook, …) — and persist them as `serp_contact` osint_findings on the subject's entity.
        Precision-first: `harvest_snippet_intel` already validates national-id check digits, phone trunks and email
        shape; we additionally require one full spelling of the subject's name to appear in the SAME snippet, so a
        stray number on an unrelated result is never attributed to the subject. Returns findings written."""
        snippets = getattr(prov, "last_snippets", None) or []
        if not snippets or not subject_id or not name_forms:
            return 0
        from .providers import harvest_snippet_intel
        from .textnorm import fold
        eid = self._subject_primary_entity(subject_id, canonical)
        if not eid:
            return 0
        now = time.time()
        written = 0
        for s in snippets:
            blob = fold(f"{s.get('title', '')} {s.get('snippet', '')}")
            if not any(all(tok in blob for tok in form) for form in name_forms):   # one full spelling must be present
                continue
            intel = harvest_snippet_intel([s])
            url = s.get("url", "") or f"serp:{prov.name}"
            for ph in intel.get("phones", []):
                written += 1 if self.store.add_osint_finding(
                    eid, "serp_contact", source_tool=f"serp:{prov.name}", title=f"טלפון מתצוגת תוצאה: {ph}",
                    summary=(s.get("snippet") or s.get("title") or "")[:200], url=url,
                    extracted_data={"phone": ph, "query": query, "via": "serp_snippet"}, confidence=0.6, timestamp=now) else 0
            for em in intel.get("emails", []):
                written += 1 if self.store.add_osint_finding(
                    eid, "serp_contact", source_tool=f"serp:{prov.name}", title=f"אימייל מתצוגת תוצאה: {em}",
                    summary=(s.get("snippet") or s.get("title") or "")[:200], url=url,
                    extracted_data={"email": em, "query": query, "via": "serp_snippet"}, confidence=0.6, timestamp=now) else 0
            for nid in intel.get("national_ids", []):
                written += 1 if self.store.add_osint_finding(
                    eid, "serp_contact", source_tool=f"serp:{prov.name}", title=f"ת\"ז מתצוגת תוצאה: {nid}",
                    summary=(s.get("snippet") or s.get("title") or "")[:200], url=url,
                    extracted_data={"national_id": nid, "query": query, "via": "serp_snippet"}, confidence=0.6, timestamp=now) else 0
        return written

    def run_jobs_once(self, limit=10):
        done = 0
        now = time.time()
        with self.store.tx() as c:
            used = {r["provider"]: r["n"] for r in c.execute(
                "SELECT provider, COUNT(*) n FROM jobs WHERE state IN ('done','error','running') AND ran_at>? GROUP BY provider",
                (now - 86400,))}
            left = {p: b - used.get(p, 0) for p, b in self.cfg.budgets.items() if b}   # per-provider daily quota
            jobs = []
            for j in c.execute("SELECT * FROM jobs WHERE state='pending' ORDER BY id LIMIT 500").fetchall():
                p = j["provider"]
                if p in left:
                    if left[p] <= 0:
                        continue          # waits for tomorrow's quota
                    left[p] -= 1
                jobs.append(j)
                if len(jobs) >= limit:
                    break
            for j in jobs:
                c.execute("UPDATE jobs SET state='running', ran_at=? WHERE id=?", (now, j["id"]))
        for j in jobs:
            prov = self.providers.get(j["provider"])
            try:
                if prov is None:
                    raise RuntimeError(f"provider {j['provider']} not configured")
                urls = clean_results(prov.search(j["query"], self.cfg.results_per_query), self.cfg.block_domains)
                name_forms = self._subject_name_forms(j["subject_id"])
                subj_tokens = set().union(*name_forms) if name_forms else set()
                new = 0
                for rank, u in enumerate(urls):   # list order is the SERP rank — fold it into crawl priority
                    pr = rank_source_priority(u, rank, subj_tokens)
                    _, is_new = self.store.add_source(u, priority=pr, depth=0, origin=f"search:{j['provider']}",
                                                      subject_id=j["subject_id"])
                    new += is_new
                intel_found = 0
                if j["subject_id"]:
                    try:
                        srow = self.store.q1("SELECT canonical FROM subjects WHERE id=?", (j["subject_id"],))
                        intel_found = self._harvest_serp_intel(
                            prov, j["subject_id"], name_forms, srow["canonical"] if srow else "", j["query"])
                    except Exception:
                        log.exception("serp-intel harvest failed for job %s", j["id"])
                with self.store.tx() as c:
                    c.execute("UPDATE jobs SET state='done', ran_at=?, found=? WHERE id=?", (time.time(), new, j["id"]))
                if j["subject_id"]:
                    self.store.add_event(j["subject_id"], "discovery", {"provider": j["provider"], "query": j["query"],
                                                                         "urls": len(urls), "new": new, "serp_intel": intel_found})
            except Exception as e:
                log.warning("job %s failed: %s", j["id"], e)
                with self.store.tx() as c:
                    c.execute("UPDATE jobs SET state='error', ran_at=?, error=? WHERE id=?", (time.time(), str(e)[:200], j["id"]))
            done += 1
        return done

    # ------------------------------------------------------------ run loops
    def step(self, n=1):
        """Claim and process up to n due sources synchronously. Returns number processed."""
        with self._dlock:
            rows = self.store.claim(n, time.time(), self._busy)
            self._busy.update(r["domain"] for r in rows)
        for r in rows:
            try:
                self.process(r)
            except Exception as e:      # never let one page kill a worker
                log.exception("process failed for %s", r["url"])
                self._fail(r, f"{type(e).__name__}: {e}", 0, time.time())
            finally:
                with self._dlock:
                    self._busy.discard(r["domain"])
        return len(rows)

    def drain(self, max_sources=10_000, rounds_of_jobs=True):
        """Synchronously run until no job/source is due (used by CLI one-shots and tests)."""
        total = 0
        while total < max_sources:
            jobs = self.run_jobs_once() if rounds_of_jobs else 0
            for t in self.tickers:
                t()
            got = self.step(8)
            total += got
            if not got and not jobs and not self.run_jobs_once():   # pending-but-over-budget jobs must not spin
                break
        return total

    def pause(self):
        self._pause.set()

    def resume(self):
        self._pause.clear()

    @property
    def is_paused(self):
        return self._pause.is_set()

    def _worker(self):
        while not self._stop.is_set():
            if self._pause.is_set() or self.step(1) == 0:
                self._stop.wait(1.0)

    def _job_loop(self):
        while not self._stop.is_set():
            if self._pause.is_set() or self.run_jobs_once() == 0:
                self._stop.wait(2.0)

    def _tick_loop(self):
        while not self._stop.is_set():
            for t in self.tickers:
                try:
                    t()
                except Exception:
                    log.exception("ticker failed")
            self._stop.wait(5.0)

    def start(self):
        self._stop.clear()
        targets = [self._job_loop, self._tick_loop] + [self._worker] * self.cfg.workers
        for i, t in enumerate(targets):
            th = threading.Thread(target=t, daemon=True, name=f"osnit-{i}")
            th.start()
            self._threads.append(th)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
