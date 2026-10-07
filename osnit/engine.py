"""Crawl/scan engine: claims due sources, fetches, detects change, parses, extracts, persists, follows links."""
import hashlib
import json
import logging
import threading
import time

from .config import Config
from .extract import Extractor, SubjectSpec
from .fetch import Fetcher
from .parse import ParseError, parse
from .providers import build_providers, clean_results
from .store import Store
from .urls import DOC_EXT, SKIP_EXT, ext_of, host_of, registered_domain
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


class Engine:
    def __init__(self, store: Store, cfg: Config = None, fetcher=None, providers=None):
        self.store, self.cfg = store, cfg or Config()
        self.fetcher = fetcher or Fetcher(self.cfg)
        self.providers = providers if providers is not None else build_providers(self.cfg)
        self.tickers = []
        self._stop = threading.Event()
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
        return self.ingest(row, parsed, now, raw_hash=raw_hash, http=res, size=size)

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

    def ingest(self, row, parsed, now=None, raw_hash=None, http=None, size=0, state="scanned"):
        """Parse result -> entities/evidence/relations. Shared by crawler and historical importers."""
        now = now or time.time()
        sid, st = row["id"], self.store
        text_hash = sha(parsed.title + "\n" + parsed.text)
        if row["text_hash"] == text_hash and state == "scanned":   # same content under a different raw encoding
            st.update_source(sid, raw_hash=raw_hash)
            return self._unchanged(row, now, http)
        specs = self.specs(force=True)
        ex = Extractor(specs).extract(parsed.text, parsed.title)
        spec_keys = {s.id: (("person" if s.kind == "person" else s.kind), s.key) for s in specs}
        new_findings = []
        with st.tx():
            ids = {}
            for (t, k), e in ex.ents.items():
                eid = ids[(t, k)] = st.resolve_entity(t, k, e["display"], now)
                for alias in e["aliases"]:
                    st.add_alias(eid, alias, sid, now)
                for snip, conf in e["hits"]:
                    st.add_evidence(eid, sid, snip, conf, now)
            for (ka, kb, kind), hits in ex.links.items():
                a, b = ids[ka], ids[kb]
                if a == b:
                    continue
                rid = st.add_relation(a, b, kind, now)
                for snip, conf in hits:
                    if st.add_rel_evidence(rid, sid, snip, conf, now):
                        for subj_id in ex.subject_hits:
                            sk = spec_keys.get(subj_id)
                            if sk in (ka, kb) and kind != "co_mentioned":
                                other = kb if sk == ka else ka
                                new_findings.append((subj_id, other, kind, conf, snip))
            added, removed = st.count_new(sid, now), st.count_stale(sid, now)
            first = row["scan_count"] == 0 and not row["text_hash"]
            if added or removed or first:
                st.add_change(sid, now, "new" if first else "changed", added, removed)
            hit = 1 if ex.subject_hits else 0
            iv = self._next_interval({**dict(row), "hit": hit}, True)
            st.update_source(
                sid, state=state, kind=parsed.kind, title=parsed.title[:300], raw_hash=raw_hash, text_hash=text_hash,
                etag=getattr(http, "etag", None), last_modified=getattr(http, "last_modified", None),
                http_status=getattr(http, "status", None), bytes=size, hit=hit, page_type=ex.page_type,
                quality={"normal": 1.0, "directory": 0.5, "spam": 0.0}.get(ex.page_type, 1.0),
                last_scanned=now, last_seen=now,
                last_changed=now, lease_until=0, scan_interval=iv,
                next_scan_at=now + iv if state == "scanned" else 9e15, scan_count=row["scan_count"] + 1,
                fail_count=0, error=None)
            for subj_id in ex.subject_hits:
                st.add_event(subj_id, "source_hit", {"url": row["url"], "title": parsed.title[:120], "kind": parsed.kind,
                                                      "new": first, "added": added, "removed": removed}, now)
            seen_f = set()
            for subj_id, other, kind, conf, snip in new_findings:
                if (subj_id, other, kind) in seen_f:
                    continue
                seen_f.add((subj_id, other, kind))
                disp = ex.ents[other]["display"]
                st.add_event(subj_id, "finding", {"type": other[0], "value": disp, "kind": kind,
                                                   "confidence": round(conf, 2), "url": row["url"]}, now)
        self.stats["scanned"] += 1
        if state == "scanned":
            self._enqueue_links(row, parsed, bool(ex.subject_hits))
        return "scanned"

    def _enqueue_links(self, row, parsed, hit):
        cfg = self.cfg
        if row["depth"] + 1 > cfg.max_depth + (1 if hit else 0):
            return
        same = registered_domain(host_of(row["url"]))
        n = 0
        for u, _anchor in parsed.links:
            if n >= cfg.max_links_per_page:
                break
            ext = ext_of(u)
            if ext in SKIP_EXT:
                continue
            dom = registered_domain(host_of(u))
            if dom != same and not (hit or cfg.follow_external):
                continue
            if self.store.domain_count(dom) >= cfg.max_pages_per_domain:
                continue
            pri = (row["priority"] - 5 if hit else row["priority"] - 20) + (2 if ext in DOC_EXT else 0)
            _, new = self.store.add_source(u, priority=max(pri, 0), depth=row["depth"] + 1, origin=row["url"],
                                           subject_id=row["subject_id"] if hit else None)
            n += new

    # ------------------------------------------------------------ discovery jobs
    def run_jobs_once(self, limit=10):
        done = 0
        with self.store.tx() as c:
            jobs = c.execute("SELECT * FROM jobs WHERE state='pending' ORDER BY id LIMIT ?", (limit,)).fetchall()
            for j in jobs:
                c.execute("UPDATE jobs SET state='running' WHERE id=?", (j["id"],))
        for j in jobs:
            prov = self.providers.get(j["provider"])
            try:
                if prov is None:
                    raise RuntimeError(f"provider {j['provider']} not configured")
                urls = clean_results(prov.search(j["query"], self.cfg.results_per_query))
                new = 0
                for u in urls:
                    _, is_new = self.store.add_source(u, priority=100, depth=0, origin=f"search:{j['provider']}",
                                                      subject_id=j["subject_id"])
                    new += is_new
                with self.store.tx() as c:
                    c.execute("UPDATE jobs SET state='done', ran_at=?, found=? WHERE id=?", (time.time(), new, j["id"]))
                if j["subject_id"]:
                    self.store.add_event(j["subject_id"], "discovery", {"provider": j["provider"], "query": j["query"],
                                                                         "urls": len(urls), "new": new})
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
            if not got and not jobs and not self.store.q1("SELECT 1 FROM jobs WHERE state='pending'"):
                break
        return total

    def _worker(self):
        while not self._stop.is_set():
            if self.step(1) == 0:
                self._stop.wait(1.0)

    def _job_loop(self):
        while not self._stop.is_set():
            if self.run_jobs_once() == 0:
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
