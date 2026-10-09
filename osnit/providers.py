"""Discovery providers: turn a query into candidate public URLs. Prefer official APIs; scraping is opt-in."""
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from html import unescape

from .urls import DOC_EXT, ext_of, host_of, is_generic, is_private_host, normalize_url

log = logging.getLogger("osnit.providers")


def _get(url, cfg, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000)


class Provider:
    name = "base"

    def __init__(self, cfg, **_):
        self.cfg = cfg

    def search(self, query: str, limit: int) -> list:
        raise NotImplementedError

    def accepts(self, query: str) -> bool:
        return not query.startswith("archive:")


class Wikipedia(Provider):
    """Official MediaWiki search API (he + en). Opt-in only (OSNIT_PROVIDERS=wikipedia): an encyclopaedia rarely
    holds anything about a private person, and its pages name thousands of unrelated people."""
    name = "wikipedia"
    plain = True   # no search operators

    def search(self, query, limit):
        urls = []
        for lang in ("he", "en"):
            api = (f"https://{lang}.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit={min(limit, 10)}"
                   f"&srsearch={urllib.parse.quote(query)}")
            data = json.loads(_get(api, self.cfg))
            for it in data.get("query", {}).get("search", []):
                t = urllib.parse.quote(it["title"].replace(" ", "_"))
                urls.append(f"https://{lang}.wikipedia.org/wiki/{t}")
        return urls


class SearXNG(Provider):
    """Self-hosted meta-search (JSON API). Set SEARXNG_URL."""
    name = "searxng"

    def search(self, query, limit):
        if not self.cfg.searxng_url:
            return []
        url = f"{self.cfg.searxng_url.rstrip('/')}/search?format=json&q={urllib.parse.quote(query)}"
        data = json.loads(_get(url, self.cfg))
        return [r["url"] for r in data.get("results", [])][:limit]


class Brave(Provider):
    """Brave Search API. Set BRAVE_API_KEY."""
    name = "brave"

    def search(self, query, limit):
        if not self.cfg.brave_key:
            return []
        url = f"https://api.search.brave.com/res/v1/web/search?count={min(limit, 20)}&q={urllib.parse.quote(query)}"
        data = json.loads(_get(url, self.cfg, {"X-Subscription-Token": self.cfg.brave_key, "Accept": "application/json"}))
        return [r["url"] for r in data.get("web", {}).get("results", [])][:limit]


class GoogleCSE(Provider):
    """Google Programmable Search JSON API (official). Set GOOGLE_API_KEY + GOOGLE_CSE_ID (engine set to search the web).
    Supports the same operators as google.com: "exact phrase", filetype:pdf, site:."""
    name = "google"

    def search(self, query, limit):
        if not (self.cfg.google_key and self.cfg.google_cx):
            return []
        out = []
        for start in range(1, min(limit, 30) + 1, 10):
            url = ("https://www.googleapis.com/customsearch/v1?num=10&hl=he"
                   f"&key={urllib.parse.quote(self.cfg.google_key)}&cx={urllib.parse.quote(self.cfg.google_cx)}"
                   f"&start={start}&q={urllib.parse.quote(query)}")
            items = json.loads(_get(url, self.cfg)).get("items", [])
            out += [it["link"] for it in items]
            if len(items) < 10:
                break
        return out[:limit]


class SerpAPI(Provider):
    """Google results through SerpAPI (paid, ToS-compliant access to google.com results). Set SERPAPI_KEY."""
    name = "serpapi"

    def search(self, query, limit):
        if not self.cfg.serpapi_key:
            return []
        url = (f"https://serpapi.com/search.json?engine=google&hl=iw&gl=il&num={min(limit, 100)}"
               f"&api_key={urllib.parse.quote(self.cfg.serpapi_key)}&q={urllib.parse.quote(query)}")
        return [r["link"] for r in json.loads(_get(url, self.cfg)).get("organic_results", [])][:limit]


class Wayback(Provider):
    """Internet Archive CDX API: historical captures of a site the subject is tied to ('archive:<domain>').
    Documents first; returns raw-capture URLs (id_) so the archived file itself is parsed."""
    name = "archive"
    DOC_MIME = ("application/pdf", "application/msword", "application/vnd.openxmlformats", "text/csv", "text/plain")

    def accepts(self, query):
        return query.startswith("archive:")

    def search(self, query, limit):
        domain = query.split(":", 1)[1].strip().split()[0]
        base = self.cfg.wayback_url.rstrip("/")
        url = (f"{base}/cdx/search/cdx?url={urllib.parse.quote(domain)}/*&output=json&fl=timestamp,original,mimetype"
               f"&filter=statuscode:200&collapse=urlkey&limit=3000")
        rows = json.loads(_get(url, self.cfg, timeout=60) or b"[]")[1:]
        docs = [r for r in rows if r[2].startswith(self.DOC_MIME)]
        pages = [r for r in rows if r[2] == "text/html" and r[1].count("/") <= 5]
        return [f"{base}/web/{ts}id_/{orig}" for ts, orig, _m in (docs + pages)[:limit * 3]]


class DuckDuckGo(Provider):
    """HTML endpoint scraping: opt-in only (OSNIT_PROVIDERS=ddg); check the engine's terms before enabling."""
    name = "ddg"

    def search(self, query, limit):
        html = _get("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query), self.cfg).decode("utf-8", "replace")
        out = []
        for m in re.finditer(r'class="result__a"[^>]*href="([^"]+)"', html):
            href = unescape(m.group(1))
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
            out.append(q["uddg"][0] if "uddg" in q else href)
        return out[:limit]


class BrowserSearch(Provider):
    """No-API discovery through the pre-installed headless Chromium (Playwright), driven as a Node subprocess — the
    way Burp/Acunetix use a real browser rather than shipping a scraper. Opt-in (OSNIT_PROVIDERS=browser). It runs
    ONE search-engine results page and returns the outbound URLs; the engine then pipes them through clean_results
    (so Wikipedia/scripture/generic sites are dropped). When Node/Playwright/Chromium is absent, or the engine is
    unreachable or challenges the visit, it logs why and returns [] — it never raises. With a fetcher and
    OSNIT_BROWSER_DOWNLOAD=1 it downloads the result page's own document links into the import inbox, through the
    fetcher's robots.txt + SSRF + size-cap posture (never the browser's)."""
    name = "browser"
    plain = False
    _lock = threading.Lock()
    _last = 0.0
    _no_node = False               # cache a missing browser so repeated jobs don't respawn uselessly

    def __init__(self, cfg, fetcher=None, inbox=None, **_):
        super().__init__(cfg)
        self.fetcher = fetcher
        self.inbox = inbox or os.path.join(os.path.dirname(cfg.db_path) or ".", "inbox")
        self.bridge = os.path.join(os.path.dirname(__file__), "browser_search.cjs")

    def _node(self):
        return self.cfg.browser_node or shutil.which("node")

    def search(self, query, limit):
        node = self._node()
        if BrowserSearch._no_node or not node or not os.path.exists(self.bridge):
            if not node:
                BrowserSearch._no_node = True
            log.warning("browser provider unavailable (node/bridge missing); returning no results")
            return []
        with BrowserSearch._lock:                       # engine workers run concurrently — stay polite to the engine
            wait = self.cfg.browser_delay - (time.time() - BrowserSearch._last)
            if wait > 0:
                time.sleep(wait)
            BrowserSearch._last = time.time()
        req = dict(action="search", query=query, engine=self.cfg.browser_engine, limit=limit,
                   user_agent=self.cfg.browser_ua, nav_timeout_ms=int(self.cfg.browser_timeout * 1000),
                   proxy=self.cfg.browser_proxy or os.environ.get("HTTPS_PROXY", ""), headful=self.cfg.browser_headful)
        try:
            proc = subprocess.run([node, self.bridge], input=json.dumps(req), capture_output=True, text=True,
                                  timeout=self.cfg.browser_timeout + 15, env=os.environ.copy(), start_new_session=True)
        except subprocess.TimeoutExpired:
            log.warning("browser search timed out for %r", query[:80])
            return []
        except (OSError, ValueError) as e:
            log.warning("browser search failed to launch: %s", e)
            return []
        try:
            res = json.loads(proc.stdout or "{}")
        except ValueError:
            log.warning("browser bridge returned non-JSON (stderr: %s)", (proc.stderr or "")[:200])
            return []
        if not res.get("ok"):
            if res.get("code") == "no-browser":
                BrowserSearch._no_node = True
            log.warning("browser search %s: %s", res.get("code"), (res.get("error") or "")[:200])
            return []
        urls = res.get("urls") or []
        if self.cfg.browser_download and self.fetcher:
            downloaded = self._download(res.get("doc_links") or [])
            urls = [u for u in urls if u not in downloaded]   # a file we ingested is not also crawled as a page
        return urls

    def _download(self, doc_links):
        """Download the result page's document links into the inbox, honouring the fetcher's full posture
        (robots.txt, SSRF, content-type allow-list, size cap). Returns the set of URLs actually saved."""
        saved = set()
        try:
            os.makedirs(self.inbox, exist_ok=True)
        except OSError:
            return saved
        for u in clean_results(doc_links, self.cfg.block_domains):
            if len(saved) >= self.cfg.browser_download_max:
                break
            if ext_of(u) not in DOC_EXT:
                continue
            host = host_of(u)
            if not self.cfg.allow_private_hosts and is_private_host(host):
                continue
            try:
                ok = self.fetcher.allowed(u)
                if isinstance(ok, tuple):
                    ok = ok[0]
                if not ok:
                    continue
                res = self.fetcher.fetch(u)
            except Exception as e:
                log.warning("browser download failed for %s: %s", u[:120], e)
                continue
            body = getattr(res, "body", None)
            if not body:
                continue
            safe = re.sub(r"[^\w.\-]+", "_", os.path.basename(urllib.parse.urlsplit(u).path)) or "download"
            if ext_of(safe) not in DOC_EXT:
                safe += ext_of(u)
            dest = os.path.join(self.inbox, f"{int(time.time()*1000)}_{safe}")
            try:
                with open(dest + ".part", "wb") as f:   # .part is not importable, so a partial file is never scanned
                    f.write(body)
                os.replace(dest + ".part", dest)        # atomic: scan_inbox only sees the complete file
                saved.add(u)
            except OSError as e:
                log.warning("could not save %s: %s", u[:120], e)
        return saved


REGISTRY = {c.name: c for c in (Wikipedia, SearXNG, Brave, GoogleCSE, SerpAPI, Wayback, DuckDuckGo, BrowserSearch)}


def build_providers(cfg, fetcher=None, inbox=None):
    names = list(cfg.providers)
    if cfg.searxng_url and "searxng" not in names:
        names.append("searxng")
    for key, name in ((cfg.brave_key, "brave"), (cfg.google_key and cfg.google_cx, "google"),
                      (cfg.serpapi_key, "serpapi")):
        if key and name not in names:
            names.append(name)
    return {n: REGISTRY[n](cfg, fetcher=fetcher, inbox=inbox) for n in dict.fromkeys(names) if n in REGISTRY}


def clean_results(urls, block=()):
    """Normalised, de-duplicated result URLs without general-knowledge sites (Wikipedia, scripture, dictionaries…)."""
    seen, out = set(), []
    for u in urls:
        n = normalize_url(u)
        if n and "web.archive.org/web/" not in n and is_generic(n, block):
            continue
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out
