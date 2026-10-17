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

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    sync_playwright = None
    HAS_PLAYWRIGHT = False

try:
    import playwright_stealth
    HAS_PLAYWRIGHT_STEALTH = True
except ImportError:
    playwright_stealth = None
    HAS_PLAYWRIGHT_STEALTH = False

from .urls import DOC_EXT, ext_of, host_of, is_generic, is_private_host, normalize_url

log = logging.getLogger("osnit.providers")


def _get(url, cfg, headers=None, timeout=20, cap=2_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(cap)


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
        rows = json.loads(_get(url, self.cfg, timeout=60, cap=48_000_000) or b"[]")[1:]
        docs = [r for r in rows if r[2].startswith(self.DOC_MIME)]
        pages = [r for r in rows if r[2] == "text/html" and r[1].count("/") <= 5]
        return [f"{base}/web/{ts}id_/{orig}" for ts, orig, _m in (docs + pages)[:limit * 3]]


class DuckDuckGo(Provider):
    """HTML endpoint scraping: opt-in only (OSNIT_PROVIDERS=ddg); check the engine's terms before enabling."""
    name = "ddg"

    def __init__(self, cfg, **_):
        super().__init__(cfg, **_)
        self.last_snippets = []
        self.last_snippet_intel = {}

    def search(self, query, limit):
        html = _get("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query), self.cfg).decode("utf-8", "replace")
        self.last_snippets = extract_serp_snippets(html)
        self.last_snippet_intel = harvest_snippet_intel(self.last_snippets)
        out = [s["url"] for s in self.last_snippets if s.get("url")]
        for m in re.finditer(r'class="result__a"[^>]*href="([^"]+)"', html):
            u = unwrap_search_redirect(m.group(1))
            if u and u not in out:
                out.append(u)
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
        res = self._run(node, req, self.cfg.browser_timeout + 15, query[:80])
        if not res:
            return []
        urls = res.get("urls") or []
        if self.cfg.browser_download and self.fetcher:
            downloaded = self._download(res.get("doc_links") or [])
            urls = [u for u in urls if u not in downloaded]   # a file we ingested is not also crawled as a page
        return urls

    def plan_concurrency(self, n_items):
        """How many searches to run at once: the operator's setting, else auto-scaled to available RAM. Capped by
        the number of items and the max-workers ceiling."""
        from .sysmem import plan_concurrency
        want = self.cfg.browser_concurrency or plan_concurrency(
            per_task_mb=self.cfg.browser_per_mb, target_fraction=self.cfg.browser_ram_fraction,
            cap=self.cfg.browser_max_workers)
        return max(1, min(want, self.cfg.browser_max_workers, max(1, n_items)))

    def search_many(self, queries, limit=None):
        """Run many queries in parallel across one browser's pages, scaling concurrency to the machine's RAM — the
        aggressive-scan path. Returns {query: [clean urls]}; downloaded documents are scanned locally at once."""
        queries = [q for q in dict.fromkeys(queries) if q]
        node = self._node()
        if BrowserSearch._no_node or not node or not os.path.exists(self.bridge) or not queries:
            if not node:
                BrowserSearch._no_node = True
            return {}
        conc = self.plan_concurrency(len(queries))
        req = dict(action="search", queries=queries, engine=self.cfg.browser_engine,
                   limit=limit or self.cfg.__dict__.get("results_per_query", 15), concurrency=conc,
                   user_agent=self.cfg.browser_ua, nav_timeout_ms=int(self.cfg.browser_timeout * 1000),
                   proxy=self.cfg.browser_proxy or os.environ.get("HTTPS_PROXY", ""), headful=self.cfg.browser_headful)
        rounds = (len(queries) + conc - 1) // conc
        timeout = self.cfg.browser_timeout * (rounds + 1) + 20
        log.info("browser batch: %d queries, concurrency %d (~%d rounds)", len(queries), conc, rounds)
        res = self._run(node, req, timeout, f"{len(queries)} queries")
        out = {}
        if not res:
            return out
        for r in res.get("results") or []:
            urls = clean_results(r.get("urls") or [], self.cfg.block_domains)
            out[r.get("query")] = urls
            if self.cfg.browser_download and self.fetcher:
                self._download(r.get("doc_links") or [])
        return out

    def _run(self, node, req, timeout, label):
        """Run the Node bridge once with a hard timeout; returns the parsed ok-result or None (logged)."""
        with BrowserSearch._lock:                       # engine workers run concurrently — stay polite to the engine
            wait = self.cfg.browser_delay - (time.time() - BrowserSearch._last)
            if wait > 0:
                time.sleep(wait)
            BrowserSearch._last = time.time()
        try:
            proc = subprocess.run([node, self.bridge], input=json.dumps(req), capture_output=True, text=True,
                                  timeout=timeout, env=os.environ.copy(), start_new_session=True)
        except subprocess.TimeoutExpired:
            log.warning("browser search timed out for %s", label)
            return None
        except (OSError, ValueError) as e:
            log.warning("browser search failed to launch: %s", e)
            return None
        try:
            res = json.loads(proc.stdout or "{}")
        except ValueError:
            log.warning("browser bridge returned non-JSON (stderr: %s)", (proc.stderr or "")[:200])
            return None
        if not res.get("ok"):
            if res.get("code") == "no-browser":
                BrowserSearch._no_node = True
            log.warning("browser search %s: %s", res.get("code"), (res.get("error") or "")[:200])
            return None
        return res

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
                if self.cfg.browser_scan_downloads:     # identify phones/emails in the file at once, don't wait for import
                    try:
                        from .ingest import scan_file_for_identifiers
                        hit = scan_file_for_identifiers(dest)
                        if hit.get("emails") or hit.get("phones") or hit.get("national_ids"):
                            log.info("downloaded %s -> %d emails, %d phones, %d ids", os.path.basename(dest),
                                     len(hit["emails"]), len(hit["phones"]), len(hit["national_ids"]))
                    except Exception as e:
                        log.warning("quick scan of %s failed: %s", dest, e)
            except OSError as e:
                log.warning("could not save %s: %s", u[:120], e)
        return saved


_SERP_SELF_HOSTS = {
    "duckduckgo.com", "html.duckduckgo.com", "lite.duckduckgo.com", "links.duckduckgo.com",
    "www.bing.com", "bing.com", "www.google.com", "google.com", "www.google.co.il", "google.co.il",
    "search.yahoo.com", "r.search.yahoo.com",
}


def unwrap_search_redirect(href: str) -> str:
    """
    Unwraps search engine click/redirect wrappers (DuckDuckGo uddg, Google /url?q=,
    Bing /ck/a?u=a1<base64>, Yahoo /RU=<encoded>) and returns the clean target URL.
    Returns "" if the URL is an internal search-engine page or invalid.
    """
    if not href:
        return ""
    u = unescape(str(href).strip())
    if not u or u.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return ""
    if u.startswith("//"):
        u = "https:" + u
    elif u.startswith("/l/?") or u.startswith("/l?"):
        u = "https://duckduckgo.com" + u
    elif u.startswith("/url?") or u.startswith("/url/?"):
        u = "https://www.google.com" + u

    try:
        sp = urllib.parse.urlsplit(u)
    except ValueError:
        return ""

    host = (sp.hostname or "").lower()
    qs = urllib.parse.parse_qs(sp.query)

    # 1. DuckDuckGo redirect: ?uddg=https%3A%2F%2F...
    if "uddg" in qs and qs["uddg"]:
        u = urllib.parse.unquote(qs["uddg"][0].strip())
        try:
            sp = urllib.parse.urlsplit(u)
            host = (sp.hostname or "").lower()
        except ValueError:
            return ""

    # 2. Google redirect: /url?q=... or /url?url=...
    elif host in ("www.google.com", "google.com", "www.google.co.il", "google.co.il") and sp.path.startswith("/url"):
        target = (qs.get("q") or qs.get("url") or [""])[0]
        if target:
            u = urllib.parse.unquote(target.strip())
            try:
                sp = urllib.parse.urlsplit(u)
                host = (sp.hostname or "").lower()
            except ValueError:
                return ""

    # 3. Bing click tracker: /ck/a?...&u=a1aHR0cHM6Ly...
    elif host in ("www.bing.com", "bing.com") and sp.path.startswith("/ck/a") and "u" in qs:
        raw_u = qs["u"][0]
        if raw_u.startswith("a1"):
            import base64
            b64 = raw_u[2:]
            pad = "=" * ((4 - len(b64) % 4) % 4)
            try:
                decoded = base64.urlsafe_b64decode(b64 + pad).decode("utf-8", "ignore")
                if decoded.startswith("http"):
                    u = decoded
                    sp = urllib.parse.urlsplit(u)
                    host = (sp.hostname or "").lower()
            except Exception:
                pass

    # 4. Yahoo redirect: /RU=https%3A%2F%2F.../RK=...
    elif "search.yahoo.com" in host and "/RU=" in sp.path:
        m = re.search(r"/RU=([^/]+)/", sp.path)
        if m:
            decoded = urllib.parse.unquote(m.group(1))
            if decoded.startswith("http"):
                u = decoded
                try:
                    sp = urllib.parse.urlsplit(u)
                    host = (sp.hostname or "").lower()
                except ValueError:
                    return ""

    if not u.startswith(("http://", "https://")):
        return ""
    if host in _SERP_SELF_HOSTS:
        return ""
    return u


def apply_stealth(page) -> bool:
    """
    Applies anti-bot / stealth evasions to a Playwright page across all versions of
    playwright-stealth (v1 stealth_sync, v2 Stealth().apply_stealth_sync, callable stealth)
    plus native JS navigator/chrome/language evasions. Never raises.
    """
    applied = False
    if HAS_PLAYWRIGHT_STEALTH and playwright_stealth is not None:
        try:
            if hasattr(playwright_stealth, "stealth_sync") and callable(playwright_stealth.stealth_sync):
                playwright_stealth.stealth_sync(page)
                applied = True
            elif hasattr(playwright_stealth, "Stealth"):
                stealth_obj = playwright_stealth.Stealth()
                if hasattr(stealth_obj, "apply_stealth_sync"):
                    stealth_obj.apply_stealth_sync(page)
                    applied = True
            elif hasattr(playwright_stealth, "stealth") and callable(playwright_stealth.stealth):
                playwright_stealth.stealth(page)
                applied = True
        except Exception as e:
            log.debug("playwright_stealth hook warning: %s", e)

    try:
        if hasattr(page, "add_init_script"):
            page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                window.chrome = window.chrome || { runtime: {} };
                Object.defineProperty(navigator, 'languages', {get: () => ['he-IL', 'he', 'en-US', 'en']});
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            """)
            applied = True
    except Exception as e:
        log.debug("Stealth init_script warning: %s", e)
    return applied


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tags(html_fragment: str) -> str:
    return re.sub(r"\s+", " ", unescape(_TAG_RE.sub(" ", html_fragment or ""))).strip()


def extract_serp_snippets(html: str) -> list:
    """
    Extracts structured search results [{'url': ..., 'title': ..., 'snippet': ...}]
    from DuckDuckGo HTML, Bing HTML, or generic SERP markup.
    """
    if not html:
        return []
    results = []
    seen_urls = set()

    # Pattern A: DuckDuckGo result blocks
    ddg_blocks = re.findall(
        r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>'
        r'(?:.*?<a[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>)?',
        html,
        flags=re.S | re.I,
    )
    for raw_href, raw_title, raw_snip in ddg_blocks:
        url = unwrap_search_redirect(raw_href)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        results.append({
            "url": url,
            "title": _strip_tags(raw_title),
            "snippet": _strip_tags(raw_snip),
        })

    # Pattern B: Bing <li class="b_algo"> blocks
    bing_blocks = re.findall(r'<li[^>]*class="[^"]*b_algo[^"]*"[^>]*>(.*?)</li>', html, flags=re.S | re.I)
    for blk in bing_blocks:
        m_link = re.search(r'<h2[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', blk, flags=re.S | re.I)
        if not m_link:
            continue
        url = unwrap_search_redirect(m_link.group(1))
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        m_snip = re.search(r'<p[^>]*>(.*?)</p>', blk, flags=re.S | re.I)
        results.append({
            "url": url,
            "title": _strip_tags(m_link.group(2)),
            "snippet": _strip_tags(m_snip.group(1) if m_snip else ""),
        })

    return results


def harvest_snippet_intel(snippets: list) -> dict:
    """
    Directly harvests phones, emails, valid Israeli national IDs, and social network profiles
    from SERP titles & snippets (critical when target social sites block direct crawling).
    """
    from .extract import EMAIL_RE, PHONE_IL, norm_phone_il, valid_national_id
    phones, emails, national_ids = set(), set(), set()
    social_profiles = []
    seen_social = set()

    social_domains = {
        "linkedin.com": "linkedin",
        "facebook.com": "facebook",
        "instagram.com": "instagram",
        "x.com": "x_twitter",
        "twitter.com": "x_twitter",
        "t.me": "telegram",
        "github.com": "github",
        "tiktok.com": "tiktok",
    }

    for item in snippets or []:
        url = item.get("url", "")
        text = f"{item.get('title', '')} {item.get('snippet', '')}"
        for m in PHONE_IL.finditer(text):
            p = norm_phone_il(m.group(0))
            if p:
                phones.add(p)
        for m in EMAIL_RE.finditer(text):
            emails.add(m.group(0).lower().rstrip(".,;:"))
        for m in re.finditer(r"(?<!\d)(\d{9})(?!\d)", text):
            if valid_national_id(m.group(1)):
                national_ids.add(m.group(1))
        if url:
            host = host_of(url)
            for sdom, label in social_domains.items():
                if host == sdom or host.endswith("." + sdom):
                    if url not in seen_social:
                        seen_social.add(url)
                        social_profiles.append({
                            "platform": label,
                            "url": url,
                            "title": item.get("title", ""),
                            "snippet": item.get("snippet", ""),
                        })

    return {
        "phones": sorted(phones),
        "emails": sorted(emails),
        "national_ids": sorted(national_ids),
        "social_profiles": social_profiles,
    }


class NativeMetaSearchProvider(Provider):
    """
    Native Local Meta-Search Provider (v2.0):
    100% native Python & Playwright local search engine (Zero Docker, Zero external SearXNG server).
    Features:
      - Layer A: Playwright Stealth browser searches (DuckDuckGo + Bing fallback)
                 with persistent profile in data/browser_profile to retain cookies and prevent captchas,
                 plus HTTP DuckDuckGo fallback and direct SERP snippet intelligence harvesting.
      - Layer B: Direct concurrent API / HTTP queries querying Wayback CDX API and optional API keys.
    """
    name = "native_meta"
    plain = False

    def __init__(self, cfg, fetcher=None, inbox=None, **_):
        super().__init__(cfg)
        self.fetcher = fetcher
        self.last_snippets = []
        self.last_snippet_intel = {}
        base_dir = os.path.dirname(getattr(cfg, "db_path", ".")) or "."
        if os.path.basename(base_dir) == "data":
            self.profile_dir = os.path.join(base_dir, "browser_profile")
        else:
            self.profile_dir = os.path.join(base_dir, "data", "browser_profile")
        try:
            os.makedirs(self.profile_dir, exist_ok=True)
        except OSError:
            pass

    def search(self, query: str, limit: int = 20) -> list:
        results = []
        self.last_snippets = []
        self.last_snippet_intel = {}

        # Layer B: Direct open repositories & CDX (fast HTTP/2)
        layer_b_results = self._search_open_repositories(query, limit=limit)
        results.extend(layer_b_results)

        # Layer A: Browser Stealth Engine (if needed to reach requested limit)
        if len(results) < limit:
            needed = limit - len(results)
            layer_a_results = self._search_playwright_stealth(query, limit=needed)
            results.extend(layer_a_results)

        if self.last_snippets:
            self.last_snippet_intel = harvest_snippet_intel(self.last_snippets)

        return clean_results(results, self.cfg.block_domains)[:limit]

    def _search_open_repositories(self, query: str, limit: int = 15) -> list:
        urls = []
        # Check configured API keys if present
        if getattr(self.cfg, "brave_key", None):
            try:
                b = Brave(self.cfg)
                urls.extend(b.search(query, limit=limit))
            except Exception as e:
                log.debug("Brave search failed: %s", e)

        if getattr(self.cfg, "google_key", None) and getattr(self.cfg, "google_cx", None):
            try:
                g = GoogleCSE(self.cfg)
                urls.extend(g.search(query, limit=limit))
            except Exception as e:
                log.debug("Google CSE search failed: %s", e)

        # Wayback CDX API for historical documents (skip email hosts and generic social/legal portals)
        try:
            wb_base = getattr(self.cfg, "wayback_url", "https://web.archive.org").rstrip("/")
            q_no_email = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", " ", query)
            domain_match = re.search(r"\b([a-zA-Z0-9\-]+\.(?:co\.il|gov\.il|org\.il|ac\.il|com|org|net))\b", q_no_email)
            skip_wb_domains = {
                "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "walla.co.il", "walla.com",
                "psakdin.co.il", "takdin.co.il", "nevo.co.il", "ruling.co.il", "gov.il", "guidestar.org.il",
                "linkedin.com", "facebook.com", "instagram.com", "github.com", "tiktok.com", "twitter.com", "x.com",
            }
            if domain_match and domain_match.group(1).lower() not in skip_wb_domains:
                dom = domain_match.group(1)
                cdx_url = (f"{wb_base}/cdx/search/cdx?url={urllib.parse.quote(dom)}/*&output=json"
                           f"&fl=timestamp,original,mimetype&filter=statuscode:200&collapse=urlkey&limit=50")
                try:
                    raw = _get(cdx_url, self.cfg, timeout=10)
                    data = json.loads(raw or b"[]")
                except Exception:
                    data = []
                if len(data) > 1:
                    for row in data[1:min(limit + 1, len(data))]:
                        ts, orig, _ = row[0], row[1], row[2]
                        urls.append(f"{wb_base}/web/{ts}id_/{orig}")
        except Exception as e:
            log.debug("Wayback query failed: %s", e)

        return urls

    def _search_http_fallback(self, query: str, limit: int = 10) -> list:
        """Direct HTTP SERP fallback (DuckDuckGo HTML + Bing HTTP) when Playwright browser is unavailable or installing."""
        out_urls = []
        try:
            ddg = DuckDuckGo(self.cfg)
            urls = ddg.search(query, limit)
            if ddg.last_snippets:
                self.last_snippets.extend(ddg.last_snippets)
            for u in urls:
                if u and u not in out_urls:
                    out_urls.append(u)
        except Exception as e:
            log.debug("HTTP DDG fallback failed: %s", e)

        if len(out_urls) < limit:
            try:
                bing_url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
                raw = _get(bing_url, self.cfg, timeout=10)
                if raw:
                    b_html = raw.decode("utf-8", "ignore")
                    b_snippets = extract_serp_snippets(b_html)
                    if b_snippets:
                        self.last_snippets.extend(b_snippets)
                        for s in b_snippets:
                            u = s.get("url")
                            if u and not is_generic(u) and u not in out_urls:
                                out_urls.append(u)
                                if len(out_urls) >= limit:
                                    break
            except Exception as e:
                log.debug("HTTP Bing fallback failed: %s", e)
        return out_urls[:limit]

    @staticmethod
    def _find_system_browser_executables() -> list[str]:
        """Locate installed Chrome / Edge binaries on Windows/Linux/macOS for Attempt 2 fallback."""
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
        ]
        return [p for p in candidates if p and os.path.isfile(p)]

    @classmethod
    def _trigger_playwright_self_heal(cls) -> None:
        """Attempt 3: One-time non-blocking background installation of Playwright Chromium."""
        if getattr(cls, "_self_heal_triggered", False):
            return
        cls._self_heal_triggered = True
        try:
            import subprocess
            import sys
            log.info("Triggering background Playwright Chromium self-healing installation...")
            subprocess.Popen(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            log.debug("Background playwright self-heal spawn failed: %s", e)

    def _launch_resilient_context(self, p, args: list[str], ua: str):
        """3-Tier Resilient Browser Launcher:
        Attempt 1: Standard Playwright Chromium (persistent context, or ephemeral context if profile locked).
        Attempt 2: System-installed Chrome / Edge via channel=('chrome', 'msedge') or explicit executable_path.
        Attempt 3: Trigger background `python -m playwright install chromium` and return (None, None) for instant HTTP fallback.
        """
        # Attempt 1: Default Playwright Chromium
        try:
            ctx = p.chromium.launch_persistent_context(
                user_data_dir=self.profile_dir,
                headless=True,
                args=args,
                user_agent=ua,
            )
            return ctx, None
        except Exception as e1:
            err_msg = str(e1)
            # If the persistent profile directory is locked by another thread/process, try ephemeral launch first
            if "Executable doesn't exist" not in err_msg and "executable" not in err_msg.lower():
                try:
                    browser = p.chromium.launch(headless=True, args=args)
                    ctx = browser.new_context(user_agent=ua)
                    return ctx, browser
                except Exception as e1b:
                    err_msg = str(e1b)

            log.debug("Playwright Attempt 1 (bundled Chromium) unavailable (%s); trying Attempt 2 (system browser)...", err_msg[:140])

        # Attempt 2A: System channels ("chrome", "msedge")
        for channel in ("chrome", "msedge"):
            try:
                browser = p.chromium.launch(headless=True, channel=channel, args=args)
                ctx = browser.new_context(user_agent=ua)
                log.info("Playwright Attempt 2 succeeded via system channel='%s'", channel)
                return ctx, browser
            except Exception:
                pass

        # Attempt 2B: Explicit Windows / OS executable paths
        for exe_path in self._find_system_browser_executables():
            try:
                browser = p.chromium.launch(headless=True, executable_path=exe_path, args=args)
                ctx = browser.new_context(user_agent=ua)
                log.info("Playwright Attempt 2 succeeded via executable_path='%s'", exe_path)
                return ctx, browser
            except Exception:
                pass

        # Attempt 3: Self-Heal in background + immediate HTTP fallback
        self._trigger_playwright_self_heal()
        return None, None

    def _search_playwright_stealth(self, query: str, limit: int = 10) -> list:
        if not HAS_PLAYWRIGHT or not sync_playwright:
            return self._search_http_fallback(query, limit=limit)

        out_urls = []
        try:
            with sync_playwright() as p:
                args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                ]
                ua = getattr(
                    self.cfg,
                    "browser_ua",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                )
                context, browser = self._launch_resilient_context(p, args, ua)
                if context is None:
                    return self._search_http_fallback(query, limit=limit)
                try:
                    page = context.new_page()
                    apply_stealth(page)

                    # Engine 1: DuckDuckGo HTML
                    search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
                    page.goto(search_url, timeout=15000, wait_until="domcontentloaded")
                    html = page.content()
                    snippets = extract_serp_snippets(html)
                    if snippets:
                        self.last_snippets.extend(snippets)
                        for s in snippets:
                            u = s.get("url")
                            if u and not is_generic(u) and u not in out_urls:
                                out_urls.append(u)
                                if len(out_urls) >= limit:
                                    break

                    if len(out_urls) < limit:
                        links = page.query_selector_all("a.result__a, a.result__url, a[href]")
                        for link in links:
                            href = link.get_attribute("href")
                            u = unwrap_search_redirect(href)
                            if u and not is_generic(u) and u not in out_urls:
                                out_urls.append(u)
                                if len(out_urls) >= limit:
                                    break

                    # Engine 2: Rotate to Bing if DuckDuckGo yielded nothing
                    if not out_urls:
                        bing_url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
                        page.goto(bing_url, timeout=15000, wait_until="domcontentloaded")
                        b_html = page.content()
                        b_snippets = extract_serp_snippets(b_html)
                        if b_snippets:
                            self.last_snippets.extend(b_snippets)
                            for s in b_snippets:
                                u = s.get("url")
                                if u and not is_generic(u) and u not in out_urls:
                                    out_urls.append(u)
                                    if len(out_urls) >= limit:
                                        break
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    if browser is not None:
                        try:
                            browser.close()
                        except Exception:
                            pass
        except Exception as e:
            log.debug("Playwright Stealth search fallback to HTTP (%s)", e)

        if not out_urls:
            out_urls = self._search_http_fallback(query, limit=limit)

        return out_urls


REGISTRY = {c.name: c for c in (Wikipedia, SearXNG, Brave, GoogleCSE, SerpAPI, Wayback, DuckDuckGo, BrowserSearch, NativeMetaSearchProvider)}


def build_providers(cfg, fetcher=None, inbox=None):
    names = list(cfg.providers)
    if cfg.searxng_url and "searxng" not in names:
        names.append("searxng")
    for key, name in ((cfg.brave_key, "brave"), (cfg.google_key and cfg.google_cx, "google"),
                      (cfg.serpapi_key, "serpapi")):
        if key and name not in names:
            names.append(name)
    # the no-API meta-search is the default discovery only when the operator did not choose providers:
    # an explicit OSNIT_PROVIDERS (even empty, e.g. offline work) is respected as given
    explicit = getattr(cfg, "providers_explicit", False)
    if not explicit and "native_meta" not in names and not any(k in names for k in ("brave", "google", "serpapi", "searxng")):
        names.append("native_meta")
    return {n: REGISTRY[n](cfg, fetcher=fetcher, inbox=inbox) for n in dict.fromkeys(names) if n in REGISTRY}


def clean_results(urls, block=()):
    """Normalised, unwrapped, de-duplicated result URLs without general-knowledge sites or SERP self-links."""
    seen, out = set(), []
    for raw_u in urls:
        unwrapped = unwrap_search_redirect(raw_u) if raw_u else ""
        if not unwrapped:
            continue
        n = normalize_url(unwrapped)
        if not n:
            continue
        if host_of(n) in _SERP_SELF_HOSTS:
            continue
        if "web.archive.org/web/" not in n and is_generic(n, block):
            continue
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out

