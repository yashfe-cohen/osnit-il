"""Discovery providers: turn a query into candidate public URLs. Prefer official APIs; scraping is opt-in."""
import json
import re
import urllib.parse
import urllib.request
from html import unescape

from .urls import normalize_url


def _get(url, cfg, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000)


class Provider:
    name = "base"

    def __init__(self, cfg):
        self.cfg = cfg

    def search(self, query: str, limit: int) -> list:
        raise NotImplementedError

    def accepts(self, query: str) -> bool:
        return not query.startswith("archive:")


class Wikipedia(Provider):
    """Official MediaWiki search API (he + en)."""
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


REGISTRY = {c.name: c for c in (Wikipedia, SearXNG, Brave, GoogleCSE, SerpAPI, Wayback, DuckDuckGo)}


def build_providers(cfg):
    names = list(cfg.providers)
    if cfg.searxng_url and "searxng" not in names:
        names.append("searxng")
    for key, name in ((cfg.brave_key, "brave"), (cfg.google_key and cfg.google_cx, "google"),
                      (cfg.serpapi_key, "serpapi")):
        if key and name not in names:
            names.append(name)
    return {n: REGISTRY[n](cfg) for n in names if n in REGISTRY}


def clean_results(urls):
    seen, out = set(), []
    for u in urls:
        n = normalize_url(u)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out
