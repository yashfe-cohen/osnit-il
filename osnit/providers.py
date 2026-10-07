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


REGISTRY = {c.name: c for c in (Wikipedia, SearXNG, Brave, DuckDuckGo)}


def build_providers(cfg):
    names = list(cfg.providers)
    if cfg.searxng_url and "searxng" not in names:
        names.append("searxng")
    if cfg.brave_key and "brave" not in names:
        names.append("brave")
    return {n: REGISTRY[n](cfg) for n in names if n in REGISTRY}


def clean_results(urls):
    seen, out = set(), []
    for u in urls:
        n = normalize_url(u)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out
