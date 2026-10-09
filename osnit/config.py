import os
from dataclasses import dataclass, field


def load_env_file(path="osnit.env"):
    """KEY=VALUE lines (API keys, settings) so nothing has to be set in the OS; real env vars win."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    if v.strip():
                        os.environ.setdefault(k.strip(), v.strip().strip('"'))
    except OSError:
        pass


load_env_file()


def _env(name, default, cast=str):
    v = os.environ.get(name)
    return cast(v) if v is not None else default


def _bool(v):
    return str(v).lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    db_path: str = field(default_factory=lambda: _env("OSNIT_DB", "data/osnit.db"))
    user_agent: str = field(default_factory=lambda: _env(
        "OSNIT_UA", "osnit-il/0.1 (public-source research crawler; honors robots.txt)"))
    request_delay: float = field(default_factory=lambda: _env("OSNIT_DELAY", 1.5, float))
    timeout: float = 20.0
    max_bytes: int = 15 * 1024 * 1024
    workers: int = field(default_factory=lambda: _env("OSNIT_WORKERS", 4, int))
    max_depth: int = 2
    max_pages_per_domain: int = 400
    max_links_per_page: int = 60
    follow_external: bool = False       # generic crawl; pages that hit a subject always follow
    respect_robots: bool = True
    allow_private_hosts: bool = field(default_factory=lambda: _bool(_env("OSNIT_ALLOW_PRIVATE", "0")))
    rescan_min: float = 3600.0
    rescan_max: float = 7 * 86400.0
    providers: list = field(default_factory=lambda: [
        p for p in _env("OSNIT_PROVIDERS", "archive").split(",") if p])
    # extra domains never to read from discovery results (comma list), on top of urls.GENERIC_DOMAINS
    block_domains: list = field(default_factory=lambda: [
        d.strip().lower() for d in _env("OSNIT_BLOCK_DOMAINS", "").split(",") if d.strip()])
    searxng_url: str = field(default_factory=lambda: _env("SEARXNG_URL", ""))
    brave_key: str = field(default_factory=lambda: _env("BRAVE_API_KEY", ""))
    google_key: str = field(default_factory=lambda: _env("GOOGLE_API_KEY", ""))
    google_cx: str = field(default_factory=lambda: _env("GOOGLE_CSE_ID", ""))
    serpapi_key: str = field(default_factory=lambda: _env("SERPAPI_KEY", ""))
    wayback_url: str = field(default_factory=lambda: _env("OSNIT_WAYBACK", "https://web.archive.org"))
    # max discovery calls per provider per 24h (free API tiers); unset = unlimited
    budgets: dict = field(default_factory=lambda: {"google": _env("OSNIT_BUDGET_GOOGLE", 100, int),
                                                   "serpapi": _env("OSNIT_BUDGET_SERPAPI", 100, int),
                                                   "brave": _env("OSNIT_BUDGET_BRAVE", 2000, int),
                                                   "browser": _env("OSNIT_BUDGET_BROWSER", 300, int)})
    results_per_query: int = 15
    max_rounds: int = 6
    round_interval: float = 600.0
    default_duration_h: float = 6.0
    # delete input files after a successful import (crawled content is never written to disk at all)
    delete_imported: bool = field(default_factory=lambda: _bool(_env("OSNIT_DELETE_IMPORTED", "0")))
    # code that must be typed to delete data in bulk (UI / API reset)
    reset_code: str = field(default_factory=lambda: _env("OSNIT_RESET_CODE", "1212"))
    # optional, opt-in AI extraction-template layer (osnit.ai) — off and inert unless all four are set
    ai_template: bool = field(default_factory=lambda: _bool(_env("OSNIT_AI_TEMPLATE", "0")))
    ai_key: str = field(default_factory=lambda: _env("OSNIT_AI_KEY", ""))
    ai_url: str = field(default_factory=lambda: _env("OSNIT_AI_URL", ""))
    ai_model: str = field(default_factory=lambda: _env("OSNIT_AI_MODEL", ""))
    ai_timeout: float = field(default_factory=lambda: _env("OSNIT_AI_TIMEOUT", 20.0, float))
    # opt-in no-API discovery through the pre-installed headless Chromium (OSNIT_PROVIDERS=browser)
    browser_engine: str = field(default_factory=lambda: _env("OSNIT_BROWSER_ENGINE", "bing"))
    browser_ua: str = field(default_factory=lambda: _env(
        "OSNIT_BROWSER_UA",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"))
    browser_timeout: float = field(default_factory=lambda: _env("OSNIT_BROWSER_TIMEOUT", 35.0, float))
    browser_delay: float = field(default_factory=lambda: _env("OSNIT_BROWSER_DELAY", 4.0, float))
    browser_node: str = field(default_factory=lambda: _env("OSNIT_BROWSER_NODE", ""))
    browser_proxy: str = field(default_factory=lambda: _env("OSNIT_BROWSER_PROXY", ""))
    browser_headful: bool = field(default_factory=lambda: _bool(_env("OSNIT_BROWSER_HEADFUL", "0")))
    browser_download: bool = field(default_factory=lambda: _bool(_env("OSNIT_BROWSER_DOWNLOAD", "0")))
    browser_download_max: int = field(default_factory=lambda: _env("OSNIT_BROWSER_DOWNLOAD_MAX", 5, int))
    # aggressive, RAM-governed parallel scanning: concurrency 0 = auto from available RAM
    browser_concurrency: int = field(default_factory=lambda: _env("OSNIT_BROWSER_CONCURRENCY", 0, int))
    browser_ram_fraction: float = field(default_factory=lambda: _env("OSNIT_BROWSER_RAM_FRACTION", 0.85, float))
    browser_per_mb: int = field(default_factory=lambda: _env("OSNIT_BROWSER_PER_MB", 350, int))
    browser_max_workers: int = field(default_factory=lambda: _env("OSNIT_BROWSER_MAX_WORKERS", 16, int))
    browser_scan_downloads: bool = field(default_factory=lambda: _bool(_env("OSNIT_BROWSER_SCAN_DOWNLOADS", "1")))
