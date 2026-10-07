import os
from dataclasses import dataclass, field


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
        p for p in _env("OSNIT_PROVIDERS", "wikipedia").split(",") if p])
    searxng_url: str = field(default_factory=lambda: _env("SEARXNG_URL", ""))
    brave_key: str = field(default_factory=lambda: _env("BRAVE_API_KEY", ""))
    results_per_query: int = 15
    max_rounds: int = 6
    round_interval: float = 600.0
    default_duration_h: float = 6.0
    # delete input files after a successful import (crawled content is never written to disk at all)
    delete_imported: bool = field(default_factory=lambda: _bool(_env("OSNIT_DELETE_IMPORTED", "0")))
