"""Polite fetcher: robots.txt, per-host delay, size caps, conditional GET, SSRF guard. Body stays in memory."""
import threading
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from .urls import is_private_host

ALLOWED_PREFIX = ("text/", "application/pdf", "application/json", "application/xml", "application/xhtml",
                  "application/vnd.openxmlformats", "application/octet-stream", "application/rss", "application/atom")


@dataclass
class FetchResult:
    status: int = 0
    url: str = ""
    content_type: str = ""
    body: bytes = None
    etag: str = None
    last_modified: str = None
    not_modified: bool = False
    skipped: str = None       # reason the URL was deliberately not fetched/parsed
    error: str = None
    retry_after: float = 0.0
    truncated: bool = False


class _Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, fetcher):
        self.f = fetcher

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.f.cfg.allow_private_hosts and is_private_host(urlsplit(newurl).hostname or ""):
            raise urllib.error.URLError("redirect to private host blocked")
        if not newurl.lower().startswith(("http://", "https://")):
            raise urllib.error.URLError("redirect to non-http scheme")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self, cfg):
        self.cfg = cfg
        self._opener = urllib.request.build_opener(_Redirect(self))
        self._host_lock = {}
        self._host_next = {}
        self._glock = threading.Lock()
        self._robots = {}   # origin -> (expires, parser|None, delay)

    # ------------------------------------------------------------ politeness
    def _wait_turn(self, host, delay):
        with self._glock:
            lock = self._host_lock.setdefault(host, threading.Lock())
        with lock:
            wait = self._host_next.get(host, 0) - time.time()
            if wait > 0:
                time.sleep(wait)
            self._host_next[host] = time.time() + delay

    def _robots_for(self, url):
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        now = time.time()
        ent = self._robots.get(origin)
        if ent and ent[0] > now:
            return ent[1], ent[2], ent[3]
        rp, delay, ok = RobotFileParser(), 0.0, True
        try:
            req = urllib.request.Request(origin + "/robots.txt", headers={"User-Agent": self.cfg.user_agent})
            with self._opener.open(req, timeout=self.cfg.timeout) as r:
                txt = r.read(512 * 1024).decode("utf-8", "replace")
            rp.parse(txt.splitlines())
            delay = float(rp.crawl_delay(self.cfg.user_agent) or 0)
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                ok = False                       # server trouble: be conservative, retry later
            else:
                rp = None                        # 4xx: no robots => allowed
        except Exception:
            ok = False
        self._robots[origin] = (now + (3600 if ok else 120), rp, min(delay, 30.0), ok)
        return rp, min(delay, 30.0), ok

    def allowed(self, url):
        if not self.cfg.respect_robots:
            return True, 0.0
        rp, delay, ok = self._robots_for(url)
        if not ok:
            return False, delay
        return (rp.can_fetch(self.cfg.user_agent, url) if rp else True), delay

    # ------------------------------------------------------------ fetch
    def fetch(self, url, etag=None, last_modified=None) -> FetchResult:
        host = urlsplit(url).hostname or ""
        if not self.cfg.allow_private_hosts and is_private_host(host):
            return FetchResult(url=url, skipped="private-host")
        ok, delay = self.allowed(url)
        if not ok:
            return FetchResult(url=url, skipped="robots")
        self._wait_turn(host, max(self.cfg.request_delay, delay))
        headers = {"User-Agent": self.cfg.user_agent, "Accept-Encoding": "gzip, deflate",
                   "Accept": "text/html,application/pdf,application/json,text/*;q=0.9,*/*;q=0.5",
                   "Accept-Language": "he,en;q=0.8"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        try:
            with self._opener.open(urllib.request.Request(url, headers=headers), timeout=self.cfg.timeout) as r:
                ct = r.headers.get("Content-Type", "")
                res = FetchResult(status=r.status, url=r.geturl(), content_type=ct, etag=r.headers.get("ETag"),
                                  last_modified=r.headers.get("Last-Modified"))
                if not ct or ct.lower().startswith(ALLOWED_PREFIX) or "xml" in ct.lower() or "json" in ct.lower():
                    body, res.truncated = self._read(r)
                    res.body = body
                else:
                    res.skipped = f"content-type {ct.split(';')[0]}"
                return res
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return FetchResult(status=304, url=url, not_modified=True, etag=etag, last_modified=last_modified)
            ra = e.headers.get("Retry-After", "") if e.headers else ""
            return FetchResult(status=e.code, url=url, error=f"http {e.code}",
                               retry_after=float(ra) if ra.isdigit() else 0.0)
        except Exception as e:
            return FetchResult(url=url, error=f"{type(e).__name__}: {e}")

    def _read(self, r):
        enc = (r.headers.get("Content-Encoding") or "").lower()
        limit = self.cfg.max_bytes
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if enc == "gzip" else -zlib.MAX_WBITS if enc == "deflate" else 0)
        out, size, trunc = [], 0, False
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            if enc in ("gzip", "deflate"):
                try:
                    chunk = d.decompress(chunk, limit - size + 1)
                except zlib.error:
                    if enc == "deflate":          # zlib-wrapped deflate
                        d = zlib.decompressobj()
                        chunk = d.decompress(chunk, limit - size + 1)
                    else:
                        raise
            out.append(chunk)
            size += len(chunk)
            if size > limit:
                trunc = True
                break
        return b"".join(out)[:limit], trunc
