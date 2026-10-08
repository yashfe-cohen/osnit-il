import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

TRACKING = ("utm_", "fbclid", "gclid", "mc_cid", "mc_eid", "igshid", "ref_src", "yclid")
SECOND_LEVEL = {"co.il", "org.il", "ac.il", "gov.il", "muni.il", "net.il", "k12.il", "idf.il",
                "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp"}
PUBLIC_MAIL = {"gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
               "msn.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com",
               "mail.com", "yandex.com", "mail.ru", "walla.co.il", "walla.com", "zahav.net.il",
               "bezeqint.net", "netvision.net.il", "012.net.il", "013.net", "013net.net",
               "inter.net.il", "smile.net.il", "actcom.net.il", "netvision.net"}
SKIP_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".mp3", ".mp4", ".avi",
            ".mov", ".mkv", ".wav", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dmg", ".iso",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".apk", ".bin"}
# general-knowledge sites: encyclopaedias, scripture, dictionaries, name-meaning and lyrics sites. They mention
# names all the time (biblical figures, definitions) and are almost never about the private person searched.
GENERIC_DOMAINS = {
    "wikipedia.org", "wikimedia.org", "wiktionary.org", "wikisource.org", "wikiquote.org", "wikidata.org",
    "wikibooks.org", "wikivoyage.org", "wikinews.org", "wikiwand.com", "fandom.com", "britannica.com",
    "sefaria.org", "sefaria.org.il", "mechon-mamre.org", "tanach.us", "chabad.org", "daat.ac.il", "hebrewbooks.org",
    "biblegateway.com", "biblehub.com", "bible.com", "kingjamesbibleonline.org", "alhatorah.org", "yeshiva.org.il",
    "929.org.il", "torah.org", "aish.com", "jewishvirtuallibrary.org", "wikishiva.org", "hamichlol.org.il",
    "morfix.co.il", "milog.co.il", "dictionary.com", "merriam-webster.com", "thefreedictionary.com", "collinsdictionary.com",
    "behindthename.com", "babynames.com", "nameberry.com", "names.org", "forebears.io", "ancestry.com", "familysearch.org",
    "geni.com", "myheritage.com", "myheritage.co.il", "shironet.mako.co.il", "genius.com", "azlyrics.com", "imdb.com",
    "quora.com", "pinterest.com", "goodreads.com", "amazon.com", "ebay.com", "aliexpress.com", "archive.org",
}


def is_generic(url_or_host: str, extra=()) -> bool:
    host = url_or_host.split("://", 1)[-1].split("/", 1)[0].lower()
    d = registered_domain(host)
    return d in GENERIC_DOMAINS or d in extra or any(host == x or host.endswith("." + x) for x in extra)


DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".json", ".vcf", ".xml", ".rtf"}


def normalize_url(url: str, base: str = None):
    url = (url or "").strip()
    if not url or url.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None
    if base:
        url = urljoin(base, url)
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not host:
        return None
    try:
        host = host.encode("idna").decode()
    except UnicodeError:
        return None
    netloc = host + (f":{port}" if port and port not in (80, 443) else "")
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
         if not k.lower().startswith(TRACKING)]
    return urlunsplit((p.scheme, netloc, p.path or "/", urlencode(q), ""))


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if host.replace(".", "").isdigit() or ":" in host:   # IP literal
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def ext_of(url: str) -> str:
    path = urlsplit(url).path.lower()
    i = path.rfind(".")
    return path[i:] if i != -1 and "/" not in path[i:] else ""


def is_private_host(host: str) -> bool:
    if host in ("localhost", "") or host.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        infos = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, None)]
        except (socket.gaierror, UnicodeError, OSError):
            return False  # unresolvable here (e.g. egress proxy resolves); real request decides
    return any(i.is_private or i.is_loopback or i.is_link_local or i.is_reserved or i.is_multicast
               for i in infos)
