"""Plausibility gate: what is a believable contact, and what kind of page are we looking at."""
import re

ROLE_MAILBOX = {"info", "office", "support", "sales", "contact", "admin", "hello", "noreply", "no-reply", "mail",
                "webmaster", "service", "team", "hr", "marketing", "billing", "postmaster", "press", "jobs", "careers",
                "enquiries", "inquiries", "help", "general", "reception", "secretary"}
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "test.com", "domain.com", "email.com",
                       "yourdomain.com", "yourcompany.com", "company.com", "site.com", "website.com", "mydomain.com"}
PLACEHOLDER_LOCALS = {"name", "your", "yourname", "user", "username", "email", "example", "test", "someone", "firstname",
                      "lastname", "first.last", "john.doe", "you"}


def valid_phone(key: str) -> bool:
    d = re.sub(r"\D", "", key)
    if key.startswith("*") or d.startswith(("1700", "1800", "1599", "1801")):
        return True
    tail = d[-7:]
    if len(set(tail)) <= 2 or tail in ("1234567", "7654321", "0123456", "9876543", "2345678"):
        return False
    return 8 <= len(d) <= 15


def valid_email(addr: str) -> bool:
    local, _, domain = addr.partition("@")
    return domain not in PLACEHOLDER_DOMAINS and local not in PLACEHOLDER_LOCALS and len(local) >= 2


def is_role_mailbox(addr: str) -> bool:
    return addr.split("@")[0].lower() in ROLE_MAILBOX


def classify(text: str, ex) -> str:
    """normal | directory | spam, from contact density/repetition on the page."""
    words = max(1, len(text.split()))
    phones = [k for (t, k) in ex.ents if t == "phone"]
    emails = [k for (t, k) in ex.ents if t == "email"]
    distinct = len(phones) + len(emails)
    hits = sum(len(v["hits"]) for (t, _), v in ex.ents.items() if t in ("phone", "email"))
    if distinct and hits >= 12 and distinct <= 3:
        return "spam"                                  # same few numbers hammered over and over
    owners = sum(1 for (t, _) in ex.ents if t in ("person", "org"))
    if distinct >= 6 and words < 80 and not owners:
        return "spam"                                  # stub page that is nothing but contact data, nobody named
    persons_hits = sum(len(v["hits"]) for (t, _), v in ex.ents.items() if t == "person")
    if persons_hits >= 15 and words / persons_hits < 12 and distinct <= 2:
        return "spam"                                  # keyword stuffing of names
    # many contacts that cannot be tied to named people/orgs: a phone book, not a team page with cards
    unowned = distinct / max(1, owners) > 3
    if distinct >= 12 or (unowned and distinct >= 6 and distinct / (words / 100) >= 4):
        return "directory"
    return "normal"


def prune_shared(ex):
    """A number/mailbox tied to 3+ different owners is a switchboard, not a personal contact."""
    owners = {}
    for (ka, kb, kind), hits in ex.links.items():
        if kind != "contact":
            continue
        for c, o in ((ka, kb), (kb, ka)):
            if c[0] in ("phone", "email") and o[0] in ("person", "org"):
                owners.setdefault(c, set()).add(o)
    shared = {c for c, os_ in owners.items() if len(os_) > 2}
    for key in list(ex.links):
        ka, kb, kind = key
        if kind != "contact":
            continue
        c, o = (ka, kb) if ka[0] in ("phone", "email") else (kb, ka)
        if c in shared and o[0] in ("person", "org"):
            del ex.links[key]
        elif c[0] == "email" and o[0] == "person" and is_role_mailbox(c[1]):
            ex.links[key] = [(s, round(conf * 0.5, 3)) for s, conf in ex.links[key]]
    return len(shared)
