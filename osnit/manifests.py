"""Keyless username-presence manifests (WhatsMyName / Sherlock schema) folded into Layer 3.

Instead of a handful of hand-written sites, Layer 3 checks a username against many public profile URLs using
the community-maintained detection rules those projects publish as plain JSON. No API key, no extra runtime
dependency, no subprocess: every site is probed through the SAME async checker and the SAME strict
false-positive filtering that the curated `SOCIAL_PLATFORMS` use.

Precision-first (rule 1): a manifest site counts as a hit only when its required "exists" string is present on
a page whose status code is accepted AND no "missing" marker appears — a status code alone never asserts a
profile. A site with no usable "exists" string is dropped, so a weak rule loses a hit, never invents one.

Data:
  - A curated subset ships in `osnit/data/username_sites.json` so the engine works fully offline and the tests
    are deterministic.
  - `tools/sync_manifests.py` refreshes/expands it from WhatsMyName and Sherlock into
    `osnit/data/username_sites.synced.json`, which is preferred when present.

The WhatsMyName site schema this module reads:
    {"name", "uri_check" (contains {account}), "uri_pretty"?, "e_string", "e_code"?, "m_string"?, "m_code"?,
     "cat"?, "headers"?}
Sherlock's schema is normalised to the same shape by the sync tool.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

_DIR = Path(__file__).resolve().parent / "data"
_BUNDLED = _DIR / "username_sites.json"
_SYNCED = _DIR / "username_sites.synced.json"


def _max_sites() -> int:
    """Cap on manifest sites probed per username (keeps a run bounded on the operator's Windows box)."""
    try:
        return max(0, int(os.environ.get("OSNIT_USERNAME_SITES_MAX", "200")))
    except ValueError:
        return 200


def _read(path: Path) -> list[dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    sites = data.get("sites") if isinstance(data, dict) else data
    return [s for s in (sites or []) if isinstance(s, dict)]


@lru_cache(maxsize=1)
def _raw_sites() -> tuple[dict[str, Any], ...]:
    """The synced manifest when present (operator ran the sync tool), else the bundled curated subset."""
    sites = _read(_SYNCED) or _read(_BUNDLED)
    return tuple(sites)


def wmn_to_platform(site: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one WhatsMyName-schema site to the `check_username_on_platform` schema, or None if it is not
    precision-safe (no usable exists-string). `{account}` placeholders become the checker's `{username}`."""
    name = (site.get("name") or "").strip()
    uri = site.get("uri_check") or ""
    e_string = site.get("e_string")
    if not name or "{account}" not in uri or not e_string:
        return None

    def _sub(v: str) -> str:
        return str(v).replace("{account}", "{username}")

    plat: dict[str, Any] = {
        "name": name,
        "url": _sub(uri),
        "positive": [_sub(e_string)],
        "from_manifest": True,
        "category_hint": (site.get("cat") or "").strip(),
    }
    if site.get("uri_pretty"):
        plat["display_url"] = _sub(site["uri_pretty"])
    if site.get("m_string"):
        plat["negative"] = [_sub(site["m_string"])]
    # accepted "exists" status codes: e_code if given, else 200. A missing page that still returns the exists
    # code is caught by the negative / generic-not-found markers.
    try:
        plat["exist_code"] = (int(site["e_code"]),) if site.get("e_code") is not None else (200,)
    except (TypeError, ValueError):
        plat["exist_code"] = (200,)
    if isinstance(site.get("headers"), dict) and site["headers"]:
        plat["headers"] = site["headers"]
    return plat


def manifest_platforms(exclude_names: set[str] | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    """Curated/synced manifest sites as checker platforms, de-duplicated against names already covered by the
    hand-written curated platforms (those win — they extract richer metadata), capped for a bounded run."""
    exclude = {n.strip().lower() for n in (exclude_names or set())}
    cap = _max_sites() if limit is None else limit
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for site in _raw_sites():
        plat = wmn_to_platform(site)
        if not plat:
            continue
        key = plat["name"].lower()
        if key in exclude or key in seen:
            continue
        seen.add(key)
        out.append(plat)
        if len(out) >= cap:
            break
    return out


def manifest_source() -> dict[str, Any]:
    """Small description of which manifest is live and how many usable sites it holds (for logs / diagnostics)."""
    synced = bool(_read(_SYNCED))
    usable = sum(1 for s in _raw_sites() if wmn_to_platform(s))
    return {"synced": synced, "total_sites": len(_raw_sites()), "usable_sites": usable, "cap": _max_sites()}
