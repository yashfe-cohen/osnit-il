"""Runtime settings the operator manages from the UI (not everyone edits osnit.env by hand on Windows).

Only the opt-in AI fields live here: the Gemini/OpenAI-compatible key, URL and model, and the two feature
toggles (name expansion for search, column-type suggestions on import). They are stored in the `meta` table as
one JSON blob and applied onto the live Config object, so a change takes effect without a restart. Environment
variables remain the fallback: a field left blank in the UI keeps whatever osnit.env / the OS set at startup.

The key is stored in plaintext in the local SQLite DB — exactly like osnit.env — because this is a single-user
tool bound to loopback; the UI says so. `public()` never returns the full key, only a masked hint."""
import json

META_KEY = "ui_settings"
STR_FIELDS = ("ai_key", "ai_url", "ai_model")
BOOL_FIELDS = ("ai_names", "ai_template")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


def load(store) -> dict:
    raw = store.meta_get(META_KEY) if store is not None else None
    try:
        d = json.loads(raw) if raw else {}
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def apply(cfg, store):
    """Overlay the stored UI settings onto cfg. A blank/absent value leaves the env-derived default in place, so
    the model keeps working and `enabled()`/`names_enabled()` see the merged picture."""
    d = load(store)
    for k in STR_FIELDS:
        if k in d:                            # present (even "") = authoritative; absent = keep env default
            v = d.get(k)
            setattr(cfg, k, v.strip() if isinstance(v, str) else "")
    for k in BOOL_FIELDS:
        if k in d:
            setattr(cfg, k, bool(d[k]))
    return cfg


def save(store, data: dict):
    """Validate and persist the operator's settings. Only known fields are kept. A key of all '•' means 'leave
    the stored key unchanged' (the UI shows the key masked, so re-saving must not overwrite it with the mask)."""
    cur = load(store)
    out = dict(cur)
    for k in STR_FIELDS:
        if k in data:
            v = data.get(k)
            v = v.strip() if isinstance(v, str) else ""
            if k == "ai_key" and v and set(v) <= {"•", "·", "*"}:
                continue                      # the masked placeholder — keep the existing key
            out[k] = v
    for k in BOOL_FIELDS:
        if k in data:
            out[k] = bool(data[k])
    store.meta_set(META_KEY, json.dumps(out, ensure_ascii=False))
    return out


def _mask(key: str) -> str:
    if not key:
        return ""
    key = key.strip()
    return ("•" * max(0, len(key) - 4) + key[-4:]) if len(key) > 4 else "•" * len(key)


def public(cfg, store) -> dict:
    """What the Settings screen shows: the current effective AI config, the key masked, and where each value
    comes from (so the operator understands env vs. UI)."""
    stored = load(store)
    key = getattr(cfg, "ai_key", "") or ""
    return {
        "ai_key_set": bool(key),
        "ai_key_mask": _mask(key),
        "ai_url": getattr(cfg, "ai_url", "") or "",
        "ai_model": getattr(cfg, "ai_model", "") or "",
        "ai_names": bool(getattr(cfg, "ai_names", False)),
        "ai_template": bool(getattr(cfg, "ai_template", False)),
        "from_env_key": bool(key) and not (stored.get("ai_key") or "").strip(),
        "gemini_url": GEMINI_URL,
    }
