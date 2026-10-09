"""Optional, opt-in AI-assisted extraction template. BEFORE the deterministic cataloguing decides a file, when
the operator enabled it AND a model is configured, we show an LLM the column headers and ~5 sample rows from the
MIDDLE of each table (analyze.middle_rows already produced them for the preview — no second file read) and get
back a template: each column mapped to one of THIS installation's known semantic type keys, plus optional split
and merge hints. The template is validated against the live Registry, converted into the SAME overrides channel
the UI already uses ({table: {column: typeKey, "__merge__": [...], "__spans__": [...]}}), and ALWAYS surfaced to
the operator to confirm/edit before import.

It is a SUGGESTION, never an authority: the operator and the deterministic layer remain in charge. With no model
configured, or on ANY failure, behaviour is byte-for-byte today's stdlib-only path — so the test+eval gate is
unaffected. The data rules hold: the AI only reassigns types; it can never mark a column 'skip'/'internal' (that
stays a human action), an unknown key degrades to an 'unknown' attribute (nothing dropped), national_id stays a
linking identifier, and a value without a trunk-0/972 can never become a phone (norm_phone_il still decides).
Security-group column values are redacted before leaving the machine; only headers and ≤5 already-truncated rows
are sent; the cache stores only (signature -> validated template), never raw values.
"""
import hashlib
import json
import urllib.request

from .urls import host_of, is_private_host

RULES = (
    "Rules you MUST follow: national_id is a LINKING identifier, never 'skip' it. "
    "A bare 8-9 digit number is national_id, NOT a phone. "
    "Never invent a person: if a column is not clearly a known field, use the best attribute type or 'unknown'. "
    "Credential columns map to password / hash / card / secret / national_id. "
    "Output MUST be a single JSON object and nothing else."
)


def enabled(cfg) -> bool:
    return bool(getattr(cfg, "ai_template", False) and cfg.ai_key and cfg.ai_url and cfg.ai_model)


def _security_cols(registry, table):
    return {c["name"] for c in table.get("columns", []) if registry.group(c.get("type", "")) == "security"}


def signature(table) -> str:
    """A cache key that is the same for any file with this header set and these per-column content kinds — so a
    re-import of the same export, or a same-shaped file, reuses one template and never re-calls the model."""
    cols = sorted(str(c) for c in (table.get("cols") or []))
    kinds = [c.get("kind", "") for c in table.get("columns", [])]
    return hashlib.sha1(json.dumps([cols, kinds], ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_prompt(registry, table) -> str:
    allowed = [{"key": k, "label": t.label, "group": t.group} for k, t in registry.types.items()]
    redact = _security_cols(registry, table)
    rows = []
    for r in (table.get("raw") or [])[:5]:
        rows.append({c: ("•••" if c in redact else r.get(c)) for c in (table.get("cols") or r.keys())})
    body = {
        "task": ("Map each column of this data table to the best semantic type. Return JSON only, of the shape "
                 '{"columns": {"<header>": "<type_key>"}, '
                 '"splits": [{"column":"<header>","delimiter":";","fields":[{"label":"...","type":"<type_key>"}]}], '
                 '"merges": [{"columns":["street","house","city"],"type":"address"}]}. '
                 "Use ONLY type keys from allowed_types. Omit a column you are unsure about."),
        "rules": RULES,
        "allowed_types": allowed,
        "table": table.get("table", ""),
        "headers": list(table.get("cols") or []),
        "sample_rows": rows,
    }
    return json.dumps(body, ensure_ascii=False)


# ---------------------------------------------------------------- the single network seam (tests monkeypatch this)
def _call(cfg, prompt: str) -> str:
    """POST the prompt to the configured OpenAI-compatible endpoint (or Anthropic /v1/messages when the host is
    api.anthropic.com) and return the model's text. Raises on any transport/HTTP error — the caller turns that
    into a graceful skip."""
    host = host_of(cfg.ai_url)
    if not getattr(cfg, "allow_private_hosts", False) and is_private_host(host):
        raise OSError(f"AI endpoint host {host!r} is private; set OSNIT_ALLOW_PRIVATE=1 to allow it")
    anthropic = "anthropic.com" in host
    if anthropic:
        headers = {"x-api-key": cfg.ai_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        payload = {"model": cfg.ai_model, "max_tokens": 1500,
                   "messages": [{"role": "user", "content": prompt}]}
    else:
        headers = {"Authorization": f"Bearer {cfg.ai_key}", "Content-Type": "application/json"}
        payload = {"model": cfg.ai_model, "temperature": 0, "max_tokens": 1500,
                   "messages": [{"role": "system", "content": "You map data columns to types. JSON only."},
                                {"role": "user", "content": prompt}]}
    req = urllib.request.Request(cfg.ai_url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=getattr(cfg, "ai_timeout", 20.0)) as r:
        data = json.loads(r.read(4_000_000))
    if anthropic:
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    return data["choices"][0]["message"]["content"]


def parse(text: str) -> dict:
    """The first JSON object in the model's reply, tolerant of code fences and surrounding prose. {} on failure."""
    if not text:
        return {}
    s = text.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s.strip("`")
        s = s[s.index("{"):] if "{" in s else s
    i = s.find("{")
    if i < 0:
        return {}
    depth, instr, esc = 0, False, False
    for j in range(i, len(s)):
        ch = s[j]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    o = json.loads(s[i:j + 1])
                    return o if isinstance(o, dict) else {}
                except ValueError:
                    return {}
    return {}


def _split_examples(values, delimiter, index):
    """For field `index` of each sample value split on `delimiter`, the span examples spans.learn() wants."""
    out = []
    for v in values:
        if v is None:
            continue
        s = str(v)
        parts = s.split(delimiter)
        if len(parts) <= index:
            continue
        off = sum(len(p) + len(delimiter) for p in parts[:index])
        piece = parts[index]
        out.append({"text": s, "start": off, "end": off + len(piece)})
    return out


def to_overrides(template, registry, table) -> dict:
    """Validate the model's template against the live Registry and build the per-table overrides. Unknown or
    'skip'/'internal' type keys are dropped (those columns fall back to the deterministic cascade); impossible
    merges/splits yield nothing. Never raises."""
    from . import spans
    from .importdb import merge_layout, merged_name
    cols = [str(c) for c in (table.get("cols") or [])]
    colset = set(cols)
    ov = {}
    try:
        for header, key in (template.get("columns") or {}).items():
            if header in colset and isinstance(key, str) and key in registry.types and key not in ("skip", "internal"):
                ov[header] = key
        merges = []
        for m in (template.get("merges") or []):
            group = [str(c) for c in (m.get("columns") or [])]
            t = m.get("type")
            if merge_layout(cols, [group]):                       # only >=2 adjacent, non-overlapping existing cols
                merges.append(group)
                if isinstance(t, str) and t in registry.types and t not in ("skip", "internal"):
                    ov[merged_name(group)] = t
        if merges:
            ov["__merge__"] = merges
        rules = []
        raw = table.get("raw") or []
        for sp in (template.get("splits") or []):
            col = sp.get("column")
            delim = sp.get("delimiter")
            if col not in colset or not isinstance(delim, str) or not delim:
                continue
            values = [r.get(col) for r in raw]
            for i, fld in enumerate(sp.get("fields") or []):
                label = str(fld.get("label") or "").strip() or f"{col}{i + 1}"
                t = fld.get("type")
                if not (isinstance(t, str) and t in registry.types and t not in ("skip", "internal")):
                    continue
                rule = spans.learn(_split_examples(values, delim, i))
                if not rule:
                    continue
                rules.append(dict(col=col, label=label, type=t, rule=rule,
                                  examples=_split_examples(values, delim, i)[:30]))
                ov[spans.virtual_name(col, label)] = t
        if rules:
            ov["__spans__"] = rules
    except Exception:
        return {}
    return ov


def template_for(cfg, store, analysis):
    """-> (overrides, note). Per table: cache lookup -> model call -> parse -> validate -> cache. Aggregates into
    the {table: {...}} overrides dict. NEVER raises: any failure returns ({}, note) and the caller keeps the
    untouched deterministic preview."""
    from .semantic import Registry
    reg = Registry(store.custom_types() if store is not None else ())
    overrides, used, calls = {}, [], 0
    try:
        for table in analysis.get("tables", []):
            if not table.get("usable") or not (table.get("cols") and table.get("raw")):
                continue
            sig = signature(table)
            cached = store.ai_template_get(sig) if store is not None else None
            if cached is not None:
                tmpl = cached
            else:
                tmpl = parse(_call(cfg, build_prompt(reg, table)))
                calls += 1
                if store is not None:
                    store.ai_template_put(sig, tmpl, cfg.ai_model)
            ov = to_overrides(tmpl, reg, table)
            if ov:
                overrides[table["table"]] = ov
                used.append(dict(table=table["table"], columns=[c for c in ov if not c.startswith("__")]))
    except Exception as e:
        return ({}, {"status": "error", "reason": f"{type(e).__name__}: {e}"[:200], "model": cfg.ai_model})
    if not overrides:
        return ({}, {"status": "skipped", "reason": "no usable template", "model": cfg.ai_model, "calls": calls})
    return (overrides, {"status": "applied", "model": cfg.ai_model, "calls": calls, "tables": used})
