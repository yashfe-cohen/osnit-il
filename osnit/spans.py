"""Teach by example: the user wraps pieces of a raw value in markers (***יונתן חייט***, **0541234567**) and says what
each one is. From those examples we learn a rule that finds the same kind of piece in every other row — and in
later files with the same column — so a column that mixes several details becomes separate, typed fields.

A rule is learned with the most robust strategy the examples support:
  field    the piece is a whole field of the value when split by , | ; tab or " - " (same position every time)
  context  the piece follows the same words every time ("ת.ז:", "Name:") — the text right before it
  shape    the piece has a recognisable form (digits, an email, a code) and is found by its shape alone
"""
import re

MARK = re.compile(r"(\*{1,3}|\[\[)(.+?)(\1|\]\])", re.S)
SEP = re.compile(r"\s*(?:\||;|,|\t|\s-\s|\s–\s)\s*")


def parse_marked(text: str):
    """'name: ***יונתן חייט*** tel **0541234567**' -> (clean text, [(start, end, piece), ...]) in clean coordinates."""
    clean, spans, pos = [], [], 0
    for m in MARK.finditer(text):
        if m.group(1) == "[[" and m.group(3) != "]]":
            continue
        if m.group(1) != "[[" and m.group(3) != m.group(1):
            continue
        clean.append(text[pos:m.start()])
        start = sum(len(x) for x in clean)
        piece = m.group(2)
        clean.append(piece)
        spans.append((start, start + len(piece), piece))
        pos = m.end()
    clean.append(text[pos:])
    return "".join(clean), spans


def _fields(text):
    return [f.strip() for f in SEP.split(text)]


def _shape(piece: str) -> str:
    """A regex for 'things that look like this': letters generalise to any word, digit runs keep their length."""
    out = []
    for tok in re.findall(r"\d+|[^\W\d_]+|\s+|.", piece):
        if tok.isdigit():
            out.append(r"\d{%d}" % len(tok))
        elif tok.isspace():
            out.append(r"\s+")
        elif re.fullmatch(r"[^\W\d_]+", tok):
            out.append(r"[^\W\d_]{1,40}")
        else:
            out.append(re.escape(tok))
    return "".join(out)


def _merge_shapes(shapes):
    """Several examples: one alternative per distinct shape; digit runs widened to the seen range."""
    uniq = list(dict.fromkeys(shapes))
    return uniq[0] if len(uniq) == 1 else "(?:" + "|".join(uniq) + ")"


def _common_suffix(strs):
    if not strs:
        return ""
    s = strs[0]
    for t in strs[1:]:
        i = 0
        while i < min(len(s), len(t)) and s[-1 - i] == t[-1 - i]:
            i += 1
        s = s[len(s) - i:] if i else ""
    return s


def _label_context(before: str) -> str:
    """The label that introduces a piece: the text after the last separator, and of that only the part that
    names a field — 'X, ת.ז: ' -> 'ת.ז:' ; 'שם הלקוח: משה לוי טלפון ' -> 'טלפון'. Digits are never a label."""
    seg = re.split(r"[,;|\t]", before)[-1]
    seg = re.sub(r"\s+", " ", seg)
    if seg.rstrip().endswith(":"):                    # "label:" — keep the label words up to the previous colon
        lab = seg.rstrip()[:-1]
        lab = lab.split(":")[-1].strip()
        lab = " ".join(t for t in lab.split() if not re.search(r"\d", t))
        return (lab + ":") if lab else ""
    toks = [t for t in seg.split() if t]
    if toks and not re.search(r"\d", toks[-1]):
        return toks[-1]
    return ""


def learn(examples):
    """examples: [{"text": clean value, "start": int, "end": int}] for ONE column and ONE type -> rule dict."""
    exs = [e for e in examples if 0 <= e["start"] < e["end"] <= len(e["text"])]
    if not exs:
        return None
    pieces = [e["text"][e["start"]:e["end"]].strip() for e in exs]
    # 1) a whole field at the same index every time
    idx = set()
    for e, p in zip(exs, pieces):
        fs = _fields(e["text"])
        idx.add(fs.index(p) if p in fs and len(fs) > 1 else -1)
    if len(idx) == 1 and -1 not in idx:
        return dict(strategy="field", index=idx.pop(), shape=_merge_shapes([_shape(p) for p in pieces]))
    # 2) the same label just before it ("ת.ז:", "טלפון", "Name:") — never the variable data before the label
    befores = [_label_context(e["text"][max(0, e["start"] - 40):e["start"]]) for e in exs]
    ctx = _common_suffix(befores).lstrip() if all(befores) else ""
    shape = _merge_shapes([_shape(p) for p in pieces])
    distinctive = bool(re.search(r"\\d|@|\\\.|\\-", shape))
    labelled = ctx.rstrip().endswith(":")
    if len(ctx.strip(" :-–")) >= 2 and (labelled or not distinctive):
        return dict(strategy="context", context=ctx, shape=shape)
    # 3) its own shape (only safe when the shape is distinctive, i.e. contains digits / @ / punctuation)
    return dict(strategy="shape", shape=shape, distinctive=distinctive)


def apply(rule, text):
    """All pieces of `text` the rule finds."""
    if not rule or text is None:
        return []
    text = str(text)
    if rule["strategy"] == "field":
        fs = _fields(text)
        i = rule["index"]
        return [fs[i]] if i < len(fs) and fs[i] else []
    if rule["strategy"] == "context":
        ctx = re.escape(rule["context"].strip()).replace(r"\ ", r"\s+")
        return [m.group(1).strip() for m in re.finditer(ctx + r"\s*(" + rule["shape"] + r")(?![\w])", text)]
    if rule["strategy"] == "shape" and rule.get("distinctive"):
        return [m.group(0).strip() for m in re.finditer(r"(?<![\w])" + rule["shape"] + r"(?![\w])", text)]
    return []


def virtual_name(col, label):
    return f"{col} ▸ {label}"


def augment(row, rules):
    """Add one virtual column per rule to a row: '<column> ▸ <label>' -> the pieces found (joined with '; ')."""
    if not rules:
        return row
    row = dict(row)
    for r in rules:
        found = apply(r["rule"], row.get(r["col"]))
        row[virtual_name(r["col"], r["label"])] = "; ".join(dict.fromkeys(found)) if found else None
    return row
