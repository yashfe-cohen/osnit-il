"""Read a SQL dump (mysqldump / pg_dump / sqlite .dump) as tables of rows, without a database engine.

Parses CREATE TABLE for column names and INSERT INTO ... VALUES (...),(...) for rows. Tolerant of
quoting styles (backticks, double quotes, brackets) and escaped strings. Streaming over the text.
"""
import re

_CREATE = re.compile(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"\[]?(\w+)[`"\]]?\s*\((.*?)\)\s*(?:ENGINE|;|DEFAULT|$)',
                     re.I | re.S)
_COLDEF = re.compile(r'^\s*[`"\[]?(\w+)[`"\]]?\s+', re.M)
_INSERT = re.compile(r'INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?(\w+)[`"\]]?\s*(?:\(([^)]*)\))?\s*VALUES\s*', re.I)
_COLLIST = re.compile(r'[`"\[]?(\w+)[`"\]]?')


def _columns_from_create(body: str):
    cols = []
    for line in body.split(","):
        m = _COLDEF.match(line)
        if m:
            name = m.group(1)
            if name.upper() not in ("PRIMARY", "KEY", "UNIQUE", "CONSTRAINT", "INDEX", "FOREIGN", "CHECK"):
                cols.append(name)
    return cols


def _split_tuples(s, i):
    """From position i (just after VALUES), yield each (...) row's raw inner text until the statement ends."""
    n = len(s)
    while i < n:
        while i < n and s[i] in " \t\r\n,":
            i += 1
        if i >= n or s[i] != "(":
            return i
        i += 1
        start, depth, in_str, q, esc = i, 1, False, "", False
        while i < n and depth:
            c = s[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == q:
                    if i + 1 < n and s[i + 1] == q:   # doubled quote = literal
                        i += 1
                    else:
                        in_str = False
            elif c in "'\"":
                in_str, q = True, c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        yield s[start:i - 1]


def _split_fields(row: str):
    out, cur, in_str, q, esc, depth = [], [], False, "", False, 0
    for c in row:
        if in_str:
            if esc:
                cur.append(c); esc = False
            elif c == "\\":
                esc = True
            elif c == q:
                in_str = False
            else:
                cur.append(c)
        elif c in "'\"":
            in_str, q = True, c
        elif c == "," and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            cur.append(c)
    out.append("".join(cur))
    res = []
    for f in out:
        f = f.strip()
        res.append(None if f.upper() == "NULL" else f)
    return res


def read_sql_dump(text: str):
    """Yields (table_name, columns, rows_iter). Columns may be [] if neither CREATE nor INSERT named them."""
    schema = {}
    for m in _CREATE.finditer(text):
        schema[m.group(1)] = _columns_from_create(m.group(2))
    tables = {}
    for m in _INSERT.finditer(text):
        name = m.group(1)
        cols = _COLLIST.findall(m.group(2)) if m.group(2) else schema.get(name, [])
        rows = []
        for raw in _split_tuples(text, m.end()):
            vals = _split_fields(raw)
            if cols and len(cols) == len(vals):
                rows.append(dict(zip(cols, vals)))
            elif not cols:
                rows.append({f"col{i}": v for i, v in enumerate(vals)})
            else:
                rows.append({(cols[i] if i < len(cols) else f"col{i}"): v for i, v in enumerate(vals)})
        tables.setdefault(name, (cols, []))[1].extend(rows)
    for name, (cols, rows) in tables.items():
        yield name, cols or (list(rows[0].keys()) if rows else []), rows
