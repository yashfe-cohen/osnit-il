r"""
osnit.sql_parser: State-Machine SQL dump parser & deep cell unpacker (v2.0).
Supports:
1. State-machine tracking of CREATE TABLE -> INSERT column bindings across thousands of lines.
2. Dialects: MySQL / MariaDB (multi-row inserts), PostgreSQL (COPY ... FROM stdin; \.), SQL Server ([dbo].[table]), SQLite.
3. Escaping & Hex literals: \' \" \\ \r \n \t 0x... X'...' NULL \N.
4. Automatic encoding fallbacks (UTF-8, windows-1255, iso-8859-8, cp862, latin-1).
5. Deep Cell Unpacking: JSON ({...}, [...]), PHP Serialize (a:N:{...}), and Query Strings (k=v&k2=v2).
6. Automatic Key-Value table pivot (wp_usermeta, wp_postmeta).
"""
import binascii
import json
import logging
import os
import re
import urllib.parse
from collections import defaultdict
from itertools import chain
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("osnit.sql_parser")

# Regex patterns for CREATE TABLE and dialects
_CREATE_TABLE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'(?:[`"\[]?(\w+)[`"\]]?\.)?[`"\[]?(\w+)[`"\]]?\s*\((.*?)\)\s*'
    r'(?:ENGINE|DEFAULT|COLLATE|CHARACTER\s+SET|ROW_FORMAT|AUTO_INCREMENT|;|#|\n|$)',
    re.I | re.S
)

_INSERT_RE = re.compile(
    r'(?:INSERT|REPLACE)\s+(?:IGNORE\s+|LOW_PRIORITY\s+|DELAYED\s+)?(?:INTO\s+)?'
    r'(?:[`"\[]?(\w+)[`"\]]?\.)?[`"\[]?(\w+)[`"\]]?\s*(?:\(([^)]*)\))?\s*VALUES\s*',
    re.I
)

_COPY_RE = re.compile(
    r'COPY\s+(?:[`"\[]?(\w+)[`"\]]?\.)?[`"\[]?(\w+)[`"\]]?\s*'
    r'(?:\(([^)]*)\))?\s*FROM\s+(?:stdin|\'stdin\')(?:\s+WITH\s*\(?[^;)]*\)?)?\s*;',
    re.I
)

_COL_NAME_RE = re.compile(r'[`"\[]?(\w+)[`"\]]?')
_COL_DEF_RE = re.compile(r'^\s*[`"\[]?(\w+)[`"\]]?\s+([A-Za-z0-9_]+)', re.M)

# ----------------------------------------------------------------------
# 1. PHP Unserialize & Deep Cell Unpacking
# ----------------------------------------------------------------------

def parse_php_serialized(s: str) -> Tuple[Optional[Any], int]:
    """
    Safely parses a PHP serialized string into native Python types.
    Returns (parsed_value, consumed_characters).
    Handles a:N:{...}, s:N:"...", i:N;, d:N;, b:N;, N;, O:N:"class":N:{...}
    Tolerates character/byte count mismatches caused by UTF-8 Hebrew characters.
    """
    if not s or len(s) < 2:
        return None, 0

    code = s[0]
    colon1 = s.find(":", 1) if code in ("a", "s", "i", "d", "b", "O") else -1

    if code == "N" and s.startswith("N;"):
        return None, 2

    if code in ("i", "d", "b") and colon1 != -1:
        semi = s.find(";", colon1 + 1)
        if semi == -1:
            return None, 0
        raw_val = s[colon1 + 1:semi]
        if code == "i":
            try:
                return int(raw_val), semi + 1
            except ValueError:
                return None, 0
        elif code == "d":
            try:
                return float(raw_val), semi + 1
            except ValueError:
                return None, 0
        elif code == "b":
            return (raw_val == "1"), semi + 1

    if code == "s" and colon1 != -1:
        quote_start = s.find('"', colon1 + 1)
        if quote_start == -1:
            return None, 0
        try:
            expected_len = int(s[colon1 + 1:quote_start - 1])
        except ValueError:
            expected_len = -1

        # Locate closing quote followed by semicolon (";)
        idx = quote_start + 1
        found_end = -1
        while idx < len(s):
            close_quote = s.find('"', idx)
            if close_quote == -1:
                break
            # Check if this quote is escaped
            backslashes = 0
            k = close_quote - 1
            while k >= quote_start + 1 and s[k] == '\\':
                backslashes += 1
                k -= 1
            if backslashes % 2 == 0:
                if close_quote + 1 < len(s) and s[close_quote + 1] in (';', '}'):
                    found_end = close_quote
                    break
            idx = close_quote + 1

        if found_end != -1:
            content = s[quote_start + 1:found_end]
            next_idx = found_end + 1
            if next_idx < len(s) and s[next_idx] == ';':
                next_idx += 1
            return content, next_idx
        return None, 0

    if code == "a" and colon1 != -1:
        brace_open = s.find("{", colon1 + 1)
        if brace_open == -1:
            return None, 0
        try:
            count = int(s[colon1 + 1:brace_open - 1])
        except ValueError:
            count = 0

        res_dict = {}
        curr = brace_open + 1
        n = len(s)
        items_read = 0

        while curr < n and s[curr] != "}":
            # Skip whitespace
            while curr < n and s[curr] in " \t\r\n":
                curr += 1
            if curr >= n or s[curr] == "}":
                break

            # Read key
            key, adv_k = parse_php_serialized(s[curr:])
            if adv_k == 0:
                break
            curr += adv_k

            # Read val
            val, adv_v = parse_php_serialized(s[curr:])
            if adv_v == 0:
                break
            curr += adv_v

            if key is not None:
                res_dict[str(key)] = val
            items_read += 1

        if curr < n and s[curr] == "}":
            curr += 1
            if curr < n and s[curr] == ';':
                curr += 1
            return res_dict, curr
        return res_dict, curr

    if code == "O" and colon1 != -1:
        # Object format: O:8:"stdClass":1:{s:4:"prop";s:3:"val";}
        brace_open = s.find("{", colon1 + 1)
        if brace_open == -1:
            return None, 0
        # Parse inner body like an array
        dummy_array = "a:" + s[s.rfind(":", 0, brace_open) + 1:brace_open] + "{" + s[brace_open + 1:]
        val, adv = parse_php_serialized(dummy_array)
        if adv > 0:
            return val, brace_open + adv - 2
        return None, 0

    return None, 0


def flatten_nested(data: Any, prefix: str = "", max_depth: int = 4) -> Dict[str, Any]:
    """Recursively flattens dicts and lists into single-level key-value mappings."""
    out = {}
    if max_depth <= 0:
        if prefix:
            out[prefix] = str(data)
        return out

    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(flatten_nested(v, full_key, max_depth - 1))
            else:
                out[full_key] = v
    elif isinstance(data, list):
        for i, item in enumerate(data):
            full_key = f"{prefix}[{i}]" if prefix else f"[{i}]"
            if isinstance(item, (dict, list)):
                out.update(flatten_nested(item, full_key, max_depth - 1))
            else:
                out[full_key] = item
    else:
        if prefix:
            out[prefix] = data
    return out


def unpack_cell_value(val: Any) -> Optional[Dict[str, Any]]:
    """
    Detects and unpacks JSON, PHP Serialize, or URL-encoded query strings inside a table cell.
    Returns flattened dictionary of child fields, or None if not serialized.
    """
    if not isinstance(val, str) or len(val) < 4:
        return None

    s = val.strip()

    # 1. JSON check: {...} or [...]
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict, list)) and parsed:
                return flatten_nested(parsed)
        except (ValueError, TypeError):
            pass

    # 2. PHP Serialized check: a:N:{...} or O:N:"...":N:{...}
    if s.startswith(("a:", "O:")) and "{" in s and s.endswith("}"):
        try:
            parsed, adv = parse_php_serialized(s)
            if isinstance(parsed, dict) and parsed and adv > 0:
                return flatten_nested(parsed)
        except Exception:
            pass

    # 3. Query string check: key=val&key2=val2
    if "=" in s and "&" in s and not s.startswith(("http://", "https://", "ftp://")):
        try:
            # Must look like param=val&param2=val2 without whitespace
            if "\n" not in s and " " not in s and s.count("=") >= 2:
                parsed = urllib.parse.parse_qs(s, keep_blank_values=True)
                if parsed and len(parsed) >= 2:
                    flat = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                    return flat
        except Exception:
            pass

    return None


def unpack_row_cells(row: Dict[str, Any], max_unpacked_cols: int = 50) -> Dict[str, Any]:
    """
    Enriches a row by unpacking any serialized JSON/PHP cells into virtual columns.
    Original columns are preserved.
    """
    unpacked_cols = {}
    for col_name, val in list(row.items()):
        if isinstance(val, str) and len(val) >= 4:
            nested = unpack_cell_value(val)
            if nested:
                for sub_key, sub_val in nested.items():
                    if len(unpacked_cols) >= max_unpacked_cols:
                        break
                    target_name = f"{col_name}.{sub_key}" if not sub_key.startswith("[") else f"{col_name}{sub_key}"
                    unpacked_cols[target_name] = sub_val

    if unpacked_cols:
        new_row = dict(row)
        new_row.update(unpacked_cols)
        return new_row
    return row


# ----------------------------------------------------------------------
# 2. Key-Value Meta Table Pivot (wp_usermeta, wp_postmeta)
# ----------------------------------------------------------------------

_META_ID_COLS = {"user_id", "customer_id", "client_id", "post_id", "entity_id", "member_id", "account_id"}
_META_KEY_COLS = {"meta_key", "key", "name", "field_name", "meta_name"}
_META_VAL_COLS = {"meta_value", "value", "val", "field_value"}


def detect_key_value_table(cols: List[str], table_name: str = "") -> Optional[Tuple[str, str, str]]:
    """
    Returns (id_col, key_col, val_col) if the table has a key-value meta structure like wp_usermeta.
    """
    cols_lower = [c.lower() for c in cols]
    id_col = None
    key_col = None
    val_col = None

    for c, cl in zip(cols, cols_lower):
        if cl in _META_ID_COLS and id_col is None:
            id_col = c
        elif cl in _META_KEY_COLS and key_col is None:
            key_col = c
        elif cl in _META_VAL_COLS and val_col is None:
            val_col = c

    if id_col and key_col and val_col:
        return id_col, key_col, val_col

    # Fallback by table name
    if "meta" in table_name.lower():
        for c in cols:
            if c.lower().endswith("_id") and id_col is None:
                id_col = c
            elif "key" in c.lower() and key_col is None:
                key_col = c
            elif "val" in c.lower() and val_col is None:
                val_col = c
        if id_col and key_col and val_col:
            return id_col, key_col, val_col

    return None


def pivot_key_value_rows(
    rows: Iterable[Dict[str, Any]],
    id_col: str,
    key_col: str,
    val_col: str,
    max_cached_ids: int = 50000
) -> Generator[Dict[str, Any], None, None]:
    """
    Groups rows by id_col and pivots key_col -> val_col into columns of that record.
    Unpacks nested values inside val_col automatically.
    """
    pivoted_records: Dict[Any, Dict[str, Any]] = defaultdict(dict)
    seen_order = []

    for r in rows:
        uid = r.get(id_col)
        if uid is None:
            continue

        if uid not in pivoted_records:
            pivoted_records[uid][id_col] = uid
            seen_order.append(uid)

        k = str(r.get(key_col) or "").strip()
        v = r.get(val_col)

        if k:
            pivoted_records[uid][k] = v
            # Unpack serialized value if applicable
            nested = unpack_cell_value(v)
            if nested:
                for sub_k, sub_v in nested.items():
                    pivoted_records[uid][f"{k}.{sub_k}"] = sub_v

        # Flush if cache exceeds limit
        if len(seen_order) >= max_cached_ids:
            for entity_id in seen_order:
                yield pivoted_records.pop(entity_id)
            seen_order.clear()

    for entity_id in seen_order:
        if entity_id in pivoted_records:
            yield pivoted_records.pop(entity_id)


# ----------------------------------------------------------------------
# 3. SQL Unescaping & Field/Tuple Splitting
# ----------------------------------------------------------------------

def _unescape_hex(s: str) -> str:
    """Decodes hex literals like 0x616263 or X'616263' to string."""
    try:
        raw_hex = s[2:] if s.startswith(("0x", "0X")) else s[2:-1]
        raw_bytes = binascii.unhexlify(raw_hex)
        for enc in ("utf-8", "windows-1255", "iso-8859-8", "latin-1"):
            try:
                return raw_bytes.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw_hex
    except Exception:
        return s


def split_fields(row: str) -> List[Optional[str]]:
    """Splits a single tuple '(val1, val2, ...)' into raw values with full SQL unescaping."""
    out = []
    cur = []
    in_str = False
    quote_char = ""
    esc = False
    depth = 0

    for c in row:
        if in_str:
            if esc:
                if c == "n":
                    cur.append("\n")
                elif c == "r":
                    cur.append("\r")
                elif c == "t":
                    cur.append("\t")
                elif c == "0":
                    cur.append("\0")
                elif c == "Z":
                    cur.append("\x1a")
                else:
                    cur.append(c)
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote_char:
                in_str = False
            else:
                cur.append(c)
        elif c in ("'", '"'):
            in_str = True
            quote_char = c
        elif c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            cur.append(c)

    out.append("".join(cur))

    res = []
    for f in out:
        f_strip = f.strip()
        f_upper = f_strip.upper()
        if f_upper in ("NULL", r"\N") or f_strip == "":
            res.append(None)
        elif f_strip.startswith(("0x", "0X")) and len(f_strip) > 2 and re.fullmatch(r"0[xX][0-9a-fA-F]+", f_strip):
            res.append(_unescape_hex(f_strip))
        elif f_strip.upper().startswith("X'") and f_strip.endswith("'"):
            res.append(_unescape_hex(f_strip))
        else:
            res.append(f_strip)
    return res


def split_tuples(s: str, start_pos: int) -> Generator[str, None, int]:
    """Yields each (...) row's raw inner text from start_pos until statement ends."""
    n = len(s)
    i = start_pos
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
                    if i + 1 < n and s[i + 1] == q:  # doubled quote ''
                        i += 1
                    else:
                        in_str = False
            elif c in ("'", '"'):
                in_str, q = True, c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        yield s[start:i - 1]
    return i


def columns_from_create(body: str) -> List[str]:
    """Extracts column names from CREATE TABLE body."""
    cols = []
    for line in body.split(","):
        line_clean = line.strip()
        m = _COL_DEF_RE.match(line_clean)
        if m:
            name = m.group(1)
            if name.upper() not in ("PRIMARY", "KEY", "UNIQUE", "CONSTRAINT", "INDEX", "FOREIGN", "CHECK", "FULLTEXT", "SPATIAL"):
                cols.append(name)
    return cols


def find_table_pk(table_name: str, cols: List[str]) -> Optional[str]:
    """Finds primary key column in table by common conventions."""
    cols_lower = [str(c).lower() for c in cols]
    tbl = str(table_name).lower()
    tbl_sing = tbl[:-1] if tbl.endswith("s") else tbl
    for cand in ("id", f"{tbl}_id", f"{tbl_sing}_id", "pk", "uid"):
        if cand in cols_lower:
            return cols[cols_lower.index(cand)]
    return None


def find_row_foreign_keys(rec: dict, table_name: str = "") -> List[Tuple[str, str, List[str]]]:
    """
    Returns list of (fk_column, fk_value, candidate_parent_tables).
    E.g. ('user_id', '504', ['users', 'user', 'customers', 'clients', 'members', 'accounts', 'people'])
    """
    out = []
    tbl_lower = str(table_name).lower()
    for col, val in rec.items():
        if val is None:
            continue
        v_str = str(val).strip()
        if not v_str or v_str in ("0", "NULL", r"\N", "None", "-1"):
            continue
        c_lower = str(col).lower()
        if c_lower in ("id", f"{tbl_lower}_id"):
            continue
        if c_lower in ("user_id", "id_user", "uid"):
            out.append((col, v_str, ["users", "user", "app_users", "wp_users", "tbl_users", "customers", "clients"]))
        elif c_lower in ("customer_id", "id_customer", "cust_id"):
            out.append((col, v_str, ["customers", "customer", "clients", "client", "users", "user"]))
        elif c_lower in ("client_id", "id_client"):
            out.append((col, v_str, ["clients", "client", "customers", "customer", "users", "user"]))
        elif c_lower in ("member_id", "id_member"):
            out.append((col, v_str, ["members", "member", "users", "user"]))
        elif c_lower in ("account_id", "id_account"):
            out.append((col, v_str, ["accounts", "account", "users", "user"]))
        elif c_lower in ("person_id", "contact_id"):
            out.append((col, v_str, ["people", "person", "contacts", "contact", "users", "user"]))
        elif c_lower.endswith("_id") and len(c_lower) > 3:
            parent = c_lower[:-3]
            out.append((col, v_str, [parent, parent + "s", "users", "customers"]))
    return out


def find_foreign_keys(table_name: str, columns: List[str]) -> Dict[str, Tuple[str, str]]:
    """Identifies foreign key columns in a table and their likely parent tables."""
    fks = {}
    tbl = str(table_name).lower()
    for col in columns:
        c_lower = str(col).lower()
        if c_lower in ("id", f"{tbl}_id"):
            continue
        if c_lower in ("user_id", "id_user", "uid"):
            fks[col] = ("users", "id")
        elif c_lower in ("customer_id", "id_customer", "cust_id"):
            fks[col] = ("customers", "id")
        elif c_lower in ("client_id", "id_client"):
            fks[col] = ("clients", "id")
        elif c_lower in ("member_id", "id_member"):
            fks[col] = ("members", "id")
        elif c_lower in ("account_id", "id_account"):
            fks[col] = ("accounts", "id")
        elif c_lower in ("person_id", "contact_id"):
            fks[col] = ("people", "id")
        elif c_lower.endswith("_id") and len(c_lower) > 3:
            parent = c_lower[:-3]
            fks[col] = (parent + "s", "id")
    return fks


# ----------------------------------------------------------------------
# 4. State Machine Parser
# ----------------------------------------------------------------------

class SQLStateMachineParser:
    """
    Maintains active schemas across statements and streams tables and rows.
    Tracks primary keys and foreign keys for cross-table relational joins.
    """
    def __init__(self, unpack_cells: bool = True, pivot_meta: bool = True):
        self.schemas: Dict[str, List[str]] = {}
        self.primary_keys: Dict[str, str] = {}
        self.foreign_keys: Dict[str, Dict[str, Tuple[str, str]]] = {}
        self.unpack_cells = unpack_cells
        self.pivot_meta = pivot_meta

    def register_create(self, table_name: str, body: str) -> List[str]:
        cols = columns_from_create(body)
        self.schemas[table_name] = cols

        # Extract primary key
        pk_m = re.search(r"PRIMARY\s+KEY\s*\(\s*[`\"\[]?(\w+)[`\"\]]?\s*\)", body, re.IGNORECASE)
        if pk_m:
            self.primary_keys[table_name] = pk_m.group(1)
        else:
            pk = find_table_pk(table_name, cols)
            if pk:
                self.primary_keys[table_name] = pk

        # Extract foreign keys from DDL
        fk_matches = re.findall(
            r"FOREIGN\s+KEY\s*\(\s*[`\"\[]?(\w+)[`\"\]]?\s*\)\s*REFERENCES\s*[`\"\[]?(\w+)[`\"\]]?\s*\(\s*[`\"\[]?(\w+)[`\"\]]?\s*\)",
            body, re.IGNORECASE
        )
        if fk_matches:
            self.foreign_keys.setdefault(table_name, {})
            for fk_col, ref_table, ref_col in fk_matches:
                self.foreign_keys[table_name][fk_col] = (ref_table, ref_col)

        # Also include heuristic FKs for this table
        heuristics = find_foreign_keys(table_name, cols)
        if heuristics:
            self.foreign_keys.setdefault(table_name, {})
            for fk_c, target in heuristics.items():
                if fk_c not in self.foreign_keys[table_name]:
                    self.foreign_keys[table_name][fk_c] = target

        return cols

    def parse_insert_statement(self, stmt: str) -> Tuple[Optional[str], List[str], List[Dict[str, Any]]]:
        m = _INSERT_RE.search(stmt)
        if not m:
            return None, [], []

        table_name = m.group(2) or m.group(1)
        raw_cols = m.group(3)

        if raw_cols:
            cols = _COL_NAME_RE.findall(raw_cols)
        else:
            cols = self.schemas.get(table_name, [])

        rows = []
        for raw_tuple in split_tuples(stmt, m.end()):
            vals = split_fields(raw_tuple)
            if cols and len(cols) == len(vals):
                row = dict(zip(cols, vals))
            elif not cols:
                row = {f"col{i}": v for i, v in enumerate(vals)}
            else:
                row = {(cols[i] if i < len(cols) else f"col{i}"): v for i, v in enumerate(vals)}

            if self.unpack_cells:
                row = unpack_row_cells(row)
            rows.append(row)

        final_cols = cols or (list(rows[0].keys()) if rows else [])
        return table_name, final_cols, rows

    def parse_copy_block(self, lines: List[str], header_match) -> Tuple[str, List[str], List[Dict[str, Any]]]:
        table_name = header_match.group(2) or header_match.group(1)
        raw_cols = header_match.group(3)
        cols = _COL_NAME_RE.findall(raw_cols) if raw_cols else self.schemas.get(table_name, [])

        rows = []
        for line in lines:
            line_clean = line.strip("\r\n")
            if not line_clean.strip() or line_clean.strip() == r"\.":
                continue
            parts = line_clean.split("\t")
            vals = [None if p.strip() == r"\N" else p.strip() for p in parts]
            if cols and len(cols) == len(vals):
                row = dict(zip(cols, vals))
            elif not cols:
                row = {f"col{i}": v for i, v in enumerate(vals)}
            else:
                row = {(cols[i] if i < len(cols) else f"col{i}"): v for i, v in enumerate(vals)}

            if self.unpack_cells:
                row = unpack_row_cells(row)
            rows.append(row)

        final_cols = cols or (list(rows[0].keys()) if rows else [])
        return table_name, final_cols, rows


# ----------------------------------------------------------------------
# 5. Public API: read_sql_dump & stream_sql_dump
# ----------------------------------------------------------------------

def _iter_statements(path: str, encoding: str = "utf-8") -> Generator[str, None, None]:
    """Yields complete SQL statements from a file stream."""
    buf = []
    in_copy = False
    with open(path, encoding=encoding, errors="replace") as f:
        for line in f:
            s = line.strip()
            if not in_copy and not buf and (not s or s.startswith("--") or (s.startswith("/*") and s.endswith("*/;"))):
                continue

            buf.append(line)

            if not in_copy and _COPY_RE.search(line):
                in_copy = True
                continue

            if in_copy:
                if s == r"\.":
                    in_copy = False
                    yield "".join(buf)
                    buf = []
                continue

            if s.endswith(";"):
                yield "".join(buf)
                buf = []

        if buf:
            yield "".join(buf)


def stream_sql_dump(
    path: str,
    encoding: str = "utf-8",
    pivot_meta: bool = True,
    unpack_cells: bool = True
) -> Generator[Tuple[str, List[str], Iterable[Dict[str, Any]]], None, None]:
    """
    Streaming generator over SQL dump files of any size.
    Yields (table_name, column_names, rows_generator) lazily in file order.
    """
    parser = SQLStateMachineParser(unpack_cells=unpack_cells, pivot_meta=pivot_meta)
    stmts = _iter_statements(path, encoding)

    def next_action():
        for st in stmts:
            head = st.lstrip()[:40].upper()
            if head.startswith("CREATE TABLE"):
                m = _CREATE_TABLE_RE.search(st)
                if m:
                    tname = m.group(2) or m.group(1)
                    parser.register_create(tname, m.group(3))
            elif head.startswith(("INSERT", "REPLACE")):
                m = _INSERT_RE.search(st)
                if m:
                    tname = m.group(2) or m.group(1)
                    return ("INSERT", tname, st)
            elif head.startswith("COPY"):
                m = _COPY_RE.search(st)
                if m:
                    tname = m.group(2) or m.group(1)
                    return ("COPY", tname, st)
        return (None, None, None)

    kind, name, st = next_action()
    while name:
        table = name
        first_kind, first_st = kind, st
        state = {"next": None}

        def raw_rows_gen(t=table, fkind=first_kind, fst=first_st, s=state):
            if fkind == "INSERT":
                _, _, r_batch = parser.parse_insert_statement(fst)
                yield from r_batch
            elif fkind == "COPY":
                lines = fst.splitlines()
                m = _COPY_RE.search(lines[0])
                if m:
                    _, _, r_batch = parser.parse_copy_block(lines[1:], m)
                    yield from r_batch

            while True:
                k2, n2, s2 = next_action()
                if n2 != t:
                    s["next"] = (k2, n2, s2)
                    return
                if k2 == "INSERT":
                    _, _, r_batch = parser.parse_insert_statement(s2)
                    yield from r_batch
                elif k2 == "COPY":
                    lines = s2.splitlines()
                    m = _COPY_RE.search(lines[0])
                    if m:
                        _, _, r_batch = parser.parse_copy_block(lines[1:], m)
                        yield from r_batch

        gen = raw_rows_gen()
        head_row = next(gen, None)
        base_cols = parser.schemas.get(table) or (list(head_row.keys()) if head_row else [])

        if head_row is None:
            yield table, base_cols, iter(())
            kind, name, st = state["next"] or (None, None, None)
            continue

        full_gen = chain([head_row], gen)

        # Check for key-value meta table pivot (wp_usermeta)
        meta_spec = detect_key_value_table(base_cols, table) if pivot_meta else None
        if meta_spec:
            id_col, key_col, val_col = meta_spec
            pivoted_iter = pivot_key_value_rows(full_gen, id_col, key_col, val_col)
            first_piv = next(pivoted_iter, None)
            piv_cols = list(first_piv.keys()) if first_piv else base_cols
            yield table, piv_cols, (chain([first_piv], pivoted_iter) if first_piv else iter(()))
        else:
            yield table, base_cols, full_gen

        # Drain if partially read
        for _ in gen:
            pass
        kind, name, st = state["next"] or (None, None, None)


def read_sql_dump(
    text: str,
    pivot_meta: bool = True,
    unpack_cells: bool = True
) -> Generator[Tuple[str, List[str], List[Dict[str, Any]]], None, None]:
    """
    In-memory parser for SQL dumps, returning (table, columns, rows_list).
    """
    parser = SQLStateMachineParser(unpack_cells=unpack_cells, pivot_meta=pivot_meta)

    # 1. Register all CREATE TABLE schemas
    for m in _CREATE_TABLE_RE.finditer(text):
        tname = m.group(2) or m.group(1)
        parser.register_create(tname, m.group(3))

    tables: Dict[str, Tuple[List[str], List[Dict[str, Any]]]] = {}

    # 2. Parse INSERT statements
    for m in _INSERT_RE.finditer(text):
        tname = m.group(2) or m.group(1)
        raw_cols = m.group(3)
        cols = _COL_NAME_RE.findall(raw_cols) if raw_cols else parser.schemas.get(tname, [])
        rows = []
        for raw_tuple in split_tuples(text, m.end()):
            vals = split_fields(raw_tuple)
            if cols and len(cols) == len(vals):
                row = dict(zip(cols, vals))
            elif not cols:
                row = {f"col{i}": v for i, v in enumerate(vals)}
            else:
                row = {(cols[i] if i < len(cols) else f"col{i}"): v for i, v in enumerate(vals)}
            if unpack_cells:
                row = unpack_row_cells(row)
            rows.append(row)

        curr_cols, curr_rows = tables.setdefault(tname, (cols, []))
        if not curr_cols and cols:
            tables[tname] = (cols, curr_rows)
        curr_rows.extend(rows)

    # 3. Parse PostgreSQL COPY statements
    for m in _COPY_RE.finditer(text):
        tname = m.group(2) or m.group(1)
        start_idx = m.end()
        end_idx = text.find(r"\.", start_idx)
        if end_idx != -1:
            body = text[start_idx:end_idx]
            lines = [ln.strip("\r\n") for ln in body.splitlines() if ln.strip("\r\n")]
            _, cols, rows = parser.parse_copy_block(lines, m)
            curr_cols, curr_rows = tables.setdefault(tname, (cols, []))
            if not curr_cols and cols:
                tables[tname] = (cols, curr_rows)
            curr_rows.extend(rows)

    for name, (cols, rows) in tables.items():
        base_cols = cols or (list(rows[0].keys()) if rows else [])
        meta_spec = detect_key_value_table(base_cols, name) if pivot_meta else None
        if meta_spec and rows:
            id_col, key_col, val_col = meta_spec
            pivoted = list(pivot_key_value_rows(rows, id_col, key_col, val_col))
            piv_cols = list(pivoted[0].keys()) if pivoted else base_cols
            yield name, piv_cols, pivoted
        else:
            yield name, base_cols, rows
