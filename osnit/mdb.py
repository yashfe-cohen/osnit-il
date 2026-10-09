"""Read Microsoft Access databases — .mdb (Jet 3 / Jet 4) and .accdb (ACE 2007…2016) — with the standard library
only, so an Access file imports like any other database: no driver, no ODBC, no install.

The file is a sequence of fixed-size pages. Page 0 is the header (partly RC4-masked); MSysObjects (its table
definition is always page 2) lists the tables; each table has a definition page chain ("TDEF": columns, types,
offsets) and data pages that point back to it. Rows are cracked from the end of the page: a null mask, a table
of variable-length column offsets, then the fixed columns from the start. Long text/memo/OLE values live in
LVAL pages (inline, one page, or a page chain). The file is read page by page — never loaded whole.

Deep reading (access_tables): an Access file is relational. A "fact" table with no identity of its own (orders,
calls, payments…) points at a person/org table by a foreign key — from MSysRelationships, or a column named
like the parent's key. Its rows are given the parent's identity columns ('<parent>.<column>'), so every order
links to the customer who made it, not just to itself.
"""
import os
import struct
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

MAGIC = (b"Standard Jet DB", b"Standard ACE DB")
EXTS = (".mdb", ".accdb", ".mde", ".accde")

# column types
BOOL, BYTE, INT, LONG, MONEY, FLOAT, DOUBLE, DATETIME, BINARY, TEXT, OLE, MEMO = range(1, 13)
GUID, NUMERIC, COMPLEX, BIGINT = 15, 16, 18, 19
TYPE_NAMES = {BOOL: "BOOLEAN", BYTE: "BYTE", INT: "INT", LONG: "LONG", MONEY: "MONEY", FLOAT: "FLOAT",
              DOUBLE: "DOUBLE", DATETIME: "SHORT_DATE_TIME", BINARY: "BINARY", TEXT: "TEXT", OLE: "OLE",
              MEMO: "MEMO", GUID: "GUID", NUMERIC: "NUMERIC", COMPLEX: "COMPLEX_TYPE", BIGINT: "BIG_INT"}
EPOCH = datetime(1899, 12, 30)
CODEPAGES = {1255: "cp1255", 1252: "cp1252", 1251: "cp1251", 1256: "cp1256", 1250: "cp1250", 1253: "cp1253",
             1254: "cp1254", 1257: "cp1257", 874: "cp874", 932: "cp932", 936: "gbk", 949: "cp949", 950: "cp950"}


class AccessError(Exception):
    pass


def is_access(path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(19)[4:19] in MAGIC
    except OSError:
        return False


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out, i, j = bytearray(len(data)), 0, 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


class Column:
    __slots__ = ("name", "type", "num", "var_idx", "fixed_off", "size", "flags", "scale", "prec")

    @property
    def fixed(self):
        return bool(self.flags & 0x01)

    @property
    def autonumber(self):
        return bool(self.flags & 0x04)


class Table:
    def __init__(self, name, tdef_pg, cols, num_rows, num_var):
        self.name, self.tdef_pg, self.num_rows, self.num_var = name, tdef_pg, num_rows, num_var
        self.columns = cols                                   # in column-number order
        self.fixed_cols = [c for c in cols if c.fixed]
        self.var_cols = [c for c in cols if not c.fixed]


class AccessDB:
    """One open Access file. Pages are read on demand (a small cache), so memory stays flat for a 2 GB file."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        head = self.f.read(4096)
        if head[4:19] not in MAGIC:
            self.f.close()
            raise AccessError("not an Access database")
        self.jet3 = head[0x14] == 0
        self.ps = 2048 if self.jet3 else 4096
        hdr = bytearray(head[:self.ps])
        n = 126 if self.jet3 else 128
        hdr[0x18:0x18 + n] = _rc4(b"\xc7\xda\x39\x6b", bytes(hdr[0x18:0x18 + n]))
        cp = struct.unpack_from("<H", hdr, 0x3C)[0]
        self.codepage = CODEPAGES.get(cp, "cp1252")
        self.key = struct.unpack_from("<I", hdr, 0x3E)[0]     # Jet "encoding": pages are RC4'd with key ^ page
        self.pages = max(1, os.path.getsize(path) // self.ps)
        self._cache, self._data_pages = {}, None
        self.version = {0: "Jet 3 (Access 97)", 1: "Jet 4 (Access 2000-2003)", 2: "ACE 12 (Access 2007)",
                        3: "ACE 14 (Access 2010)", 4: "ACE 15 (Access 2013)", 5: "ACE 16 (Access 2016+)"
                        }.get(head[0x14], f"version {head[0x14]}")
        try:
            self._tables = self._catalog()
        except (AccessError, struct.error, IndexError, UnicodeDecodeError) as e:
            self.f.close()
            raise AccessError(f"cannot read the table catalogue (encrypted or damaged file?): {e}") from e

    # ------------------------------------------------------------ pages
    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def page(self, n) -> bytes:
        b = self._cache.get(n)
        if b is None:
            self.f.seek(n * self.ps)
            b = self.f.read(self.ps)
            if len(b) < self.ps:
                raise AccessError(f"page {n} is beyond the end of the file")
            if n and self.key:
                b = _rc4(struct.pack("<I", self.key ^ n), b)
            if len(self._cache) > 512:
                self._cache.clear()
            self._cache[n] = b
        return b

    def _row_bounds(self, b, i):
        """(start, end, flags) of row i on a data page."""
        nrow_off, base = (8, 10) if self.jet3 else (12, 14)
        n = struct.unpack_from("<H", b, nrow_off)[0]
        if i >= n:
            raise AccessError("row pointer past the page's rows")
        off = struct.unpack_from("<H", b, base + 2 * i)[0]
        end = self.ps if i == 0 else struct.unpack_from("<H", b, base + 2 * (i - 1))[0] & 0x1FFF
        return off & 0x1FFF, end, off & 0xE000

    def _data_pages_of(self, tdef_pg):
        """Data pages per table, found in ONE pass over the page headers (no usage maps needed)."""
        if self._data_pages is None:
            by = {}
            self.f.seek(0)
            chunk = self.ps * 256
            pg = 0
            while True:
                buf = self.f.read(chunk)
                if not buf:
                    break
                for k in range(0, len(buf) - self.ps + 1, self.ps):
                    if pg and self.key:
                        head = self.page(pg)[:8]
                    else:
                        head = buf[k:k + 8]
                    if head[0] == 0x01:
                        by.setdefault(struct.unpack_from("<I", head, 4)[0], []).append(pg)
                    pg += 1
            self._data_pages = by
        return self._data_pages.get(tdef_pg, [])

    # ------------------------------------------------------------ table definitions
    def _tdef(self, pg, name=""):
        b = self.page(pg)
        if b[0] != 0x02:
            raise AccessError(f"page {pg} is not a table definition")
        buf = bytearray(b)
        nxt, seen = struct.unpack_from("<I", b, 4)[0], {pg}
        while nxt and nxt not in seen:
            seen.add(nxt)
            p = self.page(nxt)
            buf += p[8:]
            nxt = struct.unpack_from("<I", p, 4)[0]
        u16 = lambda o: struct.unpack_from("<H", buf, o)[0]
        u32 = lambda o: struct.unpack_from("<I", buf, o)[0]
        if self.jet3:
            num_rows, num_var, num_cols, num_ridx = u32(12), u16(23), u16(25), u32(31)
            pos, ent = 43 + num_ridx * 8, 18
            o = dict(num=1, var=3, fixed=14, size=16, flags=13, scale=9, prec=10)
        else:
            num_rows, num_var, num_cols, num_ridx = u32(16), u16(43), u16(45), u32(51)
            pos, ent = 63 + num_ridx * 12, 25
            o = dict(num=5, var=7, fixed=21, size=23, flags=15, scale=12, prec=11)
        cols = []
        for i in range(num_cols):
            e = pos + i * ent
            c = Column()
            c.type, c.num, c.var_idx = buf[e], u16(e + o["num"]), u16(e + o["var"])
            c.fixed_off, c.size, c.flags = u16(e + o["fixed"]), u16(e + o["size"]), buf[e + o["flags"]]
            c.scale, c.prec = buf[e + o["scale"]], buf[e + o["prec"]]
            cols.append(c)
        pos += num_cols * ent
        for c in cols:
            if self.jet3:
                ln = buf[pos]
                c.name = bytes(buf[pos + 1:pos + 1 + ln]).decode(self.codepage, "replace")
                pos += 1 + ln
            else:
                ln = u16(pos)
                c.name = bytes(buf[pos + 2:pos + 2 + ln]).decode("utf-16-le", "replace")
                pos += 2 + ln
        cols.sort(key=lambda c: c.num)
        return Table(name, pg, cols, num_rows, num_var)

    def _catalog(self):
        sysobj = self._tdef(2, "MSysObjects")
        out = {}
        for r in self._rows(sysobj):
            name, typ, flags, oid = r.get("Name"), r.get("Type"), r.get("Flags") or 0, r.get("Id")
            if name is None or typ is None or oid is None:
                continue
            if (typ & 0x7FFF) == 1:
                out[name] = dict(pg=oid & 0x00FFFFFF, system=bool(flags & 0x80000002) or name.startswith(("MSys", "~")))
        return out

    def table_names(self, system=False):
        return [n for n, t in self._tables.items() if system or not t["system"]]

    def table(self, name) -> Table:
        t = self._tables[name]
        if "tdef" not in t:
            t["tdef"] = self._tdef(t["pg"], name)
        return t["tdef"]

    # ------------------------------------------------------------ rows
    def rows(self, name):
        """Every live row of a table as {column: value} (native Python values), page by page."""
        return self._rows(self.table(name))

    def _rows(self, t: Table):
        for pg in self._data_pages_of(t.tdef_pg):
            b = self.page(pg)
            n = struct.unpack_from("<H", b, 8 if self.jet3 else 12)[0]
            for i in range(n):
                s, e, fl = self._row_bounds(b, i)
                if fl & 0x8000 or e <= s:                  # deleted
                    continue
                if fl & 0x4000:                            # a row that grew and moved: its slot starts with a
                    ptr = struct.unpack_from("<I", b, s)[0]    # pointer to the real row (stored flagged deleted)
                    tb = self.page(ptr >> 8)
                    ts, te, _ = self._row_bounds(tb, ptr & 0xFF)
                    yield self._crack(t, tb[ts:te])
                    continue
                yield self._crack(t, b[s:e])

    def _crack(self, t: Table, row: bytes) -> dict:
        L = len(row)
        if self.jet3:
            ncols = row[0]
            fixed_start = 1
        else:
            ncols = struct.unpack_from("<H", row, 0)[0]
            fixed_start = 2
        bm = (ncols + 7) // 8
        mask = row[L - bm:]
        offs, nvar = [], 0
        if t.num_var:
            if self.jet3:
                end = L - 1
                nvar = row[end - bm]
                jumps = end // 256
                col_ptr = end - bm - jumps - 1
                if (col_ptr - nvar) // 256 < jumps:
                    jumps -= 1
                used = 0
                for i in range(nvar + 1):
                    while used < jumps and i == row[end - bm - used - 1]:
                        used += 1
                    offs.append(row[col_ptr - i] + used * 256)
            else:
                nvar = struct.unpack_from("<H", row, L - bm - 2)[0]
                offs = [struct.unpack_from("<H", row, L - bm - 4 - 2 * i)[0] for i in range(nvar + 1)]
        nfixed = ncols - nvar
        out = {}
        fi = 0
        for c in t.columns:
            bit = c.num < ncols and (mask[c.num >> 3] >> (c.num & 7)) & 1
            if c.type == BOOL:
                out[c.name] = bool(bit)
                if c.fixed:
                    fi += 1
                continue
            if c.fixed:
                here = fi < nfixed
                fi += 1
                if not bit or not here:
                    out[c.name] = None
                    continue
                st = fixed_start + c.fixed_off
                data = row[st:st + c.size]
            else:
                if not bit or c.var_idx >= nvar:
                    out[c.name] = None
                    continue
                data = row[offs[c.var_idx]:offs[c.var_idx + 1]]
            try:
                out[c.name] = self._value(c, data)
            except (struct.error, AccessError, IndexError, ValueError, OverflowError):
                out[c.name] = None
        return out

    # ------------------------------------------------------------ values
    def _text(self, data: bytes) -> str:
        if self.jet3:
            return data.decode(self.codepage, "replace")
        if data[:2] == b"\xff\xfe":                        # "compressed unicode": 1-byte runs, 0x00 toggles
            parts, start, comp = [], 2, True
            for i in range(2, len(data) + 1):
                if i == len(data) or data[i] == 0:
                    seg = data[start:i]
                    parts.append(seg.decode("latin-1") if comp else seg.decode("utf-16-le", "replace"))
                    comp, start = not comp, i + 1
            return "".join(parts)
        return data.decode("utf-16-le", "replace")

    def _lval(self, data: bytes) -> bytes:
        ln = struct.unpack_from("<I", data, 0)[0]
        size = ln & 0x3FFFFFFF
        if ln & 0x80000000:
            return data[12:12 + size]
        ptr = struct.unpack_from("<I", data, 4)[0]
        if ln & 0x40000000:
            b = self.page(ptr >> 8)
            s, e, _ = self._row_bounds(b, ptr & 0xFF)
            return b[s:e][:size]
        out, seen = bytearray(), set()
        while ptr and len(out) < size and ptr not in seen:
            seen.add(ptr)
            b = self.page(ptr >> 8)
            s, e, _ = self._row_bounds(b, ptr & 0xFF)
            ptr = struct.unpack_from("<I", b, s)[0]
            out += b[s + 4:e]
        return bytes(out[:size])

    def _value(self, c: Column, d: bytes):
        t = c.type
        if t == BYTE:
            return d[0]
        if t == INT:
            return struct.unpack_from("<h", d)[0]
        if t in (LONG, COMPLEX):
            return struct.unpack_from("<i", d)[0]
        if t == BIGINT:
            return struct.unpack_from("<q", d)[0]
        if t == MONEY:
            return Decimal(struct.unpack_from("<q", d)[0]).scaleb(-4)
        if t == FLOAT:
            return struct.unpack_from("<f", d)[0]
        if t == DOUBLE:
            return struct.unpack_from("<d", d)[0]
        if t == DATETIME:
            v = struct.unpack_from("<d", d)[0]
            day = int(v)
            return EPOCH + timedelta(days=day) + timedelta(days=abs(v - day))
        if t == GUID:
            return "{" + str(uuid.UUID(bytes_le=bytes(d[:16]))).upper() + "}"
        if t == NUMERIC:
            mag = b"".join(d[1 + k:5 + k][::-1] for k in (0, 4, 8, 12))
            v = Decimal(int.from_bytes(mag, "big")).scaleb(-c.scale)
            return -v if d[0] else v
        if t == TEXT:
            return self._text(d)
        if t == MEMO:
            return self._text(self._lval(d))
        if t == OLE:
            return self._lval(d)
        return bytes(d)

    # ------------------------------------------------------------ relations
    def relationships(self):
        """Declared foreign keys: [(child_table, child_col, parent_table, parent_col)]."""
        if "MSysRelationships" not in self._tables:
            return []
        out = []
        for r in self.rows("MSysRelationships"):
            child, parent = r.get("szObject"), r.get("szReferencedObject")
            ccol, pcol = r.get("szColumn"), r.get("szReferencedColumn")
            if child and parent and ccol and pcol:
                out.append((child, ccol, parent, pcol))
        return out


# ---------------------------------------------------------------- the import side
def display(v):
    """A stored value as the importer wants it: text/number, dates as ISO, money/decimals exact, blobs labelled."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, Decimal):
        s = format(v, "f")
        return s.rstrip("0").rstrip(".") if "." in s else s
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d") if (v.hour, v.minute, v.second) == (0, 0, 0) else v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, (bytes, bytearray)):
        return f"[קובץ / נתון בינארי, {len(v)} בתים]" if v else None
    return str(v)


def count_access(path):
    """{table: (rows, exact)} from the table definitions — no row is read."""
    try:
        with AccessDB(path) as db:
            return {n: (db.table(n).num_rows, True) for n in db.table_names()}
    except (AccessError, OSError):
        return {}


PERSONAL = ("name", "first", "last", "phone", "email", "national_id", "username")   # a row's own identity
IDENTITY = PERSONAL + ("org",)                                                       # what a parent lends
GENERIC_KEYS = {"id", "מזהה", "קוד", "code", "key", "no", "num", "מס", "מספר"}
JOIN_CAP = 2_000_000          # a parent table bigger than this is not indexed for joining (memory)


def _identity_cols(cols, sample, kinds=IDENTITY):
    from .catalog import plan_columns
    plan = plan_columns(cols, sample)
    return [c.name for c in plan.columns if c.status == "entity" and c.type in kinds]


def _key_of(t: Table):
    """A table's own key column: its autonumber, else a first column named like an ID."""
    for c in t.columns:
        if c.autonumber:
            return c.name
    first = t.columns[0].name if t.columns else None
    if first and any(w in first.lower() for w in ("id", "מזהה", "קוד", "מס")):
        return first
    return None


def find_links(db: AccessDB, samples):
    """Foreign keys worth joining: child table (no identity of its own) -> parent table that holds identities.
    Declared relationships first, then a child column named exactly like the parent's (non-generic) key.
    samples: {table: (cols, sample rows)} with display values."""
    ident = {t: _identity_cols(cols, rows) for t, (cols, rows) in samples.items()}
    own = {t: _identity_cols(cols, rows, PERSONAL) for t, (cols, rows) in samples.items()}
    _declared = set(db.relationships())
    cands = []
    for child, ccol, parent, pcol in db.relationships():
        cands.append((child, ccol, parent, pcol))
    keys = {t: _key_of(db.table(t)) for t in samples}
    for parent, pk in keys.items():
        if not pk or pk.strip().lower() in GENERIC_KEYS:
            continue
        for child, (cols, _) in samples.items():
            if child != parent and any(c.lower() == pk.lower() for c in cols):
                ccol = next(c for c in cols if c.lower() == pk.lower())
                if keys.get(child) != ccol:
                    cands.append((child, ccol, parent, pk))
    out, seen = [], set()
    for child, ccol, parent, pcol in cands:
        if (child, ccol) in seen or child not in samples or parent not in samples:
            continue
        if own.get(child) or not ident.get(parent):
            continue                       # the child has its own identity, or the parent holds no one
        cvals = [str(r.get(ccol)) for r in samples[child][1] if r.get(ccol) is not None]
        if not cvals:
            continue
        seen.add((child, ccol))
        out.append(dict(child=child, col=ccol, parent=parent, key=pcol, cols=ident[parent],
                        declared=(child, ccol, parent, pcol) in _declared))
    return out


def _sample(db, name, n=300):
    out = []
    for r in db.rows(name):
        out.append({k: display(v) for k, v in r.items()})
        if len(out) >= n:
            break
    return out


def access_tables(path, deep=True):
    """Yields (table, columns, rows_iter) for every user table; with deep=True, fact tables get their parent's
    identity columns ('<parent>.<column>') through the foreign key, so their rows link to the right person."""
    db = AccessDB(path)
    try:
        names = db.table_names()
        samples = {n: ([c.name for c in db.table(n).columns], _sample(db, n)) for n in names}
        links = find_links(db, samples) if deep else []
    except Exception:
        db.close()
        raise
    by_child = {}
    for lk in links:
        by_child.setdefault(lk["child"], []).append(lk)
    try:
        for n in names:
            cols = list(samples[n][0])
            joins = []
            for lk in by_child.get(n, []):
                p = db.table(lk["parent"])
                if p.num_rows > JOIN_CAP:
                    continue
                idx = {}
                for r in db.rows(lk["parent"]):
                    k = r.get(lk["key"])
                    if k is not None:
                        idx[str(display(k))] = {c: display(r.get(c)) for c in lk["cols"]}
                vals = [str(r.get(lk["col"])) for r in samples[n][1] if r.get(lk["col"]) is not None]
                if sum(v in idx for v in vals) < 0.5 * len(vals):
                    continue                     # the key does not really point there: no join
                lk["matched"] = True
                names_j = {c: f"{lk['parent']}.{c}" for c in lk["cols"]}
                cols += [v for v in names_j.values() if v not in cols]
                joins.append((lk["col"], idx, names_j))

            def rows(n=n, joins=joins):
                for r in db.rows(n):
                    r = {k: display(v) for k, v in r.items()}
                    for col, idx, names_j in joins:
                        hit = idx.get(str(r.get(col))) if r.get(col) is not None else None
                        for c, vn in names_j.items():
                            r[vn] = hit.get(c) if hit else None
                    yield r
            yield n, cols, rows()
    finally:
        db.close()
