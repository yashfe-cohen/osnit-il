"""Read .xlsx (and .xls via openpyxl/xlrd when present) worksheets as rows of {header: value} dicts,
so spreadsheets of contacts go through the same column-mapped record extraction as CSV/SQL."""
import io
import zipfile
from xml.etree import ElementTree as ET

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
MAX_PART = 60 * 1024 * 1024


def _col_index(ref):
    """'B7' -> 1 (zero-based column)."""
    c = 0
    for ch in ref:
        if ch.isalpha():
            c = c * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return c - 1


def _shared_strings(z):
    out = []
    if "xl/sharedStrings.xml" in z.namelist():
        with z.open("xl/sharedStrings.xml") as f:
            for si in ET.fromstring(f.read(MAX_PART)).iter(NS + "si"):
                out.append("".join(t.text or "" for t in si.iter(NS + "t")))
    return out


def read_xlsx(path):
    """Yields (sheet_name, header, rows) where rows are dicts keyed by header cells."""
    z = zipfile.ZipFile(path)
    shared = _shared_strings(z)
    sheets = sorted(n for n in z.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
    for si, name in enumerate(sheets, 1):
        with z.open(name) as f:
            root = ET.fromstring(f.read(MAX_PART))
        grid = []
        for row in root.iter(NS + "row"):
            cells = {}
            maxc = -1
            for c in row.iter(NS + "c"):
                idx = _col_index(c.get("r", "A"))
                v = c.find(NS + "v")
                if c.get("t") == "inlineStr":
                    val = "".join(t.text or "" for t in c.iter(NS + "t"))
                elif v is not None and v.text is not None:
                    val = shared[int(v.text)] if c.get("t") == "s" and v.text.isdigit() and int(v.text) < len(shared) else v.text
                else:
                    val = ""
                cells[idx] = val
                maxc = max(maxc, idx)
            grid.append([cells.get(i, "") for i in range(maxc + 1)])
        grid = [r for r in grid if any(str(x).strip() for x in r)]
        if not grid:
            continue
        header = [str(h).strip() or f"col{i}" for i, h in enumerate(grid[0])]
        rows = [{header[i]: r[i] for i in range(min(len(header), len(r)))} for r in grid[1:]]
        yield (f"sheet{si}" if name.endswith("sheet1.xml") and len(sheets) == 1 else name.split("/")[-1][:-4]), header, rows


def read_xls(path):
    """Legacy BIFF .xls via xlrd when installed; raises ImportError otherwise."""
    import xlrd
    book = xlrd.open_workbook(path)
    for sh in book.sheets():
        if sh.nrows == 0:
            continue
        header = [str(sh.cell_value(0, c)).strip() or f"col{c}" for c in range(sh.ncols)]
        rows = [{header[c]: sh.cell_value(r, c) for c in range(sh.ncols)} for r in range(1, sh.nrows)]
        yield sh.name, header, rows
