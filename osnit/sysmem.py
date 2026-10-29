"""Memory-aware concurrency planning, so an aggressive scan opens as many parallel browsers / fetchers as the
machine can hold — scaling to the available RAM the way heavy scanners do — without oversubscribing it into a
swap-death. Stdlib-only and cross-platform (Linux /proc, Windows GlobalMemoryStatusEx, a BSD/macOS sysctl
fallback, and a safe default when none is readable)."""
import ctypes
import os
import subprocess

DEFAULT_TOTAL = 8 * 1024 ** 3          # assume 8 GB when the real figure cannot be read


def _linux_meminfo():
    out = {}
    try:
        with open("/proc/meminfo", "rb") as f:
            for ln in f:
                k, _, rest = ln.partition(b":")
                parts = rest.split()
                if parts:
                    out[k.decode()] = int(parts[0]) * 1024     # values are in kB
    except OSError:
        return None
    return out


def _windows_mem():
    class MS(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    try:
        ms = MS()
        ms.dwLength = ctypes.sizeof(MS)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
            return int(ms.ullTotalPhys), int(ms.ullAvailPhys)
    except (AttributeError, OSError):
        return None
    return None


def _bsd_total():
    for key in ("hw.memsize", "hw.physmem"):
        try:
            out = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=2)
            if out.returncode == 0 and out.stdout.strip().isdigit():
                return int(out.stdout.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    return None


def memory():
    """(total_bytes, available_bytes). 'available' is what can be allocated now without paging; it falls back to
    total when only total is known, and to a safe default when nothing is readable."""
    mi = _linux_meminfo()
    if mi and "MemTotal" in mi:
        avail = mi.get("MemAvailable")
        if avail is None:
            avail = mi.get("MemFree", 0) + mi.get("Cached", 0) + mi.get("Buffers", 0)
        return mi["MemTotal"], min(avail, mi["MemTotal"])
    win = _windows_mem()
    if win:
        return win
    total = _bsd_total()
    if total:
        try:
            page = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
            return total, min(page, total)
        except (ValueError, OSError, AttributeError):
            return total, total // 2
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        avail = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
        return total, avail
    except (ValueError, OSError, AttributeError):
        return DEFAULT_TOTAL, DEFAULT_TOTAL // 2


def plan_concurrency(per_task_mb=350, target_fraction=0.85, cap=16, floor=1, reserve_mb=1024):
    """How many parallel heavy tasks (each ~per_task_mb) the machine can hold now: fill up to target_fraction of
    TOTAL RAM, but never past what is actually AVAILABLE minus a safety reserve, clamped to [floor, cap].

    target_fraction is the ceiling the user sets (e.g. 0.9 = 'use up to 90% of RAM'); the available-memory guard
    keeps it honest on a machine that is already busy."""
    total, avail = memory()
    per = max(64, per_task_mb) * 1024 ** 2
    by_total = int(total * target_fraction / per)
    by_avail = int(max(0, avail - reserve_mb * 1024 ** 2) / per)
    n = min(by_total, by_avail)
    return max(floor, min(cap, n))
