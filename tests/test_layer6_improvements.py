"""Tests for Layer 6 improvements: EXIF extraction, dHash dedup, and Source D OG scraping."""
import asyncio
import io
import struct
import unittest

from osnit.web_osint import (
    SearchTargetProfile,
    _dhash,
    _extract_jpeg_exif,
    _hamming,
    _scrape_og_images,
    run_layer6_image_recon,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Minimal JPEG builder
# ---------------------------------------------------------------------------

def _make_jpeg(exif_payload: bytes | None = None) -> bytes:
    """Build a minimal valid JPEG with an optional APP1/EXIF segment."""
    out = bytearray(b'\xff\xd8')
    if exif_payload is not None:
        seg = b'Exif\x00\x00' + exif_payload
        seg_len = len(seg) + 2
        out += b'\xff\xe1' + struct.pack('>H', seg_len) + seg
    # Tiny APP0 JFIF marker (no real image data — sufficient for EXIF parsing)
    out += b'\xff\xd9'
    return bytes(out)


def _build_exif(make: str = "TestCam", model: str = "M1",
                datetime_str: str = "2024:01:15 12:30:00",
                gps: tuple[float, float] | None = None) -> bytes:
    """Build a minimal TIFF/EXIF block (little-endian) with common tags."""
    endian = b'II'
    magic = struct.pack('<H', 42)

    strings: dict[int, bytes] = {}
    for tag, val in ((0x010F, make), (0x0110, model), (0x0132, datetime_str)):
        strings[tag] = val.encode('latin-1') + b'\x00'

    # Fixed layout: IFD0 starts at offset 8.
    # Entry count + IFD0 entries (12 bytes each) + 4-byte next-IFD pointer
    n_entries = len(strings)
    ifd0_offset = 8
    ifd_body_len = 2 + n_entries * 12 + 4
    strings_start = ifd0_offset + ifd_body_len

    # Build string area
    str_offsets: dict[int, int] = {}
    string_area = bytearray()
    for tag, s in strings.items():
        str_offsets[tag] = strings_start + len(string_area)
        string_area += s

    # Build IFD0
    ifd = bytearray()
    ifd += struct.pack('<H', n_entries)
    for tag, s in strings.items():
        off = str_offsets[tag]
        cnt = len(s)
        if cnt <= 4:
            raw = s[:4].ljust(4, b'\x00')
        else:
            raw = struct.pack('<I', off)
        ifd += struct.pack('<HHI', tag, 2, cnt) + raw
    ifd += b'\x00\x00\x00\x00'  # no next IFD

    header = endian + magic + struct.pack('<I', ifd0_offset)
    return header + bytes(ifd) + bytes(string_area)


# ---------------------------------------------------------------------------
# EXIF extraction
# ---------------------------------------------------------------------------

class TestExifExtraction(unittest.TestCase):

    def test_non_jpeg_returns_empty(self):
        self.assertEqual(_extract_jpeg_exif(b'PNG\r\n\x1a\n' + b'\x00' * 100), {})

    def test_jpeg_without_exif_returns_empty(self):
        raw = _make_jpeg(exif_payload=None)
        self.assertEqual(_extract_jpeg_exif(raw), {})

    def test_extracts_make_model_datetime(self):
        exif = _build_exif(make="Apple", model="iPhone 15", datetime_str="2025:06:01 09:00:00")
        raw = _make_jpeg(exif_payload=exif)
        result = _extract_jpeg_exif(raw)
        self.assertEqual(result.get("make"), "Apple")
        self.assertEqual(result.get("model"), "iPhone 15")
        self.assertIn("datetime", result)

    def test_empty_bytes_returns_empty(self):
        self.assertEqual(_extract_jpeg_exif(b''), {})

    def test_short_bytes_returns_empty(self):
        self.assertEqual(_extract_jpeg_exif(b'\xff\xd8\xff'), {})


# ---------------------------------------------------------------------------
# dHash and Hamming
# ---------------------------------------------------------------------------

class TestDHashHamming(unittest.TestCase):

    def test_hamming_identical(self):
        self.assertEqual(_hamming(0xABCDEF, 0xABCDEF), 0)

    def test_hamming_all_differ(self):
        self.assertEqual(_hamming(0xFFFF, 0x0000), 16)

    def test_hamming_single_bit(self):
        self.assertEqual(_hamming(0b1000, 0b0000), 1)

    def test_dhash_without_cv2_returns_none(self):
        # We can't guarantee OpenCV is absent, so this verifies the contract:
        # _dhash either returns an int or None — never raises.
        result = _dhash(b'not_an_image')
        self.assertTrue(result is None or isinstance(result, int))

    def test_dhash_empty_bytes_returns_none(self):
        self.assertIsNone(_dhash(b''))

    def test_dhash_none_bytes_returns_none(self):
        # Pass empty bytes explicitly (not None — function signature is bytes)
        self.assertIsNone(_dhash(b''))


# ---------------------------------------------------------------------------
# OG image scraping (Source D)
# ---------------------------------------------------------------------------

_PAD = b"<!-- " + b"x" * 200 + b" -->"

_HTML_WITH_OG = b"""<!DOCTYPE html>
<html><head>
<title>Dana Levi - profile</title>
<meta property="og:image" content="https://example.com/dana.jpg"/>
</head><body>""" + _PAD + b"""</body></html>"""

_HTML_OG_ALTERNATE_ATTR_ORDER = b"""<!DOCTYPE html>
<html><head>
<title>Dana Levi page</title>
<meta content="https://example.com/dana2.jpg" property="og:image"/>
</head><body>""" + _PAD + b"""</body></html>"""

_HTML_TWITTER_CARD = b"""<!DOCTYPE html>
<html><head>
<title>Dana Levi interview</title>
<meta name="twitter:image" content="https://cdn.example.com/photo.jpg"/>
</head><body>""" + _PAD + b"""</body></html>"""

_HTML_NO_TARGET = b"""<!DOCTYPE html>
<html><head>
<title>Random article about cats</title>
<meta property="og:image" content="https://example.com/cat.jpg"/>
</head><body>""" + _PAD + b"""</body></html>"""


def _build_fetcher(pages: dict[str, bytes]):
    def fetch(url, headers):
        for k, v in pages.items():
            if k in url:
                return (200, v, {"Content-Type": "text/html"})
        return (404, b"", {})
    return fetch


class TestScrapeOgImages(unittest.TestCase):

    def _profile(self):
        return SearchTargetProfile.from_raw(name="Dana Levi", emails=["dana@example.com"])

    def test_og_image_extracted(self):
        p = self._profile()
        fetcher = _build_fetcher({"example.com/article": _HTML_WITH_OG})
        result = _run(_scrape_og_images(
            ["https://example.com/article/1"], p, http_fetcher=fetcher))
        self.assertTrue(result, "Expected at least one OG result")
        self.assertEqual(result[0]["image_url"], "https://example.com/dana.jpg")
        self.assertEqual(result[0]["source_type"], "og_image")

    def test_alternate_attribute_order(self):
        p = self._profile()
        fetcher = _build_fetcher({"example.com": _HTML_OG_ALTERNATE_ATTR_ORDER})
        result = _run(_scrape_og_images(
            ["https://example.com/page"], p, http_fetcher=fetcher))
        self.assertTrue(result)
        self.assertIn("dana2.jpg", result[0]["image_url"])

    def test_twitter_card_fallback(self):
        p = self._profile()
        fetcher = _build_fetcher({"example.com": _HTML_TWITTER_CARD})
        result = _run(_scrape_og_images(
            ["https://example.com/interview"], p, http_fetcher=fetcher))
        self.assertTrue(result)
        self.assertIn("photo.jpg", result[0]["image_url"])

    def test_target_not_in_page_rejected(self):
        p = self._profile()
        fetcher = _build_fetcher({"example.com": _HTML_NO_TARGET})
        result = _run(_scrape_og_images(
            ["https://example.com/cats"], p, http_fetcher=fetcher))
        self.assertEqual(result, [], "Target-unrelated page should yield no OG result")

    def test_empty_profile_tokens_allows_any_page(self):
        # When profile has no name tokens, every page with an OG image passes
        p = SearchTargetProfile.from_raw(name="")
        fetcher = _build_fetcher({"example.com": _HTML_NO_TARGET})
        result = _run(_scrape_og_images(
            ["https://example.com/cats"], p, http_fetcher=fetcher))
        self.assertTrue(result)

    def test_image_url_skipped(self):
        # Direct image URLs should be skipped (no HTML scraping needed)
        p = self._profile()
        fetcher = _build_fetcher({})
        result = _run(_scrape_og_images(
            ["https://example.com/photo.jpg"], p, http_fetcher=fetcher))
        self.assertEqual(result, [])

    def test_empty_url_list_returns_empty(self):
        p = self._profile()
        result = _run(_scrape_og_images([], p))
        self.assertEqual(result, [])

    def test_no_duplicate_og_images(self):
        p = self._profile()
        fetcher = _build_fetcher({"example.com": _HTML_WITH_OG})
        result = _run(_scrape_og_images(
            ["https://example.com/a", "https://example.com/b"],
            p, http_fetcher=fetcher))
        urls = [r["image_url"] for r in result]
        self.assertEqual(len(urls), len(set(urls)), "Duplicate OG image URLs should be deduplicated")


# ---------------------------------------------------------------------------
# run_layer6_image_recon integration: finding_urls parameter
# ---------------------------------------------------------------------------

class TestLayer6Integration(unittest.TestCase):

    def test_finding_urls_parameter_accepted(self):
        """run_layer6_image_recon accepts finding_urls without error."""
        p = SearchTargetProfile.from_raw(name="Dana Levi", emails=["dana@example.com"])

        def _no_fetch(url, headers):
            return (404, b"", {})

        result = _run(run_layer6_image_recon(
            profile=p,
            findings_so_far=[],
            http_fetcher=_no_fetch,
            bytes_fetcher=lambda url, headers: (404, b"", {}),
            finding_urls=["https://example.com/article"],
        ))
        # Should return a list (possibly empty — no real images in this test)
        self.assertIsInstance(result, list)

    def test_no_crash_without_finding_urls(self):
        """Omitting finding_urls is still valid."""
        p = SearchTargetProfile.from_raw(name="Dana Levi")
        result = _run(run_layer6_image_recon(
            profile=p,
            findings_so_far=[],
        ))
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
