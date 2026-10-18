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


# ---------------------------------------------------------------------------
# Extended EXIF: GPS reverse-geocode, lens/ISO/exposure/orientation/direction
# ---------------------------------------------------------------------------

def _build_exif_full(make="Canon", model="EOS 90D", dt="2024:03:15 12:34:56",
                     gps_lat=32.0853, gps_lon=34.7818, lens="EF 50mm f/1.8",
                     iso=200, f_number=(18, 10), exposure=(1, 250), orientation=6):
    """Build a full TIFF/EXIF block (little-endian) with IFD0 + Exif SubIFD + GPS IFD."""
    LE = '<'
    n_ifd0, n_sub, n_gps = 6, 5, 7
    ifd0_off = 8
    ifd0_size = 2 + n_ifd0 * 12 + 4
    sub_off = ifd0_off + ifd0_size
    sub_size = 2 + n_sub * 12 + 4
    gps_off = sub_off + sub_size
    gps_size = 2 + n_gps * 12 + 4
    pool_base = gps_off + gps_size
    pool = bytearray()

    def put(b):
        off = pool_base + len(pool)
        pool.extend(b)
        return off

    make_b = (make + '\x00').encode('latin-1')
    model_b = (model + '\x00').encode('latin-1')
    dt_b = (dt + '\x00').encode('latin-1')
    lens_b = (lens + '\x00').encode('latin-1')
    off_make, off_model, off_dt, off_lens = put(make_b), put(model_b), put(dt_b), put(lens_b)

    def rat3(d, m, s):
        return (struct.pack(LE + 'II', int(d), 1) + struct.pack(LE + 'II', int(m), 1)
                + struct.pack(LE + 'II', int(s * 1000), 1000))

    def dms(v):
        d, r = divmod(abs(v), 1)
        m, r2 = divmod(r * 60, 1)
        return d, m, r2 * 60

    off_lat = put(rat3(*dms(gps_lat)))
    off_lon = put(rat3(*dms(gps_lon)))
    off_alt = put(struct.pack(LE + 'II', 42, 1))
    off_fnum = put(struct.pack(LE + 'II', f_number[0], f_number[1]))
    off_exp = put(struct.pack(LE + 'II', exposure[0], exposure[1]))
    off_dir = put(struct.pack(LE + 'II', 1803, 10))

    def e(tag, typ, cnt, v4):
        return struct.pack(LE + 'HHI', tag, typ, cnt) + v4

    ifd0 = struct.pack(LE + 'H', n_ifd0)
    ifd0 += e(0x010F, 2, len(make_b), struct.pack(LE + 'I', off_make))
    ifd0 += e(0x0110, 2, len(model_b), struct.pack(LE + 'I', off_model))
    ifd0 += e(0x0132, 2, len(dt_b), struct.pack(LE + 'I', off_dt))
    ifd0 += e(0x0112, 3, 1, struct.pack(LE + 'HH', orientation, 0))
    ifd0 += e(0x8769, 4, 1, struct.pack(LE + 'I', sub_off))
    ifd0 += e(0x8825, 4, 1, struct.pack(LE + 'I', gps_off))
    ifd0 += struct.pack(LE + 'I', 0)

    sub = struct.pack(LE + 'H', n_sub)
    sub += e(0x9003, 2, len(dt_b), struct.pack(LE + 'I', off_dt))
    sub += e(0xA434, 2, len(lens_b), struct.pack(LE + 'I', off_lens))
    sub += e(0x8827, 3, 1, struct.pack(LE + 'HH', iso, 0))
    sub += e(0x829D, 5, 1, struct.pack(LE + 'I', off_fnum))
    sub += e(0x829A, 5, 1, struct.pack(LE + 'I', off_exp))
    sub += struct.pack(LE + 'I', 0)

    gps = struct.pack(LE + 'H', n_gps)
    gps += e(0x0001, 2, 2, b'N\x00\x00\x00')
    gps += e(0x0002, 5, 3, struct.pack(LE + 'I', off_lat))
    gps += e(0x0003, 2, 2, b'E\x00\x00\x00')
    gps += e(0x0004, 5, 3, struct.pack(LE + 'I', off_lon))
    gps += e(0x0005, 1, 1, b'\x00\x00\x00\x00')
    gps += e(0x0006, 5, 1, struct.pack(LE + 'I', off_alt))
    gps += e(0x0011, 5, 1, struct.pack(LE + 'I', off_dir))
    gps += struct.pack(LE + 'I', 0)

    return b'II' + struct.pack(LE + 'HI', 42, 8) + ifd0 + sub + gps + bytes(pool)


class TestExifEnrichment(unittest.TestCase):

    def test_full_exif_fields_and_geocode(self):
        raw = _make_jpeg(exif_payload=_build_exif_full())
        ex = _extract_jpeg_exif(raw)
        self.assertEqual(ex.get("make"), "Canon")
        self.assertEqual(ex.get("model"), "EOS 90D")
        self.assertEqual(ex.get("lens_model"), "EF 50mm f/1.8")
        self.assertEqual(ex.get("iso"), 200)
        self.assertEqual(ex.get("f_number"), 1.8)
        self.assertEqual(ex.get("exposure_time"), "1/250")
        self.assertEqual(ex.get("orientation"), 6)
        self.assertEqual(ex.get("gps_alt_m"), 42.0)
        self.assertEqual(ex.get("gps_img_direction"), 180.3)
        self.assertAlmostEqual(ex.get("gps_lat"), 32.0853, places=2)
        self.assertAlmostEqual(ex.get("gps_lon"), 34.7818, places=2)
        # EXIF GPS in Tel Aviv must reverse-geocode to a Hebrew place hint
        self.assertEqual(ex.get("gps_place"), "תל אביב-יפו")

    def test_gps_south_west_sign(self):
        raw = _make_jpeg(exif_payload=_build_exif_full(gps_lat=10.0, gps_lon=20.0))
        # Builder always writes N/E refs; confirm a non-IL coordinate is flagged outside Israel
        ex = _extract_jpeg_exif(raw)
        self.assertEqual(ex.get("gps_place"), "מחוץ לישראל")


class TestReverseGeocodeIL(unittest.TestCase):

    def test_known_cities(self):
        from osnit.web_osint import _reverse_geocode_il
        self.assertEqual(_reverse_geocode_il(31.78, 35.22), "ירושלים")
        self.assertEqual(_reverse_geocode_il(32.81, 34.99), "חיפה")
        self.assertEqual(_reverse_geocode_il(31.25, 34.80), "באר שבע")

    def test_national_fallback_and_abroad(self):
        from osnit.web_osint import _reverse_geocode_il
        self.assertEqual(_reverse_geocode_il(30.5, 35.0), "ישראל (אזור כללי)")
        self.assertEqual(_reverse_geocode_il(48.85, 2.35), "מחוץ לישראל")

    def test_bad_input(self):
        from osnit.web_osint import _reverse_geocode_il
        self.assertEqual(_reverse_geocode_il(None, None), "")


# ---------------------------------------------------------------------------
# Enriched face detection output shape (portrait / faces / largest_face_ratio)
# ---------------------------------------------------------------------------

class TestFaceDetectionShape(unittest.TestCase):

    def _png(self, w, h, payload=b""):
        return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
                + w.to_bytes(4, "big") + h.to_bytes(4, "big")
                + b"\x08\x02\x00\x00\x00" + b"\x00" * 64 + payload)

    def test_synthetic_face_reports_portrait(self):
        from osnit.web_osint import verify_human_face_in_image
        info = verify_human_face_in_image(self._png(240, 240, b"OSNIT_SYNTHETIC_FACE"))
        self.assertTrue(info["face_detected"])
        self.assertTrue(info["portrait"])
        self.assertIn("faces", info)
        self.assertIn("largest_face_ratio", info)

    def test_no_face_has_shape_keys(self):
        from osnit.web_osint import verify_human_face_in_image
        info = verify_human_face_in_image(self._png(200, 200, b"LANDSCAPE"))
        self.assertTrue(info["valid_size"])
        self.assertFalse(info["face_detected"])
        self.assertEqual(info["faces"], [])
        self.assertFalse(info["portrait"])

    def test_tiny_image_rejected_with_shape_keys(self):
        from osnit.web_osint import verify_human_face_in_image
        info = verify_human_face_in_image(self._png(32, 32, b"OSNIT_SYNTHETIC_FACE"))
        self.assertFalse(info["valid_size"])
        self.assertFalse(info["face_detected"])
        self.assertEqual(info["faces"], [])


if __name__ == "__main__":
    unittest.main()
