from __future__ import annotations

import io
import json
import plistlib
import unittest
import zipfile
from unittest.mock import MagicMock

from osintdepintel.discovery.plugins import (
    MobileArtifactPlugin,
    _extract_axml_strings,
    _is_apk,
    _is_ipa,
    _parse_apk,
    _parse_ipa,
    _safe_zip_read,
)
from osintdepintel.http import HttpError
from osintdepintel.models import TargetConfig
from osintdepintel.registry import GlobalRegistry


def _apk_axml() -> bytes:
    return (
        b"p\x00a\x00c\x00k\x00a\x00g\x00e\x00\x00\x00"
        b"c\x00o\x00m\x00.\x00e\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00a\x00p\x00p\x00\x00\x00"
        b"v\x00e\x00r\x00s\x00i\x00o\x00n\x00N\x00a\x00m\x00e\x00\x00\x00"
        b"1\x00.\x000\x00.\x000\x00\x00\x00"
        b"m\x00i\x00n\x00S\x00d\x00k\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
        b"3\x000\x00.\x000\x00\x00\x00"
    )


def _make_apk_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", _apk_axml())
        zf.writestr("classes.dex", b"dex content")
        zf.writestr("classes2.dex", b"dex content 2")
        zf.writestr("libs/okhttp.jar", b"jar content")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0")
    return buf.getvalue()


def _make_ipa_zip() -> bytes:
    plist_data = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.iosapp",
            "CFBundleShortVersionString": "2.1.0",
            "MinimumOSVersion": "14.0",
        }
    )
    resolved_data = json.dumps(
        {
            "pins": [
                {"identity": "alamofire", "state": {"version": "5.6.1"}},
                {"identity": "swiftyjson", "state": {"version": "4.0.0"}},
            ]
        }
    ).encode()
    podfile_data = (
        b"PODS:\n  - Alamofire (5.6.1)\n  - SwiftyJSON (4.0.0)\n\nDEPENDENCIES:\n  - Alamofire\n  - SwiftyJSON\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/App.app/Info.plist", plist_data)
        zf.writestr("Payload/App.app/Package.resolved", resolved_data)
        zf.writestr("Podfile.lock", podfile_data)
    return buf.getvalue()


def _make_ipa_zip_no_plist() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/App.app/somefile", b"data")
    return buf.getvalue()


def _make_ipa_zip_with_frameworks() -> bytes:
    plist_data = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.iosapp",
        }
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/App.app/Info.plist", plist_data)
        zf.writestr("Payload/App.app/Frameworks/Alamofire.framework/Alamofire", b"binary")
        zf.writestr("Payload/App.app/Frameworks/Alamofire.framework/Info.plist", b"ignored")
        zf.writestr("Payload/App.app/Frameworks/SDWebImage.framework/SDWebImage", b"binary")
    return buf.getvalue()


def _make_zip_no_apk_no_ipa() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("random.txt", b"just a file")
    return buf.getvalue()


class MobilePluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetConfig(
            "testapp",
            "https://example.test",
            mobile_artifacts=["https://example.test/app.apk"],
        )
        self.registry = GlobalRegistry()

    # --- discover() edge cases ---

    def test_no_mobile_artifacts_returns_empty(self) -> None:
        target = TargetConfig("test", "https://example.test")
        result = MobileArtifactPlugin(offline=False).discover(target, GlobalRegistry())
        self.assertEqual(len(result.records), 0)

    def test_offline_mode_returns_empty_with_gaps(self) -> None:
        result = MobileArtifactPlugin(offline=True).discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        gap_msgs = [g.get("message", "") for g in self.registry.collection_gaps]
        self.assertTrue(any("offline" in m.lower() for m in gap_msgs))

    def test_download_http_error_adds_failure(self) -> None:
        mock_http = MagicMock()
        mock_http.fetch_bytes.side_effect = HttpError("connection refused")
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("could not download" in f for f in result.failures))

    def test_download_os_error_adds_failure(self) -> None:
        mock_http = MagicMock()
        mock_http.fetch_bytes.side_effect = OSError("permission denied")
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("could not download" in f for f in result.failures))

    def test_not_a_zip_file_adds_failure(self) -> None:
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = b"not a zip file at all"
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("not a valid ZIP" in f for f in result.failures))

    def test_bad_zip_file_adds_failure(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("somefile", b"data")
        raw = buf.getvalue()
        corrupted = raw[: len(raw) // 2]
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = corrupted
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("could not parse" in f for f in result.failures))

    def test_zip_neither_apk_nor_ipa_adds_assumption(self) -> None:
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = _make_zip_no_apk_no_ipa()
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("does not match" in a for a in result.assumptions))

    # --- discover() APK path ---

    def test_discover_apk_success(self) -> None:
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = _make_apk_zip()
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        self.assertGreater(len(result.records), 0)
        versions = [r.version for r in result.records if r.name == "com.example.app"]
        self.assertIn("1.0.0", versions)
        obs_source_types = [o["source_type"] for o in result.observations]
        self.assertIn("mobile_artifact", obs_source_types)

    def test_discover_apk_with_dex_jar_deps(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", _apk_axml())
            zf.writestr("classes.dex", b"")
            zf.writestr("classes2.dex", b"")
            zf.writestr("libs/okhttp.jar", b"")
            zf.writestr("libs/retrofit.jar", b"")
            zf.writestr("META-INF/proguard.jar", b"not a dep")
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = buf.getvalue()
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(self.target, self.registry)
        names = [r.name for r in result.records]
        self.assertIn("okhttp", names)
        self.assertIn("retrofit", names)

    # --- discover() IPA path ---

    def test_discover_ipa_success(self) -> None:
        target = TargetConfig(
            "testapp",
            "https://example.test",
            mobile_artifacts=["https://example.test/app.ipa"],
        )
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = _make_ipa_zip()
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(target, self.registry)
        bundle_ids = [r.name for r in result.records if r.ecosystem == "ios"]
        self.assertIn("com.example.iosapp", bundle_ids)

    def test_discover_ipa_with_frameworks(self) -> None:
        target = TargetConfig(
            "testapp",
            "https://example.test",
            mobile_artifacts=["https://example.test/app.ipa"],
        )
        mock_http = MagicMock()
        mock_http.fetch_bytes.return_value = _make_ipa_zip_with_frameworks()
        plugin = MobileArtifactPlugin(offline=False, http=mock_http)
        result = plugin.discover(target, self.registry)
        names = [r.name for r in result.records]
        self.assertIn("Alamofire", names)
        self.assertIn("SDWebImage", names)

    # --- _is_apk / _is_ipa ---

    def test_is_apk_detects_android_manifest(self) -> None:
        self.assertTrue(_is_apk(["AndroidManifest.xml", "classes.dex"]))
        self.assertFalse(_is_apk(["Payload/App.app/Info.plist"]))
        self.assertFalse(_is_apk([]))

    def test_is_ipa_detects_payload(self) -> None:
        self.assertTrue(_is_ipa(["Payload/App.app/Info.plist"]))
        self.assertFalse(_is_ipa(["AndroidManifest.xml"]))
        self.assertFalse(_is_ipa([]))

    # --- _safe_zip_read ---

    def test_safe_zip_read_returns_content(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"hello")
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            content = _safe_zip_read(zf, "test.txt")
            self.assertEqual(content, b"hello")

    def test_safe_zip_read_raises_on_missing(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("other.txt", b"data")
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf, self.assertRaises(KeyError):
            _safe_zip_read(zf, "missing.txt")

    def test_safe_zip_read_raises_on_oversized(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"x" * (10 * 1024 * 1024 + 1))
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf, self.assertRaises(ValueError):
            _safe_zip_read(zf, "big.bin", max_size=10 * 1024 * 1024)

    # --- _extract_axml_strings ---

    def test_extract_axml_strings_parses_ucs2(self) -> None:
        data = b"p\x00a\x00c\x00k\x00a\x00g\x00e\x00\x00\x00c\x00o\x00m\x00.\x00f\x00o\x00o\x00\x00\x00"
        strings = _extract_axml_strings(data)
        self.assertIn("package", strings)
        self.assertIn("com.foo", strings)

    def test_extract_axml_strings_min_length(self) -> None:
        data = b"a\x00\x00\x00b\x00c\x00\x00\x00"
        strings = _extract_axml_strings(data, min_length=3)
        self.assertEqual(strings, [])

    def test_extract_axml_strings_skips_non_printable(self) -> None:
        data = b"\x00\x01\x02\x00\x00\x00"
        strings = _extract_axml_strings(data, min_length=1)
        self.assertEqual(strings, [])

    # --- _parse_apk ---

    def test_parse_apk_creates_record(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", _apk_axml())
            zf.writestr("classes.dex", b"")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_apk(self.target, self.registry, result, zf, zf.namelist(), "https://example.test/app.apk")
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "com.example.app")
        self.assertEqual(result.records[0].version, "1.0.0")

    def test_parse_apk_missing_manifest_adds_gap(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("other.xml", b"data")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_apk(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("not found" in f for f in result.failures))

    def test_parse_apk_no_package_name_adds_gap(self) -> None:
        data = b"n\x00o\x00p\x00k\x00g\x00\x00\x00"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", data)
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_apk(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertEqual(len(result.records), 0)

    def test_parse_apk_with_dex_jars(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", _apk_axml())
            zf.writestr("classes.dex", b"")
            zf.writestr("classes2.dex", b"")
            zf.writestr("classes3.dex", b"")
            zf.writestr("okhttp.jar", b"")
            zf.writestr("retrofit.jar", b"")
            zf.writestr("META-INF/extra.jar", b"")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_apk(self.target, self.registry, result, zf, zf.namelist(), "locator")
        names = [r.name for r in result.records]
        self.assertNotIn("classes", names)
        self.assertIn("okhttp", names)
        self.assertIn("retrofit", names)

    # --- _parse_ipa ---

    def test_parse_ipa_creates_record(self) -> None:
        buf = io.BytesIO()
        plist_data = plistlib.dumps(
            {
                "CFBundleIdentifier": "com.example.iosapp",
                "CFBundleShortVersionString": "2.1.0",
                "MinimumOSVersion": "14.0",
            }
        )
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", plist_data)
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "com.example.iosapp")
        self.assertEqual(result.records[0].version, "2.1.0")

    def test_parse_ipa_missing_plist_adds_failure(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("random.txt", b"data")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertTrue(any("not found" in f for f in result.failures))
        self.assertEqual(len(result.records), 0)

    def test_parse_ipa_empty_bundle_id_adds_gap(self) -> None:
        buf = io.BytesIO()
        plist_data = plistlib.dumps({"CFBundleIdentifier": ""})
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", plist_data)
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertEqual(len(result.records), 0)

    def test_parse_ipa_parses_package_resolved(self) -> None:
        buf = io.BytesIO()
        plist_data = plistlib.dumps({"CFBundleIdentifier": "com.example.iosapp"})
        resolved = json.dumps(
            {
                "pins": [
                    {"identity": "alamofire", "state": {"version": "5.6.1"}},
                ]
            }
        ).encode()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", plist_data)
            zf.writestr("Payload/App.app/Package.resolved", resolved)
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        names = [r.name for r in result.records]
        self.assertIn("alamofire", names)

    def test_parse_ipa_parses_podfile_lock(self) -> None:
        buf = io.BytesIO()
        plist_data = plistlib.dumps({"CFBundleIdentifier": "com.example.iosapp"})
        podfile = (
            b"PODS:\n  - Alamofire (5.6.1)\n  - SwiftyJSON (4.0.0)\n\nDEPENDENCIES:\n  - Alamofire\n  - SwiftyJSON\n"
        )
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", plist_data)
            zf.writestr("Podfile.lock", podfile)
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        names = [r.name for r in result.records]
        self.assertIn("Alamofire", names)
        self.assertIn("SwiftyJSON", names)

    def test_parse_ipa_identifies_frameworks(self) -> None:
        buf = io.BytesIO()
        plist_data = plistlib.dumps({"CFBundleIdentifier": "com.example.iosapp"})
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", plist_data)
            zf.writestr("Payload/App.app/Frameworks/Alamofire.framework/Alamofire", b"bin")
            zf.writestr("Payload/App.app/Frameworks/SDWebImage.framework/SDWebImage", b"bin")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        names = [r.name for r in result.records]
        self.assertIn("Alamofire", names)
        self.assertIn("SDWebImage", names)

    def test_parse_ipa_bad_plist_does_not_crash(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Payload/App.app/Info.plist", b"not valid plist at all")
        result = MagicMock()
        result.records = []
        result.inferences = []
        result.assumptions = []
        result.failures = []
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            _parse_ipa(self.target, self.registry, result, zf, zf.namelist(), "locator")
        self.assertEqual(len(result.records), 0)


if __name__ == "__main__":
    unittest.main()
