from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from arcturion_gate import config
from arcturion_gate.mcp_server import admin
from arcturion_gate.mcp_server.state import State

from helpers import TEST_EXTENSION_ID, isolate

REPO = Path(__file__).resolve().parents[1]


class BridgeSetupCase(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)

    def test_extension_id_derivation_matches_chrome_rule(self):
        der = b"synthetic public key bytes"
        expected = "".join("abcdefghijklmnop"[int(c, 16)] for c in hashlib.sha256(der).hexdigest()[:32])
        self.assertEqual(admin.extension_id_from_public_der(der), expected)
        self.assertRegex(expected, config.EXTENSION_ID_PATTERN)

    def test_extension_key_is_generated_once_and_reused(self):
        key_path = self.base / "keys" / "extension.pem"
        first = admin.extension_key(key_path)
        second = admin.extension_key(key_path)
        self.assertEqual(first, second)
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(admin.extension_id_from_public_der(base64.b64decode(first["manifest_key"])), first["extension_id"])

    def test_install_native_allows_exactly_one_extension(self):
        manifests = self.base / "NativeMessagingHosts"
        result = admin.install_native(TEST_EXTENSION_ID, "com.example.gate_test", manifests, "Profile 1")
        manifest = json.loads((manifests / "com.example.gate_test.json").read_text())
        self.assertEqual(manifest["allowed_origins"], ["chrome-extension://" + TEST_EXTENSION_ID + "/"])
        self.assertEqual(manifest["type"], "stdio")
        launcher = Path(manifest["path"])
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o700)
        self.assertIn("-I -m arcturion_gate.mcp_server.native", launcher.read_text())
        self.assertEqual(config.extension_id(), TEST_EXTENSION_ID)
        self.assertEqual(config.native_host(), "com.example.gate_test")
        self.assertEqual(config.chrome_profile_directory(), "Profile 1")
        self.assertEqual(result["native_host"], "com.example.gate_test")

    def test_install_native_rejects_malformed_identity(self):
        with self.assertRaises(SystemExit):
            admin.install_native("not-an-id", "com.example.gate", self.base, None)
        with self.assertRaises(SystemExit):
            admin.install_native(TEST_EXTENSION_ID, "Bad Host!", self.base, None)

    def test_enrollment_nonce_is_private_and_expiring(self):
        with patch.dict(os.environ, {"ARCTURION_GATE_EXTENSION_ID": TEST_EXTENSION_ID}):
            result = admin.enroll(print_only=True)
        self.assertTrue(result["url"].startswith("chrome-extension://" + TEST_EXTENSION_ID + "/operation.html#enroll="))
        path = config.bridge_root() / "enrollment.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        nonce = result["url"].split("#enroll=", 1)[1]
        self.assertEqual(json.loads(path.read_text())["nonce"], nonce)

    def test_enrollment_nonce_file_is_owner_only_from_creation(self):
        state = State(self.base / "bridge-perm", extension_id=TEST_EXTENSION_ID)
        staging = state.root / "enrollment.staging"
        staging.symlink_to(self.base / "elsewhere.txt")
        old_umask = os.umask(0)
        try:
            with patch("os.chmod"):
                state.create_enrollment()
        finally:
            os.umask(old_umask)
        self.assertFalse((self.base / "elsewhere.txt").exists())
        self.assertEqual(stat.S_IMODE((state.root / "enrollment.json").stat().st_mode), 0o600)

    def test_enrollment_expires(self):
        now = [1000.0]
        state = State(self.base / "bridge", clock=lambda: now[0], extension_id=TEST_EXTENSION_ID)
        nonce = state.create_enrollment()
        now[0] = 1000.0 + 120
        with self.assertRaises(Exception):
            state.enroll("12345678-1234-1234-1234-123456789abc", "a" * 64, nonce)

    def test_defaults_point_inside_configurable_home(self):
        self.assertEqual(config.vault_root(), self.base / "home" / "vault")
        self.assertEqual(config.bridge_root(), self.base / "home" / "bridge")
        self.assertIsNone(config.extension_id())
        self.assertEqual(config.native_host(), config.DEFAULT_NATIVE_HOST)

    def test_extension_ships_unpinned_and_host_matches_default(self):
        manifest = json.loads((REPO / "extension" / "manifest.json").read_text())
        self.assertNotIn("key", manifest)
        self.assertNotIn("externally_connectable", manifest)
        self.assertNotIn("web_accessible_resources", manifest)
        self.assertIn('"' + config.DEFAULT_NATIVE_HOST + '"', (REPO / "extension" / "config.js").read_text())


if __name__ == "__main__":
    unittest.main()
