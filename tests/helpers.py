"""Shared isolation for tests: synthetic root key, temp data home, no Keychain access."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

TEST_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
TEST_EXTENSION_ORIGIN = "chrome-extension://" + TEST_EXTENSION_ID


def isolate(case, root_key: bytes = b"s" * 32) -> Path:
    """Point every default path at a temp dir and replace the Keychain with a constant."""
    temp = tempfile.TemporaryDirectory()
    case.addCleanup(temp.cleanup)
    base = Path(temp.name)
    env = patch.dict("os.environ", {"ARCTURION_GATE_HOME": str(base / "home")})
    env.start()
    case.addCleanup(env.stop)
    for name, value in (("get_root_key", root_key), ("put_root_key", None), ("delete_root_key", None)):
        mocked = patch("arcturion_gate.keychain." + name, return_value=value)
        mocked.start()
        case.addCleanup(mocked.stop)
    return base
