#!/usr/bin/env python3
"""Test-only stdio MCP server backed by a temporary synthetic vault (never a real one)."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

SYNTHETIC_ONLY = "synthetic-stdio-credential-928754617"
TEST_EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-root", required=True)
    args = parser.parse_args()
    root = Path(args.fixture_root).resolve()
    if not root.is_dir() or root.name != "gate-synthetic-fixture":
        raise SystemExit("fixture directory required")
    os.environ["ARCTURION_GATE_HOME"] = str(root / "home")
    from arcturion_gate.broker import Broker
    from arcturion_gate.store import Gate, GateStore
    from arcturion_gate.mcp_server import server
    from arcturion_gate.mcp_server.service import Service
    from arcturion_gate.mcp_server.state import State
    with patch("arcturion_gate.keychain.get_root_key", return_value=b"t" * 32), patch("arcturion_gate.keychain.put_root_key"):
        store = GateStore(root / "vault", catalog=root / "catalog")
        store.initialize()
        broker = Broker(store)
        state = State(root / "operations", extension_id=TEST_EXTENSION_ID)
        service = Service(state, Gate(store=store), broker)
        broker.put_secret("MCP Synthetic Fixture", SYNTHETIC_ONLY, field="password", expected_version=0,
                          idempotency_key="mcp-synthetic-fixture",
                          metadata={"category": "Secret", "tags": ["gate:synthetic"]})
        state.publish("synthetic-test-profile", [{
            "tab_id": 1, "frame_id": 0, "document_id": "synthetic-stdio-document",
            "origin": "chrome-extension://" + TEST_EXTENSION_ID, "document_path": "/fixture.html",
            "field": {"selector": "#password", "fingerprint": "synthetic-field", "kind": "password"},
            "account_hash": "a" * 64, "synthetic": True,
        }])
        # Browser launch is suppressed: this test covers the MCP transport only.
        with patch.object(server, "service", return_value=service), patch.object(server, "launch", side_effect=lambda result: result):
            server.main()


if __name__ == "__main__":
    main()
