"""End-to-end MCP transport check over a real stdio subprocess, synthetic data only.

Skipped when the optional ``mcp`` SDK is not installed (``pip install .[mcp]``).
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SYNTHETIC_ONLY = "synthetic-stdio-credential-928754617"
TOOLS = {
    "credential_search", "credential_inspect", "credential_organize", "credential_generate",
    "credential_capture", "credential_use", "credential_workflow", "credential_backup", "credential_health",
}


@unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK not installed")
class StdioTransportCase(unittest.TestCase):
    def test_tools_round_trip_without_values(self):
        asyncio.run(self.probe())

    async def probe(self):
        from mcp import Client, StdioServerParameters, stdio_client
        with tempfile.TemporaryDirectory(prefix="gate-mcp-probe-") as temporary:
            root = Path(temporary) / "gate-synthetic-fixture"
            root.mkdir(mode=0o700)
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(Path(__file__).with_name("synthetic_mcp_server.py")), "--fixture-root", str(root)],
                env={"PYTHONDONTWRITEBYTECODE": "1"},
            )
            transcript = []
            with (Path(temporary) / "stderr.txt").open("w+") as error_log:
                async with Client(stdio_client(params, errlog=error_log)) as client:
                    discovered = await client.list_tools()
                    self.assertEqual({tool.name for tool in discovered.tools}, TOOLS)
                    transcript.append(discovered.model_dump(mode="json", by_alias=True))

                    async def call(name, arguments):
                        result = await client.call_tool(name, arguments)
                        transcript.append(result.model_dump(mode="json", by_alias=True))
                        envelope = result.structured_content
                        if envelope is None:
                            envelope = json.loads(result.content[0].text)
                        if set(envelope) == {"result"}:
                            envelope = envelope["result"]
                        self.assertTrue(envelope.get("ok"), envelope)
                        return envelope["data"]

                    health = await call("credential_health", {})
                    self.assertTrue(health["gate"]["healthy"])
                    records = await call("credential_search", {"query": "MCP Synthetic Fixture"})
                    fixture = records["records"][0]
                    inspected = await call("credential_inspect", {"record_ref": fixture["id"]})
                    self.assertTrue(inspected["capabilities"]["password"])
                    generated = await call("credential_generate", {"title": "MCP Generated Synthetic", "synthetic": True})
                    self.assertEqual(generated["status"], "stored_pending")
                    await call("credential_organize", {"record_ref": generated["record_id"],
                                                       "expected_version": generated["version"], "tags": ["integration"]})
                    status = await call("credential_workflow", {"record_ref": generated["record_id"]})
                    self.assertEqual(status["workflow"]["state"], "stored_pending")
                    use = await call("credential_use", {"record_ref": fixture["id"],
                                                        "destination_ref": records["destinations"][0]["target_id"],
                                                        "expected_version": fixture["version"]})
                    self.assertTrue(use["operation_handle"])
                    await call("credential_backup", {})
            self.assertNotIn(SYNTHETIC_ONLY, json.dumps(transcript))
            for artifact in Path(temporary).rglob("*"):
                if artifact.is_file():
                    self.assertNotIn(SYNTHETIC_ONLY.encode(), artifact.read_bytes())


if __name__ == "__main__":
    unittest.main()
