from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import sys
import unittest
import unittest.mock
from unittest.mock import patch

from arcturion_gate import cli

from helpers import isolate

SECRET = "synthetic-cli-secret-55120"


class CliCase(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)
        self.root = str(self.base / "vault")

    def gate(self, *argv, stdin=""):
        out = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out):
            code = cli.run(cli.parser().parse_args(["--root", self.root, *argv]))
        text = out.getvalue()
        return code, (json.loads(text) if text.strip().startswith("{") else text)

    def test_create_find_inspect_never_print_values(self):
        self.gate("init", "--recovery-file", str(self.base / "recovery.txt"))
        _, created = self.gate("create", "--stdin-json", stdin=json.dumps(
            {"title": "Fixture API", "category": "APICredential", "fields": {"credential": SECRET}}))
        rid = created["data"]["id"]
        for argv in (("find", "Fixture"), ("inspect", rid), ("health",), ("audit",)):
            with self.subTest(command=argv[0]):
                code, output = self.gate(*argv)
                self.assertEqual(code, 0)
                self.assertNotIn(SECRET, json.dumps(output))

    def test_exec_injects_value_into_child_environment_only(self):
        self.gate("init", "--recovery-file", str(self.base / "recovery.txt"))
        self.gate("create", "--stdin-json", stdin=json.dumps(
            {"title": "Fixture API", "category": "APICredential", "fields": {"credential": SECRET}}))
        check = "import os,sys; sys.exit(0 if os.environ.get('FIXTURE_TOKEN') == %r else 7)" % SECRET
        code, _ = self.gate("exec", "--env", "FIXTURE_TOKEN=Fixture API:credential", "--", sys.executable, "-c", check)
        self.assertEqual(code, 0)

    def test_patch_requires_matching_version(self):
        self.gate("init", "--recovery-file", str(self.base / "recovery.txt"))
        _, created = self.gate("create", "--stdin-json", stdin=json.dumps(
            {"title": "Fixture", "category": "Secret", "fields": {"credential": "one"}}))
        rid = created["data"]["id"]
        code, patched = self.gate("patch", rid, "--if-version", "1", stdin=json.dumps({"fields": {"credential": "two"}}))
        self.assertEqual(patched["data"]["version"], 2)
        with self.assertRaises(Exception) as caught:
            self.gate("patch", rid, "--if-version", "1", stdin=json.dumps({"fields": {"credential": "three"}}))
        self.assertEqual(getattr(caught.exception, "code", None), "VERSION_CONFLICT")


    def test_copy_sends_digest_over_a_pipe_never_argv(self):
        self.gate("init", "--recovery-file", str(self.base / "recovery.txt"))
        self.gate("create", "--stdin-json", stdin=json.dumps(
            {"title": "Clip", "category": "Secret", "fields": {"password": SECRET}}))
        runs, spawned = [], []

        class Timer:
            def __init__(self, argv, **kwargs):
                spawned.append((argv, kwargs)); self.written = b""
                self.stdin = self
            def write(self, data): self.written += data
            def close(self): pass

        def fake_run(argv, **kwargs):
            runs.append((argv, kwargs)); return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(cli.subprocess, "run", side_effect=fake_run), patch.object(cli.subprocess, "Popen", side_effect=Timer) as popen:
            code, output = self.gate("copy", "Clip", "--ttl", "5")
        self.assertEqual(code, 0)
        self.assertEqual(runs[0][1]["input"], SECRET.encode())
        digest = hashlib.sha256(SECRET.encode()).hexdigest()
        argv, kwargs = spawned[0]
        self.assertNotIn(digest, " ".join(argv))
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertEqual(kwargs["stdin"], subprocess.PIPE)
        self.assertEqual(popen.call_args, unittest.mock.call(argv, **kwargs))
        self.assertNotIn(SECRET, json.dumps(output))

    def test_clear_clipboard_matches_bytes_including_carriage_returns(self):
        value = ("synthetic\r\nmulti-line\rvalue-" + SECRET).encode()
        digest = hashlib.sha256(value).hexdigest()
        for clipboard, cleared in ((value, True), (b"something the user copied later", False)):
            with self.subTest(cleared=cleared):
                calls = []

                def fake_run(argv, **kwargs):
                    calls.append((argv, kwargs))
                    return subprocess.CompletedProcess(argv, 0, clipboard if argv[0].endswith("pbpaste") else b"", b"")

                with patch.object(cli.subprocess, "run", side_effect=fake_run), patch.object(cli.time, "sleep") as sleep:
                    code, _ = self.gate("_clear-clipboard", "5", stdin=digest + "\n")
                self.assertEqual(code, 0)
                sleep.assert_called_once_with(5)
                wrote = [kw.get("input") for argv, kw in calls if argv[0].endswith("pbcopy")]
                self.assertEqual(wrote, [b""] if cleared else [])

    def test_copy_rejects_ttls_that_would_never_clear(self):
        self.gate("init", "--recovery-file", str(self.base / "recovery.txt"))
        for ttl in ("0", "-1", "999999999"):
            with self.subTest(ttl=ttl):
                with patch.object(cli.subprocess, "run") as run, self.assertRaises(Exception) as caught:
                    self.gate("copy", "anything", "--ttl", ttl)
                self.assertEqual(getattr(caught.exception, "code", None), "INVALID")
                run.assert_not_called()

if __name__ == "__main__":
    unittest.main()
