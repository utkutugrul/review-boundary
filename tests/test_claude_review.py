"""Ordinary CLI contract tests. Every reviewer executable here is a trusted fake."""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("claude_review", ROOT / "scripts/claude_review.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


@unittest.skipUnless(os.name == "posix", "The helper explicitly requires POSIX process groups")
class ClaudeReviewContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gh13-contract-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "--template=")
        (self.repo / "safe.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        (self.repo / "other.md").write_text("Unrelated source.\n", encoding="utf-8")
        self.head = self.commit()

    def git(self, *args):
        env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        return subprocess.check_output(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture",
             "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
            env=env, stderr=subprocess.DEVNULL,
        ).decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture source")
        return self.git("rev-parse", "HEAD")

    def executable(self, mode="ok"):
        fake = self.root / "trusted-claude"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, os, signal, sys, time\n"
            f"mode = {mode!r}\n"
            f"flags = {bridge.FLAGS!r}\n"
            "args = sys.argv[1:]\n"
            "if args == ['--version']:\n"
            "    if mode == 'version_timeout': time.sleep(60)\n"
            "    print('private failure' if mode == 'version_bad' else '2.1.319 (Claude Code)')\n"
            "    sys.exit(0)\n"
            "if args == ['--help']:\n"
            "    names = [f for f in flags if f.startswith('--')]\n"
            "    names += ['--system-prompt', '--json-schema']\n"
            "    if mode == 'unsupported': names.remove('--tools')\n"
            "    if mode == 'flag_prefix': names = [f + 'BAD' for f in names]\n"
            "    print(' \\n'.join(names) + ' ')\n"
            "    sys.exit(0)\n"
            "assert args[:len(flags)] == flags\n"
            "assert args[len(flags)] == '--system-prompt'\n"
            "assert args[-2] == '--json-schema'\n"
            "assert not any(n in os.environ for n in [\n"
            "    'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'SYMPHONY_GITHUB_TOKEN',\n"
            "    'CLAUDE_CONFIG_DIR', 'UNRELATED_SECRET'])\n"
            "assert not os.path.exists('safe.py')\n"
            "if mode == 'blocked_input': time.sleep(60)\n"
            "request = json.load(sys.stdin)\n"
            "schema = json.loads(args[-1])\n"
            "assert schema['properties']['revision']['const'] == request['revision']\n"
            "assert schema['properties']['review_key']['const'] == request['review_key']\n"
            "if mode == 'assert_frozen':\n"
            "    assert request['files'][0]['current']['content'] == 'def value():\\n    return 1\\n'\n"
            "review = {\n"
            "    'revision': request['revision'], 'review_key': request['review_key'],\n"
            "    'assessment': 'reviewed', 'coverage': [\n"
            "        {'path': f['path'], 'status': 'reviewed'} for f in request['files']],\n"
            "    'findings': [], 'limitations': []}\n"
            "envelope = {'type': 'result', 'subtype': 'success', 'is_error': False,\n"
            "            'permission_denials': [], 'structured_output': review}\n"
            "if mode == 'finding':\n"
            "    review['findings'] = [{'priority': 'P2', 'path': 'safe.py', 'line_start': 1,\n"
            "        'line_end': 2, 'title': 'Synthetic finding', 'body': 'Synthetic evidence.'}]\n"
            "if mode == 'refusal': review['assessment'] = 'unavailable'\n"
            "if mode == 'partial': review['coverage'][0]['status'] = 'partial'\n"
            "if mode == 'missing_coverage': review['coverage'] = []\n"
            "if mode == 'duplicate_coverage': review['coverage'] = [review['coverage'][0]] * 2\n"
            "if mode == 'wrong_revision': review['revision'] = '0' * 40\n"
            "if mode == 'wrong_key': review['review_key'] = '0' * 64\n"
            "if mode == 'extra_field': review['unrequested'] = True\n"
            "if mode in ['bad_line', 'bad_path', 'bool_line']:\n"
            "    review['findings'] = [{'priority': 'P1', 'path': 'safe.py', 'line_start': 1,\n"
            "        'line_end': 200, 'title': 'Synthetic', 'body': 'Synthetic'}]\n"
            "    if mode == 'bad_path': review['findings'][0]['path'] = 'unreviewed.py'\n"
            "    if mode == 'bool_line': review['findings'][0]['line_start'] = True\n"
            "if mode == 'denial': envelope['permission_denials'] = [{'secret': 'never-retain'}]\n"
            "if mode == 'missing_denials': del envelope['permission_denials']\n"
            "if mode == 'wrong_denials': envelope['permission_denials'] = 0\n"
            "if mode == 'no_structure': del envelope['structured_output']\n"
            "if mode == 'cli_error':\n"
            "    envelope.update(is_error=True, result='never-retain-private-provider-error')\n"
            "if mode == 'cli_subtype': envelope['subtype'] = 'error_max_turns'\n"
            "if mode == 'malformed': print('never-retain-not-json'); sys.exit(0)\n"
            "if mode == 'duplicate_json': print('{\"type\":\"result\",\"type\":\"result\"}'); sys.exit(0)\n"
            "if mode == 'nonfinite': print('{\"cost\":NaN}'); sys.exit(0)\n"
            "if mode == 'invalid_utf8': os.write(1, b'\\xff'); sys.exit(0)\n"
            "if mode == 'stdout_flood': os.write(1, b'x' * (256 * 1024)); time.sleep(60)\n"
            "if mode == 'stderr_flood': os.write(2, b'x' * (256 * 1024)); time.sleep(60)\n"
            "if mode == 'timeout':\n"
            "    open('review-started', 'w').close(); time.sleep(60)\n"
            "if mode == 'closed_streams': os.close(1); os.close(2); time.sleep(60)\n"
            "if mode == 'ignore_term': signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)\n"
            "if mode == 'descendant':\n"
            "    if os.fork() == 0:\n"
            "        signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60); os._exit(0)\n"
            "print(json.dumps(envelope))\n"
            "if mode == 'nonzero': sys.exit(2)\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return str(fake)

    def args(self, mode="ok", **changes):
        args = SimpleNamespace(
            repo=self.repo, revision=self.head, base=None, path=["safe.py"], timeout=5,
            claude=self.executable(mode), describe=False,
        )
        for name, value in changes.items():
            setattr(args, name, value)
        return args

    def call(self, mode="ok", **changes):
        return bridge.review(self.args(mode, **changes))

    def assert_unavailable(self, result, reason):
        self.assertEqual(result["status"], "unavailable", result)
        self.assertEqual(result["reason"], reason, result)
        self.assertIsNone(result["review"])
        self.assertNotIn("never-retain", json.dumps(result))

    def test_positive_binding_flags_environment_and_cleanup(self):
        with patch.dict(os.environ, {name: "fixture-only" for name in (
            "UNRELATED_SECRET", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
            "SYMPHONY_GITHUB_TOKEN", "CLAUDE_CONFIG_DIR",
        )}):
            result = self.call("finding")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["source"]["revision"], self.head)
        self.assertEqual(result["review"]["revision"], self.head)
        self.assertEqual(result["review"]["review_key"], result["review_key"])
        self.assertEqual(result["permission_denials"], 0)
        self.assertEqual(result["scratch_cleanup"], "removed")
        self.assertEqual(len(result["review"]["findings"]), 1)
        for process in result["processes"]:
            self.assertTrue(process["cleanup"]["leader_reaped"])
            self.assertEqual(process["cleanup"]["group_probe"], "absent")
            self.assertTrue(process["stdout_eof"] and process["stderr_eof"])
        self.assertFalse(list(self.repo.glob("claude-review-*")))

    def test_dirty_and_untracked_files_are_not_reviewed_or_modified(self):
        dirty = "Changed after commit.\n"
        (self.repo / "safe.py").write_text(dirty)
        (self.repo / "private-untracked.txt").write_text("Synthetic untracked data.\n")
        result = self.call("assert_frozen")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual((self.repo / "safe.py").read_text(), dirty)
        self.assertEqual(result["source"]["files"][0]["current"]["sha256"],
                         bridge.digest(b"def value():\n    return 1\n"))

    def test_unrelated_commit_keeps_key_but_selected_change_invalidates_it(self):
        first = self.call(describe=True)
        (self.repo / "other.md").write_text("Unrelated update.\n")
        self.head = self.commit()
        second = self.call(describe=True)
        self.assertNotEqual(first["source"]["revision"], second["source"]["revision"])
        self.assertEqual(first["review_key"], second["review_key"])
        (self.repo / "safe.py").write_text("def value():\n    return 2\n")
        self.head = self.commit()
        third = self.call(describe=True)
        self.assertNotEqual(first["review_key"], third["review_key"])
        self.assertFalse(any(p["stage"] != "source" for p in third["processes"]))

    def test_base_contents_and_absent_new_file_are_explicit(self):
        base = self.head
        (self.repo / "new.py").write_text("new = True\n")
        (self.repo / "safe.py").write_text("def value():\n    return 2\n")
        self.head = self.commit()
        result = self.call(base=base, path=["safe.py", "new.py"])
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["source"]["base_revision"], base)
        new, existing = result["source"]["files"]
        self.assertIsNone(new["base"])
        self.assertNotEqual(existing["current"]["sha256"], existing["base"]["sha256"])

    def test_selected_file_mode_change_invalidates_key(self):
        first = self.call(describe=True)
        (self.repo / "safe.py").chmod(0o755)
        self.head = self.commit()
        second = self.call(describe=True)
        self.assertNotEqual(first["review_key"], second["review_key"])
        self.assertEqual(second["source"]["files"][0]["current"]["mode"], "100755")

    def test_protocol_failure_controls_after_genuine_positive(self):
        self.assertEqual(self.call()["status"], "completed")
        cases = {
            "refusal": "incomplete_review", "partial": "incomplete_review",
            "missing_coverage": "invalid_result", "wrong_revision": "source_binding_mismatch",
            "wrong_key": "source_binding_mismatch", "extra_field": "invalid_result",
            "bad_line": "finding_location_mismatch", "bad_path": "invalid_result",
            "bool_line": "invalid_result", "denial": "permission_denied",
            "missing_denials": "permission_evidence_missing",
            "wrong_denials": "permission_evidence_missing",
            "no_structure": "structured_result_missing", "cli_error": "cli_unsuccessful",
            "cli_subtype": "cli_unsuccessful", "malformed": "invalid_json",
            "duplicate_json": "invalid_json", "nonfinite": "invalid_json",
            "invalid_utf8": "invalid_json", "nonzero": "process_exit",
        }
        for mode, reason in cases.items():
            with self.subTest(mode=mode):
                result = self.call(mode)
                self.assert_unavailable(result, reason)
                if mode == "denial":
                    self.assertEqual(result["permission_denials"], 1)

    def test_duplicate_coverage_cannot_hide_an_unreviewed_file(self):
        result = self.call("duplicate_coverage", path=["safe.py", "other.md"])
        self.assert_unavailable(result, "coverage_mismatch")

    def test_unsupported_cli_stops_before_review(self):
        for mode, reason in (("unsupported", "unsupported_cli_flags"),
                             ("flag_prefix", "unsupported_cli_flags"),
                             ("version_bad", "unrecognized_cli_version")):
            with self.subTest(mode=mode):
                result = self.call(mode)
                self.assert_unavailable(result, reason)
                self.assertFalse(any(p["stage"] == "review" for p in result["processes"]))

    def test_missing_cli_is_unavailable_and_describe_never_launches_it(self):
        args = self.args()
        args.claude = str(self.root / "not-installed")
        self.assert_unavailable(bridge.review(args), "claude_unavailable")
        args.describe = True
        self.assertEqual(bridge.review(args)["status"], "described")

    def test_output_floods_are_bounded_and_stderr_is_not_retained(self):
        for mode in ("stdout_flood", "stderr_flood"):
            with self.subTest(mode=mode):
                began = time.monotonic()
                result = self.call(mode)
                self.assert_unavailable(result, "output_limit")
                self.assertLess(time.monotonic() - began, 3)
                record = result["processes"][-1]
                observed = record["stdout_bytes_observed"] + record["stderr_bytes_observed"]
                self.assertLessEqual(observed, bridge.MAX_OUTPUT_BYTES + 4096)
                self.assertTrue(record["cleanup"]["leader_reaped"])

    def test_timeout_covers_probes_closed_streams_and_ignored_term(self):
        for mode in ("version_timeout", "timeout", "closed_streams", "ignore_term", "descendant"):
            with self.subTest(mode=mode):
                began = time.monotonic()
                result = self.call(mode, timeout=0.4)
                self.assert_unavailable(result, "timeout")
                self.assertLess(time.monotonic() - began, 2)
                self.assertTrue(result["processes"][-1]["cleanup"]["leader_reaped"])
                self.assertIn(result["processes"][-1]["cleanup"]["kill"], ("sent", "absent", "denied"))

    def test_blocked_stdin_does_not_escape_the_deadline(self):
        (self.repo / "safe.py").write_text("x" * 60000)
        self.head = self.commit()
        result = self.call("blocked_input", timeout=0.4)
        self.assert_unavailable(result, "timeout")
        self.assertFalse(result["processes"][-1]["stdin_complete"])

    def test_cleanup_denial_does_not_become_absent_when_leader_is_reaped(self):
        process = Mock(pid=12345, returncode=0)
        with patch.object(bridge.os, "killpg", side_effect=PermissionError):
            facts = bridge.cleanup(process)
        self.assertEqual(facts, {"term": "denied", "kill": "denied",
                                 "leader_reaped": True, "group_probe": "denied"})

    def test_unconfirmed_group_cannot_complete_a_review(self):
        real_cleanup = bridge.cleanup

        def unconfirmed(process):
            facts = real_cleanup(process)
            facts["group_probe"] = "denied"
            return facts

        with patch.object(bridge, "cleanup", side_effect=unconfirmed):
            result = self.call()
        self.assert_unavailable(result, "cleanup_unconfirmed")
        self.assertEqual(result["processes"][-1]["cleanup"]["group_probe"], "denied")

    def test_scratch_cleanup_failure_is_explicit(self):
        real_temp = tempfile.TemporaryDirectory(dir=self.repo)
        self.addCleanup(real_temp.cleanup)
        fake = SimpleNamespace(name=real_temp.name, cleanup=Mock(side_effect=OSError))
        with patch.object(bridge.tempfile, "TemporaryDirectory", return_value=fake):
            result = self.call()
        self.assert_unavailable(result, "scratch_cleanup_failed")
        self.assertEqual(result["scratch_cleanup"], "failed")

    def test_invalid_scope_revision_and_timeout_never_reach_claude(self):
        cases = [
            ({"path": ["../outside"]}, "invalid_scope"),
            ({"path": ["safe.py", "safe.py"]}, "invalid_scope"),
            ({"path": [".git/config"]}, "invalid_scope"),
            ({"path": ["safe.py/"]}, "invalid_scope"),
            ({"path": ["./safe.py"]}, "invalid_scope"),
            ({"path": ["safe.py"] * 33}, "invalid_scope"),
            ({"revision": "HEAD"}, "invalid_revision"),
            ({"base": "main"}, "invalid_base_revision"),
            ({"path": ["untracked.py"]}, "source_missing"),
            ({"timeout": float("nan")}, "invalid_timeout"),
            ({"timeout": 601}, "invalid_timeout"),
        ]
        for changes, reason in cases:
            with self.subTest(changes=changes):
                result = self.call(**changes)
                self.assert_unavailable(result, reason)
                self.assertFalse(any(p["stage"] != "source" for p in result["processes"]))

    def test_symlink_directory_binary_and_oversize_sources_are_refused(self):
        (self.repo / "link").symlink_to("safe.py")
        (self.repo / "folder").mkdir()
        (self.repo / "folder/child").write_text("Synthetic\n")
        (self.repo / "binary").write_bytes(b"\0")
        (self.repo / "huge").write_bytes(b"x" * (bridge.MAX_FILE_BYTES + 1))
        self.head = self.commit()
        for path, reason in (("link", "not_regular_source"), ("folder", "not_regular_source"),
                             ("binary", "binary_source"), ("huge", "source_file_limit")):
            with self.subTest(path=path):
                self.assert_unavailable(self.call(path=[path]), reason)

    def test_aggregate_source_limit_includes_base(self):
        for name in ("a", "b"):
            (self.repo / name).write_bytes(b"x" * bridge.MAX_FILE_BYTES)
        self.head = self.commit()
        self.assert_unavailable(self.call(base=self.head, path=["a", "b"]), "source_total_limit")

    def test_sigterm_returns_unavailable_after_process_cleanup(self):
        args = self.args("timeout")
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts/claude_review.py"), "--repo", str(self.repo),
             "--revision", self.head, "--path", "safe.py", "--claude", args.claude],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # The trusted fake announces readiness; cancellation cannot race its startup.
            deadline = time.monotonic() + 3
            while not list(self.repo.glob("claude-review-*/review-started")) and process.poll() is None:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            process.send_signal(signal.SIGTERM)
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=3)
            result = json.loads(stdout)
            self.assert_unavailable(result, "interrupted")
            self.assertEqual(process.returncode, 1)
            self.assertEqual(stderr, b"")
            self.assertEqual(result["scratch_cleanup"], "removed")
            self.assertTrue(result["processes"][-1]["cleanup"]["leader_reaped"])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
