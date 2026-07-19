import hashlib
import json
import sys
import io
import contextlib
import os
import stat
import types
import signal
import subprocess
import tempfile
import unittest
import time
import threading
from pathlib import Path
from unittest import mock

from contextlib import ExitStack

import dataclasses

from mwdiff import (
    LinkCheck,
    LinkGateResolution,
    ReconstructionFocus,
    ReconstructionScore,
    UnitSnapshot,
    resolve_link_gate,
    score_reconstruction,
    select_reconstruction_focus,
    verify_current_link,
    McpClient,
    McpProtocolError,
    McpToolError,
    MAX_RECONSTRUCTION_STATE,
    OpenProgram,
    PreparedProgram,
    ProcessResult,
    RECONSTRUCTION_STATE_SCHEMA,
    SourceTransaction,
    append_reconstruction_event,
    apply_ghidra_operations,
    collect_ghidra_evidence,
    invoke_model,
    load_reconstruction_state,
    mcp_text,
    parse_open_programs,
    prepare_ghidra_program,
    reconstruction_identity,
    reconstruction_state_root,
    render_source_edits,
    require_ghidra_tools,
    run_bounded_process,
    save_reconstruction_state,
    strict_json_loads,
    validate_analysis_response,
    validate_proposal_response,
)


class FakeResponse:
    def __init__(self, body=b"", status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]


class TestMcpClient(unittest.TestCase):
    def test_initializes_session_and_parses_sse_tools(self):
        responses = iter([
            FakeResponse(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "1"},
                    },
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Mcp-Session-Id": "session-1",
                },
            ),
            FakeResponse(status=202),
            FakeResponse(
                b"event: message\n"
                b"data: {\"jsonrpc\":\"2.0\",\"id\":2,"
                b"\"result\":{\"tools\":[{\"name\":\"get_code\","
                b"\"inputSchema\":{\"type\":\"object\"}}]}}\n\n",
                headers={"Content-Type": "text/event-stream"},
            ),
        ])
        requests = []

        def open_request(request, timeout):
            requests.append((request, timeout))
            return next(responses)

        client = McpClient("http://127.0.0.1:8080/mcp", 7, open_request)
        client.initialize()
        tools = client.list_tools()

        self.assertEqual(set(tools), {"get_code"})
        headers = {
            key.lower(): value
            for key, value in requests[-1][0].header_items()
        }
        self.assertEqual(headers["mcp-session-id"], "session-1")
        self.assertEqual(headers["mcp-protocol-version"], "2025-06-18")
        self.assertIn("text/event-stream", headers["accept"])
        self.assertEqual(requests[-1][1], 7)

    def test_rejects_duplicate_json_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: schema"):
            strict_json_loads('{"schema":"a","schema":"b"}')

    def test_rejects_non_json_constants_and_malformed_content(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
            strict_json_loads('{"score":NaN}')
        with self.assertRaisesRegex(McpProtocolError, "content list"):
            mcp_text({"content": "not-a-list"})

    def test_distinguishes_tool_rejection_from_protocol_failure(self):
        client = McpClient("http://127.0.0.1:8080/mcp")
        client.request = mock.Mock(return_value={
            "isError": True,
            "content": [{"type": "text", "text": "unknown function"}],
        })
        with self.assertRaisesRegex(McpToolError, "unknown function"):
            client.call("get_code", {})

    def test_rejects_credentialed_or_non_http_urls(self):
        for url in (
            "ftp://127.0.0.1/mcp",
            "http://user:pw@127.0.0.1/mcp",
            "http://127.0.0.1/mcp?x=1",
        ):
            with self.assertRaises(ValueError):
                McpClient(url)


def _analysis(**overrides):
    value = {
        "schema": "mwdiff.reconstruct.analyze.v1",
        "summary": "x",
        "ghidra_ops": [],
    }
    value.update(overrides)
    return value


def _proposal_edit(**overrides):
    edit = {
        "path": "src/demo.cpp",
        "file_sha256": "a" * 64,
        "old": "old",
        "new": "new",
    }
    edit.update(overrides)
    return edit


def _proposal(**overrides):
    value = {
        "schema": "mwdiff.reconstruct.propose.v1",
        "summary": "x",
        "source_edits": [],
    }
    value.update(overrides)
    return value


class TestModelProtocol(unittest.TestCase):
    def test_validates_exact_phase_schemas(self):
        analysis = validate_analysis_response({
            "schema": "mwdiff.reconstruct.analyze.v1",
            "summary": "prototype evidence",
            "ghidra_ops": [{
                "op": "set_prototype",
                "function": "FUN_00001000",
                "prototype": "int FUN_00001000(void)",
                "reason": "all returns are integers",
            }],
        })
        proposal = validate_proposal_response({
            "schema": "mwdiff.reconstruct.propose.v1",
            "summary": "direct condition",
            "source_edits": [{
                "path": "src/demo.cpp",
                "file_sha256": "a" * 64,
                "old": "if (check() != FALSE)",
                "new": "if (check())",
            }],
        })
        self.assertEqual(analysis["ghidra_ops"][0]["op"], "set_prototype")
        self.assertEqual(proposal["source_edits"][0]["path"], "src/demo.cpp")

    def test_rejects_unknown_fields_and_operations(self):
        with self.assertRaisesRegex(ValueError, "unknown fields: extra"):
            validate_analysis_response({
                "schema": "mwdiff.reconstruct.analyze.v1",
                "summary": "x",
                "ghidra_ops": [],
                "extra": True,
            })
        with self.assertRaisesRegex(ValueError, "unknown Ghidra operation"):
            validate_analysis_response({
                "schema": "mwdiff.reconstruct.analyze.v1",
                "summary": "x",
                "ghidra_ops": [{"op": "patch_bytes"}],
            })
        with self.assertRaisesRegex(ValueError, "operation tag must be a string"):
            validate_analysis_response({
                "schema": "mwdiff.reconstruct.analyze.v1",
                "summary": "x",
                "ghidra_ops": [{"op": []}],
            })

    def test_rejects_wrong_scalar_types(self):
        with self.assertRaisesRegex(ValueError, "summary must be a string"):
            validate_analysis_response(_analysis(summary=3))
        with self.assertRaisesRegex(ValueError, "ghidra_ops must be a list"):
            validate_analysis_response(_analysis(ghidra_ops={}))
        with self.assertRaisesRegex(ValueError, "source_edits must be a list"):
            validate_proposal_response(_proposal(source_edits="nope"))
        with self.assertRaisesRegex(ValueError, "offset must be an integer"):
            validate_analysis_response(_analysis(ghidra_ops=[{
                "op": "set_struct_field", "structure_name": "s",
                "offset": True, "data_type": "int", "field_name": "f",
                "reason": "r",
            }]))

    def test_rejects_invalid_identifiers(self):
        with self.assertRaisesRegex(ValueError, "new_name must be a C identifier"):
            validate_analysis_response(_analysis(ghidra_ops=[{
                "op": "rename_function", "function": "FUN_1",
                "new_name": "1bad", "reason": "r",
            }]))
        with self.assertRaisesRegex(ValueError, "field_name must be a C identifier"):
            validate_analysis_response(_analysis(ghidra_ops=[{
                "op": "set_struct_field", "structure_name": "s",
                "offset": 0, "data_type": "int", "field_name": "a-b",
                "reason": "r",
            }]))

    def test_rejects_negative_offsets_and_bad_bounds(self):
        base = {
            "op": "set_struct_field", "structure_name": "s",
            "data_type": "int", "field_name": "f", "reason": "r",
        }
        with self.assertRaisesRegex(ValueError, "offset must be an integer >= 0"):
            validate_analysis_response(
                _analysis(ghidra_ops=[dict(base, offset=-4)]))
        with self.assertRaisesRegex(ValueError, "pointer_level must be <= 8"):
            validate_analysis_response(
                _analysis(ghidra_ops=[dict(base, offset=0, pointer_level=9)]))
        with self.assertRaisesRegex(ValueError, "array_count must be an integer >= 1"):
            validate_analysis_response(
                _analysis(ghidra_ops=[dict(base, offset=0, array_count=0)]))

    def test_rejects_excessive_counts(self):
        operation = {
            "op": "rename_function", "function": "FUN_1",
            "new_name": "ok", "reason": "r",
        }
        with self.assertRaisesRegex(ValueError, "too many Ghidra operations"):
            validate_analysis_response(_analysis(ghidra_ops=[operation] * 129))
        with self.assertRaisesRegex(ValueError, "too many source edits"):
            validate_proposal_response(
                _proposal(source_edits=[_proposal_edit()] * 257))

    def test_rejects_nul_text(self):
        with self.assertRaisesRegex(ValueError, "prototype contains NUL"):
            validate_analysis_response(_analysis(ghidra_ops=[{
                "op": "set_prototype", "function": "FUN_1",
                "prototype": "int f(\x00)", "reason": "r",
            }]))
        with self.assertRaisesRegex(ValueError, "data_type contains NUL"):
            validate_analysis_response(_analysis(ghidra_ops=[{
                "op": "retype_variable", "function": "FUN_1",
                "variable": "v", "data_type": "in\x00t", "reason": "r",
            }]))
        with self.assertRaisesRegex(ValueError, "path contains NUL"):
            validate_proposal_response(
                _proposal(source_edits=[_proposal_edit(path="a\x00b")]))

    def test_allows_newlines_in_c_definition(self):
        value = validate_analysis_response(_analysis(ghidra_ops=[{
            "op": "create_struct",
            "c_definition": "struct s {\n    int a;\n};",
            "reason": "layout evidence",
        }]))
        self.assertIn("\n", value["ghidra_ops"][0]["c_definition"])

    def test_rejects_malformed_sha256(self):
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            validate_proposal_response(
                _proposal(source_edits=[_proposal_edit(file_sha256="A" * 64)]))


def _write_wrapper(directory, body):
    command = Path(directory) / "model"
    command.write_text("#!/usr/bin/env python3\n" + body)
    command.chmod(0o755)
    return command


def _read_pids(pid_file):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if pid_file.exists() and pid_file.read_text().strip():
            return [int(token) for token in pid_file.read_text().split()]
        time.sleep(0.05)
    raise AssertionError("wrapper never wrote its pid file")


class TestInvokeModel(unittest.TestCase):
    def test_invokes_one_executable_without_a_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "model"
            command.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "request = json.load(sys.stdin)\n"
                "json.dump({'schema': request['schema'], 'summary': 'ok', "
                "'ghidra_ops': []}, sys.stdout)\n"
            )
            command.chmod(0o755)
            response = invoke_model(command, {
                "schema": "mwdiff.reconstruct.analyze.v1"
            }, 5)
            self.assertEqual(response["summary"], "ok")

    def test_rejects_oversized_request(self):
        request = {"schema": "x", "blob": "a" * (32 * 1024 * 1024)}
        with self.assertRaisesRegex(ValueError, "request"):
            invoke_model("/bin/true", request, 5)

    def test_rejects_nonzero_exit_with_bounded_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            command = _write_wrapper(
                directory,
                "import sys\n"
                "sys.stderr.write('boom ' * 20000)\n"
                "sys.exit(3)\n",
            )
            with self.assertRaisesRegex(RuntimeError, "exited 3") as caught:
                invoke_model(command, {"schema": "x"}, 10)
            self.assertLess(len(str(caught.exception)), 8192)
            self.assertIn("boom", str(caught.exception))

    def test_rejects_non_object_and_invalid_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            command = _write_wrapper(directory, "print('[1, 2]')\n")
            with self.assertRaisesRegex(ValueError, "object"):
                invoke_model(command, {"schema": "x"}, 10)


def _assert_pids_dead(test, pids):
    deadline = time.monotonic() + 10
    remaining = list(pids)
    while remaining and time.monotonic() < deadline:
        still_alive = []
        for pid in remaining:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            still_alive.append(pid)
        remaining = still_alive
        if remaining:
            time.sleep(0.1)
    test.assertEqual(remaining, [], f"processes still alive: {remaining}")


@unittest.skipUnless(os.name == "posix", "POSIX process-group semantics")
class TestProcessBoundaries(unittest.TestCase):
    def test_stdout_overflow_kills_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pids"
            command = _write_wrapper(
                directory,
                "import os, sys, time\n"
                f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                "sys.stdout.write('x' * (9 * 1024 * 1024))\n"
                "sys.stdout.flush()\n"
                "time.sleep(300)\n",
            )
            with self.assertRaisesRegex(RuntimeError, "stdout"):
                invoke_model(command, {"schema": "x"}, 60)
            _assert_pids_dead(self, _read_pids(pid_file))

    def test_stderr_limit_is_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pids"
            command = _write_wrapper(
                directory,
                "import os, sys, time\n"
                f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                "sys.stderr.write('e' * 4096)\n"
                "sys.stderr.flush()\n"
                "time.sleep(300)\n",
            )
            with self.assertRaisesRegex(RuntimeError, "stderr"):
                run_bounded_process(
                    [str(command)], timeout=60,
                    stdout_limit=1024 * 1024, stderr_limit=1024,
                )
            _assert_pids_dead(self, _read_pids(pid_file))

    def test_timeout_kills_whole_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pids"
            command = _write_wrapper(
                directory,
                "import os, subprocess, time\n"
                "child = subprocess.Popen(['sleep', '300'])\n"
                f"open({str(pid_file)!r}, 'w').write("
                "f'{os.getpid()} {child.pid}')\n"
                "time.sleep(300)\n",
            )
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                invoke_model(command, {"schema": "x"}, 2)
            pids = _read_pids(pid_file)
            self.assertEqual(len(pids), 2)
            _assert_pids_dead(self, pids)

    def test_raising_cancel_kills_whole_process_group(self):
        class Cancelled(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pids"
            command = _write_wrapper(
                directory,
                "import os, subprocess, time\n"
                "child = subprocess.Popen(['sleep', '300'])\n"
                f"open({str(pid_file)!r}, 'w').write("
                "f'{os.getpid()} {child.pid}')\n"
                "time.sleep(300)\n",
            )

            def cancel():
                if pid_file.exists() and pid_file.read_text().strip():
                    raise Cancelled("stop now")

            with self.assertRaises(Cancelled):
                invoke_model(command, {"schema": "x"}, 60, cancel=cancel)
            pids = _read_pids(pid_file)
            self.assertEqual(len(pids), 2)
            _assert_pids_dead(self, pids)

    def test_bounded_process_returns_captured_output(self):
        result = run_bounded_process(
            ["/bin/sh", "-c", "echo out; echo err >&2"],
            timeout=10, stdout_limit=1024, stderr_limit=1024,
        )
        self.assertIsInstance(result, ProcessResult)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out\n")
        self.assertEqual(result.stderr, b"err\n")

    def test_grandchild_holding_stdout_cannot_hang_ordinary_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pids"
            command = _write_wrapper(
                directory,
                "import os, subprocess, sys\n"
                "child = subprocess.Popen(['sleep', '300'])\n"
                f"open({str(pid_file)!r}, 'w').write("
                "f'{os.getpid()} {child.pid}')\n"
                "sys.stdout.write('{}')\n"
                "sys.stdout.flush()\n",
            )
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                run_bounded_process(
                    [str(command)], timeout=2,
                    stdout_limit=1024 * 1024, stderr_limit=1024 * 1024,
                )
            self.assertLess(time.monotonic() - started, 15)
            pids = _read_pids(pid_file)
            self.assertEqual(len(pids), 2)
            _assert_pids_dead(self, pids)

    def test_overflow_at_exit_never_returns_truncated_success(self):
        with tempfile.TemporaryDirectory() as directory:
            command = _write_wrapper(
                directory,
                "import sys\n"
                "sys.stdout.write('x' * 4096)\n",
            )
            with self.assertRaisesRegex(RuntimeError, "stdout exceeded"):
                run_bounded_process(
                    [str(command)], timeout=10,
                    stdout_limit=1024, stderr_limit=1024,
                )


class FakeMcpClient:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.calls = []
        self.timeout = 30

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        if not self.results:
            return {"content": [{"type": "text", "text": "ok"}]}
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return {"content": [{"type": "text", "text": result}]}


def _ghidra_args(**overrides):
    values = {
        "ghidra_program": None,
        "ghidra_language": None,
        "ghidra_compiler": None,
        "mcp_timeout": 30,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _ghidra_unit(target="/tmp/project/build/GZLP01/demo/obj/demo.o"):
    return types.SimpleNamespace(name="demo.o", target=Path(target))


def _calls_cancel(client, threshold):
    def cancel():
        if len(client.calls) >= threshold:
            raise KeyboardInterrupt
    return cancel


class TestGhidraAdapter(unittest.TestCase):
    LISTING = """Open Programs in Ghidra:

1. demo.o [ACTIVE]
   Project Path: /mwdiff/demo-abc/demo.o
   Executable Path: /tmp/project/build/GZLP01/demo/obj/demo.o
   Format: Executable and Linking Format (ELF)
   Language: PowerPC:BE:32:e500
"""

    def test_parses_explicit_program_identity(self):
        programs = parse_open_programs(self.LISTING)
        self.assertEqual(programs, [OpenProgram(
            "demo.o",
            "/mwdiff/demo-abc/demo.o",
            "/tmp/project/build/GZLP01/demo/obj/demo.o",
            "PowerPC:BE:32:e500",
        )])

    def test_rejects_established_symbol_rename(self):
        client = FakeMcpClient()
        operations = [{
            "op": "rename_function",
            "function": "Create__8demo_cFv",
            "new_name": "create",
            "reason": "guess",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("not a placeholder", failures[0]["error"])
        self.assertEqual(client.calls, [])

    def test_maps_and_confirms_placeholder_rename(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
            "Renamed FUN_00001000 to load_resource",
            "Functions matching pattern:\n"
            "- load_resource @ 00001000 (0 params)\n",
        ])
        operations = [{
            "op": "rename_function",
            "function": "FUN_00001000",
            "new_name": "load_resource",
            "reason": "xref reaches resource loader",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["get_functions", "rename_symbol", "get_functions"],
        )
        self.assertTrue(all(
            arguments["program_name"] == "/mwdiff/demo/demo.o"
            for _, arguments in client.calls
        ))

    def test_requires_import_tool_when_importing(self):
        with self.assertRaisesRegex(ValueError, "import_file"):
            require_ghidra_tools({"get_functions"}, importing=True)

    def test_unconfirmed_rename_is_protocol_error(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
            "Renamed FUN_00001000 to load_resource",
            "Functions in program:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
        ])
        operations = [{
            "op": "rename_function",
            "function": "FUN_00001000",
            "new_name": "load_resource",
            "reason": "xref reaches resource loader",
        }]
        with self.assertRaisesRegex(McpProtocolError, "not reflected"):
            apply_ghidra_operations(client, "/mwdiff/demo/demo.o", operations)

    def test_missing_pre_read_entity_is_rejected_operation(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "No functions found matching pattern: \"FUN_00001000\"\n",
        ])
        operations = [{
            "op": "rename_function",
            "function": "FUN_00001000",
            "new_name": "load_resource",
            "reason": "xref reaches resource loader",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("matched 0", failures[0]["error"])
        self.assertEqual([name for name, _ in client.calls], ["get_functions"])

    def test_tool_rejected_mutation_is_recorded_failure(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
            McpToolError("Ghidra rename_symbol: symbol is locked"),
        ])
        operations = [{
            "op": "rename_function",
            "function": "FUN_00001000",
            "new_name": "load_resource",
            "reason": "xref reaches resource loader",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("locked", failures[0]["error"])
        self.assertEqual(
            [name for name, _ in client.calls],
            ["get_functions", "rename_symbol"],
        )

    def test_confirms_data_rename_at_same_address(self):
        client = FakeMcpClient([
            "Defined Data Elements:\n"
            "@ 00011532 [undefined2] Value: 82BAh (DAT_00011532)\n",
            "Renamed DAT_00011532 to l_counter",
            "Defined Data Elements:\n"
            "@ 00011532 [undefined2] Value: 82BAh (l_counter)\n",
        ])
        operations = [{
            "op": "rename_data",
            "address_or_name": "DAT_00011532",
            "new_name": "l_counter",
            "reason": "counter store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["get_data_vars", "variables", "get_data_vars"],
        )

    def test_confirms_variable_rename_with_same_storage(self):
        client = FakeMcpClient([
            "Variables in function: FUN_00001000\n\n"
            "## Local Variables\n"
            "  - int local_8 (Stack[-0x8])\n",
            "Renamed local_8 to speed",
            "Variables in function: FUN_00001000\n\n"
            "## Local Variables\n"
            "  - int speed (Stack[-0x8])\n",
        ])
        operations = [{
            "op": "rename_variable",
            "function": "FUN_00001000",
            "variable": "local_8",
            "new_name": "speed",
            "reason": "velocity math",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["variables", "rename_symbol", "variables"],
        )
        self.assertEqual(client.calls[0][1]["action"], "list")
        self.assertEqual(client.calls[0][1]["function_name"], "FUN_00001000")

    def test_confirms_prototype_at_same_entry_point(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
            "Prototype set",
            "Function Information:\n"
            "Name: load_resource\n"
            "Entry Point: 00001000\n"
            "Signature: int load_resource(int param)\n",
        ])
        operations = [{
            "op": "set_prototype",
            "function": "FUN_00001000",
            "prototype": "int load_resource(int param)",
            "reason": "call signature",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["get_functions", "variables", "analyze_function"],
        )
        self.assertEqual(client.calls[2][1]["function_name"], "load_resource")

    def test_prototype_may_not_rename_established_function(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- Create__8demo_cFv @ 00001000 (0 params)\n",
        ])
        operations = [{
            "op": "set_prototype",
            "function": "Create__8demo_cFv",
            "prototype": "int create(void* param)",
            "reason": "guess",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("not a placeholder", failures[0]["error"])
        self.assertEqual([name for name, _ in client.calls], ["get_functions"])

    def test_prototype_keeping_established_name_is_allowed(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- Create__8demo_cFv @ 00001000 (0 params)\n",
            "Prototype set",
            "Function Information:\n"
            "Name: Create__8demo_cFv\n"
            "Entry Point: 00001000\n"
            "Signature: int Create__8demo_cFv(void* param)\n",
        ])
        operations = [{
            "op": "set_prototype",
            "function": "Create__8demo_cFv",
            "prototype": "int Create__8demo_cFv(void* param)",
            "reason": "call signature",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)

    STRUCT_HEADER = (
        "Data Type: demo_prm_c\n"
        "Category: /\n"
        "Size: 32 bytes\n\n"
        "Type: Structure\n\n"
        "Fields:\n"
    )

    def test_rejects_established_struct_field(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0010 [  2] short                mTimer\n",
        ])
        operations = [{
            "op": "set_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "data_type": "s16",
            "field_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("not a placeholder", failures[0]["error"])
        self.assertEqual([name for name, _ in client.calls], ["types"])

    def test_rejects_established_struct_field_with_dollar_name(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0010 [  2] short                data$1234\n",
        ])
        operations = [{
            "op": "set_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "data_type": "s16",
            "field_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("not a placeholder", failures[0]["error"])
        self.assertEqual([name for name, _ in client.calls], ["types"])

    def test_sets_struct_field_in_undefined_gap(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0000 [  4] int                  mode\n",
            "Field set",
            self.STRUCT_HEADER
            + "  +0x0000 [  4] int                  mode\n"
            + "  +0x0010 [  2] s16                  timer\n",
        ])
        operations = [{
            "op": "set_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "data_type": "s16",
            "field_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["types", "struct", "types"],
        )

    def test_struct_field_with_wrong_type_is_protocol_error(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0000 [  4] int                  mode\n",
            "Field set",
            self.STRUCT_HEADER
            + "  +0x0000 [  4] int                  mode\n"
            + "  +0x0010 [  4] int                  timer\n",
        ])
        operations = [{
            "op": "set_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "data_type": "s16",
            "field_name": "timer",
            "reason": "timer store",
        }]
        with self.assertRaises(McpProtocolError):
            apply_ghidra_operations(client, "/mwdiff/demo/demo.o", operations)

    def test_sets_struct_field_over_placeholder_name(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0010 [  2] undefined2           field_0x10\n",
            "Field set",
            self.STRUCT_HEADER
            + "  +0x0010 [  2] s16                  timer\n",
        ])
        operations = [{
            "op": "set_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "data_type": "s16",
            "field_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)

    def test_confirms_struct_field_rename_at_same_offset(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0010 [  2] undefined2           field_0x10\n",
            "Field renamed",
            self.STRUCT_HEADER
            + "  +0x0010 [  2] undefined2           timer\n",
        ])
        operations = [{
            "op": "rename_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "new_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)

    def test_struct_rename_requires_existing_field(self):
        client = FakeMcpClient([self.STRUCT_HEADER])
        operations = [{
            "op": "rename_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "new_name": "timer",
            "reason": "timer store",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("no field", failures[0]["error"])
        self.assertEqual([name for name, _ in client.calls], ["types"])

    def test_struct_field_at_wrong_offset_is_protocol_error(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0010 [  2] undefined2           field_0x10\n",
            "Field renamed",
            self.STRUCT_HEADER
            + "  +0x0014 [  2] undefined2           timer\n",
        ])
        operations = [{
            "op": "rename_struct_field",
            "structure_name": "demo_prm_c",
            "offset": 16,
            "new_name": "timer",
            "reason": "timer store",
        }]
        with self.assertRaises(McpProtocolError):
            apply_ghidra_operations(client, "/mwdiff/demo/demo.o", operations)

    def test_creates_struct_only_when_absent(self):
        client = FakeMcpClient([
            "Data type not found: demo_prm_c",
            "Structure created",
            self.STRUCT_HEADER
            + "  +0x0000 [  1] u8                   mode\n",
        ])
        operations = [{
            "op": "create_struct",
            "c_definition": "struct demo_prm_c { u8 mode; };",
            "reason": "parameter block",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(success), 1)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["types", "struct", "types"],
        )

    def test_existing_struct_rejects_create(self):
        client = FakeMcpClient([
            self.STRUCT_HEADER
            + "  +0x0000 [  1] u8                   mode\n",
        ])
        operations = [{
            "op": "create_struct",
            "c_definition": "struct demo_prm_c { u8 mode; };",
            "reason": "parameter block",
        }]
        success, failures = apply_ghidra_operations(
            client, "/mwdiff/demo/demo.o", operations
        )
        self.assertEqual(success, [])
        self.assertIn("already exists", failures[0]["error"])

    def test_cancellation_after_first_readback_stops_batch(self):
        client = FakeMcpClient([
            "Functions matching pattern:\n"
            "- FUN_00001000 @ 00001000 (0 params)\n",
            "Renamed FUN_00001000 to load_resource",
            "Functions in program:\n"
            "- load_resource @ 00001000 (0 params)\n",
        ])
        operations = [
            {
                "op": "rename_function",
                "function": "FUN_00001000",
                "new_name": "load_resource",
                "reason": "xref",
            },
            {
                "op": "rename_function",
                "function": "FUN_00002000",
                "new_name": "unload_resource",
                "reason": "xref",
            },
        ]
        with self.assertRaises(KeyboardInterrupt):
            apply_ghidra_operations(
                client, "/mwdiff/demo/demo.o", operations,
                cancel=_calls_cancel(client, 3),
            )
        self.assertEqual(len(client.calls), 3)

    def test_collects_function_evidence_with_program_names(self):
        client = FakeMcpClient()
        focus = types.SimpleNamespace(kind="function", name="FUN_00001000")
        evidence = collect_ghidra_evidence(client, "/mwdiff/demo/demo.o", focus)
        self.assertEqual(set(evidence), {
            "analyze_function", "decompiler", "pcode", "disassembly",
            "cfg", "variables", "xrefs",
        })
        self.assertEqual(len(client.calls), 7)
        self.assertTrue(all(
            arguments["program_name"] == "/mwdiff/demo/demo.o"
            for _, arguments in client.calls
        ))
        self.assertTrue(all(
            value == {"text": "ok", "truncated": False}
            for value in evidence.values()
        ))

    def test_collects_unit_evidence(self):
        client = FakeMcpClient()
        focus = types.SimpleNamespace(kind="unit-code", name="demo.o")
        evidence = collect_ghidra_evidence(client, "/mwdiff/demo/demo.o", focus)
        self.assertEqual(set(evidence), {
            "functions", "data", "strings", "relocations",
            "imports", "exports", "types", "classes",
        })
        self.assertEqual(len(client.calls), 8)

    def test_tool_error_becomes_optional_evidence(self):
        client = FakeMcpClient([McpToolError("query rejected")])
        focus = types.SimpleNamespace(kind="function", name="FUN_00001000")
        evidence = collect_ghidra_evidence(client, "/mwdiff/demo/demo.o", focus)
        self.assertEqual(
            evidence["analyze_function"],
            {"error": "query rejected", "tool_rejected": True},
        )
        self.assertEqual(len(client.calls), 7)

    def test_protocol_error_propagates_from_evidence(self):
        client = FakeMcpClient([McpProtocolError("session lost")])
        focus = types.SimpleNamespace(kind="function", name="FUN_00001000")
        with self.assertRaisesRegex(McpProtocolError, "session lost"):
            collect_ghidra_evidence(client, "/mwdiff/demo/demo.o", focus)
        self.assertEqual(len(client.calls), 1)

    def test_cancellation_after_first_evidence_query(self):
        client = FakeMcpClient()
        focus = types.SimpleNamespace(kind="function", name="FUN_00001000")
        with self.assertRaises(KeyboardInterrupt):
            collect_ghidra_evidence(
                client, "/mwdiff/demo/demo.o", focus,
                cancel=_calls_cancel(client, 1),
            )
        self.assertEqual(len(client.calls), 1)

    BINARY_INFO = "Program: demo.o\nLanguage: PowerPC/big/32/default\n"

    def test_reuses_prior_program_without_replay(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Analysis completed successfully",
        ])
        prepared = prepare_ghidra_program(
            client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
            "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
        )
        self.assertEqual(
            prepared, PreparedProgram("/mwdiff/demo-abc/demo.o", False)
        )
        self.assertEqual(
            [name for name, _ in client.calls],
            ["list_binaries", "get_binary_info", "analyze_program"],
        )

    def test_rejects_explicit_program_with_wrong_target(self):
        client = FakeMcpClient([self.LISTING])
        with self.assertRaisesRegex(ValueError, "not the target object"):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit("/tmp/other/other.o"),
                _ghidra_args(ghidra_program="/mwdiff/demo-abc/demo.o"),
                "0123456789abcdef",
            )

    def test_imports_fresh_disposable_program(self):
        imported = self.LISTING + (
            "\n2. demo.o\n"
            "   Project Path: /mwdiff/demo.o-0123456789ab-deadbeef/demo.o\n"
            "   Executable Path: /tmp/project/build/GZLP01/demo/obj/demo.o\n"
            "   Format: Executable and Linking Format (ELF)\n"
            "   Language: PowerPC:BE:32:e500\n"
        )
        client = FakeMcpClient([
            self.LISTING,
            "Imported demo.o",
            imported,
            self.BINARY_INFO,
            "Analysis completed successfully",
        ])
        with mock.patch("mwdiff.secrets.token_hex", return_value="deadbeef"):
            prepared = prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
                "0123456789abcdef",
            )
        self.assertEqual(prepared, PreparedProgram(
            "/mwdiff/demo.o-0123456789ab-deadbeef/demo.o", True
        ))
        name, arguments = client.calls[1]
        self.assertEqual(name, "import_file")
        self.assertEqual(arguments, {
            "file_path": str(
                Path("/tmp/project/build/GZLP01/demo/obj/demo.o").resolve()
            ),
            "folder": "/mwdiff/demo.o-0123456789ab-deadbeef",
            "open_after_import": True,
            "suppress_analysis_prompt": True,
        })

    def test_rejects_wrong_binary_metadata(self):
        client = FakeMcpClient([
            self.LISTING,
            "Program: demo.o\nLanguage: x86/little/64/default\n",
        ])
        with self.assertRaisesRegex(ValueError, "PowerPC"):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
                "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
            )

    def test_polls_async_analysis_to_completion(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Task submitted for async execution.\n\nTask ID: 42\n"
            "Status: PENDING\n",
            "Task Status: RUNNING",
            "Task Status: COMPLETED",
        ])
        prepared = prepare_ghidra_program(
            client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
            "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
        )
        self.assertEqual(prepared.path, "/mwdiff/demo-abc/demo.o")
        status_calls = [
            arguments for name, arguments in client.calls
            if name == "get_task_status"
        ]
        self.assertEqual(len(status_calls), 2)
        self.assertTrue(all(
            arguments == {
                "task_id": "42",
                "program_name": "/mwdiff/demo-abc/demo.o",
            }
            for arguments in status_calls
        ))

    def test_failed_analysis_task_raises(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Task ID: 42",
            "Task Status: FAILED: analyzer crash",
        ])
        with self.assertRaisesRegex(RuntimeError, "analysis failed"):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
                "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
            )

    def test_analysis_timeout_attempts_cancel(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Task ID: 42",
        ])
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(),
                _ghidra_args(mcp_timeout=0),
                "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
            )
        self.assertEqual(client.calls[-1], ("cancel_task", {
            "task_id": "42",
            "program_name": "/mwdiff/demo-abc/demo.o",
        }))

    def test_injected_cancel_attempts_task_cancel(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Task ID: 42",
        ])
        cancel = mock.Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
                "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
                cancel=cancel,
            )
        self.assertEqual(client.calls[-1][0], "cancel_task")
        self.assertNotIn(
            "get_task_status", [name for name, _ in client.calls]
        )

    def test_vague_analysis_response_is_protocol_error(self):
        client = FakeMcpClient([
            self.LISTING,
            self.BINARY_INFO,
            "Analysis maybe started",
        ])
        with self.assertRaisesRegex(McpProtocolError, "unrecognized"):
            prepare_ghidra_program(
                client, {"import_file"}, _ghidra_unit(), _ghidra_args(),
                "0123456789abcdef", prior_program="/mwdiff/demo-abc/demo.o",
            )


def _score():
    return {
        "linked_match": None, "exact": False, "classification": "scheduling",
        "functions_percent": 90.0, "code_percent": 90.0,
        "data_percent": 100.0, "focus_percent": 50.0,
        "relocation_differences": 0, "changed_calls": 0,
        "changed_memory": 0, "diff_lines": 3,
    }


def _fixed_identity():
    return {
        "project": "/p", "unit": "demo.o", "version": "GZLP01",
        "semantics": {"prove": True},
    }


def _valid_state(identity, **overrides):
    state = {
        "schema": RECONSTRUCTION_STATE_SCHEMA,
        "identity": identity,
        "rounds": 1,
        "builds": 1,
        "accepted_edits": [],
        "ghidra_ops": [],
        "score": _score(),
        "focus": None,
        "events": [],
        "feedback": [],
        "ghidra_program": None,
        "model_exchanges": [],
    }
    state.update(overrides)
    return state


class TestReconstructionFiles(unittest.TestCase):
    def test_multi_file_transaction_restores_every_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            header = root / "demo.h"
            source.write_text("source\n")
            header.write_text("header\n")
            with self.assertRaisesRegex(RuntimeError, "stop"):
                with SourceTransaction([source, header]) as transaction:
                    transaction.write_files({
                        source: "changed source\n",
                        header: "changed header\n",
                    })
                    raise RuntimeError("stop")
            self.assertEqual(source.read_text(), "source\n")
            self.assertEqual(header.read_text(), "header\n")

    def test_renders_non_overlapping_unique_edits_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "demo.cpp"
            source.write_text("alpha beta gamma\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            rendered = render_source_edits(root, {source}, [
                {"path": "demo.cpp", "file_sha256": digest,
                 "old": "alpha", "new": "one"},
                {"path": "demo.cpp", "file_sha256": digest,
                 "old": "gamma", "new": "three"},
            ])
            self.assertEqual(rendered[source], "one beta three\n")
            self.assertEqual(source.read_text(), "alpha beta gamma\n")

    def test_rejects_escape_stale_hash_and_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "demo.cpp"
            source.write_text("abcdef\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "outside project"):
                render_source_edits(root, {source}, [{
                    "path": "../escape.cpp", "file_sha256": digest,
                    "old": "a", "new": "b",
                }])
            with self.assertRaisesRegex(ValueError, "stale hash"):
                render_source_edits(root, {source}, [{
                    "path": "demo.cpp", "file_sha256": "0" * 64,
                    "old": "a", "new": "b",
                }])
            with self.assertRaisesRegex(ValueError, "overlap"):
                render_source_edits(root, {source}, [
                    {"path": "demo.cpp", "file_sha256": digest,
                     "old": "abc", "new": "x"},
                    {"path": "demo.cpp", "file_sha256": digest,
                     "old": "bcd", "new": "y"},
                ])

    def test_rejects_edit_to_disallowed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "demo.cpp"
            other = root / "other.cpp"
            source.write_text("abc\n")
            other.write_text("abc\n")
            digest = hashlib.sha256(other.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "not allowed"):
                render_source_edits(root, {source}, [{
                    "path": "other.cpp", "file_sha256": digest,
                    "old": "a", "new": "b",
                }])

    # -- resumable state ------------------------------------------------

    def _identity_env(self, stack):
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        project = Path(directory).resolve()
        source = project / "demo.cpp"
        source.write_bytes(b"source\n")
        header = project / "demo.h"
        header.write_bytes(b"header\n")
        target = project / "demo.o"
        target.write_bytes(b"target\n")
        model = project / "model"
        model.write_bytes(b"model\n")
        unit = types.SimpleNamespace(
            project=project, name="demo.o", version="GZLP01", target=target,
            compiler="mwcceppc", compiler_flags="-O4", context_path=None,
            source=source, ninja_target="demo.o")
        tools = {
            "get_code": {"inputSchema": {"type": "object", "field": 1}},
            "struct": {"inputSchema": {"type": "object", "field": 2}},
        }
        semantics = {
            "prove": True, "proof_timeout_ms": 5000, "versions": ["GZLP01"],
            "link_gate": {"path": "config/GZLP01/build.sha1", "sha256": "a" * 64},
            "build_sha1": {"GZLP01": "b" * 64},
            "ghidra_program": "/decomp/demo.o",
            "import_language": "PowerPC:BE:32:Gekko",
            "import_compiler": "default",
        }
        mcp_info = {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "ghidra"},
        }
        tool_identity = {
            "mwdiff": {"path": "/x/mwdiff", "sha256": "1" * 64},
            "dtk": {"path": "/x/dtk", "sha256": "2" * 64},
            "objdiff": {"path": "/x/objdiff", "sha256": "3" * 64},
            "ninja": {"path": "/x/ninja", "sha256": "4" * 64},
        }
        material = ["c" * 64, "flags", "d" * 64]
        stack.enter_context(mock.patch(
            "mwdiff.cache_material", lambda unit: tuple(material)))
        stack.enter_context(mock.patch(
            "mwdiff.reconstruction_tool_identity",
            lambda project: {k: dict(v) for k, v in tool_identity.items()}))
        kwargs = dict(
            unit=unit, model_command=model, editable_files={source, header},
            mcp_url="http://mcp/", mcp_info=mcp_info, tools=tools,
            required_tools={"get_code", "struct"}, semantics=semantics)
        return types.SimpleNamespace(
            project=project, source=source, header=header, model=model,
            tools=tools, semantics=semantics, tool_identity=tool_identity,
            material=material, kwargs=kwargs)

    def test_resume_identity_covers_every_input(self):
        with ExitStack() as stack:
            env = self._identity_env(stack)
            base = reconstruction_identity(**env.kwargs)
            root = reconstruction_state_root(env.project, base)
            path = save_reconstruction_state(root, _valid_state(base))
            self.assertEqual(
                load_reconstruction_state(path, base)["identity"], base)

            def expect_mismatch():
                varied = reconstruction_identity(**env.kwargs)
                with self.assertRaisesRegex(
                        ValueError, "resume identity mismatch"):
                    load_reconstruction_state(path, varied)

            env.source.write_bytes(b"SOURCE\n")
            expect_mismatch()
            env.source.write_bytes(b"source\n")

            env.model.write_bytes(b"MODEL\n")
            expect_mismatch()
            env.model.write_bytes(b"model\n")

            env.tool_identity["mwdiff"]["sha256"] = "9" * 64
            expect_mismatch()
            env.tool_identity["mwdiff"]["sha256"] = "1" * 64

            env.tool_identity["dtk"]["sha256"] = "8" * 64
            expect_mismatch()
            env.tool_identity["dtk"]["sha256"] = "2" * 64

            env.tools["get_code"]["inputSchema"]["field"] = 99
            expect_mismatch()
            env.tools["get_code"]["inputSchema"]["field"] = 1

            env.semantics["build_sha1"]["GZLP01"] = "e" * 64
            expect_mismatch()
            env.semantics["build_sha1"]["GZLP01"] = "b" * 64

            env.semantics["prove"] = False
            expect_mismatch()
            env.semantics["prove"] = True

            # Every input restored -> the saved state resumes cleanly again.
            self.assertEqual(
                load_reconstruction_state(
                    path, reconstruction_identity(**env.kwargs))["identity"],
                base)

    def _reject(self, stack, regex, **overrides):
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        path = Path(directory) / "state.json"
        path.write_text(json.dumps(_valid_state(_fixed_identity(), **overrides)))
        with self.assertRaisesRegex(ValueError, regex):
            load_reconstruction_state(path, _fixed_identity())

    def test_load_rejects_malformed_state(self):
        with ExitStack() as stack:
            self._reject(stack, "invalid resume rounds", rounds=-1)
            self._reject(stack, "invalid resume builds", builds=-1)
            self._reject(stack, "invalid resume rounds", rounds=True)
            self._reject(stack, "unknown fields", extra=1)
            self._reject(stack, "too many saved edit sets",
                         accepted_edits=[[], []], rounds=1)
            self._reject(stack, "missing fields",
                         accepted_edits=[[{"path": "demo.cpp"}]])
            self._reject(stack, "unknown Ghidra operation",
                         ghidra_ops=[{"op": "bogus"}])
            self._reject(stack, "missing fields", events=[{"kind": "x"}])
            self._reject(stack, "invalid resume model exchange phase",
                         model_exchanges=[{"phase": "bad",
                                           "request_sha256": "0" * 64,
                                           "response_sha256": "0" * 64}])
            self._reject(stack, "invalid resume request_sha256",
                         model_exchanges=[{"phase": "analyze",
                                           "request_sha256": "zz",
                                           "response_sha256": "0" * 64}])
            self._reject(stack, "unsupported state schema", schema="other")

    def test_load_validates_score_and_focus(self):
        with ExitStack() as stack:
            self._reject(stack, "unknown fields",
                         score={**_score(), "bogus": 1})
            self._reject(stack, "missing fields", score={"exact": False})
            self._reject(stack, "must be a number",
                         score={**_score(), "functions_percent": True})
            self._reject(stack, "out of range",
                         score={**_score(), "functions_percent": 150.0})
            self._reject(stack, "must be an integer",
                         score={**_score(), "changed_calls": True})
            self._reject(stack, "must be an integer",
                         score={**_score(), "diff_lines": -1})
            self._reject(stack, "linked_match",
                         score={**_score(), "linked_match": 1})
            self._reject(stack, "inconsistent score exact",
                         score={**_score(), "exact": True})
            self._reject(stack, "unsupported score classification",
                         score={**_score(), "classification": "bogus"})
            self._reject(stack, "unsupported focus kind",
                         focus={"kind": "bogus", "name": "f", "percent": 1.0})
            self._reject(stack, "focus name must be a string",
                         focus={"kind": "function", "name": 5, "percent": 1.0})
            self._reject(stack, "out of range",
                         focus={"kind": "function", "name": "f",
                                "percent": 150.0})
            self._reject(stack, "missing fields",
                         focus={"kind": "function", "name": "f"})

    def test_load_accepts_matched_with_relocations(self):
        # exact=True with a non-exact classification (relocation-alias) is a
        # legitimate fully-matched-with-relocations state.
        identity = _fixed_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(_valid_state(identity, score={
                **_score(), "exact": True, "linked_match": True,
                "classification": "relocation-alias",
                "functions_percent": 100.0, "code_percent": 100.0,
                "data_percent": 100.0, "focus_percent": 100.0,
                "relocation_differences": 2,
            })))
            loaded = load_reconstruction_state(path, identity)
            self.assertTrue(loaded["score"]["exact"])

    def test_load_accepts_function_focus_exact_in_partial_unit(self):
        # Whole-unit exact=False while the focused function classifies exact.
        identity = _fixed_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(_valid_state(identity, score={
                **_score(), "exact": False, "classification": "exact",
                "functions_percent": 80.0, "code_percent": 80.0,
                "data_percent": 100.0, "focus_percent": 100.0,
            })))
            loaded = load_reconstruction_state(path, identity)
            self.assertEqual(loaded["score"]["classification"], "exact")

    def test_load_rejects_non_finite_percentages(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(_valid_state(
                _fixed_identity(),
                score={**_score(), "code_percent": float("inf")})))
            with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
                load_reconstruction_state(path, _fixed_identity())

    def test_load_rejects_oversized_state(self):
        class _Big:
            def __len__(self):
                return MAX_RECONSTRUCTION_STATE + 1

        with mock.patch.object(Path, "read_bytes", lambda self: _Big()):
            with self.assertRaisesRegex(ValueError, "128 MiB"):
                load_reconstruction_state(Path("state.json"), _fixed_identity())

    def test_load_accepts_a_fully_populated_state(self):
        identity = _fixed_identity()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            state = _valid_state(
                identity, rounds=2, builds=2,
                accepted_edits=[[{"path": "demo.cpp", "file_sha256": "0" * 64,
                                  "old": "a", "new": "b"}]],
                ghidra_ops=[{"op": "rename_function", "function": "FUN_1",
                             "new_name": "foo", "reason": "clarity"}],
                focus={"kind": "function", "name": "foo", "percent": 100.0},
                events=[{"kind": "build", "round": 1, "build": 1,
                         "focus": None, "details": {"ok": True}}],
                feedback=[{"note": "n"}],
                model_exchanges=[{"phase": "analyze",
                                  "request_sha256": "0" * 64,
                                  "response_sha256": "1" * 64}],
                ghidra_program="/decomp/demo.o")
            path = save_reconstruction_state(root, state)
            loaded = load_reconstruction_state(path, identity)
            self.assertEqual(loaded["rounds"], 2)
            self.assertEqual(loaded["focus"]["name"], "foo")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_state_and_transcript_files_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            root.mkdir(mode=0o777)
            os.chmod(root, 0o777)
            state_file = root / "state.json"
            state_file.write_text("{}")
            os.chmod(state_file, 0o666)
            transcript = root / "transcript.jsonl"
            transcript.write_text("x\n")
            os.chmod(transcript, 0o666)
            identity = _fixed_identity()
            path = save_reconstruction_state(root, _valid_state(identity))
            append_reconstruction_event(root, {"kind": "start"})
            self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(os.stat(transcript).st_mode), 0o600)

    def test_writers_strip_sensitive_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            identity = _fixed_identity()
            state = _valid_state(identity, feedback=[{
                "authorization": "Bearer x", "headers": {"a": 1},
                "stderr": "trace", "nested": {"token": "t", "keep": 1},
            }])
            path = save_reconstruction_state(root, state)
            text = path.read_text()
            for key in ("authorization", "headers", "stderr", "token"):
                self.assertNotIn(key, text)
            self.assertIn("keep", text)
            append_reconstruction_event(root, {
                "kind": "model", "api_key": "sk",
                "detail": {"password": "p", "safe": 2}})
            transcript = (root / "transcript.jsonl").read_text()
            for key in ("api_key", "password"):
                self.assertNotIn(key, transcript)
            self.assertIn("safe", transcript)

class TestReconstructionScoring(unittest.TestCase):
    def test_selects_lowest_function_then_code_data_and_link(self):
        functions = (
            {"name": "first", "kind": "SYMBOL_FUNCTION", "match_percent": 75.0},
            {"name": "worst", "kind": "SYMBOL_FUNCTION", "match_percent": 25.0},
        )
        snapshot = UnitSnapshot(50.0, 50.0, 0.0, functions, (), ({
            "name": ".data", "kind": "SECTION_DATA", "match_percent": 0.0
        },))
        self.assertEqual(
            select_reconstruction_focus(snapshot, None),
            ReconstructionFocus("function", "worst", 25.0),
        )
        code_snapshot = UnitSnapshot(
            100.0, 50.0, 100.0,
            tuple({**item, "match_percent": 100.0} for item in functions),
            (),
            ({"name": ".text", "kind": "SECTION_CODE",
              "match_percent": 50.0},),
        )
        self.assertEqual(
            select_reconstruction_focus(code_snapshot, None).kind, "unit-code"
        )
        data_snapshot = UnitSnapshot(
            100.0, 100.0, 50.0,
            tuple({**item, "match_percent": 100.0} for item in functions),
            (),
            snapshot.sections,
        )
        self.assertEqual(
            select_reconstruction_focus(data_snapshot, None).kind, "unit-data"
        )
        exact_snapshot = UnitSnapshot(
            100.0, 100.0, 100.0,
            tuple({**item, "match_percent": 100.0} for item in functions),
            (),
            ({"name": ".data", "kind": "SECTION_DATA", "match_percent": 100.0},),
        )
        self.assertEqual(
            select_reconstruction_focus(exact_snapshot, False).kind, "unit-link"
        )
        self.assertIsNone(select_reconstruction_focus(exact_snapshot, True))

    def test_complete_unit_outweighs_pretty_function(self):
        baseline = ReconstructionScore(
            None, False, 50.0, 60.0, 70.0, 100.0,
            "exact", 0, 0, 0, 0,
        )
        improved = ReconstructionScore(
            None, False, 75.0, 70.0, 70.0, 90.0,
            "operand-order", 0, 0, 0, 4,
        )
        self.assertLess(improved.rank, baseline.rank)

    def test_link_match_is_authoritative(self):
        mismatch = ReconstructionScore(
            False, True, 100.0, 100.0, 100.0, 100.0,
            "exact", 2, 0, 0, 0,
        )
        match = dataclasses.replace(mismatch, linked_match=True)
        self.assertLess(match.rank, mismatch.rank)

    def test_scores_unit_focus_from_candidate_snapshot(self):
        focus = ReconstructionFocus("unit-code", "unit-code", 50.0)
        candidate = UnitSnapshot(100.0, 75.0, 100.0, (), (), ())
        score = score_reconstruction(mock.Mock(), candidate, focus, None)
        self.assertEqual(score.focus_percent, 75.0)

    def test_score_roundtrips_through_resume_decoder(self):
        from mwdiff import (
            _decode_reconstruction_score,
            _decode_reconstruction_focus,
        )
        focus = ReconstructionFocus("unit-code", "unit-code", 50.0)
        candidate = UnitSnapshot(100.0, 75.0, 100.0, (), (), ())
        score = score_reconstruction(mock.Mock(), candidate, focus, None)
        _decode_reconstruction_score(dataclasses.asdict(score))
        _decode_reconstruction_focus(dataclasses.asdict(focus))


def _link_unit(root, module="demo", version="GZLP01"):
    return types.SimpleNamespace(
        project=root,
        module=module,
        version=version,
        ninja_target="build/GZLP01/demo/demo.rel",
    )


class TestLinkGate(unittest.TestCase):
    def test_executable_unit_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = resolve_link_gate(_link_unit(Path(directory), module=None))
            self.assertEqual(gate.status, "not-applicable")

    def test_missing_manifest_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = resolve_link_gate(_link_unit(Path(directory)))
            self.assertEqual(gate.status, "unavailable")

    def test_malformed_manifest_raises_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha_file = root / "config/GZLP01/build.sha1"
            sha_file.parent.mkdir(parents=True)
            sha_file.write_text("nothexdigest  build/GZLP01/demo/demo.rel\n")
            with self.assertRaises(ValueError):
                resolve_link_gate(_link_unit(root))

    def test_missing_entry_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha_file = root / "config/GZLP01/build.sha1"
            sha_file.parent.mkdir(parents=True)
            sha_file.write_text("a" * 40 + "  build/GZLP01/other/other.rel\n")
            with self.assertRaises(ValueError):
                resolve_link_gate(_link_unit(root))

    def test_configured_gate_matches_only_exact_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rel = root / "build/GZLP01/demo/demo.rel"
            rel.parent.mkdir(parents=True)
            rel.write_bytes(b"linked rel")
            digest = hashlib.sha1(b"linked rel").hexdigest()
            sha_file = root / "config/GZLP01/build.sha1"
            sha_file.parent.mkdir(parents=True)
            sha_file.write_text(digest + "  build/GZLP01/demo/demo.rel\n")
            unit = _link_unit(root)
            gate = resolve_link_gate(unit)
            self.assertEqual(gate.status, "configured")
            self.assertEqual(gate.expected_sha1, digest)
            success = mock.Mock(returncode=0, stdout="", stderr="")
            check = verify_current_link(
                unit, gate, runner=mock.Mock(return_value=success)
            )
            self.assertTrue(check.matched)
            self.assertEqual(check.actual_sha1, digest)

            rel.write_bytes(b"different rel")
            check = verify_current_link(
                unit, gate, runner=mock.Mock(return_value=success)
            )
            self.assertEqual(check.status, "mismatch")
            self.assertFalse(check.matched)

    def test_unavailable_gate_skips_build(self):
        runner = mock.Mock()
        check = verify_current_link(
            mock.Mock(), LinkGateResolution("unavailable"), runner=runner
        )
        self.assertEqual(check.status, "unavailable")
        runner.assert_not_called()




# ---------------------------------------------------------------------------
# Bounded reconstruction engine tests
# ---------------------------------------------------------------------------
import shutil
import http.server
import mwdiff
from mwdiff import (
    BuildJournal,
    CompilerRejected,
    ReconstructionBuilder,
    ReconstructionEvent,
    ReconstructionResult,
    TextRunResult,
    VerificationResult,
    build_reconstruction_request,
    cmd_reconstruct,
    context_excerpt,
    editable_file_payload,
    main,
    reconstruction_compiler_command,
    render_reconstruction_human,
    run_reconstruction,
    symbol_order_payload,
    resolve_unit,
    GHIDRA_OPERATION_FIELDS,
    REQUIRED_GHIDRA_TOOLS,
)

_FAKE_NINJA = r'''#!/usr/bin/env python3
import json, os, sys, time, hashlib
proj = os.getcwd()
man = json.load(open(os.path.join(proj, "build_manifest.json")))
targets = man["targets"]
aggregates = man.get("aggregates", [])
rogue = man.get("rogue")
args = sys.argv[1:]

agg_of_output = {}
for a in aggregates:
    for o in a["outputs"]:
        agg_of_output[o] = a


def inputs_of(t):
    if t in targets:
        return targets[t].get("inputs", [])
    if t in agg_of_output:
        return agg_of_output[t]["inputs"]
    return []


def closure(roots):
    seen, stack = [], list(roots)
    while stack:
        t = stack.pop(0)
        if t in seen:
            continue
        seen.append(t)
        stack.extend(inputs_of(t))
    return seen


if args[:1] == ["-t"]:
    sub = args[1]
    rest = args[2:]
    if sub == "targets":
        for p in targets:
            print("%s: %s" % (p, targets[p].get("kind", "build")))
        for a in aggregates:
            for o in a["outputs"]:
                print("%s: %s" % (o, a.get("rule", "aggregate")))
        sys.exit(0)
    if sub == "graph":
        labeled = closure(rest)
        active = [a for a in aggregates
                  if any(o in labeled for o in a["outputs"])]
        counter = [0]
        ids = {}

        def ref(p):
            if p not in ids:
                counter[0] += 1
                ids[p] = '"0x%x"' % counter[0]
            return ids[p]

        for p in labeled:
            ref(p)
        for a in active:
            for o in a["outputs"]:
                ref(o)
        print("digraph ninja {")
        print('rankdir="LR"')
        print("node [fontsize=10, shape=box, height=0.25]")
        for p in labeled:
            print('%s [label="%s"]' % (ids[p], p))
        for p in labeled:
            if (p in targets and inputs_of(p)
                    and p not in agg_of_output):
                counter[0] += 1
                edge = '"0x%x"' % counter[0]
                print('%s [label="%s", shape=ellipse]'
                      % (edge, targets[p].get("kind", "build")))
                for i in inputs_of(p):
                    print('%s -> %s' % (ref(i), edge))
                print('%s -> %s' % (edge, ids[p]))
        for a in active:
            counter[0] += 1
            edge = '"0x%x"' % counter[0]
            print('%s [label="%s", shape=ellipse]'
                  % (edge, a.get("rule", "aggregate")))
            for i in a["inputs"]:
                print('%s -> %s' % (ref(i), edge))
            for o in a["outputs"]:
                print('%s -> %s' % (edge, ids[o]))
        print("}")
        sys.exit(0)
    if sub == "commands":
        for t in rest:
            print("build/compilers/mwcc/mwcceppc.exe -O4 -c %s" % t)
        sys.exit(0)
    sys.exit(0)

if args == ["build.ninja"]:
    sys.exit(0)

built = []


def build(t):
    if t in built:
        return
    agg = agg_of_output.get(t)
    if agg is not None:
        for i in agg["inputs"]:
            build(i)
        data = b""
        for i in agg["inputs"]:
            p = os.path.join(proj, i)
            if os.path.exists(p):
                data += open(p, "rb").read()
        for o in agg["outputs"]:
            outp = os.path.join(proj, o)
            os.makedirs(os.path.dirname(outp), exist_ok=True)
            with open(outp, "wb") as f:
                f.write(data + b"::" + o.encode())
            built.append(o)
        return
    if t not in targets:
        return
    for i in inputs_of(t):
        build(i)
    data = b""
    for i in inputs_of(t):
        p = os.path.join(proj, i)
        if os.path.exists(p):
            data += open(p, "rb").read()
    if b"FAILBUILD" in data and targets[t].get("kind") == "object":
        sys.stdout.write("FAILED: %s\n" % t)
        sys.stdout.write("mwcceppc.exe: error: syntax error near BAD\n")
        sys.exit(1)
    if b"INFRAFAIL" in data:
        sys.stdout.write("ninja: error: dependency cycle\n")
        sys.exit(1)
    if b"BLOCK" in data and targets[t].get("kind") == "object":
        open(os.path.join(proj, "ninja_started"), "w").write("1")
        time.sleep(60)
        open(os.path.join(proj, "ninja_finished"), "w").write("1")
    outp = os.path.join(proj, t)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp, "wb") as f:
        f.write(data)
    built.append(t)


for t in args:
    build(t)

if rogue:
    outp = os.path.join(proj, rogue)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    open(outp, "wb").write(b"rogue")
    built.append(rogue)

seq = int(time.monotonic() * 1000) % 1000000000
logp = os.path.join(proj, ".ninja_log")
newlog = not os.path.exists(logp)
with open(logp, "a") as f:
    if newlog:
        f.write("# ninja log v6\n")
    for i, t in enumerate(built):
        digest = hashlib.sha1(open(os.path.join(proj, t), "rb").read())
        f.write("%d\t%d\t%d\t%s\t%s\n" % (
            seq, seq + 1 + i, seq, t, digest.hexdigest()[:16]))
depp = os.path.join(proj, ".ninja_deps")
prev = open(depp, "rb").read() if os.path.exists(depp) else b""
open(depp, "wb").write(prev + bytes([len(prev) % 256]))
sys.exit(0)
'''

_FAKE_DTK = r'''#!/usr/bin/env python3
import sys, os
obj = sys.argv[3]
out = sys.argv[4]
data = open(obj, "rb").read() if os.path.exists(obj) else b""
lines = [".fn fn, local\n", "li r3, 0\n"]
if b"EXACT" not in data:
    lines.append("li r4, 1\n")
lines.append(".endfn\n")
open(out, "w").write("".join(lines))
'''

_FAKE_OBJDIFF = r'''#!/usr/bin/env python3
import json, os, sys
proj = os.getcwd()
args = sys.argv[1:]
oj = json.load(open(os.path.join(proj, "objdiff.json")))
unit = oj["units"][0]


def readobj(rel):
    p = os.path.join(proj, rel)
    return open(p, "rb").read() if os.path.exists(p) else b""


def pct(data):
    if b"EXACT" in data:
        return 100.0
    if b"BETTER" in data:
        return 75.0
    return 50.0


base = readobj(unit["base_path"])
p = pct(base)
if args[0] == "report":
    measures = {
        "matched_functions_percent": p,
        "matched_code_percent": p,
        "matched_data_percent": 100.0,
    }
    if p == 100.0:
        measures = {
            "matched_functions_percent": 100.0,
            "matched_code_percent": 100.0,
            "matched_data_percent": 100.0,
        }
    sys.stdout.write(json.dumps(
        {"units": [{"name": unit["name"], "measures": measures}]}))
    sys.exit(0)
if args[0] == "diff":
    fn = {"name": "fn", "kind": "SYMBOL_FUNCTION", "match_percent": p,
          "demangled_name": "fn", "reloc_diff": [], "data_diff": []}
    side = {"symbols": [fn], "sections": [
        {"name": ".text", "kind": "SECTION_CODE", "match_percent": p,
         "reloc_diff": [], "data_diff": []},
        {"name": ".data", "kind": "SECTION_DATA", "match_percent": 100.0,
         "reloc_diff": [], "data_diff": []},
    ]}
    out = {"left": side, "right": json.loads(json.dumps(side))}
    sys.stdout.write(json.dumps(out))
    sys.exit(0)
sys.exit(1)
'''


def _write_exec(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


class _EngineMcpClient:
    def __init__(self, unit_target, responses=None, tools=None):
        self.unit_target = str(Path(unit_target).resolve())
        self.timeout = 30
        self.calls = []
        self.responses = responses or {}
        self._tools = tools or {
            name: {"name": name, "inputSchema": {"type": "object"}}
            for name in (set(REQUIRED_GHIDRA_TOOLS) | {"import_file"})
        }

    def initialize(self):
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-ghidra"},
        }

    def list_tools(self):
        return self._tools

    def _text(self, value):
        return {"content": [{"type": "text", "text": value}], "isError": False}

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        if name in self.responses:
            value = self.responses[name]
            if callable(value):
                value = value(arguments, self.calls)
            return self._text(value)
        if name == "list_binaries":
            return self._text(
                "1. demo [ACTIVE]\n"
                "   Project Path: /decomp/demo.o\n"
                "   Executable Path: %s\n"
                "   Format: ELF\n"
                "   Language: PowerPC:BE:32:Gekko" % self.unit_target
            )
        if name == "get_binary_info":
            return self._text("Language: PowerPC/big/32/Gekko")
        if name == "analyze_program":
            return self._text("Analysis completed")
        return self._text("evidence for %s" % name)


def _engine_project(stack, *, module=None, versions=("GZLP01",),
                    source="int fn() { return low; }\n",
                    extra_files=None, manifest_extra=None):
    directory = stack.enter_context(tempfile.TemporaryDirectory())
    project = Path(directory).resolve()
    (project / "src").mkdir()
    source_path = project / "src/demo.cpp"
    source_path.write_text(source)
    ctx_rel = "build/GZLP01/demo/ctx.c"
    target_rel = "build/GZLP01/demo/target.o"
    base_rel = "build/GZLP01/demo/demo.o"
    (project / "build/GZLP01/demo").mkdir(parents=True)
    (project / target_rel).write_bytes(b"EXACT target object\n")
    # fake compiler binary for cache_material
    _write_exec(project / "build/compilers/mwcc/mwcceppc.exe", "#!/bin/sh\n")
    # fake tools
    _write_exec(project / "build/tools/dtk", _FAKE_DTK)
    _write_exec(project / "build/tools/objdiff-cli", _FAKE_OBJDIFF)
    bindir = project / ".bin"
    _write_exec(bindir / "ninja", _FAKE_NINJA)
    # configure.py: version-aware — install per-version templates if present.
    (project / "configure.py").write_text(
        "import sys, shutil, os\n"
        "v = sys.argv[sys.argv.index('--version') + 1]\n"
        "tpl = os.path.join('.mwdiff_versions', v)\n"
        "if os.path.isdir(tpl):\n"
        "    for name in ('objdiff.json', 'build_manifest.json'):\n"
        "        src = os.path.join(tpl, name)\n"
        "        if os.path.exists(src):\n"
        "            shutil.copyfile(src, name)\n"
        "open('build.ninja', 'a').close()\n"
        "sys.exit(0)\n"
    )
    # llm command
    model = project / "model"
    model.write_text("#!/bin/sh\ncat >/dev/null\n")
    model.chmod(0o755)
    # objdiff.json
    scratch = {
        "ctx_path": ctx_rel,
        "compiler": "mwcc_233_163",
        "c_flags": "-O4,p",
    }
    if module is not None:
        target_rel = "build/GZLP01/%s/obj/demo.o" % module
        base_rel = "build/GZLP01/%s/obj/demo_base.o" % module
        (project / target_rel).parent.mkdir(parents=True, exist_ok=True)
        (project / target_rel).write_bytes(b"EXACT target object\n")
    unit_json = {
        "name": "demo/demo",
        "target_path": target_rel,
        "base_path": base_rel,
        "metadata": {"source_path": "src/demo.cpp"},
        "scratch": scratch,
    }
    (project / "objdiff.json").write_text(json.dumps({"units": [unit_json]}))
    # build manifest for the fake ninja
    manifest = {
        "targets": {
            base_rel: {"inputs": ["src/demo.cpp"], "kind": "object"},
            ctx_rel: {"inputs": ["src/demo.cpp"], "kind": "context"},
        }
    }
    if manifest_extra:
        manifest["targets"].update(manifest_extra)
    (project / "build_manifest.json").write_text(json.dumps(manifest))
    # A committed decomp tree already holds the built object and context.
    base_bytes = source_path.read_bytes()
    (project / base_rel).write_bytes(base_bytes)
    (project / ctx_rel).write_bytes(base_bytes)
    for rel, text in (extra_files or {}).items():
        p = project / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    stack.enter_context(mock.patch.dict(
        os.environ, {"PATH": str(bindir) + os.pathsep + os.environ["PATH"]}))
    return types.SimpleNamespace(
        project=project, source=source_path, model=model,
        target_rel=target_rel, base_rel=base_rel, ctx_rel=ctx_rel)


def _engine_args(env, **overrides):
    args = dict(
        project=str(env.project), version="GZLP01", unit="demo/demo",
        ghidra_mcp_url="http://127.0.0.1:8080/mcp",
        llm_cmd=str(env.model), max_rounds=8, max_builds=100,
        mcp_timeout=30, llm_timeout=300, build_timeout=600,
        proof_timeout_ms=5000, prove=False, apply=False,
        verify_version=[], edit_file=[], resume=None,
        ghidra_program="/decomp/demo.o", ghidra_language=None,
        ghidra_compiler=None,
    )
    args.update(overrides)
    return types.SimpleNamespace(**args)


class _ScriptedModel:
    """Fake model runner returning phase-appropriate responses."""

    def __init__(self, edits_by_round):
        self.edits_by_round = edits_by_round
        self.requests = []

    def __call__(self, command, request, timeout, cancel=None):
        self.requests.append(request)
        phase = request["phase"]
        round_number = request["run"]["round"]
        if phase == "analyze":
            return {
                "schema": "mwdiff.reconstruct.analyze.v1",
                "summary": "analysis",
                "ghidra_ops": [],
            }
        edits = self.edits_by_round.get(round_number, [])
        rendered = []
        for entry in edits:
            path, old, new = (
                ("src/demo.cpp",) + entry if len(entry) == 2 else entry
            )
            sha = request["editable_files"][path]["sha256"]
            rendered.append({
                "path": path,
                "file_sha256": sha,
                "old": old,
                "new": new,
            })
        return {
            "schema": "mwdiff.reconstruct.propose.v1",
            "summary": "proposal",
            "source_edits": rendered,
        }


class TestReconstructionEngine(unittest.TestCase):
    def test_request_shape_for_both_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            (project / "src").mkdir()
            source = project / "src/demo.cpp"
            source.write_bytes(b"source\n")
            unit = types.SimpleNamespace(
                name="demo/demo", version="GZLP01", project=project,
                source=source, target=project / "t.o", mine=project / "m.o",
                compiler="mwcc_233_163", compiler_flags="-O4,p",
                context_path=None,
            )
            focus = ReconstructionFocus("function", "fn", 50.0)
            snapshot = UnitSnapshot(
                50.0, 50.0, 100.0,
                ({"name": "fn", "kind": "SYMBOL_FUNCTION",
                  "match_percent": 50.0},),
                (), ({"name": ".text", "kind": "SECTION_CODE",
                      "match_percent": 50.0},),
            )
            score = ReconstructionScore(
                None, False, 50.0, 50.0, 100.0, 50.0,
                "scheduling", 0, 0, 0, 3,
            )
            expected = {
                "schema": "mwdiff.reconstruct.analyze.v1",
                "phase": "analyze",
                "run": {
                    "unit": "demo/demo",
                    "version": "GZLP01",
                    "state_id": "state-id",
                    "round": 1,
                    "rounds_remaining": 7,
                    "builds_remaining": 100,
                },
                "identity": mock.ANY,
                "focus": {"kind": "function", "name": "fn", "percent": 50.0},
                "editable_files": {
                    "src/demo.cpp": {
                        "sha256": hashlib.sha256(b"source\n").hexdigest(),
                        "text": "source\n",
                    }
                },
                "compiler": {
                    "name": "mwcc_233_163",
                    "flags": "-O4,p",
                    "command": mock.ANY,
                    "context_excerpt": "",
                },
                "objdiff": mock.ANY,
                "ghidra": mock.ANY,
                "feedback": [],
                "allowed_ghidra_operations": sorted(GHIDRA_OPERATION_FIELDS),
            }
            with mock.patch("mwdiff.disasm",
                            return_value={"fn": ["li r3, 0\n"]}):
                analyze = build_reconstruction_request(
                    "mwdiff.reconstruct.analyze.v1", {"id": 1}, "state-id",
                    unit, focus, snapshot, score, {source}, "cmd",
                    {"decompiler": "x"}, [], 1, 7, 100,
                )
                propose = build_reconstruction_request(
                    "mwdiff.reconstruct.propose.v1", {"id": 1}, "state-id",
                    unit, focus, snapshot, score, {source}, "cmd",
                    {"decompiler": "x"}, [], 1, 7, 100,
                )
            self.assertEqual(analyze, expected)
            self.assertEqual(propose["schema"], "mwdiff.reconstruct.propose.v1")
            self.assertEqual(propose["phase"], "propose")

    def test_one_round_reaches_exact_and_restores_without_apply(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "EXACT")]})
            args = _engine_args(env)
            original = env.source.read_bytes()
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "exact")
            self.assertEqual(result.rounds, 1)
            self.assertEqual(result.builds, 1)
            self.assertEqual(result.outcome, "restored")
            self.assertEqual(env.source.read_bytes(), original)
            self.assertIn("src/demo.cpp", result.patches)

    def test_exact_apply_retains_source(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "EXACT")]})
            args = _engine_args(env, apply=True)
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "exact")
            self.assertEqual(result.outcome, "retained")
            self.assertIn(b"EXACT", env.source.read_bytes())
            state = env.project / ".cache/mwdiff/reconstruct"
            self.assertTrue(
                all(not (root / "state.json").exists()
                    for root in state.glob("demo_demo-*")))
            # both completion ops succeeded: journal snapshots removed
            self.assertEqual(list(state.glob(".journal-*")), [])

    def _run_exact_apply_with_completion_failure(self, patch_ctx):
        with ExitStack() as stack:
            env = _engine_project(stack)
            base = env.project / env.base_rel
            ctx = env.project / env.ctx_rel
            original_source = env.source.read_bytes()
            committed_obj = base.read_bytes()
            committed_obj_mtime = base.stat().st_mtime_ns
            committed_ctx = ctx.read_bytes()
            committed_ctx_mtime = ctx.stat().st_mtime_ns
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "EXACT")]})
            args = _engine_args(env, apply=True)
            with patch_ctx():
                with self.assertRaises(RuntimeError):
                    run_reconstruction(
                        args, client=client, model_runner=model)
            # dual rollback restored original source and every artifact
            self.assertEqual(env.source.read_bytes(), original_source)
            self.assertEqual(base.read_bytes(), committed_obj)
            self.assertEqual(base.stat().st_mtime_ns, committed_obj_mtime)
            self.assertEqual(ctx.read_bytes(), committed_ctx)
            self.assertEqual(ctx.stat().st_mtime_ns, committed_ctx_mtime)
            # resumable state retained because removal never completed
            roots = list((env.project / ".cache/mwdiff/reconstruct").glob(
                "demo_demo-*"))
            self.assertEqual(len(roots), 1)
            self.assertTrue((roots[0] / "state.json").exists())

    def test_completion_append_failure_after_apply_rolls_back(self):
        real_append = __import__("mwdiff").append_reconstruction_event

        def failing_append(root, event):
            payload = event.get("event") if isinstance(event, dict) else None
            if isinstance(payload, dict) and payload.get("kind") == "outcome":
                raise RuntimeError("completion append failed")
            return real_append(root, event)

        self._run_exact_apply_with_completion_failure(
            lambda: mock.patch(
                "mwdiff.append_reconstruction_event", failing_append))

    def test_state_removal_failure_after_apply_rolls_back(self):
        real_unlink = Path.unlink

        def failing_unlink(self, *rest, **kwargs):
            if self.name == "state.json":
                raise RuntimeError("state removal failed")
            return real_unlink(self, *rest, **kwargs)

        self._run_exact_apply_with_completion_failure(
            lambda: mock.patch.object(Path, "unlink", failing_unlink))

    def test_compiler_failure_restores_object_and_context(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            # round 1 breaks the build, round 2 fixes it exactly
            model = _ScriptedModel({
                1: [("low", "FAILBUILD")],
                2: [("low", "EXACT")],
            })
            args = _engine_args(env)
            original = env.source.read_bytes()
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "exact")
            self.assertEqual(result.builds, 2)
            self.assertTrue((env.project / env.base_rel).exists())
            self.assertTrue((env.project / env.ctx_rel).exists())
            self.assertEqual(env.source.read_bytes(), original)
            kinds = [event.kind for event in result.events]
            self.assertIn("compiler-error", kinds)

    def test_non_improvement_restores_accepted_source(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            # round 1 keeps 50% (not better); budget then exhausts
            model = _ScriptedModel({1: [("low", "meh")]})
            args = _engine_args(env, max_rounds=1)
            original = env.source.read_bytes()
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.builds, 1)
            self.assertEqual(env.source.read_bytes(), original)
            kinds = [event.kind for event in result.events]
            self.assertIn("score-rejected", kinds)

    def test_resumed_analyze_timeout_persists_consumed_round(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            original = env.source.read_bytes()

            def timing_out(command, request, timeout, cancel=None):
                raise RuntimeError("model command timed out")

            # First run: one round is consumed before the analyze timeout.
            with self.assertRaises(RuntimeError):
                run_reconstruction(
                    _engine_args(env),
                    client=_EngineMcpClient(env.project / env.target_rel),
                    model_runner=timing_out)
            self.assertEqual(env.source.read_bytes(), original)
            roots = list((env.project / ".cache/mwdiff/reconstruct").glob(
                "demo_demo-*"))
            self.assertEqual(len(roots), 1)
            state_path = roots[0] / "state.json"
            self.assertEqual(
                json.loads(state_path.read_text())["rounds"], 1)

            # Resume that state; a second timeout consumes another round.
            with self.assertRaises(RuntimeError):
                run_reconstruction(
                    _engine_args(env, resume=str(state_path)),
                    client=_EngineMcpClient(env.project / env.target_rel),
                    model_runner=timing_out)
            self.assertEqual(env.source.read_bytes(), original)
            # consumed work is never reset: N -> N + 1 across resume
            self.assertEqual(
                json.loads(state_path.read_text())["rounds"], 2)

    def test_resume_replays_accepted_edits_then_forces_rebuild(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            first_client = _EngineMcpClient(env.project / env.target_rel)
            first_model = _ScriptedModel({1: [("low", "BETTER")]})
            first = run_reconstruction(
                _engine_args(env, max_rounds=1),
                client=first_client, model_runner=first_model)
            self.assertEqual(first.status, "incomplete")
            roots = list((env.project / ".cache/mwdiff/reconstruct").glob(
                "demo_demo-*"))
            self.assertEqual(len(roots), 1)
            state_path = roots[0] / "state.json"
            saved = json.loads(state_path.read_text())
            self.assertEqual(len(saved["accepted_edits"]), 1)
            self.assertEqual(env.source.read_bytes(), b"int fn() { return low; }\n")

            second_client = _EngineMcpClient(env.project / env.target_rel)
            second_model = _ScriptedModel({2: [("BETTER", "EXACT")]})
            second = run_reconstruction(
                _engine_args(env, resume=str(state_path), max_rounds=3),
                client=second_client, model_runner=second_model)
            self.assertEqual(second.status, "exact")
            self.assertGreaterEqual(second.builds, 2)
            self.assertEqual(env.source.read_bytes(), b"int fn() { return low; }\n")

    def test_proven_different_rejects_improved_candidate(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "BETTER")]})
            args = _engine_args(env, prove=True, max_rounds=1)
            original = env.source.read_bytes()
            proof = types.SimpleNamespace(
                status="different", counterexample={"r3": "1"})
            with mock.patch("ppc_equiv.require_z3", return_value=object()), \
                    mock.patch("mwdiff.prove_objects", return_value=proof):
                result = run_reconstruction(
                    args, client=client, model_runner=model)
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(env.source.read_bytes(), original)
            kinds = [event.kind for event in result.events]
            self.assertIn("proof", kinds)
            self.assertNotIn("score-improved", kinds)

    def test_unknown_proof_keeps_candidate_eligible(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "BETTER")]})
            args = _engine_args(env, prove=True, max_rounds=1)
            proof = types.SimpleNamespace(status="unknown", counterexample=None)
            with mock.patch("ppc_equiv.require_z3", return_value=object()), \
                    mock.patch("mwdiff.prove_objects", return_value=proof):
                result = run_reconstruction(
                    args, client=client, model_runner=model)
            kinds = [event.kind for event in result.events]
            self.assertIn("proof", kinds)
            self.assertIn("score-improved", kinds)
            proof_events = [
                event for event in result.events if event.kind == "proof"]
            self.assertEqual(proof_events[0].details["status"], "unknown")

    def test_sigint_kills_build_group_and_rolls_back(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("low", "BLOCK")]})
            args = _engine_args(env)
            original = env.source.read_bytes()
            baseline_obj = (env.project / env.base_rel).read_bytes()
            started = env.project / "ninja_started"

            def killer():
                # interrupt only once the blocking candidate build is running,
                # so the signal deterministically lands inside run_bounded_process
                for _ in range(1200):
                    if started.exists():
                        break
                    time.sleep(0.05)
                os.kill(os.getpid(), signal.SIGINT)

            waiter = threading.Thread(target=killer, daemon=True)
            waiter.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    run_reconstruction(
                        args, client=client, model_runner=model)
            finally:
                waiter.join(timeout=5)
            # the blocking build started but was killed before finishing
            self.assertTrue((env.project / "ninja_started").exists())
            self.assertFalse((env.project / "ninja_finished").exists())
            # source and baseline artifact restored
            self.assertEqual(env.source.read_bytes(), original)
            self.assertEqual(
                (env.project / env.base_rel).read_bytes(), baseline_obj)

    def test_ghidra_prep_failure_restores_baseline_artifacts(self):
        with ExitStack() as stack:
            env = _engine_project(stack)
            client = _EngineMcpClient(
                env.project / env.target_rel,
                responses={"get_binary_info": "Language: x86/little/32/default"},
            )
            model = _ScriptedModel({1: [("low", "EXACT")]})
            args = _engine_args(env)
            base = env.project / env.base_rel
            ctx = env.project / env.ctx_rel
            baseline_obj = base.read_bytes()
            baseline_mtime = base.stat().st_mtime_ns
            baseline_ctx = ctx.read_bytes()
            with self.assertRaises(ValueError):
                run_reconstruction(args, client=client, model_runner=model)
            # journal cleanup restored exact pre-command artifacts + metadata
            self.assertEqual(base.read_bytes(), baseline_obj)
            self.assertEqual(base.stat().st_mtime_ns, baseline_mtime)
            self.assertEqual(ctx.read_bytes(), baseline_ctx)
            # temporary journal directories are removed on clean rollback
            leftovers = list(
                (env.project / ".cache/mwdiff/reconstruct").glob(".journal-*"))
            self.assertEqual(leftovers, [])

    def test_shared_header_rebuild_rolls_back_siblings_and_rel(self):
        with ExitStack() as stack:
            demo = "int fn(){return zzz;}\n"
            shared_before = "// shared low\n"
            shared_after = "// shared EXACT\n"
            sibling = "int sib(){return 0;}\n"
            base_obj = (demo + shared_after).encode()
            sib_obj = (sibling + shared_after).encode()
            rel_bytes = base_obj + sib_obj
            expected_sha = hashlib.sha1(rel_bytes).hexdigest()
            base_rel = "build/GZLP01/demo/obj/demo_base.o"
            sib_rel = "build/GZLP01/demo/obj/sibling.o"
            rel_rel = "build/GZLP01/demo/demo.rel"
            env = _engine_project(
                stack, module="demo", source=demo,
                extra_files={
                    "src/shared.h": shared_before,
                    "src/sibling.cpp": sibling,
                    sib_rel: "committed-sibling",
                    rel_rel: "committed-rel",
                },
                manifest_extra={
                    base_rel: {"inputs": ["src/demo.cpp", "src/shared.h"],
                               "kind": "object"},
                    sib_rel: {"inputs": ["src/sibling.cpp", "src/shared.h"],
                              "kind": "object"},
                    rel_rel: {"inputs": [base_rel, sib_rel], "kind": "rel"},
                },
            )
            sha_file = env.project / "config/GZLP01/build.sha1"
            sha_file.parent.mkdir(parents=True, exist_ok=True)
            sha_file.write_text("%s  %s\n" % (expected_sha, rel_rel))
            header = env.project / "src/shared.h"
            client = _EngineMcpClient(env.project / env.target_rel)
            model = _ScriptedModel({1: [("src/shared.h", "low", "EXACT")]})
            args = _engine_args(
                env, edit_file=[str(header)],
                verify_version=[],
            )
            header_original = header.read_bytes()
            sib_committed = (env.project / sib_rel).read_bytes()
            rel_committed = (env.project / rel_rel).read_bytes()
            sib_mtime = (env.project / sib_rel).stat().st_mtime_ns
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "exact")
            self.assertEqual(result.link.status, "match")
            # preview rollback restored the shared-header siblings and REL
            self.assertEqual(header.read_bytes(), header_original)
            self.assertEqual(
                (env.project / sib_rel).read_bytes(), sib_committed)
            self.assertEqual(
                (env.project / rel_rel).read_bytes(), rel_committed)
            self.assertEqual(
                (env.project / sib_rel).stat().st_mtime_ns, sib_mtime)

    def test_verify_version_build_rolls_back_second_version(self):
        with ExitStack() as stack:
            demo = "int fn(){return zzz;}\n"
            shared_before = "// shared low\n"
            shared_after = "// shared EXACT\n"
            sibling = "int sib(){return 0;}\n"
            base_obj = (demo + shared_after).encode()
            sib_obj = (sibling + shared_after).encode()
            rel_bytes = base_obj + sib_obj
            expected_sha = hashlib.sha1(rel_bytes).hexdigest()
            base_rel = "build/GZLP01/demo/obj/demo_base.o"
            sib_rel = "build/GZLP01/demo/obj/sibling.o"
            rel_rel = "build/GZLP01/demo/demo.rel"
            gj_base = "build/GZLJ01/demo/obj/demo_base.o"
            gj_sib = "build/GZLJ01/demo/obj/sibling.o"
            gj_rel = "build/GZLJ01/demo/demo.rel"
            gj_report_src = "build/GZLJ01/report_src.json"
            env = _engine_project(
                stack, module="demo", source=demo,
                extra_files={
                    "src/shared.h": shared_before,
                    "src/sibling.cpp": sibling,
                    sib_rel: "committed-sibling",
                    rel_rel: "committed-rel",
                    gj_base: "committed-gj-base",
                    gj_sib: "committed-gj-sibling",
                    gj_rel: "committed-gj-rel",
                    gj_report_src: json.dumps({"units": [{
                        "name": "demo/demo",
                        "measures": {
                            "matched_functions_percent": 100.0,
                            "matched_code_percent": 100.0,
                            "matched_data_percent": 100.0,
                        }}]}),
                    "orig/GZLJ01/disc.bin": "disc",
                    "config/GZLP01/config.yml": "version: GZLP01\n",
                    "config/GZLJ01/config.yml": "version: GZLJ01\n",
                },
                manifest_extra={
                    base_rel: {"inputs": ["src/demo.cpp", "src/shared.h"],
                               "kind": "object"},
                    sib_rel: {"inputs": ["src/sibling.cpp", "src/shared.h"],
                              "kind": "object"},
                    rel_rel: {"inputs": [base_rel, sib_rel], "kind": "rel"},
                },
            )
            project = env.project
            # selected-version link manifest
            (project / "config/GZLP01/build.sha1").write_text(
                "%s  %s\n" % (expected_sha, rel_rel))
            (project / "config/GZLJ01/build.sha1").write_text(
                "%s  %s\n" % (expected_sha, gj_rel))
            # per-version templates for the version-aware configure.py
            gzlp_objdiff = (project / "objdiff.json").read_text()
            gzlp_manifest = (project / "build_manifest.json").read_text()
            gzlj_objdiff = json.dumps({"units": [{
                "name": "demo/demo",
                "target_path": "build/GZLJ01/demo/obj/demo.o",
                "base_path": gj_base,
                "metadata": {"source_path": "src/demo.cpp"},
                "scratch": {"ctx_path": "build/GZLJ01/demo/ctx.c",
                            "compiler": "mwcc_233_163", "c_flags": "-O4,p"},
            }]})
            gzlj_manifest = json.dumps({"targets": {
                gj_base: {"inputs": ["src/demo.cpp", "src/shared.h"],
                          "kind": "object"},
                gj_sib: {"inputs": ["src/sibling.cpp", "src/shared.h"],
                         "kind": "object"},
                gj_rel: {"inputs": [gj_base, gj_sib], "kind": "rel"},
                "build/GZLJ01/report.json": {"inputs": [gj_report_src],
                                             "kind": "report"},
            }})
            for name, obj, man in (
                ("GZLP01", gzlp_objdiff, gzlp_manifest),
                ("GZLJ01", gzlj_objdiff, gzlj_manifest),
            ):
                tpl = project / ".mwdiff_versions" / name
                tpl.mkdir(parents=True, exist_ok=True)
                (tpl / "objdiff.json").write_text(obj)
                (tpl / "build_manifest.json").write_text(man)
            (project / "build/GZLJ01/demo/obj").mkdir(parents=True, exist_ok=True)
            (project / "build/GZLJ01/demo/obj/demo.o").write_bytes(base_obj)
            header = project / "src/shared.h"
            client = _EngineMcpClient(project / env.target_rel)
            model = _ScriptedModel({1: [("src/shared.h", "low", "EXACT")]})
            args = _engine_args(
                env, edit_file=[str(header)], verify_version=["GZLJ01"])
            committed = {
                rel: (project / rel).read_bytes()
                for rel in (gj_base, gj_sib, gj_rel)
            }
            committed_mtime = (project / gj_rel).stat().st_mtime_ns
            result = run_reconstruction(args, client=client, model_runner=model)
            self.assertEqual(result.status, "exact")
            self.assertEqual(len(result.verification), 1)
            self.assertEqual(result.verification[0].version, "GZLJ01")
            # the second-version object and REL were built during verify then
            # restored byte-for-byte by preview rollback.
            for rel, data in committed.items():
                self.assertEqual((project / rel).read_bytes(), data)
            self.assertEqual(
                (project / gj_rel).stat().st_mtime_ns, committed_mtime)


class TestBuildJournal(unittest.TestCase):
    def _journal(self, stack):
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        project = Path(directory).resolve()
        (project / "build").mkdir()
        for name in ("build.ninja", "objdiff.json", "compile_commands.json"):
            (project / name).write_text(name)
        journal = BuildJournal(project, "GZLP01", 60, cancel=None)
        stack.callback(lambda: shutil.rmtree(journal.dir, ignore_errors=True))
        return project, journal

    def test_snapshots_and_restores_regular_file(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            out = project / "build/foo.o"
            out.write_bytes(b"original")
            os.chmod(out, 0o644)
            journal._snapshot(out)
            out.write_bytes(b"candidate different length")
            os.chmod(out, 0o600)
            journal.restore_baseline()
            self.assertEqual(out.read_bytes(), b"original")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o644)

    def test_deletes_originally_absent_output(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            out = project / "build/new/deep/foo.o"
            journal._snapshot(out)
            out.parent.mkdir(parents=True)
            out.write_bytes(b"built")
            journal.restore_baseline()
            self.assertFalse(out.exists())
            self.assertFalse((project / "build/new").exists())

    def test_restores_symlink(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            link = project / "build/link"
            link.symlink_to("target-a")
            journal._snapshot(link)
            link.unlink()
            link.symlink_to("target-b")
            journal.restore_baseline()
            self.assertEqual(os.readlink(link), "target-a")

    def test_graph_dot_escaping_and_multi_output(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            labels = journal._split_label(r"build/a.o\nbuild/b.o")
            self.assertEqual(labels, ["build/a.o", "build/b.o"])
            self.assertEqual(journal._split_label(r'build/quote\".o'),
                             ['build/quote".o'])

    def test_path_escape_is_rejected(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            with self.assertRaisesRegex(RuntimeError, "escapes project"):
                journal._consider_path("../../etc/passwd")

    def test_changed_output_outside_closure_is_unsafe(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            pre = {}
            post = {"build/unsnapshotted.o": ("1", "2", "3", "abc")}
            with self.assertRaisesRegex(RuntimeError, "unsnapshotted"):
                journal._verify_closure(pre, post)

    def test_control_files_restored(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            (project / ".ninja_deps").write_bytes(b"mutated")
            (project / "build.ninja").write_text("regenerated")
            journal.restore_baseline()
            self.assertFalse((project / ".ninja_deps").exists())
            self.assertEqual((project / "build.ninja").read_text(),
                             "build.ninja")

    def test_force_reruns_restoration_after_restored_flag(self):
        with ExitStack() as stack:
            project, journal = self._journal(stack)
            out = project / "build/foo.o"
            out.write_bytes(b"baseline")
            journal._snapshot(out)
            # simulate a prior restoration having marked the journal done
            journal._restored = True
            out.write_bytes(b"candidate")
            # default call is idempotent: the guard skips it, no restore
            journal.restore_baseline()
            self.assertEqual(out.read_bytes(), b"candidate")
            # force=True bypasses the guard and actually re-restores
            journal.restore_baseline(force=True)
            self.assertEqual(out.read_bytes(), b"baseline")

    def _ninja_journal(self, stack, manifest, committed):
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        project = Path(directory).resolve()
        (project / "src").mkdir()
        (project / "src/a.c").write_text("unit body\n")
        (project / "build").mkdir()
        for name in ("build.ninja", "objdiff.json", "compile_commands.json"):
            (project / name).write_text(name)
        (project / "build_manifest.json").write_text(json.dumps(manifest))
        for rel, text in committed.items():
            p = project / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        bindir = project / ".bin"
        _write_exec(bindir / "ninja", _FAKE_NINJA)
        stack.enter_context(mock.patch.dict(
            os.environ,
            {"PATH": str(bindir) + os.pathsep + os.environ["PATH"]}))
        journal = BuildJournal(project, "GZLP01", 60,
                               cancel=None)
        stack.callback(
            lambda: shutil.rmtree(journal.dir, ignore_errors=True))
        return project, journal

    def test_aggregate_edge_co_outputs_snapshot_and_rollback(self):
        with ExitStack() as stack:
            outputs = ["build/x/r1.rel", "build/x/r2.rel", "build/x/r3.rel"]
            manifest = {
                "targets": {"build/x/mine.o": {"inputs": ["src/a.c"],
                                               "kind": "object"}},
                "aggregates": [{"rule": "makerel", "outputs": outputs,
                                "inputs": ["build/x/mine.o"]}],
            }
            committed = {rel: "committed-" + rel for rel in outputs}
            committed["build/x/mine.o"] = "committed-obj"
            project, journal = self._ninja_journal(stack, manifest, committed)
            committed_bytes = {
                rel: (project / rel).read_bytes() for rel in outputs}
            committed_mtime = {
                rel: (project / rel).stat().st_mtime_ns for rel in outputs}
            # Requesting ONE rel drives the single makerel edge that rewrites
            # every rel; the co-output map must pre-snapshot all of them.
            result = journal.run_text(["ninja", "build/x/r1.rel"])
            self.assertEqual(result.returncode, 0)
            for rel in outputs:
                self.assertIn(str(project / rel), journal.snapshots)
            # rollback restores every co-output byte-for-byte and metadata
            journal.restore_baseline()
            for rel in outputs:
                self.assertEqual((project / rel).read_bytes(),
                                 committed_bytes[rel])
                self.assertEqual((project / rel).stat().st_mtime_ns,
                                 committed_mtime[rel])

    def test_genuinely_out_of_closure_output_still_unsafe(self):
        with ExitStack() as stack:
            outputs = ["build/x/r1.rel", "build/x/r2.rel"]
            manifest = {
                "targets": {"build/x/mine.o": {"inputs": ["src/a.c"],
                                               "kind": "object"}},
                "aggregates": [{"rule": "makerel", "outputs": outputs,
                                "inputs": ["build/x/mine.o"]}],
                # a stray output no edge declares: never in any closure
                "rogue": "build/x/rogue.o",
            }
            committed = {rel: "committed-" + rel for rel in outputs}
            committed["build/x/mine.o"] = "committed-obj"
            project, journal = self._ninja_journal(stack, manifest, committed)
            with self.assertRaisesRegex(RuntimeError, "unsnapshotted"):
                journal.run_text(["ninja", "build/x/r1.rel"])

    def test_co_output_map_rebuilds_after_build_ninja_change(self):
        with ExitStack() as stack:
            outputs = ["build/x/r1.rel", "build/x/r2.rel"]
            manifest = {
                "targets": {"build/x/mine.o": {"inputs": ["src/a.c"],
                                               "kind": "object"}},
                "aggregates": [{"rule": "makerel", "outputs": list(outputs),
                                "inputs": ["build/x/mine.o"]}],
            }
            committed = {rel: "committed-" + rel for rel in outputs}
            committed["build/x/mine.o"] = "committed-obj"
            project, journal = self._ninja_journal(stack, manifest, committed)
            first = journal._co_outputs()
            self.assertEqual(
                first["build/x/r1.rel"],
                frozenset(outputs))
            # a new REL joins the aggregate; the manifest AND build.ninja change
            extended = outputs + ["build/x/r3.rel"]
            manifest["aggregates"][0]["outputs"] = extended
            (project / "build_manifest.json").write_text(json.dumps(manifest))
            (project / "build.ninja").write_text("build.ninja v2")
            rebuilt = journal._co_outputs()
            self.assertIn("build/x/r3.rel", rebuilt["build/x/r1.rel"])
            self.assertEqual(rebuilt["build/x/r1.rel"], frozenset(extended))


class TestReconstructionBuilderClassification(unittest.TestCase):
    def _builder(self, journal_result):
        unit = types.SimpleNamespace(
            project=Path("/proj"), mine=Path("/proj/build/GZLP01/demo/demo.o"),
            ninja_target="build/GZLP01/demo/demo.o", version="GZLP01",
            context_path=None,
        )
        journal = mock.Mock()
        journal.ninja.return_value = journal_result
        journal.invalidate.return_value = None
        transaction = mock.Mock()
        return ReconstructionBuilder(unit, journal, transaction)

    def test_compile_edge_failure_is_compiler_rejected(self):
        builder = self._builder(TextRunResult(
            1, "FAILED: build/GZLP01/demo/demo.o\nsyntax error\n", ""))
        with self.assertRaises(CompilerRejected):
            builder.transition({})

    def test_infrastructure_failure_is_fatal(self):
        builder = self._builder(TextRunResult(
            1, "ninja: error: unknown target\n", ""))
        with self.assertRaises(RuntimeError) as caught:
            builder.transition({})
        self.assertNotIsInstance(caught.exception, CompilerRejected)


# ---------------------------------------------------------------------------
# Public `reconstruct` CLI: exit codes, JSON/human rendering, and one
# end-to-end run driving main() through a real HTTP fake Ghidra MCP server
# plus executable fake model/ninja/dtk/objdiff.
# ---------------------------------------------------------------------------


def _cli_result(*, status="exact", outcome="restored", link=None,
                verification=(), patches=None, events=None):
    focus = ReconstructionFocus(
        "function", "fn", 100.0 if status == "exact" else 50.0)
    exact = status == "exact"
    score = ReconstructionScore(
        True, exact,
        100.0 if exact else 50.0, 100.0 if exact else 50.0, 100.0,
        100.0 if exact else 50.0,
        "exact" if exact else "scheduling", 0, 0, 0, 0 if exact else 3)
    if link is None:
        link = LinkCheck(
            "match", "build/GZLP01/demo/demo.rel", "a" * 40, "a" * 40)
    focus_dict = dataclasses.asdict(focus)
    if events is None:
        events = (
            ReconstructionEvent("round-start", 1, 0, focus_dict, {}),
            ReconstructionEvent(
                "ghidra-operation-confirmed", 1, 0, None,
                {"op": "set_prototype", "function": "fn"}),
            ReconstructionEvent(
                "ghidra-operation-failed", 1, 0, None,
                {"operation": {"op": "rename_data"}, "error": "not placeholder"}),
            ReconstructionEvent(
                "compiler-error", 1, 1, focus_dict,
                {"kind": "compiler-error", "output": "syntax error"}),
            ReconstructionEvent(
                "score-improved", 2, 2, focus_dict,
                {"kind": "accepted", "before": {"code_percent": 50.0},
                 "after": {"code_percent": 100.0}, "proof": None}),
            ReconstructionEvent(
                "score-rejected", 3, 3, focus_dict,
                {"kind": "not-improved", "proof": None}),
            ReconstructionEvent("proof", 3, 3, focus_dict, {"status": "unknown"}),
            ReconstructionEvent("no-source-edit", 3, 3, focus_dict, {}),
            ReconstructionEvent("link", 3, 3, None, {
                "status": link.status,
                "expected_sha1": link.expected_sha1,
                "actual_sha1": link.actual_sha1}),
            ReconstructionEvent(
                "outcome", 3, 3, focus_dict,
                {"outcome": outcome, "status": status}),
        )
    return ReconstructionResult(
        status=status, focus=focus, score=score, rounds=3, max_rounds=8,
        builds=3, max_builds=100, link=link, verification=tuple(verification),
        events=tuple(events), outcome=outcome,
        state_path=None if exact else "/tmp/mwdiff/state.json",
        patches=patches if patches is not None else {})


def _run_cmd_reconstruct(result=None, *, json_mode=False, raises=None):
    args = types.SimpleNamespace(json=json_mode)
    out, err = io.StringIO(), io.StringIO()
    code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if raises is not None:
            patch = mock.patch(
                "mwdiff.run_reconstruction", side_effect=raises)
        else:
            patch = mock.patch(
                "mwdiff.run_reconstruction", return_value=result)
        with patch:
            try:
                code = cmd_reconstruct(args)
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def _run_main_argv(argv):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(sys, "argv", argv), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            main()
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


class TestReconstructCli(unittest.TestCase):
    def _base_argv(self, *extra):
        return [
            "mwdiff.py", "reconstruct",
            "--project", "/nonexistent-mwdiff-project",
            "--unit", "demo/demo",
            "--ghidra-mcp-url", "http://127.0.0.1:9/mcp",
            "--llm-cmd", "/bin/true",
            *extra,
        ]

    def test_nonpositive_budgets_and_timeouts_exit_two_before_any_action(self):
        for flag in ("--max-rounds", "--max-builds", "--mcp-timeout",
                     "--llm-timeout", "--build-timeout", "--proof-timeout-ms"):
            code, stdout, stderr = _run_main_argv(self._base_argv(flag, "0"))
            # Exit 2 with the budget message proves the preflight fired before
            # project resolution, MCP, model, build, or source access.
            self.assertEqual(code, 2, flag)
            self.assertIn("must be positive", stderr, flag)
            self.assertEqual(stdout, "", flag)

    def test_resume_identity_failure_exits_two(self):
        code, _, stderr = _run_cmd_reconstruct(
            raises=ValueError("state identity does not match this run"))
        self.assertEqual(code, 2)
        self.assertIn("identity", stderr)

    def test_protocol_and_tool_failures_exit_two(self):
        for error in (RuntimeError("MCP error -32601: method not found"),
                      OSError("connection refused")):
            code, _, stderr = _run_cmd_reconstruct(raises=error)
            self.assertEqual(code, 2)
            self.assertIn("mwdiff:", stderr)

    def test_exact_returns_zero_incomplete_returns_one(self):
        code, _, _ = _run_cmd_reconstruct(_cli_result(status="exact"))
        self.assertEqual(code, 0)
        code, _, _ = _run_cmd_reconstruct(_cli_result(status="incomplete"))
        self.assertEqual(code, 1)

    def test_json_mode_emits_exactly_one_document(self):
        result = _cli_result(status="exact")
        code, stdout, _ = _run_cmd_reconstruct(result, json_mode=True)
        self.assertEqual(code, 0)
        self.assertEqual(stdout.count("\n"), 1)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "exact")
        self.assertEqual(payload["outcome"], "restored")
        self.assertEqual(payload["link"]["status"], "match")

    def test_exact_without_apply_prints_patches_and_reports_restored(self):
        result = _cli_result(
            status="exact", outcome="restored",
            patches={"src/demo.cpp": "--- a\n+++ b\n"})
        code, stdout, _ = _run_cmd_reconstruct(result)
        self.assertEqual(code, 0)
        self.assertIn("patch src/demo.cpp", stdout)
        self.assertIn("outcome restored", stdout)

    def test_exact_with_apply_reports_retained(self):
        result = _cli_result(status="exact", outcome="retained")
        code, stdout, _ = _run_cmd_reconstruct(result)
        self.assertEqual(code, 0)
        self.assertIn("outcome retained", stdout)

    def test_deferred_link_never_renders_as_unavailable(self):
        link = LinkCheck(
            "deferred", "build/GZLP01/demo/demo.rel", "b" * 40, None)
        result = _cli_result(status="incomplete", outcome="restored", link=link)
        human = render_reconstruction_human(result)
        self.assertIn("link status=deferred", human)
        self.assertNotIn("unavailable", human)
        # JSON keeps the literal gate status too.
        payload = dataclasses.asdict(result)
        self.assertEqual(payload["link"]["status"], "deferred")

    def test_json_and_human_render_the_same_facts(self):
        link = LinkCheck(
            "mismatch", "build/GZLP01/demo/demo.rel", "c" * 40, "d" * 40)
        verification = (
            VerificationResult("GZLJ01", 100.0, 100.0, 100.0, True),
            VerificationResult("GZLE01", 100.0, 100.0, 50.0, False),
        )
        result = _cli_result(
            status="incomplete", outcome="restored", link=link,
            verification=verification,
            patches={"src/demo.cpp": "diff", "src/shared.h": "diff"})
        human = render_reconstruction_human(result)
        payload = dataclasses.asdict(result)
        # Every event kind appears in the deterministic human output.
        for event in payload["events"]:
            self.assertIn("event %s" % event["kind"], human)
        # Ghidra success + failure, compiler/score deltas, and proof are shown.
        for kind in ("ghidra-operation-confirmed", "ghidra-operation-failed",
                     "compiler-error", "score-improved", "score-rejected",
                     "proof", "no-source-edit"):
            self.assertIn("event %s" % kind, human)
        # Explicit link status + expected/actual (not inferred from score).
        self.assertIn("link status=mismatch", human)
        self.assertIn("expected=" + "c" * 40, human)
        self.assertIn("actual=" + "d" * 40, human)
        self.assertEqual(payload["link"]["expected_sha1"], "c" * 40)
        self.assertEqual(payload["link"]["actual_sha1"], "d" * 40)
        # Each cross-version result rendered.
        self.assertIn("verify version=GZLJ01", human)
        self.assertIn("verify version=GZLE01", human)
        self.assertIn("rel_sha_match=True", human)
        self.assertIn("rel_sha_match=False", human)
        # Patches, state path, and outcome.
        self.assertIn("patch src/demo.cpp", human)
        self.assertIn("patch src/shared.h", human)
        self.assertIn("state /tmp/mwdiff/state.json", human)
        self.assertIn("outcome restored status=incomplete", human)
        self.assertEqual(payload["state_path"], "/tmp/mwdiff/state.json")


# --- executable fake model + real HTTP fake Ghidra MCP server --------------

_FAKE_MODEL_TMPL = r'''#!/usr/bin/env python3
import json, sys
req = json.load(sys.stdin)
with open({log!r}, "a") as handle:
    handle.write(json.dumps(req) + "\n")
phase = req["phase"]
rnd = req["run"]["round"]
g = req.get("ghidra") or {{}}


def fail(message):
    sys.stderr.write("model reject: " + message + "\n")
    sys.exit(7)


def evidence_ok(key):
    entry = g.get(key) or {{}}
    return (bool(entry.get("text"))
            and not entry.get("tool_rejected")
            and not entry.get("error"))


focus_kind = req["focus"]["kind"]
if phase == "analyze":
    if focus_kind == "function":
        for key in ("decompiler", "pcode", "cfg"):
            if not evidence_ok(key):
                fail("analyze without " + key + " evidence")
    ops = []
    if rnd == 1 and focus_kind == "function":
        ops = [{{"op": "set_prototype", "function": "fn",
                 "prototype": "int fn(void)", "reason": "placeholder name"}}]
    print(json.dumps({{"schema": "mwdiff.reconstruct.analyze.v1",
                       "summary": "analysis %d" % rnd, "ghidra_ops": ops}}))
    sys.exit(0)

if rnd == 1 and "REVISED" not in (g.get("decompiler") or {{}}).get("text", ""):
    fail("propose without re-decompiled evidence")
anchors = [p for p in sorted(req["editable_files"])
           if "low" in req["editable_files"][p]["text"]]
if not anchors:
    print(json.dumps({{"schema": "mwdiff.reconstruct.propose.v1",
                       "summary": "no anchor", "source_edits": []}}))
    sys.exit(0)
path = anchors[0]
sha = req["editable_files"][path]["sha256"]
new = {{1: "FAILBUILD", 2: "meh", 3: "EXACT"}}.get(rnd, "meh")
print(json.dumps({{"schema": "mwdiff.reconstruct.propose.v1",
                   "summary": "propose %d" % rnd,
                   "source_edits": [{{"path": path, "file_sha256": sha,
                                      "old": "low", "new": new}}]}}))
'''


class _FakeGhidraHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        message = json.loads(self.rfile.read(length).decode("utf-8"))
        method = message.get("method")
        mid = message.get("id")
        params = message.get("params") or {}
        if method == "initialize":
            self._json(mid, {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-ghidra", "version": "1"},
            }, session="mwdiff-session")
        elif method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Mcp-Session-Id", "mwdiff-session")
            self.end_headers()
        elif method == "tools/list":
            tools = [
                {"name": name, "inputSchema": {"type": "object"}}
                for name in sorted(set(REQUIRED_GHIDRA_TOOLS) | {"import_file"})
            ]
            self._sse(mid, {"tools": tools})
        elif method == "tools/call":
            text = self.server.tool_call(
                params.get("name"), params.get("arguments") or {})
            self._json(mid, {
                "content": [{"type": "text", "text": text}], "isError": False})
        else:
            self._json(mid, None, error={"code": -32601, "message": method})

    def _json(self, mid, result, *, session=None, error=None):
        payload = {"jsonrpc": "2.0", "id": mid}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, mid, result):
        payload = {"jsonrpc": "2.0", "id": mid, "result": result}
        body = ("event: message\ndata: " + json.dumps(payload)
                + "\n\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _FakeGhidraServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, program, target):
        super().__init__(("127.0.0.1", 0), _FakeGhidraHandler)
        self.program = program
        self.target = str(Path(target).resolve())
        self.lock = threading.Lock()
        self.proto_set = False
        self.calls = []
        self.violations = []
        self.selected = False

    @property
    def url(self):
        return "http://127.0.0.1:%d/mcp" % self.server_address[1]

    def tool_call(self, name, arguments):
        with self.lock:
            self.calls.append((name, arguments))
            allowed = set(REQUIRED_GHIDRA_TOOLS) | {"import_file"}
            if name not in allowed:
                self.violations.append("unallowlisted:%s" % name)
            if name == "list_binaries":
                self.selected = True
            elif self.selected and "program_name" not in arguments:
                self.violations.append("no-program:%s" % name)
            return self._respond(name, arguments)

    def _respond(self, name, arguments):
        if name == "list_binaries":
            return (
                "1. demo [ACTIVE]\n"
                "   Project Path: %s\n"
                "   Executable Path: %s\n"
                "   Format: ELF\n"
                "   Language: PowerPC:BE:32:Gekko" % (self.program, self.target)
            )
        if name == "get_binary_info":
            return "Language: PowerPC/big/32/Gekko"
        if name == "analyze_program":
            return "Analysis completed for %s" % arguments.get("program_name")
        if name == "get_functions":
            return "- fn @ 00010198 (0 params)"
        if name == "analyze_function":
            return ("Function: fn\n"
                    "Entry Point: 00010198\n"
                    "Prototype: int fn(void)\n")
        if name == "get_code":
            fmt = arguments.get("format")
            if fmt == "decompiler":
                tag = "REVISED " if self.proto_set else ""
                return "int fn(void) {\n  %sreturn local_8;\n}\n" % tag
            if fmt == "pcode":
                return "(register, r3, 4) = COPY (const, 0x0, 4)\nRETURN\n"
            return "clrlwi r3, r3, 24\nblr\n"
        if name == "get_basic_blocks":
            return "Block 00010198 -> 000101a0\nBlock 000101a0 (return)\n"
        if name == "variables":
            action = arguments.get("action")
            if action == "set_prototype":
                self.proto_set = True
                return "Prototype set on %s" % arguments.get("function_address")
            if action == "list":
                return ("Variables in function: fn\n"
                        "  - int local_8 (_r3:4)\n")
            return "ok"
        if name == "xrefs":
            return "xref: caller @ 00010100 -> fn\n"
        return "evidence for %s" % name


def _integration_project(stack):
    """Full GZLP01+GZLJ01 REL fixture with a shared header and sibling.

    Mirrors the proven in-process verify-version fixture but installs an
    executable fake model so the run can be driven end to end through main().
    """
    demo = "int fn(){return zzz;}\n"
    shared_before = "// shared low\n"
    shared_after = "// shared EXACT\n"
    sibling = "int sib(){return 0;}\n"
    base_obj = (demo + shared_after).encode()
    sib_obj = (sibling + shared_after).encode()
    expected_sha = hashlib.sha1(base_obj + sib_obj).hexdigest()
    base_rel = "build/GZLP01/demo/obj/demo_base.o"
    sib_rel = "build/GZLP01/demo/obj/sibling.o"
    rel_rel = "build/GZLP01/demo/demo.rel"
    gj_base = "build/GZLJ01/demo/obj/demo_base.o"
    gj_sib = "build/GZLJ01/demo/obj/sibling.o"
    gj_rel = "build/GZLJ01/demo/demo.rel"
    gj_report_src = "build/GZLJ01/report_src.json"
    env = _engine_project(
        stack, module="demo", source=demo,
        extra_files={
            "src/shared.h": shared_before,
            "src/sibling.cpp": sibling,
            sib_rel: "committed-sibling",
            rel_rel: "committed-rel",
            gj_base: "committed-gj-base",
            gj_sib: "committed-gj-sibling",
            gj_rel: "committed-gj-rel",
            gj_report_src: json.dumps({"units": [{
                "name": "demo/demo",
                "measures": {
                    "matched_functions_percent": 100.0,
                    "matched_code_percent": 100.0,
                    "matched_data_percent": 100.0,
                }}]}),
            "orig/GZLJ01/disc.bin": "disc",
            "config/GZLP01/config.yml": "version: GZLP01\n",
            "config/GZLJ01/config.yml": "version: GZLJ01\n",
        },
        manifest_extra={
            base_rel: {"inputs": ["src/demo.cpp", "src/shared.h"],
                       "kind": "object"},
            sib_rel: {"inputs": ["src/sibling.cpp", "src/shared.h"],
                      "kind": "object"},
            rel_rel: {"inputs": [base_rel, sib_rel], "kind": "rel"},
        },
    )
    project = env.project
    (project / "config/GZLP01/build.sha1").write_text(
        "%s  %s\n" % (expected_sha, rel_rel))
    (project / "config/GZLJ01/build.sha1").write_text(
        "%s  %s\n" % (expected_sha, gj_rel))
    gzlp_objdiff = (project / "objdiff.json").read_text()
    gzlp_manifest = (project / "build_manifest.json").read_text()
    gzlj_objdiff = json.dumps({"units": [{
        "name": "demo/demo",
        "target_path": "build/GZLJ01/demo/obj/demo.o",
        "base_path": gj_base,
        "metadata": {"source_path": "src/demo.cpp"},
        "scratch": {"ctx_path": "build/GZLJ01/demo/ctx.c",
                    "compiler": "mwcc_233_163", "c_flags": "-O4,p"},
    }]})
    gzlj_manifest = json.dumps({"targets": {
        gj_base: {"inputs": ["src/demo.cpp", "src/shared.h"], "kind": "object"},
        gj_sib: {"inputs": ["src/sibling.cpp", "src/shared.h"],
                 "kind": "object"},
        gj_rel: {"inputs": [gj_base, gj_sib], "kind": "rel"},
        "build/GZLJ01/report.json": {"inputs": [gj_report_src],
                                     "kind": "report"},
    }})
    for name, obj, man in (
        ("GZLP01", gzlp_objdiff, gzlp_manifest),
        ("GZLJ01", gzlj_objdiff, gzlj_manifest),
    ):
        tpl = project / ".mwdiff_versions" / name
        tpl.mkdir(parents=True, exist_ok=True)
        (tpl / "objdiff.json").write_text(obj)
        (tpl / "build_manifest.json").write_text(man)
    (project / "build/GZLJ01/demo/obj").mkdir(parents=True, exist_ok=True)
    (project / "build/GZLJ01/demo/obj/demo.o").write_bytes(base_obj)
    # Executable fake model driving the three source rounds.
    log = project / "model_requests.log"
    env.model.write_text(_FAKE_MODEL_TMPL.format(log=str(log)))
    env.model.chmod(0o755)
    return types.SimpleNamespace(
        env=env, project=project, header=project / "src/shared.h",
        expected_sha=expected_sha, log=log,
        base_rel=base_rel, sib_rel=sib_rel, rel_rel=rel_rel,
        gj_base=gj_base, gj_sib=gj_sib, gj_rel=gj_rel)


class TestReconstructCliIntegration(unittest.TestCase):
    def _drive(self, stack, fix, *, apply=False, json_mode=False,
               verify_version="GZLJ01", max_rounds=None):
        server = _FakeGhidraServer("/decomp/demo.o",
                                   fix.project / fix.env.target_rel)
        stack.callback(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(lambda: (server.shutdown(), thread.join(timeout=5)))
        argv = [
            "mwdiff.py", "reconstruct",
            "--project", str(fix.project),
            "--version", "GZLP01",
            "--unit", "demo/demo",
            "--ghidra-mcp-url", server.url,
            "--ghidra-program", "/decomp/demo.o",
            "--llm-cmd", str(fix.env.model),
            "--edit-file", str(fix.header),
        ]
        if max_rounds is not None:
            argv += ["--max-rounds", str(max_rounds)]
        if verify_version:
            argv += ["--verify-version", verify_version]
        if apply:
            argv.append("--apply")
        if json_mode:
            argv.append("--json")
        dtk = str(fix.project / "build/tools/dtk")
        objdiff = str(fix.project / "build/tools/objdiff-cli")
        with mock.patch.object(mwdiff, "DTK", dtk), \
                mock.patch.object(mwdiff, "OBJDIFF", objdiff):
            code, stdout, stderr = _run_main_argv(argv)
        return code, stdout, stderr, server

    def _model_requests(self, fix):
        return [json.loads(line)
                for line in fix.log.read_text().splitlines() if line]

    def test_end_to_end_run_restores_everything_without_apply(self):
        with ExitStack() as stack:
            fix = _integration_project(stack)
            project = fix.project
            header = fix.header
            # Capture the committed baseline the preview run must restore.
            header_bytes = header.read_bytes()
            header_mode = header.stat().st_mode
            header_mtime = header.stat().st_mtime_ns
            ctx = project / fix.env.ctx_rel
            committed = {
                rel: (project / rel).read_bytes()
                for rel in (fix.base_rel, fix.sib_rel, fix.rel_rel,
                            fix.gj_base, fix.gj_sib, fix.gj_rel, fix.env.ctx_rel)
            }
            committed_mtime = {
                rel: (project / rel).stat().st_mtime_ns
                for rel in (fix.sib_rel, fix.gj_rel, fix.env.ctx_rel)
            }

            code, stdout, stderr, server = self._drive(stack, fix)

            self.assertEqual(code, 0, stderr)
            # -- the drove-through-main human document ------------------
            self.assertIn("outcome restored status=exact", stdout)
            self.assertIn("link status=match", stdout)
            self.assertIn("verify version=GZLJ01", stdout)
            self.assertIn("patch src/shared.h", stdout)
            for kind in ("ghidra-operation-confirmed", "compiler-error",
                         "score-rejected", "score-improved", "link",
                         "verify-version", "outcome"):
                self.assertIn("event %s" % kind, stdout)

            # -- three real candidate builds (compile fail, non-improve,
            #    exact) each consumed one build --------------------------
            outcome_line = next(
                line for line in stdout.splitlines()
                if line.startswith("outcome "))
            self.assertIn("builds=3/", outcome_line)
            self.assertIn("rounds=3/", outcome_line)

            requests = self._model_requests(fix)
            phases = [(r["phase"], r["run"]["round"]) for r in requests]
            self.assertEqual(phases, [
                ("analyze", 1), ("propose", 1),
                ("analyze", 2), ("propose", 2),
                ("analyze", 3), ("propose", 3),
            ])
            # The confirmed Ghidra update produced re-decompiled evidence that
            # the following propose request actually received.
            first_propose = requests[1]
            self.assertIn(
                "REVISED", first_propose["ghidra"]["decompiler"]["text"])
            # The compiler failure from round 1 reached round 2's request.
            second_analyze = requests[2]
            feedback_kinds = [f.get("kind") for f in second_analyze["feedback"]]
            self.assertIn("compiler-error", feedback_kinds)
            # Round 2's context excerpt came from the accepted (baseline)
            # source rebuilt after the round-1 rollback.
            self.assertIn(
                "fn", second_analyze["compiler"]["context_excerpt"])

            # -- exactly one confirmed allowed Ghidra update ------------
            self.assertEqual(
                stdout.count("event ghidra-operation-confirmed"), 1)

            # -- the handler stayed inside the contract -----------------
            self.assertEqual(server.violations, [])
            self.assertTrue(server.proto_set)

            # -- without --apply the source and every rebuilt artifact is
            #    restored byte-for-byte (mode + mtime preserved) --------
            self.assertEqual(header.read_bytes(), header_bytes)
            self.assertEqual(header.stat().st_mode, header_mode)
            self.assertEqual(header.stat().st_mtime_ns, header_mtime)
            for rel, data in committed.items():
                self.assertEqual((project / rel).read_bytes(), data, rel)
            for rel, when in committed_mtime.items():
                self.assertEqual(
                    (project / rel).stat().st_mtime_ns, when, rel)
            self.assertTrue(ctx.exists())

    def test_end_to_end_run_retains_source_with_apply(self):
        with ExitStack() as stack:
            fix = _integration_project(stack)
            code, stdout, stderr, server = self._drive(stack, fix, apply=True)
            self.assertEqual(code, 0, stderr)
            self.assertIn("outcome retained status=exact", stdout)
            # The exact source is kept only after linked + cross-version gates.
            self.assertIn(b"EXACT", fix.header.read_bytes())
            self.assertEqual(server.violations, [])

    def test_json_mode_is_one_document_matching_human_facts(self):
        with ExitStack() as stack:
            fix = _integration_project(stack)
            code, stdout, stderr, _ = self._drive(
                stack, fix, json_mode=True)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stdout.count("\n"), 1)
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "exact")
            self.assertEqual(payload["outcome"], "restored")
            self.assertEqual(payload["link"]["status"], "match")
            self.assertEqual(payload["link"]["actual_sha1"], fix.expected_sha)
            self.assertEqual(len(payload["verification"]), 1)
            self.assertEqual(payload["verification"][0]["version"], "GZLJ01")
            kinds = {event["kind"] for event in payload["events"]}
            for kind in ("ghidra-operation-confirmed", "compiler-error",
                         "score-rejected", "score-improved", "link",
                         "verify-version", "outcome"):
                self.assertIn(kind, kinds)

    def test_current_link_mismatch_is_incomplete_and_restores_source(self):
        with ExitStack() as stack:
            fix = _integration_project(stack)
            # Corrupt the selected-version SHA so the exact object never links.
            (fix.project / "config/GZLP01/build.sha1").write_text(
                "%s  %s\n" % ("f" * 40, fix.rel_rel))
            header_bytes = fix.header.read_bytes()
            code, stdout, stderr, _ = self._drive(stack, fix, max_rounds=3)
            self.assertEqual(code, 1, stderr)
            self.assertIn("outcome restored status=incomplete", stdout)
            self.assertIn("link status=mismatch", stdout)
            # A failed link gate never retains the source.
            self.assertEqual(fix.header.read_bytes(), header_bytes)

    def test_cross_version_failure_is_incomplete_and_restores_source(self):
        with ExitStack() as stack:
            fix = _integration_project(stack)
            # Break only the requested cross-version REL SHA.
            (fix.project / "config/GZLJ01/build.sha1").write_text(
                "%s  %s\n" % ("e" * 40, fix.gj_rel))
            header_bytes = fix.header.read_bytes()
            code, stdout, stderr, _ = self._drive(stack, fix)
            self.assertEqual(code, 1, stderr)
            self.assertIn("status=incomplete", stdout)
            self.assertIn("verify version=GZLJ01", stdout)
            self.assertIn("rel_sha_match=False", stdout)
            self.assertEqual(fix.header.read_bytes(), header_bytes)


if __name__ == "__main__":
    unittest.main()
