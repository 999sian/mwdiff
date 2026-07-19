#!/usr/bin/env python3
"""
mwdiff.py - per-function asm diff helper for dtk-based (MWCC) matching decomp.

Compares two object files by disassembling each with `dtk elf disasm` and
diffing function-by-function, normalising away cosmetic noise (comments,
local label names, `@NNNN`/`$NNNN` compiler counters, anonymous section
symbols, and the address columns) so only *real* instruction differences show.

`try` brute-forces an explicit variants file. `search` generates bounded MWCC
source mutations and can reject behavior-changing candidates with the optional
Z3-backed `--prove` gate. `diagnose` classifies one mismatch; `prove` checks
supported acyclic integer functions directly. `reconstruct` autonomously drives
one configured unit to an exact match with a Ghidra MCP server and an LLM.

Usage:
  mwdiff.py diff  <target.o> <mine.o>
  mwdiff.py show  <target.o> <mine.o> <mangled_fn>
  mwdiff.py try   <src.cpp> <obj_to_build> <target.o> <mangled_fn> <variants.py>
  mwdiff.py diagnose --unit <unit> --fn <mangled_fn>
  mwdiff.py search --unit <unit> --fn <mangled_fn> --line <range> --families <list>
  mwdiff.py prove <target.o> <mine.o> <mangled_fn>
  mwdiff.py reconstruct --unit <unit> --ghidra-mcp-url <url> --llm-cmd <cmd>

`dtk` is found via $DTK or ./build/tools/dtk. `prove` and `search --prove`
require `z3-solver`; other commands do not. Exit status: 0 = exact/equivalent,
1 = different or unknown, 2 = usage/tool error.
"""
from contextlib import ExitStack
import dataclasses
import hashlib
from dataclasses import dataclass
from pathlib import Path
import argparse
import difflib
import itertools
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import signal
import stat
import tempfile
import threading
import time
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

DTK = os.environ.get("DTK", "build/tools/dtk")
OBJDIFF = os.environ.get("OBJDIFF", "build/tools/objdiff-cli")

# Pre-compiled normalisation patterns (order matters).
_NORM = [
    (re.compile(r"/\*.*?\*/"), ""),           # address / hex columns
    (re.compile(r"\.L[0-9a-fA-F_]+:\s*"), ""),  # local label names
    (re.compile(r"@\d+"), "@N"),              # float/string pool counters
    (re.compile(r"\$\d+"), "$N"),             # static-local counters
    (re.compile(r"\.\.\.(?:ro)?data\.0"), "@N"),  # anonymous section symbols
]
_LOCAL_LABEL = re.compile(r"\.L[0-9a-fA-F_]+")
_LOCAL_LABEL_DEFINITION = re.compile(r"(?P<label>\.L[0-9a-fA-F_]+):")

_REGISTER = re.compile(r"\b(?:r(?:[12]?\d|3[01])|f(?:[12]?\d|3[01]))\b")
_BRANCHES = {"b", "beq", "bne", "blt", "ble", "bgt", "bge", "bdnz", "bdz"}
_CALLS = {"bl", "bctrl"}
_MEMORY = {"lbz", "lha", "lhz", "lwz", "stb", "sth", "stw", "lmw", "stmw"}
_RELOCATION = re.compile(
    r"(?P<symbol>(?:\.\.\.)?[A-Za-z_.$][\w.$]*)@(?P<suffix>ha|h|l|sda21)")
_RELOCATION_NEUTRAL = re.compile(
    r"(?:@N|(?:\.\.\.)?[A-Za-z_.$][\w.$]*)@(?P<suffix>ha|h|l|sda21)")


@dataclass(frozen=True)
class Instruction:
    opcode: str
    operands: tuple[str, ...]


@dataclass(frozen=True)
class Diagnosis:
    classification: str
    diff_lines: int
    register_map: dict[str, str]
    relocation_aliases: tuple[tuple[str, str], ...]
    suggested_families: tuple[str, ...]


def parse_instruction(line):
    text = line.strip()
    opcode, _, operands = text.partition(" ")
    return Instruction(opcode, tuple(part.strip() for part in operands.split(",") if part.strip()))


def infer_register_map(target, candidate):
    target_i = [parse_instruction(line) for line in target]
    candidate_i = [parse_instruction(line) for line in candidate]
    if len(target_i) != len(candidate_i):
        return {}
    mapping = {}
    reverse = {}
    for left, right in zip(target_i, candidate_i):
        if left.opcode != right.opcode or len(left.operands) != len(right.operands):
            return {}
        for left_op, right_op in zip(left.operands, right.operands):
            left_regs = _REGISTER.findall(left_op)
            right_regs = _REGISTER.findall(right_op)
            if len(left_regs) != len(right_regs):
                return {}
            for source, dest in zip(left_regs, right_regs):
                if source in mapping and mapping[source] != dest:
                    return {}
                if dest in reverse and reverse[dest] != source:
                    return {}
                mapping[source] = dest
                reverse[dest] = source
    return mapping


def _rename_registers(line, mapping):
    return _REGISTER.sub(lambda match: mapping.get(match.group(), match.group()), line)


def _relocation_neutral(line):
    return _RELOCATION_NEUTRAL.sub(
        lambda match: f"<reloc>@{match.group('suffix')}", line)


def _relocation_aliases(target, candidate):
    aliases = []
    for left, right in zip(target, candidate):
        left_relocs = _RELOCATION.findall(left)
        right_relocs = _RELOCATION.findall(right)
        for (left_symbol, left_suffix), (right_symbol, right_suffix) in zip(
                left_relocs, right_relocs):
            pair = (left_symbol, right_symbol)
            if left_suffix == right_suffix and left_symbol != right_symbol and pair not in aliases:
                aliases.append(pair)
    return tuple(aliases)


def _families_for(classification):
    return {
        "global-register-permutation": ("bool", "compare", "local-form"),
        "local-register-allocation": ("cast", "load", "local-form"),
        "scheduling": ("load", "local-form", "evaluation-order"),
        "operand-order": ("evaluation-order", "reassociate"),
        "branch-shape": ("bool", "switch", "return"),
        "call-wrapper": ("wrapper", "evaluation-order"),
        "constant-pool": ("local-form", "reassociate"),
        "data-layout": (),
        "relocation-alias": (),
        "semantic-instruction": (),
        "exact": (),
    }[classification]


def diagnose_lines(target, candidate):
    left, right = norm(target), norm(candidate)
    aliases = _relocation_aliases(target, candidate)
    neutral_left = [_relocation_neutral(line) for line in left]
    neutral_right = [_relocation_neutral(line) for line in right]
    mapping = {}
    if left == right:
        classification = "exact"
    elif neutral_left == neutral_right:
        classification = "relocation-alias"
    else:
        left_i = [parse_instruction(line) for line in left]
        right_i = [parse_instruction(line) for line in right]
        mapping = infer_register_map(left, right)
        if mapping and [_rename_registers(line, mapping) for line in neutral_left] == neutral_right:
            classification = "global-register-permutation"
        elif len(left_i) == len(right_i) and all(a.opcode == b.opcode for a, b in zip(left_i, right_i)):
            changed = [(a, b) for a, b in zip(left_i, right_i) if a != b]
            if any(a.opcode in _MEMORY for a, _ in changed):
                classification = "scheduling"
            elif any(a.opcode in _CALLS for a, _ in changed):
                classification = "call-wrapper"
            else:
                classification = "local-register-allocation" if mapping else "operand-order"
        elif any(a.opcode in _BRANCHES or b.opcode in _BRANCHES
                 for a, b in zip(left_i, right_i)):
            classification = "branch-shape"
        else:
            classification = "semantic-instruction"
    return Diagnosis(classification, len(fn_diff(target, candidate)), mapping, aliases,
                     _families_for(classification))


def die(msg, code=2):
    print(f"mwdiff: {msg}", file=sys.stderr)
    sys.exit(code)


MCP_PROTOCOL_VERSION = "2025-06-18"
MAX_MCP_RESPONSE = 32 * 1024 * 1024
MAX_MODEL_REQUEST = 32 * 1024 * 1024
MAX_MODEL_RESPONSE = 8 * 1024 * 1024
MAX_MODEL_STDERR = 8 * 1024 * 1024


class McpProtocolError(RuntimeError):
    pass


class McpToolError(RuntimeError):
    pass


def strict_json_loads(text):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(
        text, object_pairs_hook=object_pairs, parse_constant=reject_constant
    )


def _decode_mcp_messages(content_type, body):
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise McpProtocolError("MCP response is not valid UTF-8") from error
    media_type = content_type.split(";", 1)[0].strip().lower()
    try:
        if media_type == "application/json":
            return [strict_json_loads(text)]
        if media_type != "text/event-stream":
            raise McpProtocolError(
                f"unsupported MCP content type: {content_type}"
            )
        messages = []
        data_lines = []
        for line in text.splitlines() + [""]:
            if line == "":
                if data_lines:
                    messages.append(strict_json_loads("\n".join(data_lines)))
                    data_lines = []
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        return messages
    except ValueError as error:
        raise McpProtocolError("MCP response contains invalid JSON") from error


class McpClient:
    def __init__(self, url, timeout=30, opener=urlrequest.urlopen):
        parsed = urlparse.urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("MCP URL must be credential-free HTTP(S)")
        self.url = url
        self.timeout = timeout
        self.opener = opener
        self.session_id = None
        self.protocol_version = None
        self.next_id = 1

    def _post(self, message, response_id=None):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        request = urlrequest.Request(
            self.url,
            data=json.dumps(message, separators=(",", ":")).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                body = response.read(MAX_MCP_RESPONSE + 1)
                content_type = response.headers.get(
                    "Content-Type", "application/json"
                )
                session_id = response.headers.get("Mcp-Session-Id")
                status = response.status
        except urlerror.HTTPError as error:
            detail = error.read(4096).decode("utf-8", "replace")
            raise McpProtocolError(
                f"MCP HTTP {error.code}: {detail.strip()}"
            ) from error
        except OSError as error:
            raise McpProtocolError(f"MCP request failed: {error}") from error
        if len(body) > MAX_MCP_RESPONSE:
            raise McpProtocolError("MCP response exceeds 32 MiB")
        if session_id:
            self.session_id = session_id
        if response_id is None:
            if status != 202:
                raise McpProtocolError(
                    f"MCP notification returned HTTP {status}, expected 202"
                )
            return None
        for response in _decode_mcp_messages(content_type, body):
            if not isinstance(response, dict):
                raise McpProtocolError("MCP JSON-RPC response must be an object")
            if response.get("jsonrpc") != "2.0":
                raise McpProtocolError("MCP response has invalid JSON-RPC version")
            if response.get("id") != response_id:
                continue
            if "error" in response:
                error = response["error"]
                if not isinstance(error, dict):
                    raise McpProtocolError("MCP error payload must be an object")
                raise McpProtocolError(
                    f"MCP error {error.get('code')}: {error.get('message')}"
                )
            if "result" not in response:
                raise McpProtocolError("MCP response has no result")
            return response["result"]
        raise McpProtocolError(f"MCP response has no JSON-RPC id {response_id}")

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        return self._post({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }, request_id)

    def notify(self, method, params=None):
        return self._post({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        })

    def initialize(self):
        result = self.request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mwdiff", "version": "1"},
        })
        if not isinstance(result, dict):
            raise McpProtocolError("MCP initialize result must be an object")
        negotiated = result.get("protocolVersion")
        if negotiated != MCP_PROTOCOL_VERSION:
            raise McpProtocolError(
                f"unsupported MCP protocol version: {negotiated}"
            )
        if "tools" not in result.get("capabilities", {}):
            raise McpProtocolError("MCP server does not advertise tools")
        self.protocol_version = negotiated
        self.notify("notifications/initialized")
        return result

    def list_tools(self):
        tools = {}
        cursor = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            listed = result.get("tools") if isinstance(result, dict) else None
            if not isinstance(listed, list):
                raise McpProtocolError("MCP tools/list result has no tools list")
            for tool in listed:
                if (
                    not isinstance(tool, dict)
                    or not isinstance(tool.get("name"), str)
                    or not isinstance(tool.get("inputSchema"), dict)
                ):
                    raise McpProtocolError("MCP tools/list returned an invalid tool")
                if tool["name"] in tools:
                    raise McpProtocolError(
                        f"MCP tools/list returned duplicate {tool['name']}"
                    )
                tools[tool["name"]] = tool
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call(self, name, arguments):
        result = self.request("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        if not isinstance(result, dict):
            raise McpProtocolError(f"Ghidra {name} returned an invalid result")
        if result.get("isError"):
            raise McpToolError(f"Ghidra {name}: {mcp_text(result)}")
        return result


def mcp_text(result):
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list):
        raise McpProtocolError("MCP tool result has no content list")
    texts = []
    for item in content:
        if not isinstance(item, dict):
            raise McpProtocolError("MCP tool content item must be an object")
        if item.get("type") == "text":
            if not isinstance(item.get("text"), str):
                raise McpProtocolError("MCP text content must contain a string")
            texts.append(item["text"])
    return "\n".join(texts)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _drain_stream(stream, limit, state):
    # Reads until EOF; past the cap it discards so the child never blocks.
    try:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                return
            if not state["overflow"]:
                if state["size"] + len(chunk) > limit:
                    state["overflow"] = True
                else:
                    state["chunks"].append(chunk)
                    state["size"] += len(chunk)
    finally:
        stream.close()


def _terminate_process_tree(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.wait()
        return
    cleanup_error = None
    try:
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(process.pid)],
            capture_output=True, timeout=15, check=False,
        )
    except Exception as error:
        cleanup_error = error
    process.kill()
    process.wait()
    if cleanup_error is not None:
        raise RuntimeError(
            f"failed to terminate process tree {process.pid}: {cleanup_error}"
        ) from cleanup_error


def run_bounded_process(
        command, *, input_data=b"", cwd=None, timeout,
        stdout_limit, stderr_limit, cancel=None
):
    if os.name == "posix":
        group_options = {"start_new_session": True}
    else:
        group_options = {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
        }
    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(input_data)
        stdin_file.flush()
        stdin_file.seek(0)
        process = subprocess.Popen(
            command, shell=False, stdin=stdin_file,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, **group_options,
        )
    drainers = []
    for stream, limit in (
        (process.stdout, stdout_limit),
        (process.stderr, stderr_limit),
    ):
        state = {"chunks": [], "size": 0, "overflow": False}
        thread = threading.Thread(
            target=_drain_stream, args=(stream, limit, state), daemon=True,
        )
        thread.start()
        drainers.append((thread, state))
    stdout_state, stderr_state = drainers[0][1], drainers[1][1]
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while True:
            if cancel is not None:
                cancel()
            if stdout_state["overflow"]:
                failure = RuntimeError(
                    f"process stdout exceeded {stdout_limit} bytes: {command}"
                )
                break
            if stderr_state["overflow"]:
                failure = RuntimeError(
                    f"process stderr exceeded {stderr_limit} bytes: {command}"
                )
                break
            if process.poll() is not None:
                break
            if time.monotonic() >= deadline:
                failure = RuntimeError(
                    f"process timed out after {timeout} seconds: {command}"
                )
                break
            time.sleep(0.05)
    except BaseException:
        _terminate_process_tree(process)
        for thread, _ in drainers:
            thread.join()
        raise
    if failure is None:
        # Ordinary exit: a surviving descendant may hold a pipe open, so
        # bound the final drain by the remaining deadline; late overflow
        # must fail rather than return silently truncated output.
        for thread, _ in drainers:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread, _ in drainers):
            failure = RuntimeError(
                f"process timed out after {timeout} seconds: {command}"
            )
        elif stdout_state["overflow"]:
            failure = RuntimeError(
                f"process stdout exceeded {stdout_limit} bytes: {command}"
            )
        elif stderr_state["overflow"]:
            failure = RuntimeError(
                f"process stderr exceeded {stderr_limit} bytes: {command}"
            )
    if failure is not None:
        _terminate_process_tree(process)
        for thread, _ in drainers:
            thread.join()
        raise failure
    return ProcessResult(
        process.returncode,
        b"".join(stdout_state["chunks"]),
        b"".join(stderr_state["chunks"]),
    )


def invoke_model(command, request, timeout, cancel=None):
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MODEL_REQUEST:
        raise ValueError("model request exceeds 32 MiB")
    result = run_bounded_process(
        command, input_data=payload, timeout=timeout,
        stdout_limit=MAX_MODEL_RESPONSE, stderr_limit=MAX_MODEL_STDERR,
        cancel=cancel,
    )
    if result.returncode != 0:
        excerpt = result.stderr[:4096].decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"model command exited {result.returncode}: {excerpt}"
        )
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("model response is not valid UTF-8") from error
    response = strict_json_loads(text)
    if not isinstance(response, dict):
        raise ValueError("model response must be a JSON object")
    return response


MAX_GHIDRA_OPERATIONS = 128
MAX_SOURCE_EDITS = 256
MAX_PROTOCOL_TEXT = 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

GHIDRA_OPERATION_FIELDS = {
    "rename_function": ({"op", "function", "new_name", "reason"}, set()),
    "rename_data": ({"op", "address_or_name", "new_name", "reason"}, set()),
    "rename_variable": (
        {"op", "function", "variable", "new_name", "reason"}, set()
    ),
    "set_prototype": (
        {"op", "function", "prototype", "reason"}, set()
    ),
    "retype_variable": (
        {"op", "function", "variable", "data_type", "reason"}, set()
    ),
    "create_struct": ({"op", "c_definition", "reason"}, set()),
    "set_struct_field": (
        {"op", "structure_name", "offset", "data_type", "field_name", "reason"},
        {"pointer_level", "array_count"},
    ),
    "rename_struct_field": (
        {"op", "structure_name", "offset", "new_name", "reason"}, set()
    ),
}


def _require_fields(value, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError("JSON value must be an object")
    missing = sorted(set(required) - set(value))
    unknown = sorted(set(value) - set(required) - set(optional))
    if missing:
        raise ValueError("missing fields: " + ", ".join(missing))
    if unknown:
        raise ValueError("unknown fields: " + ", ".join(unknown))


def _protocol_text(value, field, *, empty=False, limit=MAX_PROTOCOL_TEXT):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if not empty and not value:
        raise ValueError(f"{field} must be nonempty")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{field} is too large")
    return value


def _operation_integer(operation, field, minimum, maximum=None):
    value = operation.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{field} must be <= {maximum}")


def validate_analysis_response(value):
    _require_fields(value, {"schema", "summary", "ghidra_ops"})
    if value["schema"] != "mwdiff.reconstruct.analyze.v1":
        raise ValueError(f"wrong analysis schema: {value['schema']}")
    _protocol_text(value["summary"], "summary", limit=65536)
    if not isinstance(value["ghidra_ops"], list):
        raise ValueError("ghidra_ops must be a list")
    if len(value["ghidra_ops"]) > MAX_GHIDRA_OPERATIONS:
        raise ValueError("too many Ghidra operations")
    for operation in value["ghidra_ops"]:
        if not isinstance(operation, dict):
            raise ValueError("Ghidra operation must be an object")
        tag = operation.get("op")
        if not isinstance(tag, str):
            raise ValueError("operation tag must be a string")
        if tag not in GHIDRA_OPERATION_FIELDS:
            raise ValueError("unknown Ghidra operation")
        required, optional = GHIDRA_OPERATION_FIELDS[tag]
        _require_fields(operation, required, optional)
        for field, field_value in operation.items():
            if field not in {"offset", "pointer_level", "array_count"}:
                _protocol_text(
                    field_value, field,
                    limit=65536 if field == "c_definition" else 4096,
                )
        for field in {"new_name", "field_name"} & set(operation):
            if not _IDENTIFIER.fullmatch(operation[field]):
                raise ValueError(f"{field} must be a C identifier")
        if "offset" in operation:
            _operation_integer(operation, "offset", 0)
        if "pointer_level" in operation:
            _operation_integer(operation, "pointer_level", 0, 8)
        if "array_count" in operation:
            _operation_integer(operation, "array_count", 1, 1048576)
    return value


def validate_proposal_response(value):
    _require_fields(value, {"schema", "summary", "source_edits"})
    if value["schema"] != "mwdiff.reconstruct.propose.v1":
        raise ValueError(f"wrong proposal schema: {value['schema']}")
    _protocol_text(value["summary"], "summary", limit=65536)
    if not isinstance(value["source_edits"], list):
        raise ValueError("source_edits must be a list")
    if len(value["source_edits"]) > MAX_SOURCE_EDITS:
        raise ValueError("too many source edits")
    required = {"path", "file_sha256", "old", "new"}
    for edit in value["source_edits"]:
        _require_fields(edit, required)
        _protocol_text(edit["path"], "path", limit=4096)
        _protocol_text(edit["file_sha256"], "file_sha256", limit=64)
        _protocol_text(edit["old"], "old")
        _protocol_text(edit["new"], "new", empty=True)
        if not re.fullmatch(r"[0-9a-f]{64}", edit["file_sha256"]):
            raise ValueError("source edit file_sha256 must be lowercase SHA-256")
    return value


REQUIRED_GHIDRA_TOOLS = {
    "analyze_function", "analyze_program", "cancel_task", "classes",
    "get_basic_blocks", "get_binary_info", "get_code", "get_data_vars",
    "get_exports", "get_functions", "get_imports", "get_relocations",
    "get_strings", "get_task_status", "list_binaries", "struct", "types",
    "rename_symbol",
    "variables", "xrefs",
}
_PLACEHOLDER_NAME = re.compile(
    r"^(?:FUN|DAT)_[0-9A-Fa-f]+$|^(?:param|local)_\w+$|^field_0x[0-9A-Fa-f]+$"
)


@dataclass(frozen=True)
class OpenProgram:
    name: str
    project_path: str
    executable_path: str
    language: str


@dataclass(frozen=True)
class PreparedProgram:
    path: str
    replay_required: bool


def parse_open_programs(text):
    pattern = re.compile(
        r"(?m)^\d+\. (?P<name>.+?)(?: \[ACTIVE\])?\n"
        r"\s+Project Path: (?P<project>.+)\n"
        r"\s+Executable Path: (?P<executable>.+)\n"
        r"\s+Format: .+\n"
        r"\s+Language: (?P<language>.+)$"
    )
    return [
        OpenProgram(
            match.group("name"),
            match.group("project"),
            match.group("executable"),
            match.group("language"),
        )
        for match in pattern.finditer(text)
    ]


def require_ghidra_tools(tools, importing):
    required = set(REQUIRED_GHIDRA_TOOLS)
    if importing:
        required.add("import_file")
    missing = sorted(required - set(tools))
    if missing:
        raise ValueError("Ghidra MCP missing tools: " + ", ".join(missing))


def prepare_ghidra_program(
        client, tools, unit, args, state_id, prior_program=None, cancel=None):
    target = unit.target.resolve()
    listing = mcp_text(client.call("list_binaries", {}))
    programs = parse_open_programs(listing)
    replay_required = True
    if args.ghidra_program:
        matches = [
            program for program in programs
            if program.project_path == args.ghidra_program
        ]
        if len(matches) != 1:
            raise ValueError(
                f"Ghidra program {args.ghidra_program!r} is not open"
            )
        program = matches[0]
        if Path(program.executable_path).resolve() != target:
            raise ValueError(
                f"Ghidra program {program.project_path!r} is not the target object"
            )
        replay_required = program.project_path != prior_program
    else:
        reused = [
            program for program in programs
            if program.project_path == prior_program
            and Path(program.executable_path).resolve() == target
        ]
        if len(reused) > 1:
            raise RuntimeError(f"duplicate Ghidra program {prior_program}")
        if reused:
            program = reused[0]
            replay_required = False
        else:
            folder = (
                "/mwdiff/"
                + re.sub(r"[^A-Za-z0-9_.-]", "_", unit.name)
                + "-"
                + state_id[:12]
                + "-"
                + secrets.token_hex(4)
            )
            arguments = {
                "file_path": str(target),
                "folder": folder,
                "open_after_import": True,
                "suppress_analysis_prompt": True,
            }
            if args.ghidra_language:
                arguments["language"] = args.ghidra_language
            if args.ghidra_compiler:
                arguments["compiler"] = args.ghidra_compiler
            client.call("import_file", arguments)
            listing = mcp_text(client.call("list_binaries", {}))
            programs = parse_open_programs(listing)
            matches = [
                item for item in programs
                if item.project_path.startswith(folder + "/")
                and Path(item.executable_path).resolve() == target
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    f"expected one imported Ghidra program in {folder}, "
                    f"found {len(matches)}"
                )
            program = matches[0]
    if not program.language.startswith("PowerPC:BE:32:"):
        raise ValueError(f"unsupported Ghidra language: {program.language}")
    binary_info = mcp_text(client.call("get_binary_info", {
        "program_name": program.project_path,
    }))
    if not re.search(r"(?m)^Language:\s*PowerPC/big/32/", binary_info):
        raise ValueError("Ghidra binary metadata is not 32-bit big-endian PowerPC")
    analysis = mcp_text(client.call("analyze_program", {
        "program_name": program.project_path,
        "mode": "full",
    }))
    task = re.search(r"(?i)task(?: id)?:\s*([0-9A-Za-z-]+)", analysis)
    if task is None:
        if re.search(r"(?i)failed|cancelled", analysis):
            raise RuntimeError(f"Ghidra analysis failed: {analysis}")
        if not re.search(r"(?i)completed|succeeded", analysis):
            raise McpProtocolError(
                f"unrecognized Ghidra analysis response: {analysis}"
            )
    else:
        task_id = task.group(1)
        deadline = time.monotonic() + args.mcp_timeout
        failed_result = None
        try:
            while True:
                if cancel is not None:
                    cancel()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Ghidra analysis timed out")
                request_timeout = client.timeout
                client.timeout = min(request_timeout, remaining)
                try:
                    result = mcp_text(client.call("get_task_status", {
                        "task_id": task_id,
                        "program_name": program.project_path,
                    }))
                finally:
                    client.timeout = request_timeout
                if re.search(r"(?i)failed|cancelled", result):
                    failed_result = result
                    break
                if re.search(r"(?i)completed|succeeded", result):
                    break
                if not re.search(
                        r"(?i)queued|pending|running|in[ -]?progress", result):
                    raise McpProtocolError(
                        f"unrecognized Ghidra task status: {result}"
                    )
                if time.monotonic() >= deadline:
                    raise RuntimeError("Ghidra analysis timed out")
                time.sleep(0.25)
        except BaseException as error:
            try:
                client.call("cancel_task", {
                    "task_id": task_id,
                    "program_name": program.project_path,
                })
            except BaseException as cancel_error:
                raise RuntimeError(
                    f"{error}; Ghidra task cancellation failed: {cancel_error}"
                ) from error
            raise
        if failed_result is not None:
            raise RuntimeError(f"Ghidra analysis failed: {failed_result}")
    return PreparedProgram(program.project_path, replay_required)


MAX_GHIDRA_EVIDENCE = 1024 * 1024


def _ghidra_evidence_call(client, name, arguments, cancel=None):
    if cancel is not None:
        cancel()
    try:
        text = mcp_text(client.call(name, arguments))
        encoded = text.encode()
        if len(encoded) > MAX_GHIDRA_EVIDENCE:
            text = encoded[:MAX_GHIDRA_EVIDENCE].decode("utf-8", "replace")
            return {"text": text, "truncated": True}
        return {"text": text, "truncated": False}
    except McpToolError as error:
        return {"error": str(error), "tool_rejected": True}
    finally:
        if cancel is not None:
            cancel()


def collect_ghidra_evidence(client, program, focus, cancel=None):
    base = {"program_name": program}
    if focus.kind == "function":
        function = focus.name
        return {
            "analyze_function": _ghidra_evidence_call(
                client, "analyze_function",
                {**base, "function_name": function},
                cancel=cancel,
            ),
            "decompiler": _ghidra_evidence_call(
                client, "get_code",
                {**base, "function": function, "format": "decompiler"},
                cancel=cancel,
            ),
            "pcode": _ghidra_evidence_call(
                client, "get_code",
                {**base, "function": function, "format": "pcode", "raw": False},
                cancel=cancel,
            ),
            "disassembly": _ghidra_evidence_call(
                client, "get_code",
                {**base, "function": function, "format": "disassembly"},
                cancel=cancel,
            ),
            "cfg": _ghidra_evidence_call(
                client, "get_basic_blocks",
                {**base, "function": function},
                cancel=cancel,
            ),
            "variables": _ghidra_evidence_call(
                client, "variables",
                {**base, "action": "list", "function_name": function},
                cancel=cancel,
            ),
            "xrefs": _ghidra_evidence_call(
                client, "xrefs",
                {**base, "function": function, "direction": "both",
                 "include_calls": True, "depth": 1, "limit": 100},
                cancel=cancel,
            ),
        }
    return {
        "functions": _ghidra_evidence_call(
            client, "get_functions", {**base, "offset": 0, "limit": 500},
            cancel=cancel,
        ),
        "data": _ghidra_evidence_call(
            client, "get_data_vars", {**base, "offset": 0, "limit": 500},
            cancel=cancel,
        ),
        "strings": _ghidra_evidence_call(
            client, "get_strings", {**base, "offset": 0, "limit": 500},
            cancel=cancel,
        ),
        "relocations": _ghidra_evidence_call(
            client, "get_relocations", {**base, "offset": 0, "limit": 500},
            cancel=cancel,
        ),
        "imports": _ghidra_evidence_call(
            client, "get_imports", base, cancel=cancel,
        ),
        "exports": _ghidra_evidence_call(
            client, "get_exports", base, cancel=cancel,
        ),
        "types": _ghidra_evidence_call(
            client, "types", {**base, "action": "list", "offset": 0, "limit": 500},
            cancel=cancel,
        ),
        "classes": _ghidra_evidence_call(
            client, "classes", {**base, "action": "list", "offset": 0, "limit": 500},
            cancel=cancel,
        ),
    }


# Readback formats captured from a live GhidrAssistMCP server:
#   get_functions:  "- name @ 00010198 (0 params)"
#   get_data_vars:  "@ 00011534 [string] String: \"Htetu1\" (name)"
#   variables list: "  - int iVar1 (_r3:4)" under "Variables in function: name"
#   types get:      "  +0x0000 [  4] float                x" under "Fields:"
_GHIDRA_READBACK_LIMIT = 10000
_FUNCTION_ENTRY = re.compile(
    r"(?m)^\s*-\s+(?P<name>\S+)\s+@\s+(?P<address>[0-9A-Fa-f]+)\b"
)
_DATA_ENTRY = re.compile(
    r"(?m)^\s*@\s*(?P<address>[0-9A-Fa-f]+)\s+\[[^\]]*\].*"
    r"\((?P<name>[^()]*)\)\s*$"
)
_VARIABLE_ENTRY = re.compile(
    r"(?m)^\s*-\s+(?P<type>.+?)\s+(?P<name>\S+)\s+\((?P<storage>[^()]*)\)\s*$"
)
_STRUCT_FIELD_ENTRY = re.compile(
    r"(?m)^\s*\+0x(?P<offset>[0-9A-Fa-f]+)\s+\[\s*\d+\]\s+"
    r"(?P<type>\S+(?:\s+\S+)*?)(?:\s+(?P<name>[A-Za-z_$][\w$]*))?\s*$"
)
_STRUCT_DECLARATION = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*\{")
_RENAMABLE_FIELD = re.compile(r"field_0x[0-9A-Fa-f]+")
_TYPE_NOT_FOUND = re.compile(r"(?im)^.*\btype not found\b")


def _ghidra_readback(client, name, arguments, cancel, *, post=False):
    if cancel is not None:
        cancel()
    try:
        return mcp_text(client.call(name, arguments))
    except McpToolError as error:
        if post:
            raise McpProtocolError(
                f"Ghidra post-condition query rejected: {error}"
            ) from error
        raise
    finally:
        if cancel is not None:
            cancel()


def _function_entries(text):
    return [
        (match.group("name"), match.group("address").lower())
        for match in _FUNCTION_ENTRY.finditer(text)
    ]


def _data_entries(text):
    return [
        (match.group("name"), match.group("address").lower())
        for match in _DATA_ENTRY.finditer(text)
    ]


def _variable_entries(text):
    return [
        (match.group("name"), match.group("type"), match.group("storage"))
        for match in _VARIABLE_ENTRY.finditer(text)
    ]


def _struct_fields(text):
    return [
        (int(match.group("offset"), 16), match.group("name") or "",
         match.group("type"))
        for match in _STRUCT_FIELD_ENTRY.finditer(text)
    ]


def _resolve_unique(entries, description):
    if len(entries) != 1:
        raise ValueError(f"{description} matched {len(entries)} entries")
    return entries[0]


def _require_variable_listing(text, function, *, post):
    if not re.search(
            rf"(?m)^Variables in function:\s*{re.escape(function)}\s*$", text):
        message = f"Ghidra did not list variables for function {function!r}"
        if post:
            raise McpProtocolError(message)
        raise ValueError(message)


def _renamable_struct_field(name):
    return name in {"", "undefined"} or _RENAMABLE_FIELD.fullmatch(name)


def _declared_struct_name(c_definition):
    names = set(_STRUCT_DECLARATION.findall(c_definition))
    if len(names) != 1:
        raise ValueError("c_definition must declare exactly one structure")
    return names.pop()


def _despace(text):
    return re.sub(r"\s+", "", text)


def inspect_ghidra_operation(client, program, operation, cancel=None):
    name = operation["op"]
    base = {"program_name": program}
    if name == "rename_function":
        current = operation["function"]
        text = _ghidra_readback(
            client, "get_functions", {**base, "pattern": current}, cancel)
        entry = _resolve_unique(
            [item for item in _function_entries(text) if item[0] == current],
            f"function {current!r}")
        return {"address": entry[1]}
    if name == "rename_data":
        current = operation["address_or_name"]
        text = _ghidra_readback(
            client, "get_data_vars",
            {**base, "offset": 0, "limit": _GHIDRA_READBACK_LIMIT}, cancel)
        entry = _resolve_unique(
            [item for item in _data_entries(text) if item[0] == current],
            f"data symbol {current!r}")
        return {"address": entry[1]}
    if name in {"rename_variable", "retype_variable"}:
        function = operation["function"]
        variable = operation["variable"]
        text = _ghidra_readback(
            client, "variables",
            {**base, "action": "list", "function_name": function}, cancel)
        _require_variable_listing(text, function, post=False)
        entry = _resolve_unique(
            [item for item in _variable_entries(text) if item[0] == variable],
            f"variable {variable!r} in function {function!r}")
        return {"storage": entry[2]}
    if name == "set_prototype":
        function = operation["function"]
        text = _ghidra_readback(
            client, "get_functions", {**base, "pattern": function}, cancel)
        address = function.lower().removeprefix("0x")
        entry = _resolve_unique(
            [item for item in _function_entries(text)
             if item[0] == function or item[1] == address],
            f"function {function!r}")
        declared = re.search(
            r"([A-Za-z_][\w:]*)\s*\(", operation["prototype"])
        if (declared is not None
                and declared.group(1) != entry[0]
                and not _PLACEHOLDER_NAME.fullmatch(entry[0])):
            raise ValueError(
                f"{entry[0]} is not a placeholder; set_prototype may not "
                "rename it")
        return {"name": entry[0], "address": entry[1]}
    if name == "create_struct":
        structure = _declared_struct_name(operation["c_definition"])
        try:
            text = _ghidra_readback(
                client, "types",
                {**base, "action": "get", "name": structure}, cancel)
        except McpToolError:
            return {"structure": structure}
        if not _TYPE_NOT_FOUND.search(text):
            raise ValueError(f"type {structure!r} already exists")
        return {"structure": structure}
    if name in {"set_struct_field", "rename_struct_field"}:
        structure = operation["structure_name"]
        offset = operation["offset"]
        text = _ghidra_readback(
            client, "types",
            {**base, "action": "get", "name": structure}, cancel)
        if _TYPE_NOT_FOUND.search(text):
            raise ValueError(f"structure {structure!r} does not exist")
        fields = [
            field for field in _struct_fields(text) if field[0] == offset
        ]
        if len(fields) > 1:
            raise ValueError(
                f"{structure!r} offset {offset:#x} is ambiguous")
        if fields:
            field_name = fields[0][1]
            if not _renamable_struct_field(field_name):
                raise ValueError(
                    f"{structure}.{field_name} at offset {offset:#x} "
                    "is not a placeholder")
        elif name == "rename_struct_field":
            raise ValueError(
                f"{structure!r} has no field at offset {offset:#x}")
        return {"structure": structure, "offset": offset}
    raise ValueError(f"unknown Ghidra operation: {name}")


def confirm_ghidra_operation(client, program, operation, expected, cancel=None):
    name = operation["op"]
    base = {"program_name": program}
    if name in {"rename_function", "rename_data"}:
        if name == "rename_function":
            current = operation["function"]
            tool, entries_of = "get_functions", _function_entries
        else:
            current = operation["address_or_name"]
            tool, entries_of = "get_data_vars", _data_entries
        new_name = operation["new_name"]
        text = _ghidra_readback(
            client, tool,
            {**base, "offset": 0, "limit": _GHIDRA_READBACK_LIMIT},
            cancel, post=True)
        entries = entries_of(text)
        if ((new_name, expected["address"]) not in entries
                or any(entry[0] == current for entry in entries)):
            raise McpProtocolError(
                f"rename of {current!r} to {new_name!r} at address "
                f"{expected['address']} is not reflected in Ghidra")
        return
    if name in {"rename_variable", "retype_variable"}:
        function = operation["function"]
        text = _ghidra_readback(
            client, "variables",
            {**base, "action": "list", "function_name": function},
            cancel, post=True)
        _require_variable_listing(text, function, post=True)
        entries = _variable_entries(text)
        if name == "rename_variable":
            current, new_name = operation["variable"], operation["new_name"]
            confirmed = any(
                entry[0] == new_name and entry[2] == expected["storage"]
                for entry in entries
            ) and all(entry[0] != current for entry in entries)
            detail = f"rename of variable {current!r} to {new_name!r}"
        else:
            variable = operation["variable"]
            data_type = _despace(operation["data_type"])
            confirmed = any(
                entry[0] == variable
                and entry[2] == expected["storage"]
                and _despace(entry[1]) == data_type
                for entry in entries
            )
            detail = f"retype of variable {variable!r}"
        if not confirmed:
            raise McpProtocolError(
                f"{detail} in function {function!r} is not reflected in Ghidra")
        return
    if name == "set_prototype":
        prototype = operation["prototype"]
        match = re.search(r"([A-Za-z_][\w:]*)\s*\(", prototype)
        post_name = match.group(1) if match else expected["name"]
        text = _ghidra_readback(
            client, "analyze_function", {**base, "function_name": post_name},
            cancel, post=True)
        entry_point = re.search(
            r"(?im)^Entry Point:\s*([0-9A-Fa-f]+)\s*$", text)
        if (entry_point is None
                or entry_point.group(1).lower() != expected["address"]
                or _despace(prototype) not in _despace(text)):
            raise McpProtocolError(
                f"prototype {prototype!r} is not reflected at address "
                f"{expected['address']} in Ghidra")
        return
    if name == "create_struct":
        structure = expected["structure"]
        text = _ghidra_readback(
            client, "types", {**base, "action": "get", "name": structure},
            cancel, post=True)
        if (_TYPE_NOT_FOUND.search(text)
                or not re.search(
                    rf"(?m)^Data Type:\s*{re.escape(structure)}\s*$", text)):
            raise McpProtocolError(
                f"structure {structure!r} was not created in Ghidra")
        return
    if name in {"set_struct_field", "rename_struct_field"}:
        structure = expected["structure"]
        offset = expected["offset"]
        wanted = (
            operation["field_name"] if name == "set_struct_field"
            else operation["new_name"]
        )
        text = _ghidra_readback(
            client, "types", {**base, "action": "get", "name": structure},
            cancel, post=True)
        matched = [
            field for field in _struct_fields(text)
            if field[0] == offset and field[1] == wanted
        ]
        if name == "set_struct_field":
            expected_type = (
                _despace(operation["data_type"])
                + "*" * operation.get("pointer_level", 0)
            )
            if "array_count" in operation:
                expected_type += f"[{operation['array_count']}]"
            matched = [
                field for field in matched
                if _despace(field[2]) == expected_type
            ]
        if not matched:
            raise McpProtocolError(
                f"{structure}.{wanted} at offset {offset:#x} "
                "is not reflected in Ghidra")
        return
    raise McpProtocolError(f"unknown Ghidra operation to confirm: {name}")


def apply_ghidra_operations(client, program, operations, cancel=None):
    successes = []
    failures = []
    for operation in operations:
        if cancel is not None:
            cancel()
        try:
            name = operation["op"]
            if name == "rename_function":
                current = operation["function"]
                if not _PLACEHOLDER_NAME.fullmatch(current):
                    raise ValueError(f"{current} is not a placeholder")
                tool = "rename_symbol"
                arguments = {
                    "program_name": program,
                    "target_type": "function",
                    "identifier": current,
                    "new_name": operation["new_name"],
                }
            elif name == "rename_data":
                current = operation["address_or_name"]
                if not _PLACEHOLDER_NAME.fullmatch(current):
                    raise ValueError(f"{current} is not a placeholder")
                tool = "variables"
                arguments = {
                    "program_name": program,
                    "action": "rename",
                    "scope": "global",
                    "address_or_name": current,
                    "new_name": operation["new_name"],
                }
            elif name == "rename_variable":
                current = operation["variable"]
                if not _PLACEHOLDER_NAME.fullmatch(current):
                    raise ValueError(f"{current} is not a placeholder")
                tool = "rename_symbol"
                arguments = {
                    "program_name": program,
                    "target_type": "variable",
                    "identifier": operation["function"],
                    "variable_name": current,
                    "new_name": operation["new_name"],
                }
            elif name == "set_prototype":
                tool = "variables"
                arguments = {
                    "program_name": program,
                    "action": "set_prototype",
                    "function_address": operation["function"],
                    "prototype": operation["prototype"],
                }
            elif name == "retype_variable":
                tool = "variables"
                arguments = {
                    "program_name": program,
                    "action": "retype",
                    "function_name": operation["function"],
                    "variable_name": operation["variable"],
                    "data_type": operation["data_type"],
                }
            elif name == "create_struct":
                tool = "struct"
                arguments = {
                    "program_name": program,
                    "action": "create",
                    "c_definition": operation["c_definition"],
                }
            elif name == "set_struct_field":
                tool = "struct"
                arguments = {
                    "program_name": program,
                    "action": "set_field",
                    "structure_name": operation["structure_name"],
                    "offset": operation["offset"],
                    "data_type": operation["data_type"],
                    "field_name": operation["field_name"],
                    "pointer_level": operation.get("pointer_level", 0),
                }
                if "array_count" in operation:
                    arguments["array_count"] = operation["array_count"]
            elif name == "rename_struct_field":
                tool = "struct"
                arguments = {
                    "program_name": program,
                    "action": "rename_field",
                    "structure_name": operation["structure_name"],
                    "offset": operation["offset"],
                    "new_field_name": operation["new_name"],
                }
            else:
                raise ValueError(f"unknown Ghidra operation: {name}")
            expected = inspect_ghidra_operation(
                client, program, operation, cancel=cancel
            )
            result = client.call(tool, arguments)
            if result.get("isError"):
                raise McpToolError(f"Ghidra {tool}: {mcp_text(result)}")
            confirm_ghidra_operation(
                client, program, operation, expected, cancel=cancel
            )
            successes.append(operation)
        except (ValueError, McpToolError) as error:
            failures.append({"operation": operation, "error": str(error)})
        finally:
            if cancel is not None:
                cancel()
    return successes, failures


def replace_unique(source, old, new):
    count = source.count(old)
    if count != 1:
        raise ValueError(f"source anchor must be unique; found {count}")
    return source.replace(old, new, 1)


@dataclass(frozen=True)
class SourceCandidate:
    name: str
    text: str
    depth: int


def source_range(text, selection):
    match = re.fullmatch(r"([1-9]\d*)(?::([1-9]\d*))?", selection)
    if not match:
        raise ValueError("--line must be N or START:END")
    start = int(match.group(1))
    end = int(match.group(2) or start)
    lines = text.splitlines(keepends=True)
    if start > end or end > len(lines):
        raise ValueError(f"source range {selection} is outside 1:{len(lines)}")
    return "".join(lines[start - 1:end]), start - 1, end


def _split_top_level(expression, separator):
    parts, start, depth = [], 0, 0
    for index, char in enumerate(expression):
        depth += char in "([{"
        depth -= char in ")]}"
        if char == separator and depth == 0:
            parts.append(expression[start:index].strip())
            start = index + 1
    parts.append(expression[start:].strip())
    return parts


def _mutate_bool(snippet):
    match = re.search(r"if\s*\((.*)\)(\s*\{?)", snippet)
    if not match:
        return {}
    expression = match.group(1).strip()
    base = re.sub(r"\s*(?:!=\s*FALSE|==\s*TRUE)$", "", expression)
    forms = [base, f"{base} != FALSE", f"{base} == TRUE", f"{base} != 0"]
    return {f"bool:{index}": snippet[:match.start(1)] + form + snippet[match.end(1):]
            for index, form in enumerate(forms) if form != expression}


def _mutate_cast(snippet):
    variants = {}
    for source in ("s8", "u8", "char"):
        for dest in ("s8", "u8", "char"):
            if source != dest and f"({source})" in snippet:
                variants[f"cast:{source}-to-{dest}"] = snippet.replace(
                    f"({source})", f"({dest})")
    return variants


def _mutate_load(snippet):
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?:s8|u8|char) (?P<name>[a-zA-Z_]\w*) = "
        r"(?P<expr>[^;]+);$")
    match = pattern.search(snippet)
    if not match:
        return {}
    direct = f"{match.group('indent')}u8 {match.group('name')} = {match.group('expr')};"
    volatile = (f"{match.group('indent')}u8 {match.group('name')} = "
                f"*(volatile u8*)&{match.group('expr')};")
    return {
        "load:u8-local": snippet[:match.start()] + direct + snippet[match.end():],
        "load:volatile-u8": snippet[:match.start()] + volatile + snippet[match.end():],
    }


def _mutate_reassociate(snippet):
    match = re.search(r"(?P<prefix>=\s*)(?P<expr>[^;]+)(?P<suffix>;)", snippet)
    if not match:
        return {}
    terms = _split_top_level(match.group("expr"), "+")
    if len(terms) != 3:
        return {}
    variants = {}
    for index, order in enumerate(itertools.permutations(terms)):
        for grouping, expression in (
            ("flat", " + ".join(order)),
            ("left", f"({order[0]} + {order[1]}) + {order[2]}"),
            ("right", f"{order[0]} + ({order[1]} + {order[2]})"),
        ):
            variants[f"reassociate:{index}-{grouping}"] = (
                snippet[:match.start("expr")] + expression + snippet[match.end("expr"):])
    return variants


def _mutate_switch(snippet):
    cases = [int(value, 0) for value in re.findall(r"case\s+(0x[0-9a-fA-F]+|\d+)\s*:", snippet)]
    close = snippet.rfind("}")
    if not cases or close < 0:
        return {}
    next_case = max(cases) + 1
    indent_match = re.search(r"(?m)^(\s*)case\s+", snippet)
    indent = indent_match.group(1) if indent_match else ""
    insertion = f"{indent}case {next_case}: break;\n"
    return {f"switch:empty-{next_case}": snippet[:close] + insertion + snippet[close:]}


def _mutate_wrapper(snippet):
    pattern = re.compile(
        r"dComIfGs_isSwitch\((?P<switch>[^,]+),\s*"
        r"fopAcM_GetHomeRoomNo\((?P<actor>[^)]+)\)\)")
    match = pattern.search(snippet)
    if not match:
        return {}
    wrapper = f"fopAcM_isSwitch({match.group('actor').strip()}, {match.group('switch').strip()})"
    return {"wrapper:fopAcM-isSwitch": snippet[:match.start()] + wrapper + snippet[match.end():]}


def _mutate_compare(snippet):
    variants = _mutate_bool(snippet)
    return {name.replace("bool:", "compare:"): text for name, text in variants.items()}


def _mutate_local_form(snippet):
    match = re.search(r"(?m)^(\s*)([a-zA-Z_]\w*) = ([^;]+);$", snippet)
    if not match:
        return {}
    indent, name, expression = match.groups()
    return {"local-form:auto": snippet[:match.start()] +
            f"{indent}auto {name} = {expression};" + snippet[match.end():]}


def _mutate_return(snippet):
    match = re.search(r"return\s+([a-zA-Z_]\w*)\s*;", snippet)
    if not match:
        return {}
    name = match.group(1)
    return {"return:direct-true": snippet.replace(f"return {name};", "return TRUE;", 1),
            "return:direct-false": snippet.replace(f"return {name};", "return FALSE;", 1)}


def _mutate_version(snippet):
    pattern = re.compile(
        r"#if\s+VERSION\s*(?P<operator>==|!=|<=|>=|<|>)\s*"
        r"(?P<constant>VERSION_(?:DEMO|JPN|USA|PAL))")
    match = pattern.search(snippet)
    if not match:
        return {}
    variants = {}
    for operator in ("==", "!=", "<=", ">=", "<", ">"):
        if operator != match.group("operator"):
            variants[f"version:{operator}"] = (
                snippet[:match.start("operator")] + operator +
                snippet[match.end("operator"):])
    return variants


MUTATION_FAMILIES = {
    "bool": _mutate_bool,
    "compare": _mutate_compare,
    "cast": _mutate_cast,
    "load": _mutate_load,
    "reassociate": _mutate_reassociate,
    "switch": _mutate_switch,
    "wrapper": _mutate_wrapper,
    "local-form": _mutate_local_form,
    "return": _mutate_return,
    "evaluation-order": _mutate_reassociate,
    "version": _mutate_version,
}


def generate_candidates(snippet, families, depth=1):
    unknown = sorted(set(families) - MUTATION_FAMILIES.keys())
    if unknown:
        raise ValueError(f"unknown mutation families: {', '.join(unknown)}")
    seen = {snippet}
    frontier = [SourceCandidate("baseline", snippet, 0)]
    results = []
    for level in range(1, depth + 1):
        next_frontier = []
        level_seen = set()
        for parent in frontier:
            parent_seen = set()
            for family in families:
                for name, text in MUTATION_FAMILIES[family](parent.text).items():
                    if text in seen or text in parent_seen:
                        continue
                    parent_seen.add(text)
                    if level == 1 and text in level_seen:
                        continue
                    level_seen.add(text)
                    candidate = SourceCandidate(
                        f"{parent.name}+{name}", text, level
                    )
                    results.append(candidate)
                    next_frontier.append(candidate)
        seen.update(level_seen)
        frontier = next_frontier
    return results


class CandidateCache:
    def __init__(self, root):
        self.root = Path(root)

    @staticmethod
    def key(compiler_hash, flags, context_hash, candidate, version, function):
        payload = "\0".join(
            (compiler_hash, flags, context_hash, candidate, version, function)
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def get(self, key):
        path = self.root / f"{key}.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def put(self, key, value):
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = self.root / f".{key}.tmp"
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.root / f"{key}.json")


class SourceTransaction:
    def __init__(self, path):
        if isinstance(path, (str, os.PathLike)):
            self.paths = (Path(path),)
        else:
            self.paths = tuple(Path(item) for item in path)
        if not self.paths:
            raise ValueError("source transaction requires at least one file")
        if len(set(self.paths)) != len(self.paths):
            raise ValueError("source transaction paths must be unique")
        self.path = self.paths[0]
        self.data = {}
        self.stats = {}
        self.keep = False
        self.handlers = {}
        self.pending_signal = None

    def handle_signal(self, signum, frame):
        if self.pending_signal is None:
            self.pending_signal = signum

    def _restore_handlers(self):
        first_error = None
        for signum, handler in self.handlers.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        self.handlers.clear()
        if first_error is not None:
            raise first_error

    def __enter__(self):
        self.pending_signal = None
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                self.handlers[signum] = signal.signal(signum, self.handle_signal)
            for path in self.paths:
                self.stats[path] = path.stat()
                self.data[path] = path.read_bytes()
        except BaseException:
            self._restore_handlers()
            raise
        return self

    def write_text(self, text, path=None):
        target = self.path if path is None else Path(path)
        if target not in self.data:
            raise ValueError(f"{target} is not in source transaction")
        target.write_text(text)

    def write_files(self, contents):
        unknown = set(map(Path, contents)) - set(self.paths)
        if unknown:
            raise ValueError(
                "files are not in source transaction: "
                + ", ".join(str(path) for path in sorted(unknown))
            )
        for path, text in contents.items():
            Path(path).write_text(text)

    def read_files(self):
        return {path: path.read_bytes() for path in self.paths}

    def restore_files(self, contents):
        for path, data in contents.items():
            if path not in self.data:
                raise ValueError(f"{path} is not in source transaction")
            path.write_bytes(data)

    def retain(self):
        self.keep = True

    def rollback(self):
        self.keep = False
        first_error = None
        for path in self.paths:
            try:
                path.write_bytes(self.data[path])
                os.chmod(path, stat.S_IMODE(self.stats[path].st_mode))
                os.utime(path, ns=(self.stats[path].st_atime_ns,
                                   self.stats[path].st_mtime_ns))
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def raise_pending(self):
        if self.pending_signal is None:
            return
        signum = self.pending_signal
        self.pending_signal = None
        raise KeyboardInterrupt(f"received {signal.Signals(signum).name}")

    def __exit__(self, exc_type, exc, traceback):
        restore_error = None
        # Roll back with our handlers still installed so a signal arriving
        # mid-restore is deferred, not delivered into partially-restored state.
        dirty = (exc_type is not None
                 or self.pending_signal is not None
                 or not self.keep)
        if dirty:
            try:
                self.rollback()
            except BaseException as error:
                restore_error = error
        handler_error = None
        try:
            self._restore_handlers()
        except BaseException as error:
            handler_error = error
        # A handler-restoration failure also means the exit is not clean.
        if handler_error is not None and not dirty:
            try:
                self.rollback()
            except BaseException as error:
                if restore_error is None:
                    restore_error = error
        first = restore_error if restore_error is not None else handler_error
        if first is not None:
            raise first
        self.raise_pending()
        return False


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def render_source_edits(project, allowed_files, edits):
    project = Path(project).resolve()
    allowed = {Path(path).resolve() for path in allowed_files}
    grouped = {}
    for edit in edits:
        path = (project / edit["path"]).resolve()
        if not path.is_relative_to(project):
            raise ValueError(f"source edit path is outside project: {edit['path']}")
        if path not in allowed:
            raise ValueError(f"source edit path is not allowed: {edit['path']}")
        if not path.is_file():
            raise ValueError(f"source edit path is not a file: {edit['path']}")
        grouped.setdefault(path, []).append(edit)
    rendered = {}
    for path, path_edits in grouped.items():
        data = path.read_bytes()
        digest = _sha256_bytes(data)
        text = data.decode("utf-8")
        ranges = []
        for edit in path_edits:
            if edit["file_sha256"] != digest:
                raise ValueError(f"stale hash for {edit['path']}")
            start = text.find(edit["old"])
            if start < 0 or text.find(edit["old"], start + 1) >= 0:
                count = text.count(edit["old"])
                raise ValueError(
                    f"source anchor in {edit['path']} must be unique; found {count}"
                )
            end = start + len(edit["old"])
            if any(start < other_end and other_start < end
                   for other_start, other_end, _ in ranges):
                raise ValueError(f"source edits overlap in {edit['path']}")
            ranges.append((start, end, edit["new"]))
        for start, end, replacement in sorted(ranges, reverse=True):
            text = text[:start] + replacement + text[end:]
        rendered[path] = text
    return rendered


RECONSTRUCTION_STATE_SCHEMA = "mwdiff.reconstruct.state.v1"
MAX_RECONSTRUCTION_STATE = 128 * 1024 * 1024
MAX_RECONSTRUCTION_JSON_DEPTH = 32
_SENSITIVE_STATE_KEYS = {
    "authorization", "headers", "environment", "stderr",
    "token", "api_key", "password", "cookie",
}
_RECONSTRUCTION_FOCUS_KINDS = {
    "function", "unit-code", "unit-data", "unit-link",
}
_RECONSTRUCTION_CLASSES = {
    "exact", "relocation-alias", "global-register-permutation",
    "local-register-allocation", "scheduling", "operand-order",
    "branch-shape", "call-wrapper", "constant-pool", "data-layout",
    "semantic-instruction",
}


def _reconstruction_percent(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"score {field} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"score {field} must be finite")
    if not 0.0 <= number <= 100.0:
        raise ValueError(f"score {field} out of range")
    return number


def _reconstruction_count(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"score {field} must be an integer >= 0")
    return value


def _decode_reconstruction_score(value):
    if not isinstance(value, dict):
        raise ValueError("invalid resume score")
    _require_fields(value, {
        "linked_match", "exact", "functions_percent", "code_percent",
        "data_percent", "focus_percent", "classification",
        "relocation_differences", "changed_calls", "changed_memory",
        "diff_lines",
    })
    if value["linked_match"] is not None and not isinstance(
            value["linked_match"], bool):
        raise ValueError("score linked_match must be null or boolean")
    if not isinstance(value["exact"], bool):
        raise ValueError("score exact must be boolean")
    if value["classification"] not in _RECONSTRUCTION_CLASSES:
        raise ValueError(f"unsupported score classification: {value['classification']}")
    percents = {
        field: _reconstruction_percent(value[field], field)
        for field in ("functions_percent", "code_percent",
                      "data_percent", "focus_percent")
    }
    for field in ("relocation_differences", "changed_calls",
                  "changed_memory", "diff_lines"):
        _reconstruction_count(value[field], field)
    complete = (percents["functions_percent"] == 100.0
                and percents["code_percent"] == 100.0
                and percents["data_percent"] == 100.0)
    if value["exact"] != complete:
        raise ValueError("inconsistent score exact value")
    return value


def _decode_reconstruction_focus(value):
    if not isinstance(value, dict):
        raise ValueError("invalid resume focus")
    _require_fields(value, {"kind", "name", "percent"})
    if value["kind"] not in _RECONSTRUCTION_FOCUS_KINDS:
        raise ValueError(f"unsupported focus kind: {value['kind']}")
    if not isinstance(value["name"], str):
        raise ValueError("focus name must be a string")
    _reconstruction_percent(value["percent"], "focus percent")
    return value


def _bounded_json_value(value, field, depth=0):
    if depth > MAX_RECONSTRUCTION_JSON_DEPTH:
        raise ValueError(f"{field} nesting is too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} object keys must be strings")
            _bounded_json_value(item, field, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded_json_value(item, field, depth + 1)
    elif isinstance(value, bool) or value is None:
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} numbers must be finite")
    elif isinstance(value, str):
        pass
    else:
        raise ValueError(f"{field} has an unsupported value type")
    return value


def reconstruction_tool_identity(project):
    configured = {
        "mwdiff": Path(__file__).resolve(),
        "dtk": _project_tool(project, DTK),
        "objdiff": _project_tool(project, OBJDIFF),
        "ninja": shutil.which("ninja"),
    }
    result = {}
    for name, configured_path in configured.items():
        if not configured_path:
            raise ValueError(f"required executable is unavailable: {name}")
        path = Path(configured_path).resolve()
        if not path.is_file():
            raise ValueError(f"required executable is unavailable: {path}")
        result[name] = {
            "path": str(path),
            "sha256": _sha256_bytes(path.read_bytes()),
        }
    return result


def reconstruction_identity(
        unit, model_command, editable_files, mcp_url, mcp_info, tools,
        required_tools, semantics):
    material = cache_material(unit)
    if material is None:
        raise ValueError("cannot identify MWCC compiler and context")
    compiler_hash, flags, context_hash = material
    model_command = Path(model_command).resolve()
    tool_schemas = {
        name: tools[name]["inputSchema"] for name in sorted(required_tools)
    }
    return {
        "project": str(unit.project.resolve()),
        "unit": unit.name,
        "version": unit.version,
        "target_sha256": _sha256_bytes(unit.target.read_bytes()),
        "compiler_sha256": compiler_hash,
        "flags_sha256": _sha256_bytes(flags.encode()),
        "context_sha256": context_hash,
        "model": {
            "path": str(model_command),
            "sha256": _sha256_bytes(model_command.read_bytes()),
        },
        "executables": reconstruction_tool_identity(unit.project),
        "mcp": {
            "url_sha256": _sha256_bytes(mcp_url.encode()),
            "protocol_version": mcp_info["protocolVersion"],
            "server_info_sha256": _sha256_bytes(json.dumps(
                mcp_info.get("serverInfo", {}),
                sort_keys=True, separators=(",", ":")
            ).encode()),
            "tools_sha256": _sha256_bytes(json.dumps(
                tool_schemas, sort_keys=True, separators=(",", ":")
            ).encode()),
        },
        "semantics": semantics,
        "editable_sha256": {
            str(path.resolve().relative_to(unit.project.resolve())):
                _sha256_bytes(path.read_bytes())
            for path in sorted(editable_files)
        },
    }


def reconstruction_state_root(project, identity):
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":")
    ).encode()
    state_id = _sha256_bytes(encoded)
    return Path(project) / ".cache/mwdiff/reconstruct" / (
        re.sub(r"[^A-Za-z0-9_.-]", "_", identity["unit"])
        + "-" + state_id
    )


def sanitize_reconstruction_value(value):
    if isinstance(value, dict):
        return {
            key: sanitize_reconstruction_value(item)
            for key, item in value.items()
            if key.lower() not in _SENSITIVE_STATE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_reconstruction_value(item) for item in value]
    return value


def save_reconstruction_state(root, state):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    path = root / "state.json"
    temporary = root / ".state.json.tmp"
    clean = sanitize_reconstruction_value(state)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(json.dumps(clean, sort_keys=True, indent=2) + "\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    return path


def load_reconstruction_state(path, expected_identity):
    encoded = Path(path).read_bytes()
    if len(encoded) > MAX_RECONSTRUCTION_STATE:
        raise ValueError("resume state exceeds 128 MiB")
    try:
        state = strict_json_loads(encoded.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("resume state is not valid UTF-8") from error
    _require_fields(state, {
        "schema", "identity", "rounds", "builds", "accepted_edits",
        "ghidra_ops", "score", "focus", "events", "feedback",
        "ghidra_program", "model_exchanges",
    })
    if state["schema"] != RECONSTRUCTION_STATE_SCHEMA:
        raise ValueError(f"unsupported state schema: {state['schema']}")
    if state["identity"] != expected_identity:
        raise ValueError("resume identity mismatch")
    for field in ("rounds", "builds"):
        if (
            isinstance(state[field], bool)
            or not isinstance(state[field], int)
            or state[field] < 0
        ):
            raise ValueError(f"invalid resume {field}")
    if not isinstance(state["accepted_edits"], list):
        raise ValueError("invalid resume accepted_edits")
    if len(state["accepted_edits"]) > state["rounds"]:
        raise ValueError("too many saved edit sets")
    for edits in state["accepted_edits"]:
        validate_proposal_response({
            "schema": "mwdiff.reconstruct.propose.v1",
            "summary": "resume",
            "source_edits": edits,
        })
    if not isinstance(state["ghidra_ops"], list):
        raise ValueError("invalid resume ghidra_ops")
    if len(state["ghidra_ops"]) > state["rounds"] * MAX_GHIDRA_OPERATIONS:
        raise ValueError("too many saved Ghidra operations")
    for operation in state["ghidra_ops"]:
        validate_analysis_response({
            "schema": "mwdiff.reconstruct.analyze.v1",
            "summary": "resume",
            "ghidra_ops": [operation],
        })
    if not isinstance(state["feedback"], list):
        raise ValueError("invalid resume feedback")
    for item in state["feedback"]:
        _bounded_json_value(item, "resume feedback")
    _decode_reconstruction_score(state["score"])
    if state["focus"] is not None:
        _decode_reconstruction_focus(state["focus"])
    if not isinstance(state["events"], list):
        raise ValueError("invalid resume events")
    event_limit = (
        16
        + state["rounds"] * (MAX_GHIDRA_OPERATIONS + 8)
        + state["builds"] * 3
    )
    if len(state["events"]) > event_limit:
        raise ValueError("too many resume events")
    for event in state["events"]:
        _require_fields(
            event, {"kind", "round", "build", "focus", "details"}
        )
        _protocol_text(event["kind"], "event kind", limit=256)
        for field in ("round", "build"):
            value = event[field]
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise ValueError(f"invalid event {field}")
        if event["focus"] is not None:
            _decode_reconstruction_focus(event["focus"])
        if not isinstance(event["details"], dict):
            raise ValueError("invalid event details")
        _bounded_json_value(event["details"], "event details")
    if not isinstance(state["model_exchanges"], list):
        raise ValueError("invalid resume model_exchanges")
    if len(state["model_exchanges"]) > state["rounds"] * 2:
        raise ValueError("too many saved model exchanges")
    for exchange in state["model_exchanges"]:
        _require_fields(
            exchange, {"phase", "request_sha256", "response_sha256"}
        )
        if exchange["phase"] not in {"analyze", "propose"}:
            raise ValueError("invalid resume model exchange phase")
        for field in ("request_sha256", "response_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", exchange[field]):
                raise ValueError(f"invalid resume {field}")
    if state["ghidra_program"] is not None and not isinstance(
            state["ghidra_program"], str):
        raise ValueError("invalid resume ghidra_program")
    return state


def append_reconstruction_event(root, event):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    clean = sanitize_reconstruction_value(event)
    fd = os.open(
        root / "transcript.jsonl",
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as output:
        output.write(json.dumps(clean, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


@dataclass(frozen=True)
class ProjectUnit:
    name: str
    project: Path
    source: Path
    target: Path
    mine: Path
    ninja_target: str
    version: str
    module: str | None
    compiler: str
    compiler_flags: str
    context_path: Path | None


def resolve_unit(project, unit_name, version=None):
    project = Path(project).resolve()
    data = json.loads((project / "objdiff.json").read_text())
    exact = [unit for unit in data["units"] if unit["name"] == unit_name]
    matches = exact or [unit for unit in data["units"]
                        if unit["name"].split("/")[-1].endswith(unit_name)]
    if not matches:
        suggestions = difflib.get_close_matches(unit_name,
            [unit["name"] for unit in data["units"]], n=3, cutoff=0.4)
        raise ValueError(f"unit {unit_name!r} not found" +
                         (f"; close: {', '.join(suggestions)}" if suggestions else ""))
    if len(matches) != 1:
        raise ValueError(f"unit {unit_name!r} is ambiguous: " +
                         ", ".join(unit["name"] for unit in matches))
    raw = matches[0]
    target = Path(raw["target_path"])
    mine = Path(raw["base_path"])
    version_match = re.search(r"(?:^|/)build/([^/]+)/", target.as_posix())
    if not version_match:
        raise ValueError(f"cannot infer version from {target}")
    configured = version_match.group(1)
    if version and version != configured:
        raise ValueError(f"objdiff.json is configured for {configured}, not {version}; "
                         f"run python configure.py --version {version}")
    relative_parts = target.parts
    build_index = relative_parts.index("build")
    module = (
        relative_parts[build_index + 2]
        if (len(relative_parts) > build_index + 3
            and relative_parts[build_index + 3] == "obj")
        else None
    )
    scratch = raw.get("scratch", {})
    context = scratch.get("ctx_path")
    return ProjectUnit(
        name=raw["name"], project=project,
        source=project / raw["metadata"]["source_path"],
        target=project / target, mine=project / mine,
        ninja_target=mine.as_posix(), version=configured, module=module,
        compiler=scratch.get("compiler", ""),
        compiler_flags=scratch.get("c_flags", ""),
        context_path=project / context if context else None)


def configured_versions(project):
    return sorted(
        path.parent.name for path in (Path(project) / "config").glob("*/config.yml")
    )


def available_versions(project):
    project = Path(project)
    versions = []
    for version in configured_versions(project):
        orig = project / "orig" / version
        if orig.is_dir() and any(path.name != ".gitkeep" for path in orig.iterdir()):
            versions.append(version)
    return versions


def expected_sha(sha_file, relative_path):
    for line in Path(sha_file).read_text().splitlines():
        digest, path = line.split(maxsplit=1)
        if path.lstrip("*") == relative_path:
            return digest
    raise ValueError(f"no SHA entry for {relative_path}")


def _rel_path(unit, version):
    if unit.module is None:
        raise ValueError("--verify supports configured REL units only")
    return Path("build") / version / unit.module / f"{unit.module}.rel"


@dataclass(frozen=True)
class VerificationResult:
    version: str
    functions_percent: float
    code_percent: float
    data_percent: float
    rel_sha_match: bool


def verify_version(project, unit_name, version, *, runner=None):
    project = Path(project).resolve()
    run = runner or subprocess.run
    configured = run(
        [sys.executable, "configure.py", "--version", version],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if configured.returncode:
        raise RuntimeError(configured.stderr.strip() or configured.stdout.strip())
    refreshed = run(
        ["ninja", "build.ninja"],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if refreshed.returncode:
        raise RuntimeError(refreshed.stderr.strip() or refreshed.stdout.strip())
    unit = resolve_unit(project, unit_name, version)
    rel = _rel_path(unit, version)
    process = run(
        ["ninja", f"build/{version}/report.json", rel.as_posix()],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    report = json.loads((project / "build" / version / "report.json").read_text())
    source_suffix = (
        unit.source.relative_to(project / "src").with_suffix("").as_posix()
    )
    report_units = [
        item for item in report["units"] if item["name"].endswith(source_suffix)
    ]
    if len(report_units) != 1:
        raise RuntimeError(
            f"expected one report unit ending in {source_suffix}, "
            f"found {len(report_units)}"
        )
    measures = report_units[0]["measures"]
    digest = hashlib.sha1((project / rel).read_bytes()).hexdigest()
    expected = expected_sha(
        project / "config" / version / "build.sha1", rel.as_posix()
    )
    return VerificationResult(
        version,
        float(measures["matched_functions_percent"]),
        float(measures["matched_code_percent"]),
        float(measures["matched_data_percent"]),
        digest == expected,
    )


def verify_all(project, unit_name, versions, *, runner=None):
    project = Path(project).resolve()
    run = runner or subprocess.run
    original_version = resolve_unit(project, unit_name).version
    unavailable = sorted(set(versions) - set(available_versions(project)))
    if unavailable:
        raise ValueError("missing local disc input for: " + ", ".join(unavailable))
    verification_error = None
    try:
        return [
            verify_version(project, unit_name, version, runner=runner)
            for version in versions
        ]
    except BaseException as error:
        verification_error = error
        raise
    finally:
        try:
            restored = run(
                [sys.executable, "configure.py", "--version", original_version],
                cwd=project,
                capture_output=True,
                text=True,
            )
            if restored.returncode:
                raise RuntimeError(
                    restored.stderr.strip() or restored.stdout.strip())
            refreshed = run(
                ["ninja", "build.ninja"],
                cwd=project,
                capture_output=True,
                text=True,
            )
            if refreshed.returncode:
                raise RuntimeError(
                    refreshed.stderr.strip() or refreshed.stdout.strip())
        except Exception as restore_error:
            if verification_error is not None:
                raise RuntimeError(
                    f"verification failed ({verification_error}); "
                    f"restoration also failed ({restore_error})"
                ) from verification_error
            raise


def _project_tool(project, configured):
    path = Path(configured)
    return path if path.is_absolute() else Path(project) / path


def disasm(obj, project=".", *, runner=None):
    """Return {mangled_fn_name: [instruction lines]} for an object file."""
    if not os.path.isfile(obj):
        die(f"no such object file: {obj}")
    fd, out = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    run = runner or subprocess.run
    try:
        r = run(
            [str(_project_tool(project, DTK)), "elf", "disasm", str(obj), out],
            cwd=project, capture_output=True, text=True)
        if r.returncode:
            die(f"dtk failed on {obj}. Ensure it is built ('ninja dtk') and object file is valid.\nError:\n{r.stderr.strip() or r.stdout.strip()}")
        fns, cur, buf = {}, None, []
        with open(out) as f:
            for line in f:
                if line.startswith(".fn "):
                    if cur:
                        fns[cur] = buf
                    cur, buf = line.split(",")[0][4:].strip(), []
                elif line.startswith(".endfn"):
                    if cur:
                        fns[cur] = buf
                    cur = None
                elif cur is not None:
                    buf.append(line)
        if cur:
            fns[cur] = buf
        return fns
    except FileNotFoundError:
        die(f"dtk not found at '{DTK}'.\nEnsure it is built ('ninja dtk') or set $DTK to the path.")
    finally:
        os.unlink(out)


def norm(lines):
    """Drop cosmetic noise so only real instruction differences remain."""
    labels = {}
    for line in lines:
        match = _LOCAL_LABEL_DEFINITION.search(line)
        if match and match.group("label") not in labels:
            labels[match.group("label")] = f".L{len(labels)}"

    def rename_label(match):
        label = match.group()
        if label not in labels:
            labels[label] = f".L{len(labels)}"
        return labels[label]

    out = []
    for line in lines:
        line = _LOCAL_LABEL.sub(rename_label, line)
        for pattern, replacement in _NORM:
            line = pattern.sub(replacement, line)
        line = line.strip()
        if line and not line.startswith("."):
            out.append(line)
    return out


def fn_diff(a, b):
    """Changed lines only (excluding the +++/--- header lines)."""
    return [x for x in difflib.unified_diff(norm(a), norm(b), lineterm="")
            if x[0] in "+-" and x[1:2] not in "+-"]


def resolve_fn(fns, name, label):
    """Exact lookup with fuzzy suggestions on miss."""
    if name in fns:
        return fns[name]
    hint = difflib.get_close_matches(name, fns, n=3, cutoff=0.5)
    hint = f" (close: {', '.join(hint)})" if hint else ""
    die(f"function '{name}' not in {label}{hint}")


@dataclass(frozen=True)
class ObjectScore:
    exact: bool
    function_percent: float
    classification: str
    diff_lines: int
    changed_calls: int
    changed_memory: int

    @property
    def rank(self):
        order = {"exact": 0, "relocation-alias": 1,
                 "global-register-permutation": 2,
                 "local-register-allocation": 3, "scheduling": 4,
                 "operand-order": 5, "branch-shape": 6,
                 "call-wrapper": 7, "constant-pool": 8,
                 "data-layout": 9, "semantic-instruction": 10}
        return (not self.exact, order.get(self.classification, 11),
                self.changed_calls, self.changed_memory, self.diff_lines)


@dataclass(frozen=True)
class SearchResult:
    candidate: SourceCandidate | None
    score: ObjectScore | None
    builds: int
    build_failures: int
    proof: object | None = None

    @property
    def exact(self):
        return bool(self.score and self.score.exact)

def _configured_object_measures(project, target, mine, *, runner=None):
    project = Path(project).resolve()
    config = project / "objdiff.json"
    if not config.is_file():
        return None

    def relative(path):
        path = Path(path)
        absolute = path if path.is_absolute() else project / path
        return absolute.resolve().relative_to(project).as_posix()

    target_path = relative(target)
    mine_path = relative(mine)
    units = [
        unit
        for unit in json.loads(config.read_text())["units"]
        if unit["target_path"] == target_path and unit["base_path"] == mine_path
    ]
    if not units:
        return None
    if len(units) != 1:
        raise RuntimeError(
            f"expected one configured objdiff unit for {target_path}, "
            f"found {len(units)}"
        )
    run = runner or subprocess.run
    process = run(
        [
            str(_project_tool(project, OBJDIFF)),
            "report",
            "generate",
            "--project",
            str(project),
            "--output",
            "-",
            "--format",
            "json",
        ],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    report_units = [
        unit
        for unit in json.loads(process.stdout)["units"]
        if unit["name"] == units[0]["name"]
    ]
    if len(report_units) != 1:
        raise RuntimeError(
            f"expected one report unit named {units[0]['name']}, "
            f"found {len(report_units)}"
        )
    return report_units[0]["measures"]


def score_object(project, target, mine, function, *, runner=None):
    run = runner or subprocess.run
    process = run(
        [str(_project_tool(project, OBJDIFF)), "diff",
         "-1", str(target), "-2", str(mine),
         "-o", "-", "--format", "json", function],
        cwd=project, capture_output=True, text=True)
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    data = json.loads(process.stdout)
    side = data.get("left", data.get("target"))
    symbols = side["symbols"]
    symbol = next((item for item in symbols if item.get("name") == function), None)
    if symbol is None:
        raise RuntimeError(f"objdiff output has no symbol {function}")
    percent = float(symbol.get("match_percent", 0.0))
    target_lines = resolve_fn(
        disasm(str(target), project, runner=runner), function, str(target))
    mine_lines = resolve_fn(
        disasm(str(mine), project, runner=runner), function, str(mine))
    diagnosis = diagnose_lines(target_lines, mine_lines)
    normalized_target, normalized_mine = norm(target_lines), norm(mine_lines)
    changed = [(parse_instruction(left), parse_instruction(right))
               for left, right in itertools.zip_longest(
                   normalized_target, normalized_mine, fillvalue="")
               if left != right]
    changed_calls = sum(left.opcode in _CALLS or right.opcode in _CALLS
                        for left, right in changed)
    changed_memory = sum(left.opcode in _MEMORY or right.opcode in _MEMORY
                         for left, right in changed)
    classification = diagnosis.classification
    measures = _configured_object_measures(project, target, mine, runner=runner)
    if measures is not None:
        functions_percent = float(measures["matched_functions_percent"])
        code_percent = float(measures["matched_code_percent"])
        data_percent = float(measures["matched_data_percent"])
        exact = (
            functions_percent == 100.0
            and code_percent == 100.0
            and data_percent == 100.0
        )
        if exact:
            classification = "exact"
        elif classification in {"exact", "relocation-alias"}:
            classification = (
                "data-layout" if data_percent != 100.0
                else "semantic-instruction"
            )
    else:
        section_names = {"[.text]", "[.rodata]", "[.data]", "[.bss]",
                         "[.sdata]", "[.sbss]"}
        matchable = [item for item in symbols
                     if item.get("kind") in {"SYMBOL_FUNCTION", "SYMBOL_OBJECT"}
                     or item.get("name") in section_names]
        mismatched_sections = [
            item["name"] for item in matchable
            if item.get("name") in section_names
            and float(item.get("match_percent") or 0.0) != 100.0
        ]
        if classification in {"exact", "relocation-alias"} and mismatched_sections:
            classification = (
                "constant-pool"
                if any("rodata" in name for name in mismatched_sections)
                else "data-layout"
            )
        exact = bool(matchable) and all(
            float(item.get("match_percent") or 0.0) == 100.0
            for item in matchable
        )
    return ObjectScore(exact, percent, classification, diagnosis.diff_lines,
                       changed_calls, changed_memory)


@dataclass(frozen=True)
class ReconstructionFocus:
    kind: str
    name: str
    percent: float


@dataclass(frozen=True)
class UnitSnapshot:
    functions_percent: float
    code_percent: float
    data_percent: float
    symbols: tuple[dict, ...]
    mine_symbols: tuple[dict, ...]
    sections: tuple[dict, ...]


@dataclass(frozen=True)
class ReconstructionScore:
    linked_match: bool | None
    exact: bool
    functions_percent: float
    code_percent: float
    data_percent: float
    focus_percent: float
    classification: str
    relocation_differences: int
    changed_calls: int
    changed_memory: int
    diff_lines: int

    @property
    def rank(self):
        linked_rank = {True: 0, False: 1, None: 2}[self.linked_match]
        classification_rank = {
            "exact": 0, "relocation-alias": 1,
            "global-register-permutation": 2,
            "local-register-allocation": 3, "scheduling": 4,
            "operand-order": 5, "branch-shape": 6,
            "call-wrapper": 7, "constant-pool": 8,
            "data-layout": 9, "semantic-instruction": 10,
        }.get(self.classification, 11)
        return (
            linked_rank,
            not self.exact,
            -self.functions_percent,
            -self.code_percent,
            -self.data_percent,
            -self.focus_percent,
            classification_rank,
            self.relocation_differences,
            self.changed_calls,
            self.changed_memory,
            self.diff_lines,
        )


def _objdiff_unit(unit, runner=None):
    run = runner or subprocess.run
    process = run(
        [str(_project_tool(unit.project, OBJDIFF)), "diff",
         "-1", str(unit.target), "-2", str(unit.mine),
         "-o", "-", "--format", "json"],
        cwd=unit.project,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    return strict_json_loads(process.stdout)


def read_unit_snapshot(unit, runner=None):
    measures = _configured_object_measures(
        unit.project, unit.target, unit.mine, runner=runner
    )
    if measures is None:
        raise RuntimeError("reconstruct requires configured objdiff measures")
    data = _objdiff_unit(unit, runner=runner)
    target_side = data.get("left", data.get("target"))
    mine_side = data.get("right", data.get("base"))
    if not isinstance(target_side, dict) or not isinstance(mine_side, dict):
        raise RuntimeError("objdiff output is missing target or rebuilt side")
    return UnitSnapshot(
        float(measures["matched_functions_percent"]),
        float(measures["matched_code_percent"]),
        float(measures["matched_data_percent"]),
        tuple(target_side.get("symbols", [])),
        tuple(mine_side.get("symbols", [])),
        tuple(target_side.get("sections", [])),
    )


def select_reconstruction_focus(snapshot, linked_match):
    functions = [
        symbol for symbol in snapshot.symbols
        if symbol.get("kind") == "SYMBOL_FUNCTION"
        and float(symbol.get("match_percent") or 0.0) != 100.0
    ]
    if functions:
        index, symbol = min(
            enumerate(functions),
            key=lambda item: (
                float(item[1].get("match_percent") or 0.0), item[0]
            ),
        )
        return ReconstructionFocus(
            "function", symbol["name"],
            float(symbol.get("match_percent") or 0.0),
        )
    if snapshot.code_percent != 100.0:
        section_percents = [
            float(section.get("match_percent") or 0.0)
            for section in snapshot.sections
            if section.get("kind") == "SECTION_CODE"
        ]
        return ReconstructionFocus(
            "unit-code", "unit-code", min(section_percents or [0.0])
        )
    if snapshot.data_percent != 100.0:
        section_percents = [
            float(section.get("match_percent") or 0.0)
            for section in snapshot.sections
            if section.get("kind") == "SECTION_DATA"
        ]
        return ReconstructionFocus(
            "unit-data", "unit-data", min(section_percents or [0.0])
        )
    if linked_match is False:
        return ReconstructionFocus("unit-link", "unit-link", 100.0)
    return None


def _snapshot_difference_counts(snapshot, focus):
    if focus is not None and focus.kind == "function":
        items = tuple(
            item for item in snapshot.symbols if item.get("name") == focus.name
        )
        if len(items) != 1:
            raise RuntimeError(
                f"objdiff output has no unique symbol {focus.name}"
            )
    else:
        items = snapshot.sections
    relocations = sum(len(item.get("reloc_diff", [])) for item in items)
    data_bytes = sum(
        int(chunk.get("size") or 0)
        for item in items
        for chunk in item.get("data_diff", [])
    )
    return relocations, data_bytes


def score_reconstruction(
        unit, snapshot, focus, linked_match, runner=None
):
    exact = (
        snapshot.functions_percent == 100.0
        and snapshot.code_percent == 100.0
        and snapshot.data_percent == 100.0
    )
    relocations, data_bytes = _snapshot_difference_counts(snapshot, focus)
    if focus is not None and focus.kind == "function":
        focused = score_object(
            unit.project, unit.target, unit.mine, focus.name, runner=runner
        )
        focus_percent = focused.function_percent
        classification = focused.classification
        changed_calls = focused.changed_calls
        changed_memory = focused.changed_memory
        diff_lines = focused.diff_lines
    else:
        if focus is None:
            focus_percent = 100.0
        elif focus.kind == "unit-code":
            focus_percent = snapshot.code_percent
        elif focus.kind == "unit-data":
            focus_percent = snapshot.data_percent
        else:
            focus_percent = 100.0 if linked_match else 0.0
        if exact:
            classification = "relocation-alias" if relocations else "exact"
        elif focus is not None and focus.kind == "unit-code":
            classification = "semantic-instruction"
        else:
            names = [
                item.get("name", "") for item in snapshot.sections
                if float(item.get("match_percent") or 0.0) != 100.0
            ]
            classification = (
                "constant-pool"
                if any("rodata" in name for name in names)
                else "data-layout"
            )
        changed_calls = 0
        changed_memory = 0
        diff_lines = data_bytes + relocations
    return ReconstructionScore(
        linked_match, exact, snapshot.functions_percent,
        snapshot.code_percent, snapshot.data_percent, focus_percent,
        classification, relocations, changed_calls, changed_memory,
        diff_lines,
    )


@dataclass(frozen=True)
class LinkGateResolution:
    status: str
    path: Path | None = None
    expected_sha1: str | None = None


@dataclass(frozen=True)
class LinkCheck:
    status: str
    path: str | None
    expected_sha1: str | None
    actual_sha1: str | None

    @property
    def matched(self):
        return self.status == "match"


def resolve_link_gate(unit):
    if unit.module is None:
        return LinkGateResolution("not-applicable")
    relative = _rel_path(unit, unit.version)
    sha_file = unit.project / "config" / unit.version / "build.sha1"
    if not sha_file.is_file():
        return LinkGateResolution("unavailable")
    digest = expected_sha(sha_file, relative.as_posix())
    if not re.fullmatch(r"[0-9a-fA-F]{40}", digest):
        raise ValueError(f"invalid SHA-1 for {relative.as_posix()}")
    return LinkGateResolution(
        "configured", unit.project / relative, digest.lower()
    )


def verify_current_link(unit, gate, runner=None):
    if gate.status != "configured":
        return LinkCheck(gate.status, None, None, None)
    run = runner or subprocess.run
    process = run(
        ["ninja", unit.ninja_target,
         gate.path.relative_to(unit.project).as_posix()],
        cwd=unit.project,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    actual = hashlib.sha1(gate.path.read_bytes()).hexdigest()
    return LinkCheck(
        "match" if actual == gate.expected_sha1 else "mismatch",
        gate.path.relative_to(unit.project).as_posix(),
        gate.expected_sha1,
        actual,
    )


def cache_material(unit):
    commands = subprocess.run(
        ["ninja", "-t", "commands", unit.ninja_target],
        cwd=unit.project,
        capture_output=True,
        text=True,
    )
    if commands.returncode:
        raise RuntimeError(commands.stderr.strip() or commands.stdout.strip())
    compiler_matches = re.findall(
        r"(build/compilers/\S+/mwcceppc\.exe)", commands.stdout
    )
    if not compiler_matches:
        return None
    compiler_path = unit.project / compiler_matches[-1]
    if not compiler_path.is_file():
        return None
    context = (
        unit.context_path.read_bytes()
        if unit.context_path and unit.context_path.is_file()
        else unit.source.read_bytes()
    )
    compiler_hash = hashlib.sha256(compiler_path.read_bytes()).hexdigest()
    context_hash = hashlib.sha256(context).hexdigest()
    flags = "\0".join((unit.compiler, unit.compiler_flags, commands.stdout))
    return compiler_hash, flags, context_hash


def _rebuild_unit(unit):
    Path(unit.mine).unlink(missing_ok=True)
    process = subprocess.run(
        ["ninja", unit.ninja_target],
        cwd=unit.project,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        tail = (process.stdout + process.stderr).strip()[-200:]
        raise RuntimeError(f"failed to rebuild original object: {tail}")


def search_candidates(unit, function, candidates, max_builds,
                      stop_on_exact, apply, beam_width=5,
                      prove_candidate=False, proof_timeout_ms=5000, quiet=False):
    best = None
    failures = 0
    builds = 0
    parent_names = None
    stop = False
    cache = CandidateCache(unit.project / ".cache/mwdiff")
    material = cache_material(unit)
    by_depth = {
        depth: [candidate for candidate in candidates if candidate.depth == depth]
        for depth in sorted({candidate.depth for candidate in candidates})}
    with ExitStack() as stack:
        stack.callback(_rebuild_unit, unit)
        transaction = stack.enter_context(SourceTransaction(unit.source))
        for depth, depth_candidates in by_depth.items():
            if parent_names is not None:
                depth_candidates = [
                    candidate for candidate in depth_candidates
                    if any(candidate.name.startswith(parent + "+")
                           for parent in parent_names)]
                unique_candidates = {}
                for candidate in depth_candidates:
                    unique_candidates.setdefault(candidate.text, candidate)
                depth_candidates = list(unique_candidates.values())
            level_results = []
            for candidate in depth_candidates:
                if builds >= max_builds:
                    stop = True
                    break
                builds += 1
                transaction.write_text(candidate.text)
                key = (
                    CandidateCache.key(
                        *material, candidate.text, unit.version, function
                    )
                    if material
                    else None
                )
                cached = cache.get(key) if key else None
                score = ObjectScore(**cached) if cached else None
                needs_build = not cached or (
                    prove_candidate and not score.exact
                )
                if needs_build:
                    process = subprocess.run(
                        ["ninja", unit.ninja_target],
                        cwd=unit.project,
                        capture_output=True,
                        text=True,
                    )
                    if process.returncode:
                        failures += 1
                        tail = (process.stdout + process.stderr).strip()[-200:]
                        if not quiet:
                            print(f"{candidate.name}: BUILD FAIL {tail!r}")
                        continue
                if not cached:
                    score = score_object(
                        unit.project, unit.target, unit.mine, function
                    )
                    if key:
                        cache.put(key, dataclasses.asdict(score))
                proof = None
                if prove_candidate and not score.exact:
                    from ppc_equiv import require_z3

                    require_z3()
                    proof = prove_objects(
                        unit.target,
                        unit.mine,
                        function,
                        proof_timeout_ms,
                        unit.project,
                    )
                    if proof.status == "different":
                        if not quiet:
                            print(
                                f"{candidate.name}: REJECTED "
                                f"{proof.counterexample}"
                            )
                        continue
                current = SearchResult(
                    candidate, score, builds, failures, proof
                )
                level_results.append(current)
                if best is None or score.rank < best.score.rank:
                    best = current
                if not quiet:
                    status = (
                        "EXACT"
                        if score.exact
                        else f"{score.diff_lines} diff lines"
                    )
                    if proof:
                        status += f", proof {proof.status}"
                    print(f"{candidate.name}: {status}")
                if score.exact and stop_on_exact:
                    stop = True
                    break
            parent_names = {
                result.candidate.name
                for result in sorted(level_results, key=lambda result: result.score.rank)[
                    :beam_width]}
            if stop:
                break
        if best and best.exact and apply:
            transaction.write_text(best.candidate.text)
            transaction.retain()
    return best or SearchResult(None, None, builds, failures)


def prove_objects(target, candidate, function, timeout_ms=5000, project="."):
    from ppc_equiv import prove

    target_lines = resolve_fn(
        disasm(str(target), project), function, str(target)
    )
    candidate_lines = resolve_fn(
        disasm(str(candidate), project), function, str(candidate)
    )
    return prove(target_lines, candidate_lines, timeout_ms)


MAX_COMPILER_COMMAND = 256 * 1024


def reconstruction_compiler_command(unit, runner=None):
    run = runner or subprocess.run
    process = run(
        ["ninja", "-t", "commands", unit.ninja_target],
        cwd=unit.project, capture_output=True, text=True,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip())
    encoded = process.stdout.encode()
    if len(encoded) > MAX_COMPILER_COMMAND:
        raise RuntimeError("compiler command evidence exceeds 256 KiB")
    return process.stdout


def context_excerpt(unit, focus, snapshot, limit=131072):
    path = unit.context_path
    if path is None or not path.is_file() or focus.kind != "function":
        return ""
    symbol = next(
        (item for item in snapshot.symbols if item.get("name") == focus.name),
        {},
    )
    demangled = symbol.get("demangled_name", "")
    short_name = demangled.split("(", 1)[0].rsplit("::", 1)[-1]
    text = path.read_text(errors="replace")
    position = next(
        (
            found for anchor in (focus.name, demangled, short_name)
            if anchor and (found := text.find(anchor)) >= 0
        ),
        -1,
    )
    if position < 0:
        return ""
    start = max(0, position - limit // 2)
    return text[start:start + limit]


def editable_file_payload(unit, editable_files):
    result = {}
    for path in sorted(editable_files):
        relative = path.resolve().relative_to(unit.project.resolve()).as_posix()
        data = path.read_bytes()
        result[relative] = {
            "sha256": _sha256_bytes(data),
            "text": data.decode("utf-8"),
        }
    return result


def symbol_order_payload(symbols):
    fields = (
        "name", "demangled_name", "address", "size", "kind", "match_percent"
    )
    return [
        {field: symbol[field] for field in fields if field in symbol}
        for symbol in symbols
        if symbol.get("kind") in {"SYMBOL_FUNCTION", "SYMBOL_OBJECT"}
    ]


def build_reconstruction_request(
        schema, identity, state_id, unit, focus, snapshot, score,
        editable_files, compiler_command, ghidra_evidence, feedback,
        round_number, rounds_remaining, builds_remaining, runner=None):
    focused_symbol = next(
        (symbol for symbol in snapshot.symbols
         if symbol.get("name") == focus.name), None
    )
    mismatched_sections = [
        section for section in snapshot.sections
        if float(section.get("match_percent") or 0.0) != 100.0
    ]
    return {
        "schema": schema,
        "phase": {
            "mwdiff.reconstruct.analyze.v1": "analyze",
            "mwdiff.reconstruct.propose.v1": "propose",
        }[schema],
        "identity": identity,
        "run": {
            "unit": unit.name,
            "version": unit.version,
            "state_id": state_id,
            "round": round_number,
            "rounds_remaining": rounds_remaining,
            "builds_remaining": builds_remaining,
        },
        "focus": dataclasses.asdict(focus),
        "editable_files": editable_file_payload(unit, editable_files),
        "compiler": {
            "name": unit.compiler,
            "flags": unit.compiler_flags,
            "context_excerpt": context_excerpt(unit, focus, snapshot),
            "command": compiler_command,
        },
        "objdiff": {
            "score": dataclasses.asdict(score),
            "focused_symbol": focused_symbol,
            "mismatched_sections": mismatched_sections,
            "symbol_order": (
                {
                    "target": symbol_order_payload(snapshot.symbols),
                    "mine": symbol_order_payload(snapshot.mine_symbols),
                }
                if focus.kind != "function" else None
            ),
            "target_disassembly": (
                norm(resolve_fn(
                    disasm(str(unit.target), unit.project, runner=runner),
                    focus.name, str(unit.target)))
                if focus.kind == "function" else []
            ),
            "mine_disassembly": (
                norm(resolve_fn(
                    disasm(str(unit.mine), unit.project, runner=runner),
                    focus.name, str(unit.mine)))
                if focus.kind == "function" else []
            ),
        },
        "ghidra": ghidra_evidence,
        "feedback": feedback,
        "allowed_ghidra_operations": sorted(GHIDRA_OPERATION_FIELDS),
    }


class CompilerRejected(RuntimeError):
    def __init__(self, output):
        super().__init__(output)
        self.output = output


@dataclass(frozen=True)
class ReconstructionEvent:
    kind: str
    round: int | None
    build: int | None
    focus: dict | None
    details: dict


@dataclass(frozen=True)
class ReconstructionResult:
    status: str
    focus: ReconstructionFocus | None
    score: ReconstructionScore
    rounds: int
    max_rounds: int
    builds: int
    max_builds: int
    link: LinkCheck
    verification: tuple
    events: tuple
    outcome: str
    state_path: str | None
    patches: dict


@dataclass(frozen=True)
class TextRunResult:
    returncode: int
    stdout: str
    stderr: str


_JOURNAL_STDOUT_LIMIT = 256 * 1024 * 1024
_JOURNAL_STDERR_LIMIT = 8 * 1024 * 1024
_CONTROL_FILES = (
    "build.ninja", "objdiff.json", "compile_commands.json",
    ".ninja_log", ".ninja_deps",
)
_GRAPH_NODE = re.compile(r'^"[^"]+"\s*\[label="((?:[^"\\]|\\.)*)"')
_GRAPH_NODE_FULL = re.compile(
    r'^"(?P<id>[^"]+)"\s*\[label="(?P<label>(?:[^"\\]|\\.)*)"(?P<rest>[^\]]*)\]'
)
_GRAPH_ARROW = re.compile(r'^"(?P<src>[^"]+)"\s*->\s*"(?P<dst>[^"]+)"')


class BuildJournal:
    """Snapshots the Ninja artifact closure so any build can be rolled back
    byte-for-byte. Never snapshots or restores source or ``orig``."""

    def __init__(self, project, selected_version, timeout, cancel=None):
        self.project = Path(project).resolve()
        self.selected_version = selected_version
        self.timeout = timeout
        self.cancel = cancel
        self.build_dir = self.project / "build"
        self.stdout_limit = _JOURNAL_STDOUT_LIMIT
        self.stderr_limit = _JOURNAL_STDERR_LIMIT
        self.snapshots = {}
        self.control_snapshots = {}
        self.created_dirs = set()
        self.invocations = []
        self._restored = False
        self._co_outputs_cache = None
        self._co_outputs_key = None
        root = self.project / ".cache/mwdiff/reconstruct"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.dir = Path(tempfile.mkdtemp(prefix=".journal-", dir=root))
        os.chmod(self.dir, 0o700)
        for name in _CONTROL_FILES:
            path = self.project / name
            self.control_snapshots[str(path)] = self._capture(path)

    # -- bounded runner ------------------------------------------------

    def _raw(self, command, cwd=None, input=None):
        if isinstance(input, str):
            input_data = input.encode("utf-8")
        else:
            input_data = input or b""
        result = run_bounded_process(
            list(command), input_data=input_data,
            cwd=str(cwd) if cwd else str(self.project),
            timeout=self.timeout,
            stdout_limit=self.stdout_limit, stderr_limit=self.stderr_limit,
            cancel=self.cancel,
        )
        return TextRunResult(
            result.returncode,
            result.stdout.decode("utf-8", "replace"),
            result.stderr.decode("utf-8", "replace"),
        )

    def run_text(self, command, *, cwd=None, capture_output=True, text=True,
                 input=None, **_ignored):
        command = list(command)
        is_ninja_build = (
            len(command) >= 2
            and os.path.basename(str(command[0])) == "ninja"
            and command[1] != "-t"
            and command[1:] != ["build.ninja"]
        )
        if is_ninja_build:
            return self._journaled_build(command, command[1:], cwd)
        return self._raw(command, cwd=cwd, input=input)

    # -- snapshotting --------------------------------------------------

    def _safe(self, key):
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _capture(self, path):
        path = Path(path)
        record = {}
        if not (path.exists() or path.is_symlink()):
            record["absent"] = True
            return record
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            record["symlink"] = os.readlink(path)
        elif stat.S_ISREG(st.st_mode):
            copy = self.dir / self._safe(str(path))
            copy.write_bytes(path.read_bytes())
            os.chmod(copy, 0o600)
            record["copy"] = str(copy)
            record["mode"] = stat.S_IMODE(st.st_mode)
            record["atime_ns"] = st.st_atime_ns
            record["mtime_ns"] = st.st_mtime_ns
        else:
            record["other"] = True
        return record

    def _under_build(self, path):
        return path == self.build_dir or self.build_dir in path.parents

    def _record_created_dirs(self, path):
        for parent in path.parents:
            if parent == self.project or parent == self.project.parent:
                break
            if not self._under_build(parent):
                continue
            if not parent.exists():
                self.created_dirs.add(str(parent))

    def _snapshot(self, path):
        path = Path(path)
        key = str(path)
        if key in self.snapshots:
            return
        self._record_created_dirs(path)
        self.snapshots[key] = self._capture(path)

    def _consider_path(self, label):
        label = label.strip()
        if not label:
            return
        normalized = os.path.normpath(os.path.join(str(self.project), label))
        build = str(self.build_dir)
        project = str(self.project)
        if normalized == build or normalized.startswith(build + os.sep):
            self._snapshot(Path(normalized))
            return
        if not (normalized == project
                or normalized.startswith(project + os.sep)):
            raise RuntimeError(
                f"build graph path escapes project: {label}"
            )

    def _split_label(self, label):
        parts, buf, i = [], [], 0
        while i < len(label):
            char = label[i]
            if char == "\\" and i + 1 < len(label):
                nxt = label[i + 1]
                if nxt == "n":
                    parts.append("".join(buf))
                    buf = []
                    i += 2
                    continue
                buf.append(nxt)
                i += 2
                continue
            buf.append(char)
            i += 1
        parts.append("".join(buf))
        return [part for part in parts if part]

    def _parse_graph_dot(self, text):
        # Returns (node_paths, edge_ids, arrows). node_paths maps a node id to
        # the output path(s) it carries; edge_ids is the set of rule (ellipse)
        # nodes; arrows is the raw (src, dst) list.
        node_paths = {}
        edge_ids = set()
        arrows = []
        for line in text.splitlines():
            line = line.strip()
            arrow = _GRAPH_ARROW.match(line)
            if arrow:
                arrows.append((arrow.group("src"), arrow.group("dst")))
                continue
            node = _GRAPH_NODE_FULL.match(line)
            if not node:
                continue
            if "shape=ellipse" in node.group("rest"):
                edge_ids.add(node.group("id"))
            else:
                node_paths[node.group("id")] = self._split_label(
                    node.group("label"))
        return node_paths, edge_ids, arrows

    def _co_outputs(self):
        # Map every output path to the complete set of sibling outputs produced
        # by the same Ninja edge (e.g. the single `makerel` edge that writes
        # every REL). Built once from a full graph where every output is a root
        # and therefore labeled; cached and rebuilt when build.ninja changes.
        build_ninja = self.project / "build.ninja"
        current = build_ninja.read_bytes() if build_ninja.is_file() else b""
        key = hashlib.sha256(current).hexdigest()
        if self._co_outputs_cache is not None and self._co_outputs_key == key:
            return self._co_outputs_cache
        listed = self._raw(
            ["ninja", "-t", "targets", "all"], cwd=self.project)
        if listed.returncode:
            raise RuntimeError(
                "ninja -t targets all failed: "
                + (listed.stderr.strip() or listed.stdout.strip()))
        roots = [
            line.split(":", 1)[0].strip()
            for line in listed.stdout.splitlines() if line.strip()
        ]
        co = {}
        if roots:
            graph = self._raw(
                ["ninja", "-t", "graph", *roots], cwd=self.project)
            if graph.returncode:
                raise RuntimeError(
                    "ninja -t graph (full) failed: "
                    + (graph.stderr.strip() or graph.stdout.strip()))
            node_paths, edge_ids, arrows = self._parse_graph_dot(graph.stdout)
            edge_outputs = {}
            for src, dst in arrows:
                if src in edge_ids:
                    edge_outputs.setdefault(src, set()).update(
                        node_paths.get(dst, ()))
            for outputs in edge_outputs.values():
                if len(outputs) > 1:
                    frozen = frozenset(outputs)
                    for path in outputs:
                        co[path] = frozen
        self._co_outputs_cache = co
        self._co_outputs_key = key
        return co

    def _graph_snapshot(self, targets):
        result = self._raw(
            ["ninja", "-t", "graph", *targets], cwd=self.project
        )
        if result.returncode:
            raise RuntimeError(
                "ninja -t graph failed: "
                + (result.stderr.strip() or result.stdout.strip())
            )
        labels = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if "->" in line:
                continue
            match = _GRAPH_NODE.match(line)
            if not match:
                continue
            labels.extend(self._split_label(match.group(1)))
        # A rooted graph only labels the requested outputs, so the sibling
        # outputs of an aggregate edge (one edge, many outputs) never appear.
        # Expand each output to every co-output of its producing edge so the
        # full aggregate closure is snapshotted before it can change.
        co = self._co_outputs()
        expanded = set(labels)
        for label in labels:
            siblings = co.get(label)
            if siblings:
                expanded.update(siblings)
        for label in expanded:
            self._consider_path(label)

    def _parse_log(self):
        log = self.project / ".ninja_log"
        records = {}
        if not log.is_file():
            return records
        for line in log.read_text(errors="replace").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            records[parts[3]] = (parts[0], parts[1], parts[2], parts[4])
        return records

    def _verify_closure(self, pre, post):
        for output, record in post.items():
            if pre.get(output) == record:
                continue
            normalized = os.path.normpath(
                os.path.join(str(self.project), output)
            )
            if normalized not in self.snapshots:
                raise RuntimeError(
                    f"build changed unsnapshotted output: {output}"
                )

    def _journaled_build(self, command, targets, cwd):
        self._graph_snapshot(targets)
        pre = self._parse_log()
        try:
            return self._raw(command, cwd=cwd)
        finally:
            post = self._parse_log()
            self._verify_closure(pre, post)

    # -- controlled mutation -------------------------------------------

    def invalidate(self, *paths):
        for path in paths:
            path = Path(path)
            self._snapshot(path)
            if path.is_symlink() or path.exists():
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()

    def _configure(self, version):
        configured = self._raw(
            [sys.executable, "configure.py", "--version", version],
            cwd=self.project,
        )
        if configured.returncode:
            raise RuntimeError(
                "configure failed: "
                + (configured.stderr.strip() or configured.stdout.strip())
            )
        refreshed = self._raw(["ninja", "build.ninja"], cwd=self.project)
        if refreshed.returncode:
            raise RuntimeError(
                "ninja build.ninja failed: "
                + (refreshed.stderr.strip() or refreshed.stdout.strip())
            )

    def ninja(self, version, targets):
        targets = list(targets)
        self.invocations.append((version, targets))
        self._configure(version)
        return self.run_text(["ninja", *targets], cwd=self.project)

    # -- rollback ------------------------------------------------------

    def _restore_record(self, path, record):
        path = Path(path)
        if record.get("other"):
            return
        if record.get("absent"):
            if path.is_symlink() or path.exists():
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            return
        if "symlink" in record:
            if path.is_symlink() or path.exists():
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            os.symlink(record["symlink"], path)
            return
        if "copy" in record:
            if path.is_symlink():
                path.unlink()
            path.write_bytes(Path(record["copy"]).read_bytes())
            os.chmod(path, record["mode"])
            os.utime(path, ns=(record["atime_ns"], record["mtime_ns"]))

    def restore_baseline(self, force=False):
        if self._restored and not force:
            return
        self._restored = True
        errors = []
        for key, record in self.snapshots.items():
            try:
                self._restore_record(Path(key), record)
            except BaseException as error:
                errors.append(error)
        for directory in sorted(
                self.created_dirs,
                key=lambda item: item.count(os.sep), reverse=True):
            try:
                path = Path(directory)
                if (path.is_dir() and not path.is_symlink()
                        and not any(path.iterdir())):
                    path.rmdir()
            except BaseException as error:
                errors.append(error)
        for key, record in self.control_snapshots.items():
            try:
                self._restore_record(Path(key), record)
            except BaseException as error:
                errors.append(error)
        if not errors:
            shutil.rmtree(self.dir, ignore_errors=True)
        if errors:
            raise errors[0]


class ReconstructionBuilder:
    """The only engine path allowed to change source-derived build
    artifacts. Every transition invalidates and rebuilds the selected
    object and generated context in one journaled call."""

    def __init__(self, unit, journal, transaction):
        self.unit = unit
        self.journal = journal
        self.transaction = transaction
        self._context_target = (
            unit.context_path.relative_to(unit.project).as_posix()
            if unit.context_path else None
        )

    def run_text(self, command, **kwargs):
        return self.journal.run_text(command, **kwargs)

    def _outputs(self):
        outputs = [self.unit.mine]
        if self.unit.context_path:
            outputs.append(self.unit.context_path)
        return outputs

    def _targets(self):
        targets = [self.unit.ninja_target]
        if self._context_target:
            targets.append(self._context_target)
        return targets

    def _build(self):
        self.journal.invalidate(*self._outputs())
        return self.journal.ninja(self.unit.version, self._targets())

    def rebuild(self):
        result = self._build()
        if result.returncode:
            raise RuntimeError(
                "forced rebuild failed: "
                + (result.stderr.strip() or result.stdout.strip())
            )

    def _is_compiler_failure(self, output):
        failed = re.findall(r"(?m)^FAILED:.*$", output)
        if not failed:
            return False
        compile_outputs = set(self._targets())
        touches = any(
            any(token in compile_outputs for token in line.split())
            for line in failed
        )
        if not touches:
            return False
        if re.search(
                r"(?im)ninja: error|command not found|no such file|"
                r"permission denied|cannot execute|: not found", output):
            return False
        return True

    def transition(self, files):
        self.transaction.write_files(files)
        result = self._build()
        if result.returncode:
            output = result.stdout + result.stderr
            if self._is_compiler_failure(output):
                raise CompilerRejected(output)
            raise RuntimeError("build failed: " + output.strip()[-8192:])


def _ordered_unique(items):
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _resolve_editable_files(unit, edit_files):
    project = unit.project.resolve()
    resolved = []
    seen = set()
    for candidate in [unit.source] + list(edit_files or []):
        path = Path(candidate)
        if not path.is_absolute():
            path = project / path
        path = path.resolve()
        if not path.is_relative_to(project):
            raise ValueError(f"editable file is outside project: {candidate}")
        if not path.is_file():
            raise ValueError(f"editable file is not a regular file: {candidate}")
        if path in seen:
            if path == unit.source.resolve():
                continue
            raise ValueError(f"duplicate editable file: {candidate}")
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"editable file is not valid UTF-8: {candidate}"
            ) from error
        seen.add(path)
        resolved.append(path)
    return resolved


def _reconstruction_state_id(identity):
    return _sha256_bytes(json.dumps(
        identity, sort_keys=True, separators=(",", ":")
    ).encode())


def _reconstruction_semantics(unit, args, verify_versions, link_resolution):
    semantics = {
        "prove": bool(args.prove),
        "proof_timeout_ms": args.proof_timeout_ms,
        "versions": list(verify_versions),
        "ghidra_program": args.ghidra_program,
        "import_language": args.ghidra_language,
        "import_compiler": args.ghidra_compiler,
    }
    if link_resolution.status == "configured":
        manifest = (
            unit.project / "config" / unit.version / "build.sha1"
        )
        semantics["link_gate"] = {
            "path": manifest.relative_to(unit.project).as_posix(),
            "expected_sha1": link_resolution.expected_sha1,
            "sha256": _sha256_bytes(manifest.read_bytes()),
        }
    else:
        semantics["link_gate"] = {"status": link_resolution.status}
    build_sha1 = {}
    for version in verify_versions:
        manifest = unit.project / "config" / version / "build.sha1"
        if manifest.is_file():
            build_sha1[version] = _sha256_bytes(manifest.read_bytes())
    semantics["build_sha1"] = build_sha1
    return semantics


def run_reconstruction(args, client=None, model_runner=invoke_model):
    # -- preflight step 1: positive budgets and timeouts --------------
    for name, value in (
        ("--max-rounds", args.max_rounds),
        ("--max-builds", args.max_builds),
        ("--mcp-timeout", args.mcp_timeout),
        ("--llm-timeout", args.llm_timeout),
        ("--build-timeout", args.build_timeout),
        ("--proof-timeout-ms", args.proof_timeout_ms),
    ):
        if value is None or value <= 0:
            raise ValueError(f"{name} must be positive")

    # -- step 2/3: resolve unit and editable set ----------------------
    unit = resolve_unit(args.project, args.unit, args.version)
    project = unit.project
    editable_files = _resolve_editable_files(unit, args.edit_file)

    # -- step 4: resolve --llm-cmd ------------------------------------
    model_path = Path(args.llm_cmd).resolve()
    if not model_path.is_file() or not os.access(model_path, os.X_OK):
        raise ValueError(f"--llm-cmd is not an executable file: {args.llm_cmd}")
    model_command = [str(model_path)]

    # -- step 5: require z3 before any mutation when proving ----------
    if args.prove:
        import ppc_equiv
        ppc_equiv.require_z3()

    # -- step 6: MCP session and required tools -----------------------
    if client is None:
        client = McpClient(args.ghidra_mcp_url, timeout=args.mcp_timeout)
    mcp_info = client.initialize()
    tools = client.list_tools()
    importing = not args.ghidra_program
    require_ghidra_tools(tools, importing)
    required_tools = set(REQUIRED_GHIDRA_TOOLS)
    if importing:
        required_tools.add("import_file")

    # -- link gate + verification versions (identity inputs) ----------
    link_resolution = resolve_link_gate(unit)
    verify_versions = _ordered_unique(list(args.verify_version or []))
    if verify_versions:
        if unit.module is None:
            raise ValueError(
                "cross-version verification requires a linked REL unit"
            )
        missing = [
            version for version in verify_versions
            if version not in available_versions(project)
        ]
        if missing:
            raise ValueError(
                "requested verification version is unavailable: "
                + ", ".join(missing)
            )
    semantics = _reconstruction_semantics(
        unit, args, verify_versions, link_resolution
    )

    # -- identity, state root, resume validation ----------------------
    identity = reconstruction_identity(
        unit, model_path, set(editable_files), args.ghidra_mcp_url, mcp_info,
        tools, required_tools, semantics,
    )
    state_id = _reconstruction_state_id(identity)
    if args.resume:
        resume_state = load_reconstruction_state(args.resume, identity)
        state_path = Path(args.resume).resolve()
        state_root = state_path.parent
    else:
        state_root = reconstruction_state_root(project, identity)
        state_path = state_root / "state.json"
        if state_path.exists():
            raise ValueError(
                f"state already exists at {state_path}; resume it with "
                "--resume or remove it to start fresh"
            )
        resume_state = None

    # -- step 11: reject an unsafe cached Ghidra program --------------
    prior_program = resume_state["ghidra_program"] if resume_state else None
    if (prior_program is not None
            and not prior_program.startswith("/mwdiff/")
            and prior_program != args.ghidra_program):
        raise ValueError(
            f"cached Ghidra program {prior_program!r} is not disposable"
        )

    # -- resume counters and cumulative work --------------------------
    if resume_state:
        rounds = resume_state["rounds"]
        builds = resume_state["builds"]
        accepted_edit_sets = list(resume_state["accepted_edits"])
        accepted_ghidra_ops = list(resume_state["ghidra_ops"])
        feedback = list(resume_state["feedback"])
        events = list(resume_state["events"])
        model_exchanges = list(resume_state["model_exchanges"])
    else:
        rounds = 0
        builds = 0
        accepted_edit_sets = []
        accepted_ghidra_ops = []
        feedback = []
        events = []
        model_exchanges = []

    verification = []
    outcome_state = {"status": "incomplete", "state_path": str(state_path)}

    with ExitStack() as stack:
        transaction = SourceTransaction(editable_files)
        journal = BuildJournal(
            project, unit.version, args.build_timeout,
            cancel=transaction.raise_pending,
        )
        stack.callback(
            lambda: None if transaction.keep else journal.restore_baseline()
        )

        # -- step 8: journaled baseline build from untouched source ---
        context_output = unit.context_path
        baseline_outputs = [unit.mine]
        if context_output:
            baseline_outputs.append(context_output)
        journal.invalidate(*baseline_outputs)
        baseline_targets = [unit.ninja_target]
        if context_output:
            baseline_targets.append(
                context_output.relative_to(project).as_posix()
            )
        baseline_build = journal.ninja(unit.version, baseline_targets)
        if baseline_build.returncode:
            raise RuntimeError(
                "baseline build failed: "
                + (baseline_build.stderr.strip()
                   or baseline_build.stdout.strip())
            )
        compiler_command = reconstruction_compiler_command(
            unit, runner=journal.run_text
        )

        # -- step 12: prepare disposable Ghidra program ---------------
        previous = {}
        transaction.pending_signal = None
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, transaction.handle_signal)
        try:
            prepared_program = prepare_ghidra_program(
                client, tools, unit, args, state_id,
                prior_program=prior_program, cancel=transaction.raise_pending,
            )
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        transaction.raise_pending()

        # -- step 13: read the already-rebuilt untouched baseline -----
        read_unit_snapshot(unit, runner=journal.run_text)

        transaction = stack.enter_context(transaction)
        builder = ReconstructionBuilder(unit, journal, transaction)

        if (resume_state and prepared_program.replay_required
                and accepted_ghidra_ops):
            _, replay_failures = apply_ghidra_operations(
                client, prepared_program.path, accepted_ghidra_ops,
                cancel=transaction.raise_pending,
            )
            if replay_failures:
                raise RuntimeError(
                    "failed to replay saved Ghidra operations on resume"
                )

        link_resolution_configured = link_resolution.status == "configured"

        # -- shared helpers -------------------------------------------
        def build_state(score, focus, feedback_value, ghidra_program):
            return {
                "schema": RECONSTRUCTION_STATE_SCHEMA,
                "identity": identity,
                "rounds": rounds,
                "builds": builds,
                "accepted_edits": accepted_edit_sets,
                "ghidra_ops": accepted_ghidra_ops,
                "score": dataclasses.asdict(score),
                "focus": dataclasses.asdict(focus) if focus else None,
                "events": events,
                "feedback": feedback_value,
                "ghidra_program": ghidra_program,
                "model_exchanges": model_exchanges,
            }

        program_unset = object()

        def save_progress(score, feedback_value, ghidra_program=program_unset):
            program = (
                prepared_program.path if ghidra_program is program_unset
                else ghidra_program
            )
            save_reconstruction_state(
                state_root,
                build_state(score, focus, feedback_value, program),
            )

        def emit_event(kind, focus=None, details=None):
            event = {
                "kind": kind,
                "round": rounds,
                "build": builds,
                "focus": dataclasses.asdict(focus) if focus else None,
                "details": details or {},
            }
            events.append(event)
            append_reconstruction_event(state_root, {"event": event})

        def record_model_exchange(phase, request, response):
            model_exchanges.append({
                "phase": phase,
                "request_sha256": _sha256_bytes(json.dumps(
                    request, sort_keys=True, separators=(",", ":")
                ).encode()),
                "response_sha256": _sha256_bytes(json.dumps(
                    response, sort_keys=True, separators=(",", ":")
                ).encode()),
            })
            append_reconstruction_event(state_root, {
                "exchange": sanitize_reconstruction_value({
                    "phase": phase,
                    "request": request,
                    "response": response,
                }),
            })

        if resume_state:
            for edit_set in accepted_edit_sets:
                transaction.write_files(render_source_edits(
                    project, editable_files, edit_set
                ))
            builder.rebuild()
        accepted_files = transaction.read_files()

        def restore_accepted():
            transaction.restore_files(accepted_files)
            builder.rebuild()

        def current_link_check(snapshot):
            object_exact = (
                snapshot.functions_percent == 100.0
                and snapshot.code_percent == 100.0
                and snapshot.data_percent == 100.0
            )
            if link_resolution.status != "configured":
                return LinkCheck(link_resolution.status, None, None, None)
            if not object_exact:
                return LinkCheck(
                    "deferred",
                    link_resolution.path.relative_to(project).as_posix(),
                    link_resolution.expected_sha1,
                    None,
                )
            return verify_current_link(
                unit, link_resolution, runner=builder.run_text
            )

        focus = None
        score = None
        link = LinkCheck(link_resolution.status, None, None, None)
        selected_exact = False

        while True:
            transaction.raise_pending()
            snapshot = read_unit_snapshot(unit, runner=builder.run_text)
            link = current_link_check(snapshot)
            linked_match = (
                True if link.status == "match"
                else False if link.status == "mismatch"
                else None
            )
            focus = select_reconstruction_focus(snapshot, linked_match)
            score = score_reconstruction(
                unit, snapshot, focus, linked_match,
                runner=builder.run_text,
            )
            if focus is None:
                selected_exact = True
                break
            if rounds >= args.max_rounds or builds >= args.max_builds:
                selected_exact = False
                break

            rounds += 1
            emit_event("round-start", focus=focus)
            save_progress(score, feedback)
            transaction.raise_pending()

            ghidra_evidence = collect_ghidra_evidence(
                client, prepared_program.path, focus,
                cancel=transaction.raise_pending,
            )
            transaction.raise_pending()
            analyze_request = build_reconstruction_request(
                "mwdiff.reconstruct.analyze.v1", identity, state_id,
                unit, focus, snapshot, score, editable_files, compiler_command,
                ghidra_evidence, feedback, rounds,
                args.max_rounds - rounds, args.max_builds - builds,
                runner=builder.run_text,
            )
            analysis_raw = model_runner(
                model_command, analyze_request, args.llm_timeout,
                cancel=transaction.raise_pending,
            )
            analysis = validate_analysis_response(analysis_raw)
            record_model_exchange("analyze", analyze_request, analysis)

            if analysis["ghidra_ops"]:
                save_progress(score, feedback, ghidra_program=None)
                applied_ops, failed_ops = apply_ghidra_operations(
                    client, prepared_program.path, analysis["ghidra_ops"],
                    cancel=transaction.raise_pending,
                )
                accepted_ghidra_ops.extend(applied_ops)
                for operation in applied_ops:
                    emit_event("ghidra-operation-confirmed", details=operation)
                for failure in failed_ops:
                    emit_event("ghidra-operation-failed", details=failure)
                save_progress(
                    score, feedback, ghidra_program=prepared_program.path
                )
            else:
                applied_ops, failed_ops = [], []

            operation_feedback = feedback + [
                {"kind": "ghidra-operation-failed", **failure}
                for failure in failed_ops
            ]
            transaction.raise_pending()
            revised_ghidra_evidence = collect_ghidra_evidence(
                client, prepared_program.path, focus,
                cancel=transaction.raise_pending,
            )
            transaction.raise_pending()
            propose_request = build_reconstruction_request(
                "mwdiff.reconstruct.propose.v1", identity, state_id,
                unit, focus, snapshot, score, editable_files, compiler_command,
                revised_ghidra_evidence, operation_feedback, rounds,
                args.max_rounds - rounds, args.max_builds - builds,
                runner=builder.run_text,
            )
            proposal_raw = model_runner(
                model_command, propose_request, args.llm_timeout,
                cancel=transaction.raise_pending,
            )
            proposal = validate_proposal_response(proposal_raw)
            record_model_exchange("propose", propose_request, proposal)
            edits = proposal["source_edits"]
            if not edits:
                feedback = [{
                    "kind": "no-source-edit",
                    "focus": focus.name,
                    "ghidra_failures": failed_ops,
                }]
                emit_event("no-source-edit", focus=focus)
                save_progress(score, feedback)
                continue

            candidate_files = render_source_edits(
                project, editable_files, edits
            )
            builds += 1
            emit_event("build-start", focus=focus)
            save_progress(score, operation_feedback)
            try:
                builder.transition(candidate_files)
            except CompilerRejected as error:
                feedback = [{
                    "kind": "compiler-error",
                    "output": error.output[-65536:],
                }]
                emit_event("compiler-error", focus=focus, details=feedback[0])
                restore_accepted()
                save_progress(score, feedback)
                continue

            candidate_snapshot = read_unit_snapshot(
                unit, runner=builder.run_text
            )
            candidate_link = current_link_check(candidate_snapshot)
            candidate_linked_match = (
                True if candidate_link.status == "match"
                else False if candidate_link.status == "mismatch"
                else None
            )
            candidate_score = score_reconstruction(
                unit, candidate_snapshot, focus, candidate_linked_match,
                runner=builder.run_text,
            )
            proof = None
            if (
                args.prove
                and focus.kind == "function"
                and not candidate_score.exact
            ):
                transaction.raise_pending()
                proof = prove_objects(
                    unit.target, unit.mine, focus.name,
                    args.proof_timeout_ms, unit.project,
                )
                emit_event(
                    "proof", focus=focus, details={"status": proof.status}
                )
                transaction.raise_pending()
            if proof is not None and proof.status == "different":
                feedback = [{
                    "kind": "proven-different",
                    "counterexample": proof.counterexample,
                }]
                restore_accepted()
                save_progress(score, feedback)
                continue

            before_score = score
            if candidate_score.rank < before_score.rank:
                accepted_files = transaction.read_files()
                accepted_edit_sets.append(edits)
                score = candidate_score
                link = candidate_link
                feedback = [{
                    "kind": "accepted",
                    "before": dataclasses.asdict(before_score),
                    "after": dataclasses.asdict(candidate_score),
                    "proof": proof.status if proof else None,
                }]
                emit_event("score-improved", focus=focus, details=feedback[0])
            else:
                feedback = [{
                    "kind": "not-improved",
                    "candidate": dataclasses.asdict(candidate_score),
                    "accepted": dataclasses.asdict(before_score),
                    "proof": proof.status if proof else None,
                }]
                emit_event("score-rejected", focus=focus, details=feedback[0])
                restore_accepted()
                score = before_score
            save_progress(score, feedback)

        # -- finalize -------------------------------------------------
        patches = {}
        for path in sorted(accepted_files):
            original = transaction.data[path]
            final = accepted_files[path]
            if original == final:
                continue
            rel = path.resolve().relative_to(project.resolve()).as_posix()
            patches[rel] = "".join(difflib.unified_diff(
                original.decode("utf-8", "replace").splitlines(keepends=True),
                final.decode("utf-8", "replace").splitlines(keepends=True),
                fromfile=f"a/{rel}", tofile=f"b/{rel}",
            ))

        failed_gates = []
        if selected_exact:
            accepted_snapshot = read_unit_snapshot(
                unit, runner=builder.run_text
            )
            link = current_link_check(accepted_snapshot)
            emit_event("link", details={
                "status": link.status,
                "expected_sha1": link.expected_sha1,
                "actual_sha1": link.actual_sha1,
            })
            if link_resolution_configured and link.status == "mismatch":
                failed_gates.append(f"linked SHA mismatch: {unit.version}")
            if verify_versions:
                verification = list(verify_all(
                    project, unit.name, verify_versions,
                    runner=builder.run_text,
                ))
                for check in verification:
                    emit_event(
                        "verify-version", details=dataclasses.asdict(check))
                    if not (
                        check.functions_percent == 100.0
                        and check.code_percent == 100.0
                        and check.data_percent == 100.0
                    ):
                        failed_gates.append(
                            f"object below 100% for {check.version}"
                        )
                    elif not check.rel_sha_match:
                        failed_gates.append(
                            f"linked SHA mismatch: {check.version}"
                        )
            if failed_gates:
                feedback = [{"kind": "verification-failed",
                             "gates": failed_gates}]
                save_progress(score, feedback)
            elif args.apply:
                transaction.retain()

        result = ReconstructionResult(
            status="exact" if selected_exact and not failed_gates
            else "incomplete",
            focus=focus,
            score=score,
            rounds=rounds,
            max_rounds=args.max_rounds,
            builds=builds,
            max_builds=args.max_builds,
            link=link,
            verification=tuple(verification),
            events=tuple(
                ReconstructionEvent(
                    event["kind"], event["round"], event["build"],
                    event["focus"], event["details"],
                )
                for event in events
            ),
            outcome="pending",
            state_path=(
                None if selected_exact and not failed_gates
                else str(state_path)
            ),
            patches=patches,
        )
        if not (selected_exact and not failed_gates):
            save_progress(score, feedback)
        outcome_state["status"] = result.status
        outcome_state["retain"] = bool(
            selected_exact and not failed_gates and args.apply
        )

    # -- outside the ExitStack: source + artifacts settled ------------
    retained = outcome_state["retain"]
    outcome = "retained" if retained else "restored"
    outcome_event = {
        "kind": "outcome",
        "round": rounds,
        "build": builds,
        "focus": dataclasses.asdict(focus) if focus else None,
        "details": {"outcome": outcome, "status": result.status},
    }
    events.append(outcome_event)
    completion_error = None
    if result.status == "exact":
        try:
            append_reconstruction_event(state_root, {"event": outcome_event})
            if state_path.exists():
                state_path.unlink()
        except BaseException as error:
            completion_error = error
    else:
        try:
            append_reconstruction_event(state_root, {"event": outcome_event})
        except BaseException:
            pass

    if completion_error is not None and retained:
        rollback_errors = []
        for action in (
            transaction.rollback,
            lambda: journal.restore_baseline(force=True),
        ):
            try:
                action()
            except BaseException as error:
                rollback_errors.append(error)
        try:
            append_reconstruction_event(state_root, {"event": {
                "kind": "outcome-rollback",
                "round": rounds,
                "build": builds,
                "focus": dataclasses.asdict(focus) if focus else None,
                "details": {"errors": [str(item) for item in rollback_errors]},
            }})
        except BaseException:
            pass
        raise RuntimeError(
            "exact result retained but completion failed; attempted rollback: "
            f"{completion_error}; rollback errors: {rollback_errors}"
        ) from completion_error

    if retained and completion_error is None:
        # Both completion operations succeeded: the ignored journal snapshots
        # are no longer needed. A deletion warning is not a run failure.
        shutil.rmtree(journal.dir, ignore_errors=True)

    result = dataclasses.replace(
        result,
        outcome=outcome,
        events=tuple(result.events) + (
            ReconstructionEvent(
                outcome_event["kind"], outcome_event["round"],
                outcome_event["build"], outcome_event["focus"],
                outcome_event["details"],
            ),
        ),
    )
    return result


def render_reconstruction_human(result):
    """Deterministic one-document view of a finalized ReconstructionResult.

    Consumes only the finalized result: every fact (events, measures, link
    status, cross-version checks, patches, state, outcome) is read straight
    off the dataclass. Link availability is reported from ``result.link``
    alone -- never inferred from ``score.linked_match`` -- so a ``deferred``
    gate is always shown as ``deferred`` and never as ``unavailable``.
    """
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    lines = []
    for event in result.events:
        lines.append(
            "event %s round=%s build=%s focus=%s details=%s" % (
                event.kind,
                "-" if event.round is None else event.round,
                "-" if event.build is None else event.build,
                canonical(event.focus) if event.focus is not None else "-",
                canonical(event.details),
            )
        )
    score = result.score
    lines.append(
        "measures functions=%.4f code=%.4f data=%.4f focus=%.4f "
        "classification=%s exact=%s" % (
            score.functions_percent, score.code_percent, score.data_percent,
            score.focus_percent, score.classification, score.exact,
        )
    )
    link = result.link
    lines.append(
        "link status=%s expected=%s actual=%s path=%s" % (
            link.status,
            link.expected_sha1 or "-",
            link.actual_sha1 or "-",
            link.path or "-",
        )
    )
    for check in result.verification:
        lines.append(
            "verify version=%s functions=%.4f code=%.4f data=%.4f "
            "rel_sha_match=%s" % (
                check.version, check.functions_percent, check.code_percent,
                check.data_percent, check.rel_sha_match,
            )
        )
    for path in sorted(result.patches):
        lines.append("patch %s" % path)
    if not result.patches:
        lines.append("patch -")
    lines.append("state %s" % (result.state_path or "-"))
    lines.append(
        "outcome %s status=%s rounds=%d/%d builds=%d/%d" % (
            result.outcome, result.status, result.rounds, result.max_rounds,
            result.builds, result.max_builds,
        )
    )
    return "\n".join(lines)


def cmd_reconstruct(args):
    try:
        result = run_reconstruction(args)
    except (OSError, ValueError, RuntimeError) as error:
        die(str(error))
    payload = dataclasses.asdict(result)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(render_reconstruction_human(result))
    return 0 if result.status == "exact" else 1


def cmd_prove(args):
    if args.timeout_ms <= 0:
        die("--timeout-ms must be positive")
    try:
        result = prove_objects(
            args.target, args.mine, args.fn, args.timeout_ms
        )
    except RuntimeError as error:
        die(str(error))
    if args.json:
        print(json.dumps(dataclasses.asdict(result), sort_keys=True))
    else:
        print(result.status)
        if result.reason:
            print(f"reason: {result.reason}")
        if result.counterexample:
            print(
                "counterexample: "
                + ", ".join(
                    f"{name}={value}"
                    for name, value in sorted(result.counterexample.items())
                )
            )
    return 0 if result.status == "equivalent" else 1


def cmd_diff(args):
    t, m = disasm(args.target), disasm(args.mine)
    results = []
    for fn in t:
        if fn not in m:
            results.append((fn, None))
        else:
            d = fn_diff(t[fn], m[fn])
            if d:
                results.append((fn, len(d)))
    # Smallest diffs first: those are the almost-matched ones worth attacking.
    for fn, n in sorted(results, key=lambda x: (x[1] is None, x[1] or 0)):
        print(f"{fn}: {'MISSING in mine' if n is None else f'{n} diff lines'}")
    extra = set(m) - set(t)
    if extra:
        print("EXTRA in mine (deadstrip candidates):", ", ".join(sorted(extra)))
    if not results and not extra:
        print(f"all {len(t)} functions EXACT")
        return 0
    return 1


def cmd_show(args):
    t, m = disasm(args.target), disasm(args.mine)
    a = resolve_fn(t, args.fn, args.target)
    b = resolve_fn(m, args.fn, args.mine)
    diff = list(difflib.unified_diff(norm(a), norm(b),
                                     "target", "mine", lineterm=""))
    for x in diff:
        print(x)
    if not diff:
        print("EXACT")
    return 1 if diff else 0


def _object_paths(args):
    project = Path(args.project).resolve()
    if args.unit:
        unit = resolve_unit(project, args.unit, args.version)
        return project, unit.target, unit.mine
    if args.target and args.mine:
        return project, Path(args.target).resolve(), Path(args.mine).resolve()
    raise ValueError("pass --unit or both --target and --mine")


def cmd_diagnose(args):
    try:
        project, target_obj, mine_obj = _object_paths(args)
    except ValueError as error:
        die(str(error))
    target = resolve_fn(disasm(target_obj, project), args.fn, str(target_obj))
    candidate = resolve_fn(disasm(mine_obj, project), args.fn, str(mine_obj))
    diagnosis = diagnose_lines(target, candidate)
    if getattr(args, "json", False):
        print(json.dumps(dataclasses.asdict(diagnosis), sort_keys=True))
    else:
        print(f"{args.fn}: {diagnosis.diff_lines} changed lines")
        print(f"  classification: {diagnosis.classification}")
        if diagnosis.register_map:
            changed = [
                f"{a} -> {b}"
                for a, b in diagnosis.register_map.items()
                if a != b
            ]
            print(f"  global register permutation: {', '.join(changed)}")
        if diagnosis.relocation_aliases:
            print("  relocation aliases: " + ", ".join(
                f"{left} <-> {right}"
                for left, right in diagnosis.relocation_aliases))
        print(
            "  suggested families: "
            + (", ".join(diagnosis.suggested_families) or "none")
        )
    return 0 if diagnosis.classification == "exact" else 1


def cmd_try(args):
    """variants.py defines: BASE (str to replace) and VARIANTS (dict name->str)."""
    ns = {}
    with open(args.variants) as f:
        exec(f.read(), ns)
    try:
        base, variants = ns["BASE"], ns["VARIANTS"]
    except KeyError as e:
        die(f"{args.variants} must define {e.args[0]}")
    with SourceTransaction(args.src) as source:
        with open(args.src) as f:
            orig = f.read()
        if base not in orig:
            die(f"BASE snippet not found in {args.src}")
        count = orig.count(base)
        if count != 1:
            die(f"source anchor must be unique; found {count}")
        tgt = resolve_fn(disasm(args.target), args.fn, args.target)
        width = max(map(len, variants), default=0)
        best = None
        best_repl = None
        candidate_attempted = False
        try:
            for name, repl in variants.items():
                source.write_text(replace_unique(orig, base, repl))
                candidate_attempted = True
                r = subprocess.run(["ninja", args.obj], capture_output=True, text=True)
                if r.returncode:
                    tail = (r.stdout + r.stderr).strip()[-200:]
                    print(f"{name:<{width}}  BUILD FAIL  {tail!r}")
                    continue
                mine = disasm(args.obj)
                if args.fn not in mine:
                    print(f"{name:<{width}}  fn missing from {args.obj}")
                    continue
                d = fn_diff(tgt, mine[args.fn])
                if best is None or len(d) < best[1]:
                    best = (name, len(d))
                    best_repl = repl
                print(f"{name:<{width}}  {'EXACT' if not d else len(d)}  {d[:6]}")
                if not d and args.stop_on_exact:
                    break
            if best:
                print(f"\nbest: {best[0]} ({'EXACT' if best[1] == 0 else f'{best[1]} diff lines'})")
            if args.show_best and best and best[1] > 0:
                source.write_text(replace_unique(orig, base, best_repl))
                r = subprocess.run(["ninja", args.obj], capture_output=True, text=True)
                if r.returncode:
                    tail = (r.stdout + r.stderr).strip()[-200:]
                    die(f"failed to rebuild best variant {best[0]}: {tail}")
                print(f"\n--- Showing best variant: {best[0]} ---")
                from argparse import Namespace
                show_args = Namespace(target=args.target, mine=args.obj, fn=args.fn)
                cmd_show(show_args)
        finally:
            try:
                source.write_text(orig)
            finally:
                if candidate_attempted:
                    Path(args.obj).unlink(missing_ok=True)
            r = subprocess.run(["ninja", args.obj], capture_output=True, text=True)
            if r.returncode:
                tail = (r.stdout + r.stderr).strip()[-200:]
                die(f"failed to rebuild original object: {tail}")
    return 0 if best and best[1] == 0 else 1


def cmd_search(args):
    try:
        if args.max_builds <= 0:
            raise ValueError("--max-builds must be positive")
        if args.beam_width <= 0:
            raise ValueError("--beam-width must be positive")
        proof_timeout_ms = getattr(args, "proof_timeout_ms", 5000)
        if proof_timeout_ms <= 0:
            raise ValueError("--proof-timeout-ms must be positive")
        if args.verify and not args.apply:
            raise ValueError("--verify requires --apply")
        prove_candidate = getattr(args, "prove", False)
        unit = resolve_unit(args.project, args.unit, args.version)
        if args.verify:
            _rel_path(unit, unit.version)
        original = unit.source.read_text()
        lines = original.splitlines(keepends=True)
        snippet, start, end = source_range(original, args.line)
        families = tuple(item for item in args.families.split(",") if item)
        candidates = generate_candidates(snippet, families, args.depth)
        full_candidates = [
            SourceCandidate(
                candidate.name,
                "".join(lines[:start]) + candidate.text + "".join(lines[end:]),
                candidate.depth,
            )
            for candidate in candidates
        ]
        result = search_candidates(
            unit,
            args.fn,
            full_candidates,
            args.max_builds,
            not args.no_stop,
            args.apply,
            args.beam_width,
            prove_candidate,
            proof_timeout_ms,
            args.json,
        )
        local_versions = available_versions(args.project)
        unavailable_versions = sorted(
            set(configured_versions(args.project)) - set(local_versions)
        )
        versions = args.verify_version or local_versions
        verification = (
            verify_all(args.project, args.unit, versions)
            if args.verify and result.exact
            else []
        )
    except (OSError, ValueError, RuntimeError) as error:
        die(str(error))

    failed = [
        item
        for item in verification
        if item.functions_percent != 100.0
        or item.code_percent != 100.0
        or item.data_percent != 100.0
        or not item.rel_sha_match
    ]
    payload = {
        "search": dataclasses.asdict(result),
        "verification": [dataclasses.asdict(item) for item in verification],
        "unavailable_versions": unavailable_versions,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        if result.candidate:
            print(
                f"best: {result.candidate.name} "
                f"({'EXACT' if result.exact else str(result.score.diff_lines) + ' diff lines'})"
            )
            if not args.apply:
                patch = difflib.unified_diff(
                    original.splitlines(),
                    result.candidate.text.splitlines(),
                    "current",
                    "candidate",
                    lineterm="",
                )
                print("\n".join(patch))
        for item in verification:
            print(
                f"{item.version}: functions {item.functions_percent:.1f}%, "
                f"code {item.code_percent:.1f}%, data {item.data_percent:.1f}%, "
                f"REL SHA {'match' if item.rel_sha_match else 'MISMATCH'}"
            )
        if args.verify:
            for version in unavailable_versions:
                print(f"unavailable: {version} (no local disc input)")
    return 0 if result.exact and not failed else 1


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("diff", help="summarise per-function diff counts")
    d.add_argument("target"), d.add_argument("mine")
    d.set_defaults(run=cmd_diff)

    s = sub.add_parser("show", help="full unified diff of one function")
    s.add_argument("target"), s.add_argument("mine"), s.add_argument("fn")
    s.set_defaults(run=cmd_show)

    t = sub.add_parser("try", help="brute-force source variants against a target fn")
    t.add_argument("src"), t.add_argument("obj"), t.add_argument("target")
    t.add_argument("fn"), t.add_argument("variants")
    t.add_argument("--no-stop", dest="stop_on_exact", action="store_false",
                   help="keep testing variants after an EXACT match")
    t.add_argument("--show-best", action="store_true",
                   help="run 'show' on the best variant if not EXACT")
    t.set_defaults(run=cmd_try)

    x = sub.add_parser("diagnose", help="classify one function mismatch")
    x.add_argument("--project", default=".")
    x.add_argument("--version")
    x.add_argument("--unit")
    x.add_argument("--target")
    x.add_argument("--mine")
    x.add_argument("--fn", required=True)
    x.add_argument("--json", action="store_true")
    x.set_defaults(run=cmd_diagnose)

    p_prove = sub.add_parser(
        "prove", help="prove supported PowerPC functions equivalent"
    )
    p_prove.add_argument("target")
    p_prove.add_argument("mine")
    p_prove.add_argument("fn")
    p_prove.add_argument("--timeout-ms", type=int, default=5000)
    p_prove.add_argument("--json", action="store_true")
    p_prove.set_defaults(run=cmd_prove)

    q = sub.add_parser("search", help="compile and rank targeted source mutations")
    q.add_argument("--project", default=".")
    q.add_argument("--version")
    q.add_argument("--unit", required=True)
    q.add_argument("--fn", required=True)
    q.add_argument("--line", required=True)
    q.add_argument("--families", required=True)
    q.add_argument("--depth", type=int, choices=(1, 2), default=1)
    q.add_argument("--max-builds", type=int, default=100)
    q.add_argument("--beam-width", type=int, default=5)
    q.add_argument("--no-stop", action="store_true")
    q.add_argument("--apply", action="store_true")
    q.add_argument("--verify", action="store_true")
    q.add_argument("--verify-version", action="append", default=[])
    q.add_argument("--json", action="store_true")
    q.add_argument(
        "--prove",
        action="store_true",
        help="reject supported candidates proven behavior-changing",
    )
    q.add_argument("--proof-timeout-ms", type=int, default=5000)
    q.set_defaults(run=cmd_search)

    r = sub.add_parser(
        "reconstruct", help="autonomously reconstruct one configured unit"
    )
    r.add_argument("--project", default=".")
    r.add_argument("--version")
    r.add_argument("--unit", required=True)
    r.add_argument("--ghidra-mcp-url", required=True)
    r.add_argument("--ghidra-program")
    r.add_argument("--ghidra-language")
    r.add_argument("--ghidra-compiler")
    r.add_argument("--llm-cmd", required=True)
    r.add_argument("--max-rounds", type=int, default=8)
    r.add_argument("--max-builds", type=int, default=100)
    r.add_argument("--mcp-timeout", type=int, default=30)
    r.add_argument("--llm-timeout", type=int, default=300)
    r.add_argument("--build-timeout", type=int, default=600)
    r.add_argument("--edit-file", action="append", default=[])
    r.add_argument("--resume")
    r.add_argument("--apply", action="store_true")
    r.add_argument("--verify-version", action="append", default=[])
    r.add_argument("--prove", action="store_true")
    r.add_argument("--proof-timeout-ms", type=int, default=5000)
    r.add_argument("--json", action="store_true")
    r.set_defaults(run=cmd_reconstruct)

    args = p.parse_args()
    sys.exit(args.run(args))


if __name__ == "__main__":
    main()
