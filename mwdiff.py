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
supported acyclic integer functions directly.

Usage:
  mwdiff.py diff  <target.o> <mine.o>
  mwdiff.py show  <target.o> <mine.o> <mangled_fn>
  mwdiff.py try   <src.cpp> <obj_to_build> <target.o> <mangled_fn> <variants.py>
  mwdiff.py diagnose --unit <unit> --fn <mangled_fn>
  mwdiff.py search --unit <unit> --fn <mangled_fn> --line <range> --families <list>
  mwdiff.py prove <target.o> <mine.o> <mangled_fn>

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
import os
import re
import subprocess
import sys
import signal
import stat
import tempfile

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
        for parent in frontier:
            for family in families:
                for name, text in MUTATION_FAMILIES[family](parent.text).items():
                    if text in seen:
                        continue
                    seen.add(text)
                    candidate = SourceCandidate(f"{parent.name}+{name}", text, level)
                    results.append(candidate)
                    next_frontier.append(candidate)
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
        self.path = Path(path)
        self.data = None
        self.stat = None
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
            self.stat = self.path.stat()
            self.data = self.path.read_bytes()
        except BaseException:
            self._restore_handlers()
            raise
        return self

    def write_text(self, text):
        self.path.write_text(text)

    def retain(self):
        self.keep = True

    def __exit__(self, exc_type, exc, traceback):
        try:
            if not self.keep:
                self.path.write_bytes(self.data)
                os.chmod(self.path, stat.S_IMODE(self.stat.st_mode))
                os.utime(self.path, ns=(self.stat.st_atime_ns, self.stat.st_mtime_ns))
        finally:
            self._restore_handlers()
        if self.pending_signal is not None:
            signum = self.pending_signal
            self.pending_signal = None
            raise KeyboardInterrupt(f"received {signal.Signals(signum).name}")
        return False


@dataclass(frozen=True)
class ProjectUnit:
    name: str
    project: Path
    source: Path
    target: Path
    mine: Path
    ninja_target: str
    version: str
    module: str
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
    module = relative_parts[build_index + 2]
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


@dataclass(frozen=True)
class VerificationResult:
    version: str
    functions_percent: float
    code_percent: float
    data_percent: float
    rel_sha_match: bool


def verify_version(project, unit_name, version):
    project = Path(project).resolve()
    configured = subprocess.run(
        [sys.executable, "configure.py", "--version", version],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if configured.returncode:
        raise RuntimeError(configured.stderr.strip() or configured.stdout.strip())
    refreshed = subprocess.run(
        ["ninja", "build.ninja"],
        cwd=project,
        capture_output=True,
        text=True,
    )
    if refreshed.returncode:
        raise RuntimeError(refreshed.stderr.strip() or refreshed.stdout.strip())
    unit = resolve_unit(project, unit_name, version)
    rel = Path("build") / version / unit.module / f"{unit.module}.rel"
    process = subprocess.run(
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


def verify_all(project, unit_name, versions):
    project = Path(project).resolve()
    original_version = resolve_unit(project, unit_name).version
    unavailable = sorted(set(versions) - set(available_versions(project)))
    if unavailable:
        raise ValueError("missing local disc input for: " + ", ".join(unavailable))
    try:
        return [verify_version(project, unit_name, version) for version in versions]
    finally:
        restored = subprocess.run(
            [sys.executable, "configure.py", "--version", original_version],
            cwd=project,
            capture_output=True,
            text=True,
        )
        if restored.returncode:
            raise RuntimeError(restored.stderr.strip() or restored.stdout.strip())
        refreshed = subprocess.run(
            ["ninja", "build.ninja"],
            cwd=project,
            capture_output=True,
            text=True,
        )
        if refreshed.returncode:
            raise RuntimeError(refreshed.stderr.strip() or refreshed.stdout.strip())


def _project_tool(project, configured):
    path = Path(configured)
    return path if path.is_absolute() else Path(project) / path


def disasm(obj, project="."):
    """Return {mangled_fn_name: [instruction lines]} for an object file."""
    if not os.path.isfile(obj):
        die(f"no such object file: {obj}")
    fd, out = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        r = subprocess.run(
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

def _configured_object_measures(project, target, mine):
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
    process = subprocess.run(
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


def score_object(project, target, mine, function):
    process = subprocess.run(
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
    target_lines = resolve_fn(disasm(str(target), project), function, str(target))
    mine_lines = resolve_fn(disasm(str(mine), project), function, str(mine))
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
    measures = _configured_object_measures(project, target, mine)
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

    args = p.parse_args()
    sys.exit(args.run(args))


if __name__ == "__main__":
    main()
