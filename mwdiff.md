# mwdiff.py — MWCC matching helper

`mwdiff` is a scriptable companion to
[objdiff](https://github.com/encounter/objdiff) for DTK-based GameCube and Wii
matching decomps. It can:

- compare object files function by function;
- show one normalized instruction diff;
- compile explicit source variants;
- diagnose common MWCC mismatch shapes;
- generate and rank bounded source mutations; and
- optionally prove supported acyclic integer PowerPC functions equivalent.

It is a guide for the inner matching loop, not a replacement for objdiff,
linked output checks, or project CI.

## Requirements

- Python 3.10+
- [DTK](https://github.com/encounter/decomp-toolkit), found through `$DTK` or
  `./build/tools/dtk`
- Ninja for `try`, `search`, and verification builds
- `objdiff.json` for project-aware unit resolution
- `objdiff-cli`, found through `$OBJDIFF` or `./build/tools/objdiff-cli`, for
  search scoring
- Optional: `z3-solver` for `prove` and `search --prove`

Run commands from the decomp project root. The examples use:

```sh
MWDIFF=/path/to/mwdiff/mwdiff.py
```

A configured dtk-template project normally provides `objdiff.json`,
`build.ninja`, `configure.py`, and target/mine object paths.

## Three different matching claims

Keep these separate:

1. **Function `EXACT`:** normalized instructions for one function match.
2. **Object exact:** every matchable function, object, and relevant section is
   100% according to the configured objdiff report.
3. **Linked exact:** the final binary or REL checksum matches the project's
   expected checksum.

`show` and `try` report function exactness. `search --apply` requires object
exactness. `search --apply --verify` also checks linked REL SHA values for the
requested locally available versions. The linked checksum remains the final
gate.

## Commands

### `diff` — summarize a translation unit

```sh
python3 "$MWDIFF" diff <target.o> <mine.o>
```

DTK disassembles both objects. `mwdiff` prints each mismatched function with a
normalized changed-line count, sorted smallest-first. It also reports missing
functions and symbols present only in the candidate object.

```text
Create__Q29daExample5Act_cFv: 2 diff lines
Execute__Q29daExample5Act_cFv: 8 diff lines
EXTRA in mine (deadstrip candidates): __dt__4cXyzFv
```

When all functions and symbol sets align:

```text
all 24 functions EXACT
```

Normalization removes address/hex columns, compiler-generated `@NNNN` and
`$NNNN` counters, anonymous section symbol names, and cosmetic local-label
numbers while preserving branch-target identity.

### `show` — display one function diff

```sh
python3 "$MWDIFF" show <target.o> <mine.o> '<mangled_fn>'
```

This prints a unified `--- target` / `+++ mine` diff of normalized
instructions. Unknown names get fuzzy suggestions.

```diff
--- target
+++ mine
@@ ...
-and. r0, r3, r0
+and. r0, r0, r3
```

Exit status is 0 for `EXACT`, otherwise 1.

### `try` — compile explicit variants

```sh
python3 "$MWDIFF" try \
  <src.cpp> <obj_to_build> <target.o> '<mangled_fn>' variants.py
```

`variants.py` defines exactly two values:

```python
BASE = """    bool set = check();
    if (set) {"""

VARIANTS = {
    "direct": """    if (check()) {""",
    "not-false": """    if (check() != FALSE) {""",
}
```

For each variant, `try` uniquely replaces `BASE`, runs
`ninja <obj_to_build>`, disassembles the result, and reports `EXACT`, a diff
count, a build failure, or a missing function.

Options:

- `--no-stop`: continue after finding an exact function.
- `--show-best`: rebuild and display the best non-exact function diff.

The source transaction preserves original bytes, mode, and timestamps. On
normal completion, exceptions, `SIGINT`, or `SIGTERM`, it restores the source,
deletes the generated object, and rebuilds the original object. Deleting the
object matters: restored timestamps could otherwise make Ninja keep stale
candidate bytes.

`try` finds a function spelling; it does not establish whole-object or linked
exactness.

### `diagnose` — classify a mismatch

Resolve paths from a configured objdiff unit:

```sh
python3 "$MWDIFF" diagnose \
  --unit d_a_example --fn '<mangled_fn>'
```

Or pass objects directly:

```sh
python3 "$MWDIFF" diagnose \
  --target <target.o> --mine <mine.o> --fn '<mangled_fn>'
```

Useful options:

- `--project <path>`: project root, default `.`.
- `--version <id>`: require a specific configured version.
- `--unit <name-or-unique-suffix>`: unit from `objdiff.json`.
- `--target` and `--mine`: explicit alternative to `--unit`.
- `--json`: emit one machine-readable document.

Instruction diagnosis can report:

| Classification | Meaning |
|---|---|
| `exact` | Normalized instructions match. |
| `relocation-alias` | Only relocation symbol names differ. |
| `global-register-permutation` | One consistent register renaming explains the diff. |
| `local-register-allocation` | Opcodes align but local register choices differ. |
| `scheduling` | Memory operations use different placement or operands. |
| `operand-order` | Opcodes align but non-memory operands differ. |
| `branch-shape` | Control-flow instruction shape differs. |
| `call-wrapper` | Call operands or wrapper selection differ. |
| `semantic-instruction` | No safer structural classification applies. |

Project-aware search scoring can additionally report `constant-pool` or
`data-layout` when function instructions align but object sections do not.
Diagnosis suggests only mutation families relevant to the observed shape.

### `search` — generate and rank MWCC source spellings

`search` requires a configured unit with source metadata in `objdiff.json`:

```sh
python3 "$MWDIFF" search \
  --unit d_a_example \
  --fn '<mangled_fn>' \
  --line 120:124 \
  --families bool,compare,local-form \
  --depth 2
```

`--line` is one line (`120`) or an inclusive range (`120:124`). The selected
text is the only source region mutated. Family names are comma-separated
without spaces.

#### Mutation families

| Family | Bounded transformation |
|---|---|
| `bool` | Toggle direct, `!= FALSE`, `== TRUE`, and `!= 0` conditions. |
| `compare` | Comparison-oriented aliases of boolean spellings. |
| `cast` | Vary explicit `s8`, `u8`, and plain `char` casts. |
| `load` | Vary direct `u8` locals and volatile byte reads. |
| `reassociate` | Permute and parenthesize three-term additions. |
| `switch` | Add the next empty numeric case. |
| `wrapper` | Replace a recognized direct switch query with its actor wrapper. |
| `local-form` | Introduce an `auto` local form for a recognized assignment. |
| `return` | Try direct `TRUE` and `FALSE` returns. |
| `evaluation-order` | Use the bounded reassociation transformations. |
| `version` | Vary the operator of an existing `VERSION_*` preprocessor guard. |

Unsupported source shapes simply generate no candidate. Search is deliberately
bounded; it is not a general C++ synthesizer.

#### Search controls

| Option | Behavior |
|---|---|
| `--project <path>` | Project root; default `.`. |
| `--version <id>` | Select one configured version. |
| `--depth {1,2}` | Apply one mutation or compose up to two; default 1. |
| `--max-builds <n>` | Hard build-attempt limit; default 100. |
| `--beam-width <n>` | Number of best parents kept for depth two; default 5. |
| `--no-stop` | Continue after an exact candidate. |
| `--apply` | Retain the best candidate only when the object is exact. |
| `--verify` | After applying exact source, verify requested versions and REL SHA. Requires `--apply`. |
| `--verify-version <id>` | Version to verify; repeat for multiple versions. |
| `--json` | Emit one JSON result document. |
| `--prove` | Reject supported candidates proven behavior-changing. |
| `--proof-timeout-ms <n>` | Per-proof Z3 timeout; default 5000. |

#### Build and scoring flow

For each candidate, search:

1. writes the complete candidate source inside a restoration transaction;
2. builds the configured object with Ninja;
3. asks objdiff for the selected function and whole-object report measures;
4. diagnoses normalized DTK differences;
5. ranks exactness, mismatch class, changed calls, changed memory operations,
   and changed-line count; and
6. optionally invokes the proof oracle for non-exact candidates.

Depth-two search keeps only the best `--beam-width` depth-one parents. Build
failures are counted and skipped. Human output prints the best candidate and a
unified source patch; `--json` returns search, proof, verification, and
unavailable-version data in one document.

#### Cache

Search stores scores in `.cache/mwdiff/`. Keys include:

- compiler binary hash;
- compiler flags and Ninja command material;
- context or source bytes;
- candidate source;
- configured version; and
- function name.

A cached score can skip compilation and scoring. With `--prove`, a cached
non-exact candidate is rebuilt first so proof always examines candidate bytes,
not the current baseline object.

#### Apply and cross-version verification

`--apply` retains source only when all configured matchable functions, objects,
and relevant sections are 100%. Otherwise the source and original object are
restored.

`--apply --verify` temporarily runs the project's `configure.py`, regenerates
`build.ninja`, builds each report and linked REL, checks function/code/data
percentages and expected REL SHA, then restores and regenerates the original
configuration in a `finally` path.

Without `--verify-version`, verification uses locally available versions.
Configured versions without real local disc input are listed as unavailable;
they are not claimed as verified.

### `prove` — check supported PowerPC equivalence

Install Z3 only for proof commands:

```sh
uv run --with z3-solver python3 "$MWDIFF" prove \
  <target.o> <mine.o> '<mangled_fn>'
```

JSON output:

```sh
uv run --with z3-solver python3 "$MWDIFF" prove \
  <target.o> <mine.o> '<mangled_fn>' --json
```

`--timeout-ms <n>` sets the positive solver timeout per proof; the default is
5000 milliseconds. `--json` emits one machine-readable result document.

Possible results:

- `equivalent`: no modeled input produces different observable behavior.
- `different`: a modeled difference exists; output includes a GPR
  counterexample.
- `unknown`: the function or potential difference exceeds the sound model.

The oracle parses raw DTK lines and symbolically executes supported acyclic
integer paths. It models integer arithmetic, logical operations, shifts,
rotates/masks, comparisons, condition-register branches, big-endian byte/
halfword/word memory, and direct external calls.

Observable behavior includes:

- ABI-visible live GPRs: `r1`, `r2`, `r3`, `r4`, `r13`, and `r14`–`r31`;
- all condition-register fields;
- memory;
- external-call targets and arguments.

External call outputs are uninterpreted functions of the target, stack/global
context (`r1`, `r2`, `r13`), argument registers, and memory. This supports
proofs when call context and effects align without pretending to know callee
semantics.

The oracle returns `unknown` for floating-point instructions, loops,
unsupported instructions or CR behavior, unresolved relocations/call targets,
incompatible call traces, solver timeouts, and witnesses that depend on the
unconstrained external-call model. These are safety boundaries, not errors to
suppress.

`search --prove` rejects only `different`. It retains and labels `unknown`
candidates because unknown is not evidence of changed behavior.

## Reading output

- `EXACT`: the compared normalized function or configured object matches at
  the command's stated level.
- `N diff lines`: normalized instruction differences remain.
- `BUILD FAIL`: the candidate did not compile; the final 200 output characters
  are shown.
- `EXTRA in mine`: candidate-only symbols, often weak dead-strip candidates.
- `REJECTED {counterexample}`: `search --prove` found a modeled behavioral
  difference.
- `proof unknown`: the candidate exceeded the oracle's sound scope.
- `unavailable: <version>`: configured version lacks real local disc input.

## Exit codes

- `0`: exact or equivalent.
- `1`: differences or unknown remain.
- `2`: usage, dependency, or tool error.

This makes commands suitable for scripts without conflating unknown with
success.

## Safety and recovery

Both `try` and `search` mutate source only inside `SourceTransaction`.
Restoration covers bytes, permissions, timestamps, and installed signal
handlers. A signal received during mutation/restoration is delivered only
after restoration finishes.

After candidate attempts, mwdiff deletes the generated object before rebuilding
the original source. If that rebuild fails, the command fails and leaves the
candidate object absent rather than silently exposing stale output.

Search applies only an exact winner requested with `--apply`. Cross-version
verification restores the original selected version even when a configured
build fails.

## The linked checksum is authoritative

Always finish with the project's real linked checksum command, for example:

```sh
ninja
build/tools/dtk shasum -q -c config/<version>/build.sha1
```

Known reasons function or object tools can be insufficient:

1. **Benign relocation naming:** a named constant and an anonymous DTK section
   symbol may refer to byte-identical data.
2. **Symbol ordering:** identical section bytes or percentages can hide
   `.data`/`.bss` symbol-order differences that change linked relocations.
3. **Dead stripping:** weak inline copies may appear in an object but disappear
   from the linked module.
4. **Unavailable versions:** local success says nothing about versions that
   were not built from real inputs.

When objdiff is 100% but the linked checksum fails, compare raw object sections,
not a linked `.plf` that includes runtime symbols.

## Troubleshooting

### DTK not found

Build the project tools or point at DTK:

```sh
DTK=/absolute/path/to/dtk python3 "$MWDIFF" diff <target.o> <mine.o>
```

### objdiff-cli not found

Set the executable used by project-aware scoring:

```sh
OBJDIFF=/absolute/path/to/objdiff-cli python3 "$MWDIFF" diagnose \
  --unit d_a_example --fn '<mangled_fn>'
```

### Unit not found or ambiguous

Use the exact `name` from `objdiff.json`, or a suffix unique within the selected
version. Pass `--version` when the configuration contains multiple versions.

### Missing Z3

Only proof paths require it. Run:

```sh
uv run --with z3-solver python3 "$MWDIFF" prove \
  <target.o> <mine.o> '<mangled_fn>'
```

### Search generates no candidates

Confirm the inclusive `--line` range contains the source shape recognized by
the selected families. Start with the families suggested by `diagnose`; do not
increase depth before a depth-one family produces a candidate.

### Original rebuild fails

Treat this as a failed run. The source was restored, and mwdiff deliberately
removed the generated object before the baseline rebuild. Fix the project build
before retrying.

## Platform scope

The parser and mutations target MWCC/PowerPC output from DTK-based GameCube and
Wii projects. They are not an N64 `asm-differ` replacement and do not claim
general C++ synthesis or whole-program equivalence.
