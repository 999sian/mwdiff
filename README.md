# mwdiff

Per-function assembly diffing, compiler-guided source search, and optional
PowerPC equivalence checking for
[decomp-toolkit](https://github.com/encounter/decomp-toolkit) projects built
with MWCC.

`mwdiff` is a scriptable companion to
[objdiff](https://github.com/encounter/objdiff). It normalizes cosmetic DTK
disassembly differences, helps test the C spellings MWCC may want, and can
reject supported behavior-changing candidates with an optional Z3-backed
oracle.

## Requirements

- Python 3.10+
- [DTK](https://github.com/encounter/decomp-toolkit), found through `$DTK` or
  `./build/tools/dtk`
- Ninja for source-variant builds
- `objdiff.json` for project-aware unit resolution
- `objdiff-cli`, found through `$OBJDIFF` or `./build/tools/objdiff-cli`, for
  search scoring
- Optional: `z3-solver` for `prove` and `search --prove`
- Only for `reconstruct`: a running GhidrAssistMCP Streamable HTTP endpoint
  (`--ghidra-mcp-url`) and an executable model wrapper (`--llm-cmd`) that reads
  one JSON document on stdin and writes one JSON document on stdout. Automatic
  target import into a disposable Ghidra program needs the MCP server's
  host-file import permission; without it, pre-import a disposable target and
  pass its exact project path with `--ghidra-program`.

Run the script from the root of the decomp project being analyzed:

```sh
python3 /path/to/mwdiff/mwdiff.py --help
```

## Commands

| Command | Purpose |
|---|---|
| `diff` | Summarize normalized per-function object differences. |
| `show` | Print one normalized function diff. |
| `try` | Compile explicit source variants. |
| `diagnose` | Classify a configured unit's mismatch and suggest mutation families. |
| `search` | Generate, compile, score, and optionally apply bounded MWCC source mutations. |
| `prove` | Prove supported acyclic integer PowerPC functions equivalent, or return a counterexample or `unknown`. |
| `reconstruct` | Bounded Ghidra/LLM/compiler feedback loop for one configured unit. |
| `bench` | Score idiom fingerprint/family detection offline (no build). |

### Compare objects

```sh
python3 /path/to/mwdiff/mwdiff.py diff <target.o> <mine.o>
python3 /path/to/mwdiff/mwdiff.py show <target.o> <mine.o> '<mangled_fn>'
```

### Diagnose and search a configured unit

`diagnose` and `search` resolve units from the decomp project's `objdiff.json`:

```sh
python3 /path/to/mwdiff/mwdiff.py diagnose \
  --unit d_a_example --fn '<mangled_fn>'

python3 /path/to/mwdiff/mwdiff.py search \
  --unit d_a_example --fn '<mangled_fn>' \
  --line 120:124 --families bool,compare,local-form --depth 2
```

Search changes only the selected source range, rebuilds the configured object,
and ranks candidates with objdiff plus normalized DTK output. Add `--apply` to
retain a whole-object exact candidate. Add `--apply --verify` to check locally
available versions, including linked REL SHA values when configured.
Verification currently supports configured REL units only; executable/DOL
units are rejected before source mutation.

### Prove supported functions

Z3 remains optional:

```sh
uv run --with z3-solver python3 /path/to/mwdiff/mwdiff.py prove \
  <target.o> <mine.o> '<mangled_fn>' --json
```

The result is `equivalent`, `different` with a counterexample, or conservative
`unknown`. `search --prove` rejects only candidates proven different; unknown
candidates remain eligible and are labeled.

### Reconstruct a configured unit

`reconstruct` drives one configured unit toward an exact match in a bounded
loop: it gathers Ghidra structural evidence, asks the model wrapper for Ghidra
metadata and source edits, compiles each candidate with the real build, scores
it with objdiff, and optionally checks the linked REL SHA:

```sh
python3 /path/to/mwdiff/mwdiff.py reconstruct \
  --project . \
  --version GZLP01 \
  --unit d_a_example \
  --ghidra-mcp-url http://127.0.0.1:8080/mcp \
  --llm-cmd ./model-wrapper \
  --max-rounds 8 \
  --max-builds 100 \
  --apply
```

The run is fully automatic; it never stops for rename, type, or edit approval.
Source is retained only with `--apply` and only when the rebuilt object is
exact and every applicable linked gate passes; otherwise the exact patch is
printed and source is restored. Automatic Ghidra names, types, and prototypes
are hypotheses: only exact object measures and a matching linked checksum are
success, never a readable decompilation or an inferred name.

## Safety

Source mutations are transactional. Original source bytes and metadata are
restored after failures and interrupts, and the original object is forcibly
rebuilt so Ninja cannot preserve a stale candidate. An applied search result is
called exact only when configured whole-object function, code, and data
measures are all 100%.

The linked binary or REL checksum remains the authoritative matching gate.

## Full guide

See [mwdiff.md](mwdiff.md) for every command, mutation family, cache key,
verification rule, proof observable, unsupported case, and troubleshooting
note.

## Tests

```sh
python3 -m unittest discover -p 'test_*.py'
uv run --with z3-solver python3 -m unittest discover -p 'test_*.py'
```

## Exit codes

`0` = exact/equivalent · `1` = different or unknown · `2` = usage/tool error

## License

MIT
