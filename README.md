# mwdiff

Per-function asm diff helper for [decomp-toolkit](https://github.com/encounter/decomp-toolkit) (dtk) based matching decomps — GameCube/Wii projects built with MWCC (Wind Waker, Twilight Princess, Pikmin, Metroid Prime, and other dtk-template projects).

It compares two object files by disassembling each with `dtk elf disasm` and diffing function-by-function, normalising away cosmetic noise (address columns, local label names, `@NNNN`/`$NNNN` compiler counters, anonymous section symbols) so only *real* instruction differences show.

The distinctive piece is `try`: a brute-forcer that substitutes each candidate C snippet into a source file, rebuilds one object with ninja, and reports the diff count of a single function — the loop that makes "guess the C that MWCC wants" fast.

## Requirements

- Python 3.8+ (stdlib only)
- `dtk` — found via `$DTK`, or `./build/tools/dtk` (the dtk-template default)
- `ninja` (for the `try` subcommand)

Run it from your decomp repo root.

## Usage

### `diff` — summarise a whole translation unit

```sh
mwdiff.py diff build/GZLE01/obj/d/d_example.o build/obj/d/d_example.o
```

Prints a per-function diff-line count, sorted smallest-first (the almost-matched functions worth attacking next are at the top). Functions missing from your object are flagged `MISSING in mine`, and functions only in yours are listed as deadstrip candidates. Prints `all N functions EXACT` when done.

### `show` — full diff of one function

```sh
mwdiff.py show <target.o> <mine.o> '<mangled_fn>'
```

Unified diff of the normalised disassembly. Unknown function names get fuzzy-match suggestions — handy with long MWCC manglings.

### `try` — brute-force source variants

```sh
mwdiff.py try src/d/d_example.cpp build/obj/d/d_example.o \
    build/GZLE01/obj/d/d_example.o '<mangled_fn>' variants.py
```

`variants.py` defines two names:

```py
BASE = """
    if (a < b)
        a = b;
"""

VARIANTS = {
    "ternary":  "    a = a < b ? b : a;\n",
    "max-call": "    a = MAX(a, b);\n",
    "orig":     BASE,
}
```

For each variant, `BASE` is replaced in the source file, the object is rebuilt with ninja, and the function's diff count is printed. Stops at the first `EXACT` (pass `--no-stop` to test everything). The original source is always restored — and rebuilt — afterwards, even on Ctrl-C.

## Exit codes

`0` = all exact · `1` = differences found · `2` = usage or tool error — safe to use in scripts and CI.

## Other tools

For interactive per-function diffing with a UI, see [objdiff](https://github.com/encounter/objdiff). mwdiff is the scriptable/batch complement: one-shot TU summaries and automated variant testing.

## License

MIT
