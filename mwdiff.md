# mwdiff.py — per-function MWCC matching helper

A small helper for the inner loop of matching decompilation: disassemble two
objects with `dtk`, diff them **function by function** with the cosmetic noise
normalized away, and (the useful part) **brute-force which C phrasing MWCC
emits** by substituting snippets, rebuilding, and reporting the diff.

It is a companion to `objdiff`, not a replacement. `objdiff` is the polished
diff viewer and CI gate; `mwdiff try` is a scriptable way to test 10–20 C
variants of one function in a couple of seconds each.

## Requirements

- A configured build: `python configure.py --version GZLP01 && ninja`
- `dtk` at `build/tools/dtk` (or set `$DTK`)
- The **target** object (the expected/original split object) and **your** built
  object. For an actor `d_a_foo`:
  - target: `build/GZLP01/d_a_foo/obj/d/actor/d_a_foo.o`
  - yours:  `build/GZLP01/src/d/actor/d_a_foo.o`

Run everything from the repo (or worktree) root.

## Commands

### `diff` — per-function summary

```
python3 tools/mwdiff.py diff <target.o> <mine.o>
```

Prints one line per function that still differs, with a normalized diff-line
count, then a list of symbols present in your object but not the target
(usually weak/inline copies that dead-strip — harmless). If everything lines
up it prints `all functions EXACT`.

```
$ python3 tools/mwdiff.py diff \
    build/GZLP01/d_a_obj_foo/obj/d/actor/d_a_obj_foo.o \
    build/GZLP01/src/d/actor/d_a_obj_foo.o
Create__Q29daObjFoo5Act_cFv: 2 diff lines
Execute__Q29daObjFoo5Act_cFv: 8 diff lines
EXTRA in mine (deadstrip candidates): __dt__4cXyzFv
```

### `show` — full diff of one function

```
python3 tools/mwdiff.py show <target.o> <mine.o> <mangled_fn>
```

A unified `--- target / +++ mine` diff of the normalized instructions for one
function. Copy the mangled name straight from `diff`'s output.

```
$ python3 tools/mwdiff.py show <target.o> <mine.o> Execute__Q29daObjFoo5Act_cFv
--- target
+++ mine
@@ ...
-and. r0, r3, r0
+and. r0, r0, r3
```

### `try` — brute-force C variants of one function

```
python3 tools/mwdiff.py try <src.cpp> <obj_to_build> <target.o> <mangled_fn> <variants.py>
```

For each candidate it: substitutes the snippet into the source, runs
`ninja <obj_to_build>`, disassembles, and prints the diff-line count (or
`EXACT`). The source file is **always restored** afterward, even on error, so
your working copy is untouched.

`variants.py` defines two names:

- `BASE` — the exact snippet currently in the source to be replaced.
- `VARIANTS` — a dict of `name -> replacement snippet`.

Example `variants.py` (testing how MWCC wants a bool guard written):

```python
BASE = """    bool not_set = !dComIfGs_isEventBit(0x2A20);
    if (!not_set) {"""

VARIANTS = {
    "eq0":  """    bool not_set = dComIfGs_isEventBit(0x2A20) == 0;
    if (not_set) {""",
    "ne":   """    bool not_set = dComIfGs_isEventBit(0x2A20) != 0;
    if (not_set) {""",
}
```

```
$ python3 tools/mwdiff.py try \
    src/d/actor/d_a_obj_foo.cpp \
    build/GZLP01/src/d/actor/d_a_obj_foo.o \
    build/GZLP01/d_a_obj_foo/obj/d/actor/d_a_obj_foo.o \
    createInit__11daFoo_cFv  /tmp/variants.py
eq0: EXACT
ne:  5 ['-srwi r30, r0, 5', '+srwi r3, r0, 5', ...]
```

Pick the `EXACT` (or lowest-count) variant and apply it for real.

## Reading the output

- `EXACT` / `all functions EXACT` — normalized instructions match. Good sign,
  **not** proof (see caveats).
- `N diff lines` — N real instruction differences after normalization.
- `EXTRA in mine` — symbols only in your object. Weak inline copies
  (`__dt__4cXyzFv`, `std::sqrtf` locals, base-class virtuals) dead-strip at
  link and are harmless; verify with `grep -c` on the linked `.plf` if unsure.

Normalization strips: `/* addr hex */` columns, `.L` label numbers, `@NNNN`
and `$NNNN` compiler counters, and `...rodata.0` / `...data.0` anonymous
section symbols.

## Caveats — it is a guide, not the gate

The authoritative check is always the REL SHA:

```
ninja && build/tools/dtk shasum -q -c config/GZLP01/build.sha1
```

`mwdiff` can be misleading in two known ways, both resolved by the SHA:

1. **Benign residual naming.** A named const used as a float-pool base
   (e.g. `M_arcname` vs dtk's `...rodata.0`) shows as a diff line but is
   byte-identical. If the SHA matches, it was noise.
2. **objdiff/mwdiff 100% ≠ SHA match.** Neither compares `.data`/`.bss`
   **symbol ordering** when section sizes are equal. If the SHA fails while
   `diff` says EXACT, byte-compare the raw sections of your `.o` vs the target
   `.o` (parse the ELF section headers) — *not* the `.plf`, which is linked and
   pulls in runtime symbols. A common fix is reordering file-scope statics vs
   function-local statics.

## Notes

- MWCC/PowerPC and `dtk elf disasm` output are assumed; this is for GC/Wii
  (`dtk`-based) projects, not N64 (use `asm-differ`/`diff.py` there).
- `$DTK` overrides the `dtk` path (default `build/tools/dtk`).
