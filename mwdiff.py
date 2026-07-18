#!/usr/bin/env python3
"""
mwdiff.py - per-function asm diff helper for dtk-based (MWCC) matching decomp.

Compares two object files by disassembling each with `dtk elf disasm` and
diffing function-by-function, normalising away cosmetic noise (comments,
local label names, `@NNNN`/`$NNNN` compiler counters, anonymous section
symbols, and the address columns) so only *real* instruction differences show.

Also includes `try` - a brute-forcer: substitute each candidate snippet into
a source file, rebuild one object with ninja, and report the diff count of a
single function. This is the loop that makes "guess the C that MWCC wants"
fast.

Usage:
  mwdiff.py diff  <target.o> <mine.o>
  mwdiff.py show  <target.o> <mine.o> <mangled_fn>
  mwdiff.py try   <src.cpp> <obj_to_build> <target.o> <mangled_fn> <variants.py>

`dtk` is found via $DTK or ./build/tools/dtk.
Exit status: 0 = all exact, 1 = differences found, 2 = usage/tool error.
"""
import argparse
import difflib
import os
import re
import subprocess
import sys
import tempfile

DTK = os.environ.get("DTK", "build/tools/dtk")

# Pre-compiled normalisation patterns (order matters).
_NORM = [
    (re.compile(r"/\*.*?\*/"), ""),           # address / hex columns
    (re.compile(r"\.L[0-9a-fA-F_]+:\s*"), ""),  # local label names
    (re.compile(r"@\d+"), "@N"),              # float/string pool counters
    (re.compile(r"\$\d+"), "$N"),             # static-local counters
    (re.compile(r"\.\.\.(?:ro)?data\.0"), "@N"),  # anonymous section symbols
]


def die(msg, code=2):
    print(f"mwdiff: {msg}", file=sys.stderr)
    sys.exit(code)


def disasm(obj):
    """Return {mangled_fn_name: [instruction lines]} for an object file."""
    if not os.path.isfile(obj):
        die(f"no such object file: {obj}")
    fd, out = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        r = subprocess.run([DTK, "elf", "disasm", obj, out],
                           capture_output=True, text=True)
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
    out = []
    for l in lines:
        for pat, repl in _NORM:
            l = pat.sub(repl, l)
        l = l.strip()
        if l and not l.startswith("."):
            out.append(l)
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


def cmd_try(args):
    """variants.py defines: BASE (str to replace) and VARIANTS (dict name->str)."""
    ns = {}
    with open(args.variants) as f:
        exec(f.read(), ns)
    try:
        base, variants = ns["BASE"], ns["VARIANTS"]
    except KeyError as e:
        die(f"{args.variants} must define {e.args[0]}")
    with open(args.src) as f:
        orig = f.read()
    if base not in orig:
        die(f"BASE snippet not found in {args.src}")
    tgt = resolve_fn(disasm(args.target), args.fn, args.target)
    width = max(map(len, variants), default=0)
    best = None
    try:
        for name, repl in variants.items():
            with open(args.src, "w") as f:
                f.write(orig.replace(base, repl))
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
            print(f"{name:<{width}}  {'EXACT' if not d else len(d)}  {d[:6]}")
            if not d and args.stop_on_exact:
                break
    finally:
        with open(args.src, "w") as f:
            f.write(orig)  # always restore
        subprocess.run(["ninja", args.obj], capture_output=True)  # rebuild original
    if best:
        print(f"\nbest: {best[0]} ({'EXACT' if best[1] == 0 else f'{best[1]} diff lines'})")
    return 0 if best and best[1] == 0 else 1
    if args.show_best and best and best[1] > 0:
        print(f"\n--- Showing best variant: {best[0]} ---")
        # Need to construct a mock args object for cmd_show
        from argparse import Namespace
        show_args = Namespace(target=args.target, mine=args.obj, fn=args.fn)
        cmd_show(show_args)
    return 0 if best and best[1] == 0 else 1


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

    args = p.parse_args()
    sys.exit(args.run(args))


if __name__ == "__main__":
    main()
