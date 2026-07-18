# mwdiff Standalone Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the verified compiler-guided search and optional PowerPC equivalence oracle from TWW commit `85c5b82e` in `999sian/mwdiff`, with accurate standalone documentation and tests.

**Architecture:** Keep the existing flat standalone layout. `mwdiff.py` owns the CLI, diagnosis, mutation search, caching, application, and verification; `ppc_equiv.py` is an import-on-demand Z3 oracle. The README remains a concise entry point and `mwdiff.md` becomes the complete operational reference.

**Tech Stack:** Python 3.10+ standard library, optional `z3-solver`, unittest, DTK, objdiff-cli, Ninja, git.

## Global Constraints

- Copy runtime and test behavior exactly from `../tww/tools/` at verified TWW commit `85c5b82e`; do not redesign it during extraction.
- Keep `z3-solver` optional and lazily imported; `diff`, `show`, `try`, `diagnose`, and exact `search` paths must work without it.
- Add no packaging, dependency manager, CI workflow, retry layer, telemetry, or generalized ISA/compiler abstraction.
- Preserve conservative proof results: unsupported or call-model-dependent cases return `unknown`, never `equivalent`.
- Documentation examples use generic dtk-template paths and state that linked REL SHA remains authoritative.
- Publish to `999sian/mwdiff` `main` only after all verification gates pass.

---

### Task 1: Sync the Verified Runtime and Behavioral Tests

**Files:**
- Modify: `mwdiff.py`
- Create: `ppc_equiv.py`
- Modify: `test_mwdiff.py`
- Create: `test_ppc_equiv.py`

**Interfaces:**
- Consumes: exact file contents from `../tww/tools/mwdiff.py`, `../tww/tools/ppc_equiv.py`, `../tww/tools/test_mwdiff.py`, and `../tww/tools/test_ppc_equiv.py` at commit `85c5b82e`.
- Produces: standalone commands `diff`, `show`, `try`, `diagnose`, `search`, and `prove`; optional module function `ppc_equiv.prove(target_lines, candidate_lines, timeout_ms=5000) -> ProofResult`.

- [ ] **Step 1: Confirm the extraction source**

Run from `../tww`:

```bash
git rev-parse HEAD
```

Expected: `85c5b82e...` or a descendant whose four `tools/` files are unchanged from that commit.

- [ ] **Step 2: Copy the verified files byte-for-byte**

Use the file Read and Write tools to replace/create these mappings without formatting or refactoring:

```text
../tww/tools/mwdiff.py       -> mwdiff.py
../tww/tools/ppc_equiv.py    -> ppc_equiv.py
../tww/tools/test_mwdiff.py  -> test_mwdiff.py
../tww/tools/test_ppc_equiv.py -> test_ppc_equiv.py
```

- [ ] **Step 3: Verify byte equality with the extraction source**

Run:

```bash
cmp mwdiff.py ../tww/tools/mwdiff.py
cmp ppc_equiv.py ../tww/tools/ppc_equiv.py
cmp test_mwdiff.py ../tww/tools/test_mwdiff.py
cmp test_ppc_equiv.py ../tww/tools/test_ppc_equiv.py
```

Expected: no output and exit status 0 for all four comparisons.

- [ ] **Step 4: Run the complete standalone suite with Z3**

Run:

```bash
uv run --with z3-solver python3 -m unittest discover -p 'test_*.py' -v
```

Expected: `Ran 73 tests` and `OK`.

- [ ] **Step 5: Verify the mandatory-dependency boundary**

Run:

```bash
PYTHONNOUSERSITE=1 python3 -c 'import mwdiff; print(sorted(mwdiff.MUTATION_FAMILIES))'
PYTHONNOUSERSITE=1 python3 -m unittest test_mwdiff.TestProofCli.test_exact_search_bypasses_oracle -v
```

Expected: import succeeds without Z3 and the exact-search regression passes.

- [ ] **Step 6: Commit the extracted implementation**

```bash
git add mwdiff.py ppc_equiv.py test_mwdiff.py test_ppc_equiv.py
git commit -m "feat: add compiler-guided search and PowerPC proof"
```

---

### Task 2: Rewrite the README as the Standalone Entry Point

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: command names and dependency behavior from Task 1.
- Produces: a short first-use path that directs advanced users to `mwdiff.md`.

- [ ] **Step 1: Replace the outdated three-command overview**

Write a concise README with these exact sections and command table:

```markdown
## Requirements

- Python 3.10+
- DTK (`$DTK` or `./build/tools/dtk`)
- Ninja for source-variant builds
- objdiff-cli for project-aware diagnosis and search
- Optional: `z3-solver` for `prove` and `search --prove`

## Commands

| Command | Purpose |
|---|---|
| `diff` | Summarize normalized per-function object differences. |
| `show` | Print one normalized function diff. |
| `try` | Compile explicit source variants. |
| `diagnose` | Classify a configured unit's mismatch and suggest mutation families. |
| `search` | Generate, compile, score, and optionally apply bounded MWCC source mutations. |
| `prove` | Prove supported acyclic integer PowerPC functions equivalent or return a counterexample/unknown. |
```

Include this minimal workflow:

```sh
python3 mwdiff.py diagnose --unit d_a_example --fn '<mangled_fn>'
python3 mwdiff.py search --unit d_a_example --fn '<mangled_fn>' \
  --line 120:124 --families bool,compare,local-form --depth 2
```

Include optional proof setup:

```sh
uv run --with z3-solver python3 mwdiff.py prove \
  <target.o> <mine.o> '<mangled_fn>' --json
```

Link to `mwdiff.md` for complete options, mutation families, verification, safety, and limitations.

- [ ] **Step 2: Verify every advertised command exists**

Run:

```bash
python3 mwdiff.py --help
```

Expected: the positional command list contains `diff,show,try,diagnose,prove,search`.

- [ ] **Step 3: Commit the README**

```bash
git add README.md
git commit -m "docs: update standalone mwdiff quick start"
```

---

### Task 3: Expand the Detailed Operational Guide

**Files:**
- Modify: `mwdiff.md`

**Interfaces:**
- Consumes: actual CLI help and safety behavior from Task 1.
- Produces: the authoritative human-readable command and limitation reference.

- [ ] **Step 1: Preserve and update existing command documentation**

Keep the useful `diff`, `show`, `try`, output-reading, and REL-SHA caveat material. Update `try` safety text to state that source bytes/metadata are restored and the original object is forcibly rebuilt after interruption or failure.

- [ ] **Step 2: Add project-aware diagnosis documentation**

Add a `diagnose` section with:

```sh
python3 mwdiff.py diagnose --unit d_a_example --fn '<mangled_fn>'
```

Document the classifications `exact`, `relocation-alias`, `global-register-permutation`, `local-register-allocation`, `scheduling`, `operand-order`, `branch-shape`, `call-wrapper`, `data-layout`, and `semantic-instruction`, plus suggested mutation families.

- [ ] **Step 3: Add bounded search documentation**

Document `--line`, `--families`, `--depth`, `--max-builds`, `--beam-width`, `--no-stop`, `--apply`, `--verify`, repeatable `--verify-version`, `--json`, `--prove`, and `--proof-timeout-ms`.

List the implemented families exactly:

```text
bool, compare, cast, load, reassociate, switch, wrapper,
local-form, return, evaluation-order, version
```

State that `--apply` retains only a whole-object exact candidate and `--verify` checks functions/code/data plus linked REL SHA across requested locally available versions.

- [ ] **Step 4: Add proof semantics and limits**

Add examples for plain and JSON output. Define `equivalent`, `different`, and `unknown`. State that observable outputs include live ABI GPRs, condition registers, memory, and external-call traces. State that floating point, loops, unresolved relocations/calls, unsupported CR behavior, and call-model-dependent differences return `unknown`.

- [ ] **Step 5: Add cache and failure-recovery notes**

Document `.cache/mwdiff`, its compiler/flags/context/candidate/version/function key material, cached non-exact rebuild-before-proof behavior, transactional source restoration, forced original-object rebuild, and original-version restoration after cross-version verification.

- [ ] **Step 6: Check the guide against CLI help**

Run:

```bash
python3 mwdiff.py diagnose --help
python3 mwdiff.py search --help
python3 mwdiff.py prove --help
```

Expected: every documented option appears in help and no help option is omitted from the relevant section.

- [ ] **Step 7: Commit the detailed guide**

```bash
git add mwdiff.md
git commit -m "docs: document search, verification, and proof"
```

---

### Task 4: Record Lessons, Verify, and Publish

**Files:**
- Modify only if verification finds a real defect: `mwdiff.py`, `ppc_equiv.py`, `test_mwdiff.py`, or `test_ppc_equiv.py`
- Local memory: one durable lesson describing extraction, mutation restoration, and proof-soundness boundaries

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: verified `999sian/mwdiff` `main` and a reusable local lesson.

- [ ] **Step 1: Run the final complete suite**

```bash
uv run --with z3-solver python3 -m unittest discover -p 'test_*.py' -v
```

Expected: `Ran 73 tests` and `OK`.

- [ ] **Step 2: Run Z3-free and CLI smoke gates**

```bash
PYTHONNOUSERSITE=1 python3 -c 'import mwdiff'
PYTHONNOUSERSITE=1 python3 -m unittest test_mwdiff.TestProofCli.test_exact_search_bypasses_oracle -v
python3 mwdiff.py --help
python3 mwdiff.py diagnose --help
python3 mwdiff.py search --help
python3 mwdiff.py prove --help
git diff --check
```

Expected: imports and tests pass, help exits 0, and `git diff --check` prints nothing.

- [ ] **Step 3: Fix only demonstrated standalone defects**

If a gate fails, reproduce it with the narrowest command, add or strengthen one behavioral regression, apply the minimum root-cause fix, rerun that regression, then rerun Steps 1-2. Do not alter verified behavior for style or speculative portability.

- [ ] **Step 4: Record the reusable lesson locally**

Use the local `learn` tool to record:

```text
When extracting mwdiff from a host decomp repository, copy the verified runtime and behavioral tests together. Source restoration must be paired with generated-object invalidation before Ninja rebuilds, because restored mtimes can otherwise preserve a stale candidate object. Symbolic equivalence must compare ABI-visible registers (including r4), CR, memory, and call traces, and return unknown for unsupported or external-call-dependent cases.
```

- [ ] **Step 5: Commit a regression fix only if Step 3 changed files**

```bash
git add mwdiff.py ppc_equiv.py test_mwdiff.py test_ppc_equiv.py
git commit -m "fix: close standalone mwdiff regression"
```

Skip this commit when no files changed.

- [ ] **Step 6: Push the verified main branch**

```bash
git push origin main
```

Expected: GitHub reports `main` updated successfully at `https://github.com/999sian/mwdiff`.
