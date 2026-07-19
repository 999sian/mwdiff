# Standalone mwdiff Sync Design

## Goal

Publish the completed compiler-guided MWCC search and optional PowerPC symbolic equivalence work in `999sian/mwdiff`, with enough documentation for users to install prerequisites, choose a command, understand safety guarantees, and interpret limitations without reading the implementation.

## Scope

The standalone repository will receive the finished `mwdiff.py`, `ppc_equiv.py`, `test_mwdiff.py`, and `test_ppc_equiv.py` from the verified TWW implementation at commit `85c5b82e`. Existing `diff`, `show`, and `try` behavior remains available. New public commands are `diagnose`, `search`, and `prove`.

This update will not add packaging, a dependency manager, CI configuration, generalized compiler support, floating-point symbolic execution, or loop reasoning. Z3 remains optional and is loaded only by `prove` and `search --prove`.

## Repository Layout

- `mwdiff.py`: CLI, DTK normalization and diffing, diagnosis, source mutations, project resolution, candidate scoring/cache, application, and cross-version verification.
- `ppc_equiv.py`: optional Z3-backed parser and equivalence checker for supported acyclic integer PowerPC functions.
- `test_mwdiff.py`: CLI, diagnosis, search, cache, restoration, and verification contracts.
- `test_ppc_equiv.py`: parser, integer, memory, call-model, control-flow, and proof-soundness contracts.
- `README.md`: concise installation, command selection, and quick-start examples.
- `mwdiff.md`: detailed command reference, search workflow, proof semantics, safety guarantees, and troubleshooting.

## Command and Data Flow

`diff` and `show` disassemble objects with DTK and normalize cosmetic labels, addresses, compiler counters, and anonymous section names before comparing functions. `try` evaluates explicit variants supplied by the user.

`diagnose` resolves a unit through `objdiff.json`, compares one function, classifies the mismatch shape, and suggests relevant mutation families. `search` applies bounded depth-one or depth-two mutations to one explicit source range, rebuilds the configured object with Ninja, scores it with objdiff plus normalized DTK output, and ranks candidates. Cache entries are keyed by compiler bytes, flags, context bytes, candidate source, version, and function.

`prove` disassembles two functions and sends their raw instruction streams to `ppc_equiv.py`. The oracle symbolically executes supported acyclic integer paths and returns `equivalent`, `different` with a counterexample, or `unknown`. `search --prove` rejects only candidates proven different; unknown candidates remain eligible and are labeled.

## Safety and Error Handling

All source mutations run inside a restoration transaction. Source bytes, metadata, and signal handlers are restored after success, failure, or interruption unless an exact candidate is explicitly applied. The generated object is invalidated and rebuilt after restoration so Ninja timestamps cannot leave a stale candidate object.

An applied candidate is considered exact only when configured whole-object function, code, and data measures are all 100%. Cross-version verification additionally checks the linked REL SHA and restores the original project configuration. Executable/DOL units are rejected before source mutation because linked-output verification currently supports configured REL units only. Build, restoration, and verification failures are surfaced with nonzero exits.

Unsupported instructions, loops, symbolic relocations, unresolved calls, incompatible call traces, and differences dependent on unconstrained external-call models produce `unknown`, never a false equivalence claim. Existing non-proof commands must import and run without Z3 installed.

## Documentation

`README.md` will stay short: requirements, six-command overview, one quick-start workflow, proof installation, and links to the detailed guide. `mwdiff.md` will document every command and option category, mutation families, scoring and cache behavior, apply/verify semantics, proof observables, unsupported cases, exit codes, and the authoritative REL-SHA caveat.

The documented minimum Python version will match the syntax used by the implementation. Examples will use generic dtk-template paths rather than TWW-only actor names where possible.

## Verification

Before publication:

1. Run all standalone tests with `z3-solver` available.
2. Confirm importing `mwdiff` and running an exact-search regression works with user site packages disabled and without requiring Z3.
3. Check top-level and subcommand help for all six commands.
4. Run `git diff --check` before commit.
5. Push the verified standalone update to `999sian/mwdiff` `main`.

## Acceptance Criteria

- The standalone repository starts from the verified implementation and behavioral tests at TWW commit `85c5b82e`, plus standalone release regressions found during review.
- Existing commands remain usable without new mandatory dependencies.
- The optional proof command has actionable missing-Z3 guidance and conservative `unknown` behavior.
- README and detailed guide describe the actual CLI and safety boundaries.
- The complete standalone test suite passes before push.
