from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from argparse import Namespace
import hashlib
import json
import os
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mwdiff import (SourceTransaction, cmd_diagnose, cmd_prove, cmd_search,
                    cmd_try, fn_diff, main, norm, prove_objects, replace_unique)
from mwdiff import diagnose_lines, infer_register_map, parse_instruction
from mwdiff import generate_candidates, source_range
from mwdiff import resolve_unit
from mwdiff import SourceCandidate
from mwdiff import (CandidateCache, ObjectScore, SearchResult, VerificationResult,
                    available_versions, cache_material, configured_versions,
                    expected_sha, score_object, search_candidates, verify_all,
                    verify_version)

class TestMwDiff(unittest.TestCase):
    def test_norm(self):
        # Test normalization patterns
        lines = [
            "/* 0x10 */ li r3, 0",
            ".L100: li r4, 1",
            "li r5, @123",
            "li r6, $456",
            "lis r7, ...rodata.0@h",
            "  addi r8, r8, 1  ", # whitespace
            ".section" # should be dropped
            ".section",
            "li r9, @0",
            "li r10, $0",
            "lis r11, ...data.0@h"
        ]
        # Expected:
        # li r3, 0
        # li r4, 1
        # li r5, @N
        # li r6, $N
        # lis r7, @N@h
        # addi r8, r8, 1
        expected = [
            "li r3, 0",
            "li r4, 1",
            "li r5, @N",
            "li r6, $N",
            "lis r7, @N@h",
            "addi r8, r8, 1",
            "li r9, @N",
            "li r10, $N",
            "lis r11, @N@h"
        ]
        self.assertEqual(norm(lines), expected)

    def test_norm_renumbers_local_labels_without_losing_branch_targets(self):
        target = [
            "beq .L_00000100",
            "b .L_00000200",
            ".L_00000100:",
            "li r3, 1",
            ".L_00000200:",
            "blr",
        ]
        shifted = [
            "beq .L_00000130",
            "b .L_00000230",
            ".L_00000130:",
            "li r3, 1",
            ".L_00000230:",
            "blr",
        ]
        wrong_target = shifted.copy()
        wrong_target[0] = "beq .L_00000230"

        self.assertEqual(norm(target), norm(shifted))
        self.assertNotEqual(norm(target), norm(wrong_target))

    def test_fn_diff(self):
        a = ["li r3, 0", "li r4, 1"]
        b = ["li r3, 0", "li r4, 2"]
        diff = fn_diff(a, b)
        # unified_diff produces lines like '- li r4, 1' and '+ li r4, 2'
        self.assertTrue(any("-li r4, 1" in line for line in diff), f"Missing -li r4, 1 in {diff}")
        self.assertTrue(any("+li r4, 2" in line for line in diff), f"Missing +li r4, 2 in {diff}")
        
        # Test identical
        self.assertEqual(fn_diff(a, a), [])

class TestSourceTransaction(unittest.TestCase):
    def test_replace_unique_rejects_zero_or_multiple_matches(self):
        with self.assertRaisesRegex(ValueError, "found 0"):
            replace_unique("alpha", "beta", "x")
        with self.assertRaisesRegex(ValueError, "found 2"):
            replace_unique("alpha alpha", "alpha", "x")
        self.assertEqual(replace_unique("alpha beta", "beta", "x"), "alpha x")

    def test_restores_bytes_mode_and_timestamp_after_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cpp"
            path.write_bytes(b"before\n")
            path.chmod(0o640)
            os.utime(path, ns=(1_600_000_000_000_000_000,) * 2)
            before = path.stat()
            read_bytes = Path.read_bytes

            def read_and_update_atime(read_path):
                data = read_bytes(read_path)
                os.utime(
                    read_path,
                    ns=(1_700_000_000_000_000_000, read_path.stat().st_mtime_ns),
                )
                return data

            with mock.patch.object(Path, "read_bytes", read_and_update_atime):
                with self.assertRaisesRegex(RuntimeError, "stop"):
                    with SourceTransaction(path) as source:
                        source.write_text("after\n")
                        raise RuntimeError("stop")

            after = path.stat()
            self.assertEqual(path.read_bytes(), b"before\n")
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(after.st_atime_ns, before.st_atime_ns)

    def test_sigterm_is_deferred_until_source_is_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cpp"
            path.write_text("before\n")
            previous = signal.getsignal(signal.SIGTERM)
            reached_after_signal = False

            with self.assertRaisesRegex(KeyboardInterrupt, "SIGTERM"):
                with SourceTransaction(path) as source:
                    source.write_text("after\n")
                    source.handle_signal(signal.SIGTERM, None)
                    reached_after_signal = True

            self.assertTrue(reached_after_signal)
            self.assertEqual(path.read_text(), "before\n")
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_signal_during_snapshot_is_deferred_and_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cpp"
            path.write_bytes(b"before\n")
            path.chmod(0o640)
            os.utime(path, ns=(1_600_000_000_000_000_000,) * 2)
            before = path.stat()
            previous = signal.getsignal(signal.SIGTERM)
            transaction = SourceTransaction(path)
            read_bytes = Path.read_bytes
            entered = False

            def interrupt_snapshot(read_path):
                handler = signal.getsignal(signal.SIGTERM)
                self.assertEqual(handler, transaction.handle_signal)
                handler(signal.SIGTERM, None)
                return read_bytes(read_path)

            with mock.patch.object(Path, "read_bytes", interrupt_snapshot), \
                    self.assertRaisesRegex(KeyboardInterrupt, "SIGTERM"):
                with transaction as source:
                    entered = True
                    source.write_text("after\n")

            after = path.stat()
            self.assertTrue(entered)
            self.assertEqual(path.read_bytes(), b"before\n")
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertEqual(after.st_atime_ns, before.st_atime_ns)
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_signal_during_restore_is_deferred_until_handlers_reinstated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cpp"
            path.write_bytes(b"before\n")
            path.chmod(0o640)
            os.utime(path, ns=(1_600_000_000_000_000_000,) * 2)
            before = path.stat()
            previous = signal.getsignal(signal.SIGTERM)
            transaction = SourceTransaction(path)
            write_bytes = Path.write_bytes
            restore_reached = False

            def interrupt_restore(write_path, data):
                nonlocal restore_reached
                handler = signal.getsignal(signal.SIGTERM)
                self.assertEqual(handler, transaction.handle_signal)
                handler(signal.SIGTERM, None)
                restore_reached = True
                return write_bytes(write_path, data)

            with mock.patch.object(Path, "write_bytes", interrupt_restore), \
                    self.assertRaisesRegex(KeyboardInterrupt, "SIGTERM"):
                with transaction as source:
                    source.write_text("after\n")

            after = path.stat()
            self.assertTrue(restore_reached)
            self.assertEqual(path.read_bytes(), b"before\n")
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertEqual(after.st_atime_ns, before.st_atime_ns)
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_snapshot_failure_reinstates_previous_handlers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cpp"
            path.write_text("before\n")
            previous = {
                signum: signal.getsignal(signum)
                for signum in (signal.SIGINT, signal.SIGTERM)
            }

            with mock.patch.object(
                    Path, "read_bytes", side_effect=RuntimeError("snapshot failed")
            ), self.assertRaisesRegex(RuntimeError, "snapshot failed"):
                with SourceTransaction(path):
                    self.fail("transaction entered after snapshot failure")

            for signum, handler in previous.items():
                self.assertIs(signal.getsignal(signum), handler)


class TestTry(unittest.TestCase):
    def make_args(self, directory, source_text, variants_text, show_best=False):
        source = Path(directory) / "source.cpp"
        variants = Path(directory) / "variants.py"
        source.write_text(source_text)
        variants.write_text(variants_text)
        return source, Namespace(
            src=str(source),
            obj="mine.o",
            target="target.o",
            fn="fn",
            variants=str(variants),
            stop_on_exact=True,
            show_best=show_best,
        )

    def test_restores_source_metadata_and_rebuilds_original(self):
        with tempfile.TemporaryDirectory() as directory:
            source, args = self.make_args(
                directory, "before\n", "BASE = 'before'\nVARIANTS = {'one': 'after'}\n"
            )
            source.chmod(0o640)
            os.utime(source, ns=(1_600_000_000_000_000_000,) * 2)
            before = source.stat()
            build = mock.Mock(returncode=0, stdout="", stderr="")
            open_file = open

            class AtimeChangingReader:
                def __init__(self, file):
                    self.file = file

                def __enter__(self):
                    self.file.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.file.__exit__(*args)

                def read(self):
                    text = self.file.read()
                    os.utime(
                        source,
                        ns=(1_700_000_000_000_000_000, source.stat().st_mtime_ns),
                    )
                    return text

            def open_and_update_atime(path, *args, **kwargs):
                file = open_file(path, *args, **kwargs)
                if os.fspath(path) == os.fspath(source):
                    return AtimeChangingReader(file)
                return file


            with mock.patch("builtins.open", side_effect=open_and_update_atime), \
                    mock.patch("mwdiff.disasm", return_value={"fn": ["li r3, 0"]}), \
                    mock.patch("mwdiff.subprocess.run", return_value=build) as run:
                self.assertEqual(cmd_try(args), 0)

            after = source.stat()
            self.assertEqual(source.read_bytes(), b"before\n")
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(after.st_atime_ns, before.st_atime_ns)
            self.assertEqual(run.call_count, 2)

    def test_duplicate_base_is_cli_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            source, args = self.make_args(
                directory, "anchor anchor\n", "BASE = 'anchor'\nVARIANTS = {'one': 'x'}\n"
            )
            argv = [
                "mwdiff.py",
                "try",
                args.src,
                args.obj,
                args.target,
                args.fn,
                args.variants,
            ]
            stderr = StringIO()

            with mock.patch("sys.argv", argv), \
                    mock.patch("mwdiff.disasm") as disasm_mock, \
                    mock.patch("mwdiff.subprocess.run") as run, \
                    redirect_stderr(stderr), \
                    self.assertRaises(SystemExit) as raised:
                main()

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("found 2", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            disasm_mock.assert_not_called()
            run.assert_not_called()
            self.assertEqual(source.read_text(), "anchor anchor\n")

    def test_interruptions_rebuild_baseline_object(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as directory:
                source, args = self.make_args(
                    directory,
                    "before\n",
                    "BASE = 'before'\nVARIANTS = {'one': 'after'}\n",
                )
                builds = []

                def interrupt_first_build(command, **kwargs):
                    builds.append(source.read_text())
                    if len(builds) == 1:
                        os.kill(os.getpid(), signum)
                    return mock.Mock(returncode=0, stdout="", stderr="")

                with mock.patch("mwdiff.disasm", return_value={"fn": ["li r3, 0"]}), \
                        mock.patch("mwdiff.subprocess.run", side_effect=interrupt_first_build), \
                        self.assertRaises(KeyboardInterrupt):
                    cmd_try(args)

                self.assertEqual(builds, ["after\n", "before\n"])
                self.assertEqual(source.read_text(), "before\n")

    def test_failed_baseline_rebuild_removes_candidate_object(self):
        with tempfile.TemporaryDirectory() as directory:
            source, args = self.make_args(
                directory,
                "before\n",
                "BASE = 'before'\nVARIANTS = {'one': 'after'}\n",
            )
            obj = Path(directory) / "mine.o"
            args.obj = str(obj)
            build_count = 0

            def fail_baseline_build(command, **kwargs):
                nonlocal build_count
                build_count += 1
                if build_count == 1:
                    obj.write_bytes(b"candidate")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                return mock.Mock(returncode=1, stdout="", stderr="baseline failed")

            stderr = StringIO()
            with mock.patch("mwdiff.disasm", return_value={"fn": ["li r3, 0"]}), \
                    mock.patch("mwdiff.subprocess.run", side_effect=fail_baseline_build), \
                    redirect_stderr(stderr), \
                    self.assertRaises(SystemExit) as raised:
                cmd_try(args)

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("failed to rebuild original object", stderr.getvalue())
            self.assertFalse(obj.exists())
            self.assertEqual(source.read_text(), "before\n")

    def test_interrupted_baseline_rebuild_removes_candidate_object(self):
        with tempfile.TemporaryDirectory() as directory:
            source, args = self.make_args(
                directory,
                "before\n",
                "BASE = 'before'\nVARIANTS = {'one': 'after'}\n",
            )
            obj = Path(directory) / "mine.o"
            args.obj = str(obj)
            build_count = 0

            def interrupt_baseline_build(command, **kwargs):
                nonlocal build_count
                build_count += 1
                if build_count == 1:
                    obj.write_bytes(b"candidate")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                raise KeyboardInterrupt("stop cleanup")

            with mock.patch("mwdiff.disasm", return_value={"fn": ["li r3, 0"]}), \
                    mock.patch("mwdiff.subprocess.run", side_effect=interrupt_baseline_build), \
                    self.assertRaisesRegex(KeyboardInterrupt, "stop cleanup"):
                cmd_try(args)

            self.assertFalse(obj.exists())
            self.assertEqual(source.read_text(), "before\n")

    def test_show_best_rebuilds_best_then_restores_baseline_object(self):
        with tempfile.TemporaryDirectory() as directory:
            source, args = self.make_args(
                directory,
                "before\n",
                "BASE = 'before'\nVARIANTS = {'best': 'best', 'worse': 'worse'}\n",
                show_best=True,
            )
            args.stop_on_exact = False
            builds = []
            built_from = {"source": None}

            def run_build(command, **kwargs):
                built_from["source"] = source.read_text()
                builds.append(built_from["source"])
                return mock.Mock(returncode=0, stdout="", stderr="")

            def disassemble(obj):
                if obj == args.target:
                    return {"fn": ["li r3, 0", "li r4, 0"]}
                variants = {
                    "best": ["li r3, 1", "li r4, 0"],
                    "worse": ["li r3, 1", "li r4, 1"],
                    "before": ["li r3, 2", "li r4, 2"],
                }
                return {"fn": variants[built_from["source"].strip()]}

            output = StringIO()
            with mock.patch("mwdiff.disasm", side_effect=disassemble), \
                    mock.patch("mwdiff.subprocess.run", side_effect=run_build), \
                    redirect_stdout(output):
                self.assertEqual(cmd_try(args), 1)

            self.assertEqual(builds, ["best\n", "worse\n", "best\n", "before\n"])
            self.assertIn("+li r3, 1", output.getvalue())
            self.assertNotIn("+li r3, 2", output.getvalue())
            self.assertEqual(source.read_text(), "before\n")
            self.assertEqual(built_from["source"], "before\n")


class TestDiagnosis(unittest.TestCase):
    TARGET = [
        "lis r30, table@ha",
        "addi r30, r30, table@l",
        "lbz r0, 0x26c(r31)",
        "mr r3, r30",
    ]
    SWAPPED = [
        "lis r31, table@ha",
        "addi r31, r31, table@l",
        "lbz r0, 0x26c(r30)",
        "mr r3, r31",
    ]

    def test_parse_instruction_preserves_operand_roles(self):
        instruction = parse_instruction("lwz r3, 0x20(r31)")
        self.assertEqual((instruction.opcode, instruction.operands),
                         ("lwz", ("r3", "0x20(r31)")))

    def test_infers_one_to_one_global_register_swap(self):
        self.assertEqual(infer_register_map(self.TARGET, self.SWAPPED),
                         {"r30": "r31", "r31": "r30", "r0": "r0", "r3": "r3"})

    def test_classifies_register_cascade(self):
        diagnosis = diagnose_lines(self.TARGET, self.SWAPPED)
        self.assertEqual(diagnosis.classification, "global-register-permutation")
        self.assertEqual(diagnosis.register_map["r30"], "r31")
        self.assertIn("bool", diagnosis.suggested_families)

    def test_register_cascade_ignores_shifted_local_label_addresses(self):
        target = [
            "mr r30, r3",
            "beq .L_00000100",
            ".L_00000100:",
            "mr r3, r30",
        ]
        candidate = [
            "mr r31, r3",
            "beq .L_00000130",
            ".L_00000130:",
            "mr r3, r31",
        ]

        diagnosis = diagnose_lines(target, candidate)
        self.assertEqual(diagnosis.classification, "global-register-permutation")
        self.assertEqual(diagnosis.register_map["r30"], "r31")

    def test_classifies_branch_shape_before_semantic_difference(self):
        target = ["cmpwi r3, 0", "beq done", "li r3, 1"]
        candidate = ["cmpwi r3, 0", "bne done", "li r3, 1"]
        diagnosis = diagnose_lines(target, candidate)
        self.assertEqual(diagnosis.classification, "branch-shape")
        self.assertIn("switch", diagnosis.suggested_families)

    def test_classifies_relocation_alias_without_mutation(self):
        target = ["lis r3, l_table@ha", "addi r3, r3, l_table@l"]
        candidate = ["lis r3, ...rodata.0@ha", "addi r3, r3, ...rodata.0@l"]
        diagnosis = diagnose_lines(target, candidate)
        self.assertEqual(diagnosis.classification, "relocation-alias")
        self.assertEqual(diagnosis.relocation_aliases,
                         (("l_table", "...rodata.0"),))
        self.assertEqual(diagnosis.suggested_families, ())
    def test_diagnose_json_is_one_machine_readable_document(self):
        args = Namespace(
            project=".",
            version=None,
            unit=None,
            target="target.o",
            mine="mine.o",
            fn="fn",
            json=True,
        )
        output = StringIO()
        functions = {"fn": ["li r3, 1", "blr"]}

        with mock.patch(
                "mwdiff._object_paths",
                return_value=(Path("."), Path("target.o"), Path("mine.o"))), \
                mock.patch("mwdiff.disasm", side_effect=[functions, functions]), \
                redirect_stdout(output):
            self.assertEqual(cmd_diagnose(args), 0)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["classification"], "exact")
        self.assertEqual(payload["diff_lines"], 0)



class TestMutations(unittest.TestCase):
    def texts(self, snippet, families, depth=1):
        return {candidate.text for candidate in generate_candidates(snippet, families, depth)}

    def test_boolean_mutation_finds_htetu1_form(self):
        variants = self.texts("    if (check_sw() != FALSE) {\n", ["bool"])
        self.assertIn("    if (check_sw()) {\n", variants)

    def test_depth_two_combines_hsehi1_load_and_cast(self):
        snippet = ("    s8 room_no = current.roomNo;\n"
                   "    call((s8)room_no);\n")
        variants = self.texts(snippet, ["load", "cast"], depth=2)
        self.assertIn(("    u8 room_no = *(volatile u8*)&current.roomNo;\n"
                       "    call((char)room_no);\n"), variants)

    def test_reassociation_includes_induction_term_first(self):
        variants = self.texts("    value = sw + sound + i * 0x100;\n", ["reassociate"])
        self.assertIn("    value = i * 0x100 + sw + sound;\n", variants)

    def test_switch_mutation_adds_next_empty_case(self):
        snippet = "switch (state) {\ncase 0: run(); break;\ncase 2: break;\n}\n"
        variants = self.texts(snippet, ["switch"])
        self.assertIn("switch (state) {\ncase 0: run(); break;\ncase 2: break;\ncase 3: break;\n}\n", variants)

    def test_version_mutation_varies_existing_guard_only(self):
        snippet = "#if VERSION == VERSION_DEMO\n"
        variants = self.texts(snippet, ["version"])
        self.assertIn("#if VERSION <= VERSION_DEMO\n", variants)
        self.assertIn("#if VERSION > VERSION_DEMO\n", variants)

    def test_source_range_accepts_one_line_or_inclusive_range(self):
        text = "one\ntwo\nthree\n"
        self.assertEqual(source_range(text, "2")[0], "two\n")
        self.assertEqual(source_range(text, "2:3")[0], "two\nthree\n")
        with self.assertRaisesRegex(ValueError, "outside"):
            source_range(text, "4")


class TestProjectResolution(unittest.TestCase):
    def test_resolves_unique_unit_and_rejects_wrong_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "objdiff.json").write_text(json.dumps({"units": [{
                "name": "d/actor/d_a_obj_demo",
                "target_path": "build/GZLP01/d_a_obj_demo/obj/d/actor/d_a_obj_demo.o",
                "base_path": "build/GZLP01/src/d/actor/d_a_obj_demo.o",
                "metadata": {"source_path": "src/d/actor/d_a_obj_demo.cpp"},
            }]}))
            unit = resolve_unit(root, "d_a_obj_demo", "GZLP01")
            self.assertEqual(unit.version, "GZLP01")
            self.assertEqual(unit.source, root / "src/d/actor/d_a_obj_demo.cpp")
            self.assertEqual(unit.module, "d_a_obj_demo")
            with self.assertRaisesRegex(ValueError, "configured for GZLP01"):
                resolve_unit(root, "d_a_obj_demo", "D44J01")

    def test_executable_unit_has_no_rel_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "objdiff.json").write_text(json.dumps({"units": [{
                "name": "d/main/d_a_demo",
                "target_path": "build/GZLP01/obj/d/main/d_a_demo.o",
                "base_path": "build/GZLP01/src/d/main/d_a_demo.o",
                "metadata": {"source_path": "src/d/main/d_a_demo.cpp"},
            }]}))

            unit = resolve_unit(root, "d_a_demo", "GZLP01")

            self.assertIsNone(unit.module)

    def test_reports_ambiguous_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = [{"name": f"a/{name}", "target_path": f"build/GZLP01/{name}/obj/x.o",
                      "base_path": f"build/GZLP01/src/{name}.o",
                      "metadata": {"source_path": f"src/{name}.cpp"}}
                     for name in ("foo", "myfoo")]
            (root / "objdiff.json").write_text(json.dumps({"units": units}))
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                resolve_unit(root, "foo")

class TestSearch(unittest.TestCase):
    def test_search_stops_on_exact_and_restores_without_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("if (check() != FALSE) {\n")
            unit = mock.Mock(project=root, source=source, ninja_target="build/demo.o",
                             target=root / "target.o", mine=root / "mine.o")
            candidates = generate_candidates(source.read_text(), ["bool"])
            scores = iter([
                ObjectScore(False, 100.0, "global-register-permutation", 4, 0, 0),
                ObjectScore(True, 100.0, "exact", 0, 0, 0),
            ])

            with mock.patch("mwdiff.subprocess.run", return_value=mock.Mock(returncode=0, stdout="", stderr="")), \
                 mock.patch("mwdiff.score_object", side_effect=lambda *args: next(scores)):
                result = search_candidates(unit, "fake", candidates, 10, True, False)

            self.assertTrue(result.exact)
            self.assertEqual(source.read_text(), "if (check() != FALSE) {\n")

    def test_depth_two_keeps_only_best_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("baseline\n")
            unit = mock.Mock(project=root, source=source, ninja_target="build/demo.o",
                             target=root / "target.o", mine=root / "mine.o")
            candidates = [
                SourceCandidate("baseline+p1", "p1\n", 1),
                SourceCandidate("baseline+p2", "p2\n", 1),
                SourceCandidate("baseline+p1+c", "p1c\n", 2),
                SourceCandidate("baseline+p2+c", "p2c\n", 2),
            ]
            scores = [
                ObjectScore(False, 99.0, "operand-order", 2, 0, 0),
                ObjectScore(False, 80.0, "semantic-instruction", 20, 0, 0),
                ObjectScore(False, 99.5, "operand-order", 1, 0, 0),
            ]
            with mock.patch("mwdiff.subprocess.run",
                            return_value=mock.Mock(returncode=0, stdout="", stderr="")), \
                 mock.patch("mwdiff.score_object", side_effect=scores) as scorer:
                search_candidates(unit, "fake", candidates, 10, False, False, 1)
            self.assertEqual(scorer.call_count, 3)

    def test_search_finds_hsehi1_volatile_char_combination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text(
                "s8 room_no = current.roomNo;\ncall((s8)room_no);\n")
            unit = mock.Mock(project=root, source=source, ninja_target="build/demo.o",
                             target=root / "target.o", mine=root / "mine.o")
            candidates = generate_candidates(
                source.read_text(), ["load", "cast"], depth=2)

            def fake_score(*args):
                text = source.read_text()
                if "volatile u8" in text and "(char)room_no" in text:
                    return ObjectScore(True, 100.0, "exact", 0, 0, 0)
                if "volatile u8" in text:
                    return ObjectScore(False, 99.0, "scheduling", 1, 0, 1)
                return ObjectScore(False, 90.0, "scheduling", 10, 0, 1)

            with mock.patch("mwdiff.subprocess.run",
                            return_value=mock.Mock(returncode=0, stdout="", stderr="")), \
                 mock.patch("mwdiff.score_object", side_effect=fake_score):
                result = search_candidates(
                    unit, "fake", candidates, 20, True, False, 1)
            self.assertTrue(result.exact)
            self.assertIn("*(volatile u8*)&current.roomNo", result.candidate.text)
            self.assertIn("(char)room_no", result.candidate.text)

    def test_depth_two_preserves_selected_parent_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text(
                "s8 room_no = current.roomNo;\ncall((s8)room_no);\n")
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
            )
            candidates = generate_candidates(
                source.read_text(), ["load", "cast"], depth=2)

            def fake_score(*args):
                text = source.read_text()
                if "volatile u8" in text and "(char)room_no" in text:
                    return ObjectScore(True, 100.0, "exact", 0, 0, 0)
                if "(char)room_no" in text:
                    return ObjectScore(
                        False, 99.0, "local-register-allocation", 1, 0, 0
                    )
                return ObjectScore(
                    False, 90.0, "semantic-instruction", 10, 0, 0
                )

            with mock.patch(
                    "mwdiff.subprocess.run",
                    return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ), mock.patch("mwdiff.score_object", side_effect=fake_score):
                result = search_candidates(
                    unit, "fake", candidates, 20, True, False, 1
                )

            self.assertTrue(result.exact)
            self.assertIn("*(volatile u8*)&current.roomNo", result.candidate.text)
            self.assertIn("(char)room_no", result.candidate.text)

    def test_keyboard_interrupt_restores_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("if (check() != FALSE) {\n")
            unit = mock.Mock(project=root, source=source, ninja_target="build/demo.o",
                             target=root / "target.o", mine=root / "mine.o")
            candidate = SourceCandidate("interrupt", "if (check()) {\n", 1)
            with mock.patch("mwdiff.subprocess.run", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    search_candidates(unit, "fake", [candidate], 10, True, False)
            self.assertEqual(source.read_text(), "if (check() != FALSE) {\n")
    def test_cached_candidate_skips_compiler_and_scorer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("baseline\n")
            candidate = SourceCandidate("cached", "candidate\n", 1)
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
                version="GZLP01",
            )
            material = ("compiler", "flags", "context")
            key = CandidateCache.key(
                *material, candidate.text, unit.version, "fake"
            )
            CandidateCache(root / ".cache/mwdiff").put(
                key,
                {
                    "exact": True,
                    "function_percent": 100.0,
                    "classification": "exact",
                    "diff_lines": 0,
                    "changed_calls": 0,
                    "changed_memory": 0,
                },
            )

            with mock.patch("mwdiff.cache_material", return_value=material), \
                    mock.patch(
                        "mwdiff.subprocess.run",
                        return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                    ) as run, \
                    mock.patch("mwdiff.score_object") as scorer:
                result = search_candidates(
                    unit, "fake", [candidate], 10, True, False
                )

            self.assertTrue(result.exact)
            self.assertEqual(run.call_count, 1)
            scorer.assert_not_called()
            self.assertEqual(source.read_text(), "baseline\n")


class TestSearchCli(unittest.TestCase):
    def test_json_verification_output_is_one_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("if (check() != FALSE) {\n")
            unit = mock.Mock(
                source=source, module="demo", version="GZLP01"
            )
            candidate = SourceCandidate("exact", "if (check()) {\n", 1)
            result = SearchResult(
                candidate,
                ObjectScore(True, 100.0, "exact", 0, 0, 0),
                1,
                0,
            )
            verification = VerificationResult(
                "GZLP01", 100.0, 100.0, 100.0, True
            )
            args = Namespace(
                project=root,
                version="GZLP01",
                unit="demo",
                fn="fn",
                line="1",
                families="bool",
                depth=1,
                max_builds=10,
                beam_width=5,
                no_stop=False,
                apply=True,
                verify=True,
                verify_version=[],
                json=True,
            )
            output = StringIO()

            with mock.patch("mwdiff.resolve_unit", return_value=unit), \
                    mock.patch("mwdiff.search_candidates", return_value=result), \
                    mock.patch("mwdiff.available_versions", return_value=["GZLP01"]), \
                    mock.patch(
                        "mwdiff.configured_versions",
                        return_value=["D44J01", "GZLP01"],
                    ), \
                    mock.patch("mwdiff.verify_all", return_value=[verification]), \
                    redirect_stdout(output):
                self.assertEqual(cmd_search(args), 0)

            payload = json.loads(output.getvalue())
            self.assertEqual(payload["search"]["candidate"]["name"], "exact")
            self.assertEqual(payload["verification"][0]["version"], "GZLP01")
            self.assertEqual(payload["unavailable_versions"], ["D44J01"])

    def test_verify_requires_apply(self):
        args = Namespace(
            project=".",
            version=None,
            unit="demo",
            fn="fn",
            line="1",
            families="bool",
            depth=1,
            max_builds=10,
            beam_width=5,
            no_stop=False,
            apply=False,
            verify=True,
            verify_version=[],
            json=False,
        )
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            cmd_search(args)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--verify requires --apply", stderr.getvalue())

    def test_verify_rejects_executable_unit_before_search(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("if (check() != FALSE) {\n")
            unit = mock.Mock(source=source, module=None)
            args = Namespace(
                project=root,
                version="GZLP01",
                unit="demo",
                fn="fn",
                line="1",
                families="bool",
                depth=1,
                max_builds=10,
                beam_width=5,
                no_stop=False,
                apply=True,
                verify=True,
                verify_version=[],
                json=False,
            )
            result = SearchResult(None, None, 0, 0)
            stderr = StringIO()

            with mock.patch("mwdiff.resolve_unit", return_value=unit), \
                    mock.patch(
                        "mwdiff.search_candidates", return_value=result
                    ) as search, \
                    mock.patch("mwdiff.available_versions", return_value=[]), \
                    mock.patch("mwdiff.configured_versions", return_value=[]), \
                    redirect_stderr(stderr), \
                    self.assertRaises(SystemExit) as raised:
                cmd_search(args)

            self.assertEqual(raised.exception.code, 2)
            self.assertIn(
                "--verify supports configured REL units only",
                stderr.getvalue(),
            )
            self.assertEqual(source.read_text(), "if (check() != FALSE) {\n")
            search.assert_not_called()





class TestObjectScoring(unittest.TestCase):
    def test_function_exact_is_not_object_exact_when_data_differs(self):
        payload = {"left": {"symbols": [
            {"name": "fn", "kind": "SYMBOL_FUNCTION", "match_percent": 100.0},
            {"name": "[.data]", "kind": "SYMBOL_SECTION", "match_percent": 90.0},
        ]}}
        process = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        functions = {"fn": ["li r3, 1", "blr"]}
        with mock.patch("mwdiff.subprocess.run", return_value=process), \
             mock.patch("mwdiff.disasm", side_effect=[functions, functions]):
            score = score_object(Path("."), "target.o", "mine.o", "fn")
        self.assertFalse(score.exact)
        self.assertEqual(score.classification, "data-layout")
    def test_configured_report_is_authoritative_for_object_exactness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "build/GZLP01/demo/obj/demo.o"
            mine = root / "build/GZLP01/src/demo.o"
            (root / "objdiff.json").write_text(
                json.dumps(
                    {
                        "units": [
                            {
                                "name": "demo/demo",
                                "target_path": target.relative_to(root).as_posix(),
                                "base_path": mine.relative_to(root).as_posix(),
                            }
                        ]
                    }
                )
            )
            one_shot = {
                "left": {
                    "symbols": [
                        {
                            "name": "fn",
                            "kind": "SYMBOL_FUNCTION",
                            "match_percent": 100.0,
                        },
                        {
                            "name": "[.text]",
                            "kind": "SYMBOL_SECTION",
                            "match_percent": None,
                        },
                        {
                            "name": "[.data]",
                            "kind": "SYMBOL_SECTION",
                            "match_percent": None,
                        },
                        {
                            "name": "[.data-0]",
                            "kind": "SYMBOL_SECTION",
                            "match_percent": 50.0,
                        },
                    ]
                }
            }
            report = {
                "units": [
                    {
                        "name": "demo/demo",
                        "measures": {
                            "matched_functions_percent": 100.0,
                            "matched_code_percent": 100.0,
                            "matched_data_percent": 100.0,
                        },
                    }
                ]
            }
            processes = [
                mock.Mock(
                    returncode=0, stdout=json.dumps(one_shot), stderr=""
                ),
                mock.Mock(returncode=0, stdout=json.dumps(report), stderr=""),
            ]
            functions = {"fn": ["li r3, 1", "blr"]}

            with mock.patch("mwdiff.subprocess.run", side_effect=processes), \
                    mock.patch(
                        "mwdiff.disasm", side_effect=[functions, functions]
                    ):
                score = score_object(root, target, mine, "fn")

            self.assertTrue(score.exact)
            self.assertEqual(score.classification, "exact")



class TestProofCli(unittest.TestCase):
    def test_prove_objects_passes_raw_function_lines(self):
        functions = {"fn": ["li r3, 1", "blr"]}
        equivalent = mock.Mock(
            status="equivalent", reason="", counterexample=None
        )
        with mock.patch("mwdiff.disasm", side_effect=[functions, functions]), \
                mock.patch(
                    "ppc_equiv.prove", return_value=equivalent
                ) as oracle:
            result = prove_objects("target.o", "candidate.o", "fn", 100)
        self.assertEqual(result.status, "equivalent")
        oracle.assert_called_once_with(functions["fn"], functions["fn"], 100)

    def test_cmd_prove_prints_counterexample_for_difference(self):
        proof = mock.Mock(
            status="different", reason="", counterexample={"r3": "0x0"}
        )
        args = Namespace(
            target="target.o",
            mine="mine.o",
            fn="fn",
            timeout_ms=5000,
            json=False,
        )
        with mock.patch("mwdiff.prove_objects", return_value=proof), \
                mock.patch("builtins.print") as output:
            self.assertEqual(cmd_prove(args), 1)
        self.assertTrue(
            any("r3" in str(call) for call in output.call_args_list)
        )

    def test_exact_search_bypasses_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("if (check() != FALSE) {\n")
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
            )
            candidate = SourceCandidate("exact", "if (check()) {\n", 1)
            exact = ObjectScore(True, 100.0, "exact", 0, 0, 0)
            with mock.patch(
                    "mwdiff.subprocess.run",
                    return_value=mock.Mock(
                        returncode=0, stdout="", stderr=""
                    )), \
                    mock.patch("mwdiff.score_object", return_value=exact), \
                    mock.patch("mwdiff.prove_objects") as oracle:
                result = search_candidates(
                    unit, "fn", [candidate], 1, True, False, 5, True, 100
                )
            self.assertTrue(result.exact)
            oracle.assert_not_called()

    def test_proven_difference_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("return value + 1;\n")
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
            )
            candidate = SourceCandidate(
                "different", "return value + 2;\n", 1
            )
            score = ObjectScore(
                False, 99.0, "semantic-instruction", 2, 0, 0
            )
            proof = mock.Mock(
                status="different", counterexample={"r3": "0x0"}
            )
            with mock.patch("ppc_equiv.require_z3"), \
                    mock.patch(
                    "mwdiff.subprocess.run",
                    return_value=mock.Mock(
                        returncode=0, stdout="", stderr=""
                    )), \
                    mock.patch("mwdiff.score_object", return_value=score), \
                    mock.patch("mwdiff.prove_objects", return_value=proof):
                result = search_candidates(
                    unit, "fn", [candidate], 1, True, False, 5, True, 100
                )
            self.assertIsNone(result.candidate)
            self.assertEqual(source.read_text(), "return value + 1;\n")

    def test_unknown_candidate_is_retained_and_labeled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("return value + 1;\n")
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
            )
            candidate = SourceCandidate("unknown", "return value + 2;\n", 1)
            score = ObjectScore(
                False, 99.0, "semantic-instruction", 2, 0, 0
            )
            proof = mock.Mock(
                status="unknown", reason="floating-point", counterexample=None
            )
            with mock.patch("ppc_equiv.require_z3"), \
                    mock.patch(
                    "mwdiff.subprocess.run",
                    return_value=mock.Mock(
                        returncode=0, stdout="", stderr=""
                    )), \
                    mock.patch("mwdiff.score_object", return_value=score), \
                    mock.patch("mwdiff.prove_objects", return_value=proof):
                result = search_candidates(
                    unit,
                    "fn",
                    [candidate],
                    1,
                    True,
                    False,
                    5,
                    True,
                    100,
                    True,
                )
            self.assertEqual(result.candidate, candidate)
            self.assertEqual(result.proof.status, "unknown")
            self.assertEqual(source.read_text(), "return value + 1;\n")

    def test_cached_nonexact_candidate_rebuilds_before_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("baseline\n")
            candidate = SourceCandidate("cached", "candidate\n", 1)
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=root / "mine.o",
                version="GZLP01",
            )
            material = ("compiler", "flags", "context")
            key = CandidateCache.key(
                *material, candidate.text, unit.version, "fn"
            )
            CandidateCache(root / ".cache/mwdiff").put(
                key,
                {
                    "exact": False,
                    "function_percent": 99.0,
                    "classification": "semantic-instruction",
                    "diff_lines": 1,
                    "changed_calls": 0,
                    "changed_memory": 0,
                },
            )
            proof = mock.Mock(
                status="unknown", reason="unsupported", counterexample=None
            )
            process = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch("ppc_equiv.require_z3"), \
                    mock.patch("mwdiff.cache_material", return_value=material), \
                    mock.patch(
                        "mwdiff.subprocess.run", return_value=process
                    ) as run, \
                    mock.patch("mwdiff.score_object") as scorer, \
                    mock.patch(
                        "mwdiff.prove_objects", return_value=proof
                    ) as oracle:
                result = search_candidates(
                    unit,
                    "fn",
                    [candidate],
                    1,
                    True,
                    False,
                    5,
                    True,
                    100,
                    True,
                )
            self.assertEqual(result.proof.status, "unknown")
            self.assertEqual(run.call_count, 2)
            scorer.assert_not_called()
            oracle.assert_called_once()

    def test_search_api_rebuilds_original_after_missing_z3(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.cpp"
            source.write_text("baseline\n")
            mine = root / "mine.o"
            mine.write_text("baseline object")
            unit = mock.Mock(
                project=root,
                source=source,
                ninja_target="build/demo.o",
                target=root / "target.o",
                mine=mine,
            )
            candidate = SourceCandidate("candidate", "changed\n", 1)
            process = mock.Mock(returncode=0, stdout="", stderr="")
            builds = []

            def run_build(*args, **kwargs):
                builds.append((args, kwargs))
                if len(builds) == 1:
                    mine.write_text("candidate object")
                elif not mine.exists():
                    mine.write_text("baseline object")
                return process
            missing = RuntimeError("install z3-solver")
            with mock.patch(
                    "ppc_equiv.require_z3", side_effect=missing
            ), mock.patch(
                    "mwdiff.cache_material", return_value=None
            ), mock.patch(
                    "mwdiff.subprocess.run", side_effect=run_build
            ) as run, mock.patch(
                    "mwdiff.score_object",
                    return_value=ObjectScore(
                        False, 99.0, "semantic-instruction", 1, 0, 0
                    ),
            ), self.assertRaisesRegex(RuntimeError, "z3-solver"):
                search_candidates(
                    unit, "fn", [candidate], 1, True, False, 5, True
                )
            self.assertEqual(run.call_count, 2)
            self.assertEqual(source.read_text(), "baseline\n")
            self.assertEqual(mine.read_text(), "baseline object")





class TestVerification(unittest.TestCase):
    def test_cache_key_changes_with_compiler_and_context(self):
        first = CandidateCache.key(
            "compiler-a", "flags", "context", "candidate", "GZLP01", "fn"
        )
        self.assertEqual(
            first,
            CandidateCache.key(
                "compiler-a", "flags", "context", "candidate", "GZLP01", "fn"
            ),
        )
        self.assertNotEqual(
            first,
            CandidateCache.key(
                "compiler-b", "flags", "context", "candidate", "GZLP01", "fn"
            ),
        )
    def test_cache_material_hashes_compiler_context_and_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / "build/compilers/GC/1/mwcceppc.exe"
            compiler.parent.mkdir(parents=True)
            compiler.write_bytes(b"compiler")
            context = root / "ctx.cpp"
            context.write_bytes(b"context")
            unit = mock.Mock(
                project=root,
                ninja_target="build/demo.o",
                context_path=context,
                source=root / "source.cpp",
                compiler="GC/1",
                compiler_flags="-O4",
            )
            commands = "wine build/compilers/GC/1/mwcceppc.exe -c ctx.cpp\n"
            process = mock.Mock(returncode=0, stdout=commands, stderr="")

            with mock.patch("mwdiff.subprocess.run", return_value=process):
                material = cache_material(unit)

            self.assertEqual(
                material,
                (
                    hashlib.sha256(b"compiler").hexdigest(),
                    "\0".join(("GC/1", "-O4", commands)),
                    hashlib.sha256(b"context").hexdigest(),
                ),
            )


    def test_available_versions_require_real_orig_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ("D44J01", "GZLP01"):
                (root / "config" / version).mkdir(parents=True)
                (root / "config" / version / "config.yml").write_text("version: 1\n")
                (root / "orig" / version).mkdir(parents=True)
            (root / "orig" / "D44J01" / ".gitkeep").write_text("")
            (root / "orig" / "GZLP01" / "sys").mkdir()
            self.assertEqual(available_versions(root), ["GZLP01"])
            self.assertEqual(configured_versions(root), ["D44J01", "GZLP01"])

    def test_expected_sha_selects_exact_rel_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.sha1"
            path.write_text("a" * 40 + "  build/GZLP01/demo/demo.rel\n")
            self.assertEqual(
                expected_sha(path, "build/GZLP01/demo/demo.rel"), "a" * 40
            )

    def test_verify_version_checks_report_and_linked_rel_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/d/actor/demo.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("")
            rel = root / "build/GZLP01/demo/demo.rel"
            rel.parent.mkdir(parents=True)
            rel.write_bytes(b"linked rel")
            report = {
                "units": [
                    {
                        "name": "d/actor/demo",
                        "measures": {
                            "matched_functions_percent": 100.0,
                            "matched_code_percent": 100.0,
                            "matched_data_percent": 100.0,
                        },
                    }
                ]
            }
            (root / "build/GZLP01/report.json").write_text(json.dumps(report))
            sha_file = root / "config/GZLP01/build.sha1"
            sha_file.parent.mkdir(parents=True)
            sha_file.write_text(
                hashlib.sha1(b"linked rel").hexdigest()
                + "  build/GZLP01/demo/demo.rel\n"
            )
            unit = mock.Mock(source=source, module="demo")
            success = mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch("mwdiff.subprocess.run", return_value=success) as run, \
                    mock.patch("mwdiff.resolve_unit", return_value=unit):
                result = verify_version(root, "demo", "GZLP01")

            self.assertEqual(
                result,
                VerificationResult("GZLP01", 100.0, 100.0, 100.0, True),
            )
            self.assertEqual(run.call_count, 3)
            self.assertEqual(
                run.call_args_list[1],
                mock.call(
                    ["ninja", "build.ninja"],
                    cwd=root.resolve(),
                    capture_output=True,
                    text=True,
                ),
            )

    def test_verify_all_restores_original_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configured_unit = mock.Mock(version="D44J01")
            result = VerificationResult(
                "GZLP01", 100.0, 100.0, 100.0, True
            )
            success = mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch("mwdiff.resolve_unit", return_value=configured_unit), \
                    mock.patch("mwdiff.available_versions", return_value=["GZLP01"]), \
                    mock.patch("mwdiff.verify_version", return_value=result), \
                    mock.patch("mwdiff.subprocess.run", return_value=success) as run:
                self.assertEqual(verify_all(root, "demo", ["GZLP01"]), [result])

            self.assertEqual(
                run.call_args_list,
                [
                    mock.call(
                        [sys.executable, "configure.py", "--version", "D44J01"],
                        cwd=root.resolve(),
                        capture_output=True,
                        text=True,
                    ),
                    mock.call(
                        ["ninja", "build.ninja"],
                        cwd=root.resolve(),
                        capture_output=True,
                        text=True,
                    ),
                ],
            )


if __name__ == '__main__':
    unittest.main()
