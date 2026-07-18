import unittest

from ppc_equiv import (
    _mask,
    CallModels,
    Inputs,
    Unsupported,
    execute,
    initial_state,
    parse_program,
    prove,
    step_call,
    step_compare,
    step_integer,
    step_memory,
)

try:
    import z3
except ImportError:
    z3 = None


@unittest.skipUnless(z3, "z3-solver is optional")
class TestPpcIntegerSemantics(unittest.TestCase):
    def test_parses_labels_and_operands_from_dtk_lines(self):
        program = parse_program([
            ".L_start:",
            "/* 00000000 38600001 */ li r3, 1",
            "/* 00000004 4E800020 */ blr",
        ])
        self.assertEqual(program.labels, {".L_start": 0})
        self.assertEqual(program.instructions[0].opcode, "li")
        self.assertEqual(program.instructions[0].operands, ("r3", "1"))

    def test_executes_integer_and_mask_operations(self):
        inputs = Inputs.create()
        state = initial_state(inputs)
        program = parse_program([
            "li r3, -1",
            "addi r4, r3, 2",
            "clrlwi r5, r4, 24",
            "extsb r6, r5",
        ])
        for instruction in program.instructions:
            state = step_integer(state, instruction)
        solver = z3.Solver()
        solver.add(state.gpr[4] != z3.BitVecVal(1, 32))
        self.assertEqual(solver.check(), z3.unsat)
        solver = z3.Solver()
        solver.add(state.gpr[6] != z3.BitVecVal(1, 32))
        self.assertEqual(solver.check(), z3.unsat)

    def test_addi_with_ra_zero_uses_literal_zero(self):
        state = step_integer(
            initial_state(Inputs.create()),
            parse_program(["addi r3, r0, 7"]).instructions[0],
        )
        solver = z3.Solver()
        solver.add(state.gpr[3] != z3.BitVecVal(7, 32))
        self.assertEqual(solver.check(), z3.unsat)

    def test_addic_with_ra_zero_reads_register_zero(self):
        inputs = Inputs.create()
        state = step_integer(
            initial_state(inputs),
            parse_program(["addic r3, r0, 7"]).instructions[0],
        )
        solver = z3.Solver()
        solver.add(state.gpr[3] != inputs.gpr[0] + 7)
        self.assertEqual(solver.check(), z3.unsat)

    def test_compare_immediates_follow_16_bit_encoding(self):
        state = initial_state(Inputs.create())
        state = step_integer(
            state, parse_program(["li r3, -1"]).instructions[0]
        )
        state = step_compare(
            state, parse_program(["cmpwi r3, 0xffff"]).instructions[0]
        )
        solver = z3.Solver()
        solver.add(z3.Not(state.cr[0].eq))
        self.assertEqual(solver.check(), z3.unsat)

        state = step_integer(
            state, parse_program(["li r3, 0xffff"]).instructions[0]
        )
        state = step_compare(
            state, parse_program(["cmplwi r3, -1"]).instructions[0]
        )
        solver = z3.Solver()
        solver.add(z3.Not(state.cr[0].eq))
        self.assertEqual(solver.check(), z3.unsat)

    def test_rejects_out_of_range_rotate_mask(self):
        with self.assertRaisesRegex(Unsupported, "mask"):
            _mask(-1, 31)

    def test_rejects_float_instruction(self):
        with self.assertRaisesRegex(Unsupported, "lfs"):
            step_integer(
                initial_state(Inputs.create()),
                parse_program(["lfs f1, 0(r3)"]).instructions[0],
            )


@unittest.skipUnless(z3, "z3-solver is optional")
class TestPpcEffects(unittest.TestCase):
    def test_big_endian_store_then_load_round_trips(self):
        inputs = Inputs.create()
        state = initial_state(inputs)
        state = step_integer(
            state, parse_program(["li r3, 0x100"]).instructions[0]
        )
        state = step_integer(
            state, parse_program(["lis r4, 0x1234"]).instructions[0]
        )
        state = step_integer(
            state, parse_program(["ori r4, r4, 0x5678"]).instructions[0]
        )
        state = step_memory(
            state, parse_program(["stw r4, 0(r3)"]).instructions[0]
        )
        state = step_memory(
            state, parse_program(["lwz r5, 0(r3)"]).instructions[0]
        )
        solver = z3.Solver()
        solver.add(state.gpr[5] != z3.BitVecVal(0x12345678, 32))
        self.assertEqual(solver.check(), z3.unsat)

    def test_memory_ra_zero_means_literal_zero(self):
        state = initial_state(Inputs.create())
        state = step_integer(
            state, parse_program(["li r0, 0x100"]).instructions[0]
        )
        state = step_integer(
            state, parse_program(["li r4, 0x7f"]).instructions[0]
        )
        state = step_memory(
            state, parse_program(["stb r4, 4(r0)"]).instructions[0]
        )
        solver = z3.Solver()
        solver.add(
            z3.Select(state.memory, z3.BitVecVal(4, 32))
            != z3.BitVecVal(0x7F, 8)
        )
        self.assertEqual(solver.check(), z3.unsat)

    def test_matching_call_models_same_return_and_memory(self):
        inputs = Inputs.create()
        models = CallModels()
        instruction = parse_program(["bl dKy_get_schbit__Fv"]).instructions[0]
        left = step_call(initial_state(inputs), instruction, models)
        right = step_call(initial_state(inputs), instruction, models)
        solver = z3.Solver()
        solver.add(
            z3.Or(left.gpr[3] != right.gpr[3], left.memory != right.memory)
        )
        self.assertEqual(solver.check(), z3.unsat)
        self.assertEqual(left.calls[0].target, "dKy_get_schbit__Fv")

    def test_call_model_names_do_not_alias_distinct_symbols(self):
        models = CallModels()
        dashed = models.functions("call-a")[0]
        underscored = models.functions("call_a")[0]
        self.assertNotEqual(dashed.name(), underscored.name())



@unittest.skipUnless(z3, "z3-solver is optional")
class TestPpcProof(unittest.TestCase):
    def test_equivalent_mask_spellings(self):
        left = ["clrlwi r3, r3, 24", "blr"]
        right = ["rlwinm r3, r3, 0, 24, 31", "blr"]
        self.assertEqual(prove(left, right).status, "equivalent")

    def test_real_difference_has_counterexample(self):
        result = prove(
            ["addi r3, r3, 1", "blr"],
            ["addi r3, r3, 2", "blr"],
        )
        self.assertEqual(result.status, "different")
        self.assertIn("r3", result.counterexample)

    def test_r4_is_observable_for_wide_returns(self):
        result = prove(
            ["li r3, 0", "li r4, 1", "blr"],
            ["li r3, 0", "li r4, 2", "blr"],
        )
        self.assertEqual(result.status, "different")

    def test_equivalent_inverted_branch_shape(self):
        left = [
            "cmpwi r3, 0",
            "beq zero",
            "li r3, 1",
            "blr",
            "zero:",
            "li r3, 0",
            "blr",
        ]
        right = [
            "cmpwi r3, 0",
            "bne nonzero",
            "li r3, 0",
            "blr",
            "nonzero:",
            "li r3, 1",
            "blr",
        ]
        self.assertEqual(prove(left, right).status, "equivalent")

    def test_float_and_loop_are_unknown(self):
        self.assertEqual(
            prove(["lfs f1, 0(r3)", "blr"], ["lfs f1, 0(r3)", "blr"]).status,
            "unknown",
        )
        self.assertEqual(
            prove(["loop:", "b loop"], ["loop:", "b loop"]).status,
            "unknown",
        )

    def test_changed_external_call_is_unknown(self):
        result = prove(["bl call_a", "blr"], ["bl call_b", "blr"])
        self.assertEqual(result.status, "unknown")
        self.assertIn("call trace", result.reason)

    def test_call_model_counterexample_is_unknown(self):
        result = prove(
            ["bl f", "clrlwi r3, r3, 31", "blr"],
            ["bl f", "li r3, 0", "blr"],
        )
        self.assertEqual(result.status, "unknown")
        self.assertIn("external call model", result.reason)

    def test_symbolic_relocation_is_unknown_not_an_exception(self):
        result = prove(
            ["lis r3, table@ha", "blr"],
            ["lis r3, table@ha", "blr"],
        )
        self.assertEqual(result.status, "unknown")
        self.assertIn("table@ha", result.reason)

    def test_explicit_unmodeled_cr_branch_is_unknown(self):
        result = prove(
            ["beq cr1, done", "li r3, 1", "done:", "blr"],
            ["beq cr1, done", "li r3, 1", "done:", "blr"],
        )
        self.assertEqual(result.status, "unknown")
        self.assertIn("conditional branch", result.reason)

    def test_call_model_observes_abi_context_registers(self):
        target = [
            "addi r1, r1, -0x10",
            "bl callee",
            "addi r1, r1, 0x10",
            "blr",
        ]
        candidate = ["bl callee", "blr"]
        result = prove(target, candidate)
        self.assertEqual(result.status, "unknown")
        self.assertIn("external call model", result.reason)


if __name__ == "__main__":
    unittest.main()
