#!/usr/bin/env python3
from dataclasses import dataclass, replace
import re

_z3 = None
_COMMENT = re.compile(r"/\*.*?\*/")
_REGISTER = re.compile(r"r(?:[12]?\d|3[01])$")


class Unsupported(Exception):
    pass


def require_z3():
    global _z3
    if _z3 is None:
        try:
            import z3
        except ImportError as error:
            raise RuntimeError(
                "mwdiff proof requires z3-solver; prefix your existing command "
                "with `uv run --with z3-solver`"
            ) from error
        _z3 = z3
    return _z3


@dataclass(frozen=True)
class Instruction:
    opcode: str
    operands: tuple[str, ...]


@dataclass(frozen=True)
class Program:
    instructions: tuple[Instruction, ...]
    labels: dict[str, int]


def parse_program(lines):
    instructions = []
    labels = {}
    for raw in lines:
        text = _COMMENT.sub("", raw).strip()
        if not text or text.startswith((".fn ", ".endfn", ".section")):
            continue
        if text.endswith(":"):
            labels[text[:-1]] = len(instructions)
            continue
        opcode, _, tail = text.partition(" ")
        operands = tuple(part.strip() for part in tail.split(",") if part.strip())
        instructions.append(Instruction(opcode, operands))
    return Program(tuple(instructions), labels)


@dataclass(frozen=True)
class CrField:
    lt: object
    gt: object
    eq: object
    so: object


@dataclass(frozen=True)
class Inputs:
    gpr: tuple[object, ...]
    cr: tuple[CrField, ...]
    memory: object

    @classmethod
    def create(cls):
        z3 = require_z3()
        gpr = tuple(z3.BitVec(f"in_r{index}", 32) for index in range(32))
        cr = tuple(
            CrField(
                *(z3.Bool(f"in_cr{field}_{bit}") for bit in ("lt", "gt", "eq", "so"))
            )
            for field in range(8)
        )
        memory = z3.Array("in_memory", z3.BitVecSort(32), z3.BitVecSort(8))
        return cls(gpr, cr, memory)


@dataclass(frozen=True)
class CallEvent:
    target: str
    arguments: tuple[object, ...]


@dataclass(frozen=True)
class State:
    gpr: tuple[object, ...]
    cr: tuple[CrField, ...]
    memory: object
    calls: tuple[CallEvent, ...]


def initial_state(inputs):
    return State(inputs.gpr, inputs.cr, inputs.memory, ())


def _set(sequence, index, value):
    result = list(sequence)
    result[index] = value
    return tuple(result)


def _reg(name):
    if not _REGISTER.fullmatch(name):
        raise Unsupported(f"expected GPR, got {name}")
    return int(name[1:])


def _number(text):
    try:
        return int(text, 0)
    except ValueError as error:
        raise Unsupported(f"unsupported immediate: {text}") from error


def _bv32(value):
    return require_z3().BitVecVal(value & 0xFFFFFFFF, 32)


def _signed(value, bits):
    z3 = require_z3()
    return z3.SignExt(32 - bits, z3.Extract(bits - 1, 0, value))


def _mask(mb, me):
    if not 0 <= mb < 32 or not 0 <= me < 32:
        raise Unsupported(f"invalid rotate mask: {mb}, {me}")
    value = 0
    bit = mb
    while True:
        value |= 1 << (31 - bit)
        if bit == me:
            return _bv32(value)
        bit = (bit + 1) & 31


def _ra(gpr, name):
    return _bv32(0) if name == "r0" else gpr[_reg(name)]


def _record_result(state, value):
    zero = _bv32(0)
    cr0 = CrField(value < zero, value > zero, value == zero, state.cr[0].so)
    return replace(state, cr=_set(state.cr, 0, cr0))


def step_integer(state, instruction):
    z3 = require_z3()
    op, args = instruction.opcode, instruction.operands
    if op.startswith("f") or any(arg.startswith("f") for arg in args):
        raise Unsupported(f"unsupported floating-point instruction: {op}")
    gpr = state.gpr
    if op == "nop":
        return state
    if op == "li":
        dest, immediate = args
        value = _bv32(_number(immediate))
    elif op == "lis":
        dest, immediate = args
        value = _bv32(_number(immediate) << 16)
    elif op == "mr":
        dest, source = args
        value = gpr[_reg(source)]
    elif op == "addi":
        dest, left, immediate = args
        value = _ra(gpr, left) + _bv32(_number(immediate))
    elif op in {"addic", "addic."}:
        dest, left, immediate = args
        value = gpr[_reg(left)] + _bv32(_number(immediate))
    elif op == "addis":
        dest, left, immediate = args
        value = _ra(gpr, left) + _bv32(_number(immediate) << 16)
    elif op == "add":
        dest, left, right = args
        value = gpr[_reg(left)] + gpr[_reg(right)]
    elif op == "subf":
        dest, left, right = args
        value = gpr[_reg(right)] - gpr[_reg(left)]
    elif op == "mulli":
        dest, left, immediate = args
        value = gpr[_reg(left)] * _bv32(_number(immediate))
    elif op in {"and", "and.", "or", "or.", "xor", "xor."}:
        dest, left, right = args
        operation = {
            "and": lambda a, b: a & b,
            "or": lambda a, b: a | b,
            "xor": lambda a, b: a ^ b,
        }[op.rstrip(".")]
        value = operation(gpr[_reg(left)], gpr[_reg(right)])
    elif op in {"andi.", "ori", "xori"}:
        dest, left, immediate = args
        operation = {
            "andi.": lambda a, b: a & b,
            "ori": lambda a, b: a | b,
            "xori": lambda a, b: a ^ b,
        }[op]
        value = operation(gpr[_reg(left)], _bv32(_number(immediate)))
    elif op in {"slw", "srw"}:
        dest, left, right = args
        shift = z3.ZeroExt(26, z3.Extract(5, 0, gpr[_reg(right)]))
        shifted = (
            gpr[_reg(left)] << shift
            if op == "slw"
            else z3.LShR(gpr[_reg(left)], shift)
        )
        value = z3.If(z3.UGT(shift, _bv32(31)), _bv32(0), shifted)
    elif op == "srawi":
        dest, left, amount = args
        value = gpr[_reg(left)] >> _number(amount)
    elif op in {"rlwinm", "rlwinm."}:
        dest, source, shift, mb, me = args
        value = z3.RotateLeft(gpr[_reg(source)], _number(shift)) & _mask(
            _number(mb), _number(me)
        )
    elif op == "clrlwi":
        dest, source, amount = args
        value = gpr[_reg(source)] & _mask(_number(amount), 31)
    elif op == "clrrwi":
        dest, source, amount = args
        value = gpr[_reg(source)] & _mask(0, 31 - _number(amount))
    elif op == "extsb":
        dest, source = args
        value = _signed(gpr[_reg(source)], 8)
    elif op == "extsh":
        dest, source = args
        value = _signed(gpr[_reg(source)], 16)
    elif op == "cntlzw":
        dest, source = args
        bits = gpr[_reg(source)]
        count = _bv32(32)
        for index in range(32):
            count = z3.If(
                z3.Extract(index, index, bits) == 1,
                _bv32(31 - index),
                count,
            )
        value = count
    else:
        raise Unsupported(f"unsupported integer instruction: {op}")
    result = replace(state, gpr=_set(gpr, _reg(dest), z3.simplify(value)))
    return _record_result(result, value) if op.endswith(".") else result


_ADDRESS = re.compile(
    r"(?P<offset>-?(?:0x[0-9a-fA-F]+|\d+))\((?P<base>r\d+)\)$"
)


def _address(state, operand):
    match = _ADDRESS.fullmatch(operand)
    if not match:
        raise Unsupported(f"unsupported address: {operand}")
    return _ra(state.gpr, match.group("base")) + _bv32(
        _number(match.group("offset"))
    )


def _load_be(memory, address, size):
    z3 = require_z3()
    bytes_ = [
        z3.Select(memory, address + _bv32(index)) for index in range(size)
    ]
    return z3.Concat(*bytes_) if size > 1 else bytes_[0]


def _store_be(memory, address, value, size):
    z3 = require_z3()
    result = memory
    for index in range(size):
        high = size * 8 - index * 8 - 1
        result = z3.Store(
            result,
            address + _bv32(index),
            z3.Extract(high, high - 7, value),
        )
    return result


def step_memory(state, instruction):
    z3 = require_z3()
    op, args = instruction.opcode, instruction.operands
    sizes = {
        "lbz": 1,
        "lha": 2,
        "lhz": 2,
        "lwz": 4,
        "stb": 1,
        "sth": 2,
        "stw": 4,
    }
    if op not in sizes:
        raise Unsupported(f"unsupported memory instruction: {op}")
    register, address_operand = args
    address = _address(state, address_operand)
    size = sizes[op]
    if op.startswith("st"):
        memory = _store_be(
            state.memory, address, state.gpr[_reg(register)], size
        )
        return replace(state, memory=memory)
    value = _load_be(state.memory, address, size)
    if op == "lha":
        value = z3.SignExt(16, value)
    elif size < 4:
        value = z3.ZeroExt(32 - size * 8, value)
    return replace(state, gpr=_set(state.gpr, _reg(register), value))


class CallModels:
    def __init__(self):
        self.returns = {}
        self.memories = {}
        self.clobbers = {}
        self.cr_clobbers = {}

    @staticmethod
    def _safe(target):
        return target.encode().hex()

    def functions(self, target):
        z3 = require_z3()
        safe = self._safe(target)
        inputs = [z3.BitVecSort(32)] * 11 + [
            z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8))
        ]
        self.returns.setdefault(
            target,
            z3.Function(
                f"call_{safe}_return", *inputs, z3.BitVecSort(32)
            ),
        )
        self.memories.setdefault(
            target,
            z3.Function(
                f"call_{safe}_memory",
                *inputs,
                z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8)),
            ),
        )
        for register in (0, *range(4, 13)):
            self.clobbers.setdefault(
                (target, register),
                z3.Function(
                    f"call_{safe}_r{register}",
                    *inputs,
                    z3.BitVecSort(32),
                ),
            )
        for field in (0, 1, 5, 6, 7):
            for bit in ("lt", "gt", "eq", "so"):
                self.cr_clobbers.setdefault(
                    (target, field, bit),
                    z3.Function(
                        f"call_{safe}_cr{field}_{bit}",
                        *inputs,
                        z3.BoolSort(),
                    ),
                )
        return self.returns[target], self.memories[target]


def step_call(state, instruction, models):
    if instruction.opcode != "bl" or len(instruction.operands) != 1:
        raise Unsupported(
            f"unsupported call instruction: {instruction.opcode}"
        )
    target = instruction.operands[0]
    if target.startswith(("0x", ".L")):
        raise Unsupported(f"unresolved call target: {target}")
    arguments = tuple(state.gpr[index] for index in range(3, 11))
    call_inputs = (
        state.gpr[1],
        state.gpr[2],
        *arguments,
        state.gpr[13],
        state.memory,
    )
    return_fn, memory_fn = models.functions(target)
    gpr = _set(state.gpr, 3, return_fn(*call_inputs))
    for register in (0, *range(4, 13)):
        gpr = _set(
            gpr,
            register,
            models.clobbers[(target, register)](*call_inputs),
        )
    cr = list(state.cr)
    for field in (0, 1, 5, 6, 7):
        cr[field] = CrField(
            *(
                models.cr_clobbers[(target, field, bit)](*call_inputs)
                for bit in ("lt", "gt", "eq", "so")
            )
        )
    return replace(
        state,
        gpr=gpr,
        cr=tuple(cr),
        memory=memory_fn(*call_inputs),
        calls=state.calls + (CallEvent(target, arguments),),
    )


def _cr_index(operands):
    if operands and re.fullmatch(r"cr[0-7]", operands[0]):
        return int(operands[0][2:]), operands[1:]
    return 0, operands


def step_compare(state, instruction):
    z3 = require_z3()
    field, args = _cr_index(instruction.operands)
    op = instruction.opcode
    if op in {"cmpwi", "cmplwi"}:
        immediate = _number(args[1]) & 0xFFFF
        if op == "cmpwi" and immediate & 0x8000:
            immediate -= 0x10000
        left, right = state.gpr[_reg(args[0])], _bv32(immediate)
    elif op in {"cmpw", "cmplw"}:
        left, right = state.gpr[_reg(args[0])], state.gpr[_reg(args[1])]
    else:
        raise Unsupported(f"unsupported compare: {op}")
    if op.startswith("cmpl"):
        lt, gt = z3.ULT(left, right), z3.UGT(left, right)
    else:
        lt, gt = left < right, left > right
    cr = CrField(lt, gt, left == right, state.cr[field].so)
    return replace(state, cr=_set(state.cr, field, cr))


def branch_condition(state, opcode):
    field = state.cr[0]
    conditions = {
        "beq": field.eq,
        "bne": require_z3().Not(field.eq),
        "blt": field.lt,
        "bge": require_z3().Not(field.lt),
        "bgt": field.gt,
        "ble": require_z3().Not(field.gt),
    }
    if opcode not in conditions:
        raise Unsupported(f"unsupported conditional branch: {opcode}")
    return conditions[opcode]


@dataclass(frozen=True)
class Outcome:
    condition: object
    state: State


def execute(program, inputs, models, max_steps=1000):
    z3 = require_z3()
    outcomes = []
    pending = [(0, initial_state(inputs), z3.BoolVal(True), frozenset())]
    steps = 0
    while pending:
        pc, state, condition, visited = pending.pop()
        if pc in visited:
            raise Unsupported("loop detected")
        if pc < 0 or pc >= len(program.instructions):
            raise Unsupported(
                f"control flow leaves function at instruction {pc}"
            )
        steps += 1
        if steps > max_steps:
            raise Unsupported("path limit exceeded")
        instruction = program.instructions[pc]
        op = instruction.opcode
        seen = visited | {pc}
        if op == "blr":
            outcomes.append(Outcome(condition, state))
        elif op == "b":
            if len(instruction.operands) != 1:
                raise Unsupported(
                    f"unsupported branch operands: {instruction.operands}"
                )
            target = instruction.operands[0]
            if target not in program.labels:
                raise Unsupported(f"unknown branch target: {target}")
            pending.append((program.labels[target], state, condition, seen))
        elif op in {"beq", "bne", "blt", "bge", "bgt", "ble"}:
            if len(instruction.operands) != 1:
                raise Unsupported(
                    "unsupported conditional branch operands: "
                    f"{instruction.operands}"
                )
            target = instruction.operands[0]
            if target not in program.labels:
                raise Unsupported(f"unknown branch target: {target}")
            predicate = branch_condition(state, op)
            pending.append(
                (
                    program.labels[target],
                    state,
                    z3.And(condition, predicate),
                    seen,
                )
            )
            pending.append(
                (
                    pc + 1,
                    state,
                    z3.And(condition, z3.Not(predicate)),
                    seen,
                )
            )
        elif op in {"cmpwi", "cmplwi", "cmpw", "cmplw"}:
            pending.append(
                (pc + 1, step_compare(state, instruction), condition, seen)
            )
        elif op in {"lbz", "lha", "lhz", "lwz", "stb", "sth", "stw"}:
            pending.append(
                (pc + 1, step_memory(state, instruction), condition, seen)
            )
        elif op == "bl":
            pending.append(
                (pc + 1, step_call(state, instruction, models), condition, seen)
            )
        else:
            pending.append(
                (pc + 1, step_integer(state, instruction), condition, seen)
            )
    if not outcomes:
        raise Unsupported("function has no return path")
    return tuple(outcomes)


LIVE_OUT_GPRS = (1, 2, 3, 4, 13, *range(14, 32))


@dataclass(frozen=True)
class ProofResult:
    status: str
    reason: str = ""
    counterexample: dict[str, str] | None = None


def _call_difference(left, right):
    z3 = require_z3()
    if len(left) != len(right):
        return z3.BoolVal(True)
    differences = []
    for first, second in zip(left, right):
        if first.target != second.target:
            return z3.BoolVal(True)
        differences.extend(
            first_arg != second_arg
            for first_arg, second_arg in zip(
                first.arguments, second.arguments
            )
        )
    return z3.Or(*differences) if differences else z3.BoolVal(False)


def _state_difference(left, right):
    z3 = require_z3()
    differences = [
        left.gpr[index] != right.gpr[index] for index in LIVE_OUT_GPRS
    ]
    differences.append(left.memory != right.memory)
    differences.append(_call_difference(left.calls, right.calls))
    for left_field, right_field in zip(left.cr, right.cr):
        differences.extend(
            (
                left_field.lt != right_field.lt,
                left_field.gt != right_field.gt,
                left_field.eq != right_field.eq,
                left_field.so != right_field.so,
            )
        )
    return z3.Or(*differences)


def prove(target_lines, candidate_lines, timeout_ms=5000):
    z3 = require_z3()
    try:
        inputs = Inputs.create()
        models = CallModels()
        target = execute(parse_program(target_lines), inputs, models)
        candidate = execute(parse_program(candidate_lines), inputs, models)
    except (Unsupported, IndexError, ValueError) as error:
        return ProofResult("unknown", str(error))

    for left in target:
        for right in candidate:
            left_trace = tuple(event.target for event in left.state.calls)
            right_trace = tuple(event.target for event in right.state.calls)
            if left_trace == right_trace:
                continue
            overlap = z3.Solver()
            overlap.set(timeout=timeout_ms)
            overlap.add(left.condition, right.condition)
            if overlap.check() != z3.unsat:
                return ProofResult("unknown", "external call trace differs")

    comparisons = [
        (
            left,
            right,
            z3.And(
                left.condition,
                right.condition,
                _state_difference(left.state, right.state),
            ),
        )
        for left in target
        for right in candidate
    ]
    differences = [difference for _, _, difference in comparisons]
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(z3.Or(*differences))
    result = solver.check()
    if result == z3.unsat:
        return ProofResult("equivalent")
    if result == z3.unknown:
        return ProofResult("unknown", solver.reason_unknown())
    model = solver.model()
    if any(
        (left.state.calls or right.state.calls)
        and z3.is_true(model.eval(difference, model_completion=True))
        for left, right, difference in comparisons
    ):
        return ProofResult(
            "unknown", "difference depends on external call model"
        )
    counterexample = {
        f"r{index}": hex(
            model.eval(inputs.gpr[index], model_completion=True).as_long()
        )
        for index in range(32)
    }
    return ProofResult("different", counterexample=counterexample)
