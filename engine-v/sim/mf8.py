#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import kast
from enum import Enum
from typing import Optional, List, Union, Tuple
from collections import defaultdict
from bv import *


class Instruction(kast.Node):
	meta = Optional[str]
class IO(Instruction):
	output = bool
	reg = int
	fsr = int
class AluOp(Enum):
	Sbc = 0x2
	Add = 0x3
	Sub = 0x6
	Adc = 0x7
	And = 0x8
	Xor = 0x9
	Or = 0xa
	Mov = 0xb
class AluRegReg(Instruction):
	op = AluOp
	dst = int
	src = int
class AluImmOp(Enum):
	Sub = 0x5
	Or = 0x6
	And = 0x7
	Ld = 0xe
class AluImm(Instruction):
	op = AluImmOp
	reg = int
	imm = int
class AluRegOp(Enum):
	Swap = 0x2
	Inc = 0x3
	Asr = 0x5
	Lsr = 0x6
	Ror = 0x7
	Dec = 0xa
class AluReg(Instruction):
	op = AluRegOp
	reg = int
class Skip(Instruction):
	bit_is_one = bool
	reg = int
	bit = int
class Mem(Instruction):
	is_store = bool
	reg = int
	offset = int
class BranchCond(Enum):
	CS = 0b00
	EQ = 0b01
	CC = 0b10
	NE = 0b11
class Branch(Instruction):
	cond = BranchCond
	offset = int
class Jump(Instruction):
	offset = int
class BasicBlock:
	def __init__(self, name: str):
		self.name = name
		self.instrs = []
		self.next = []
		self.priority = -1	# will carry a valid value after topological sort
	def __str__(self):
		to_str = ToString()
		prog = "\n".join(to_str.visit(instr) for instr in self.instrs)
		return f"{self.name}:\n{prog}"
class ResolvedBranch(Instruction):
	branch = Union[Skip, Jump, Branch]
	targets = List[BasicBlock]

def fsr(addr: int) -> str:
	map = {
		0x00: 'UART_TX',
		0x08: 'SPI_CS',
		0x10: 'SPI_SCK',
		0x18: 'SPI_IO',
		0x3f: 'FLAGS'
	}
	return map[addr]

def signed(val: BitVector) -> int:
	if val.bits < 2: return 0
	sign, mag = val[val.bits-1], val[val.bits-2:0]
	return mag + 0 if sign == 0 else -(~mag + 1)

# funny: instruction set is very similar to AVR, some of the encoding is almost (?) the same
# checkout https://www.microchip.com/webdoc/avrassembler/avrassembler.wb_instruction_list.html
def disasm(instr: BitVector) -> Instruction:
	if instr[15:12] == 0xb:
		return IO(output = (instr[11] == 1), reg = instr[8:4] + 0, fsr = cat(instr[9], instr[3:0]) + 0)
	# ALU REG
	alu_ops = { op.value: op for op in AluOp }
	if instr[15:10].value in alu_ops:
		return AluRegReg(op = alu_ops[instr[15:10].value], dst = instr[8:4] + 0, src = cat(instr[9], instr[3:0]) + 0)
	# ALU IMM
	alu_imm_ops = { op.value: op for op in AluImmOp }
	if instr[15:12].value in alu_imm_ops:
		return AluImm(op = alu_imm_ops[instr[15:12].value], reg = instr[7:4] + 16, imm = cat(instr[11:8], instr[3:0]) + 0)
	# SKIP
	if instr[15:10] == 0x3f:
		return Skip(bit_is_one = (instr[9] == 1), reg = instr[8:4] + 0, bit = instr[2:0] + 0)
	# LD/ST
	if instr[15:8].value & 0xd2 in [0x80, 0x82]:
		offset = instr[1:0] + 0  # TODO: is this correct? what about xor?
		return Mem(is_store = (instr[9] == 1), reg = instr[8:4] + 0, offset=offset)
	# UOP
	if instr[15:9] == 0x4a:
		op = next(op for op in AluRegOp if op.value == (instr[3:0] + 0))
		return AluReg(op = op, reg = instr[8:4] + 0)
	# RJMP
	if instr[15:12] == 0xC:
		return Jump(offset = signed(instr[11:0]))
	# BRANCH
	if instr[15:11] == 0x1e and instr[2:1] == 0:
		cond = next(cc for cc in BranchCond if cc.value == (cat(instr[10], instr[0]) + 0))
		return Branch(cond = cond, offset = signed(instr[9:3]))
	assert False, f"unknown instruction: {instr}"

def dbg_disasm(instr: BitVector, addr: int) -> Instruction:
	meta = f"{addr:04x}: {instr.value:04x}"
	return disasm(instr).set(meta=meta)

class ToString:
	def visit(self, node: Instruction, addr: Optional[int] = None) -> str:
		method = 'visit_' + node.__class__.__name__
		string = getattr(self, method)(node, addr)
		if node.meta is not None:
			return string + " \t\t;" + node.meta
		else:
			return string
	def visit_IO(self, instr: IO, _) -> str:
		return f"{'out' if instr.output else 'in'} r{instr.reg}, {fsr(instr.fsr)}"
	def visit_AluRegReg(self, instr: AluRegReg, _) -> str:
		return f"{instr.op.name.lower()} r{instr.dst}, r{instr.src}"
	def visit_AluImm(self, instr: AluImm, _) -> str:
		return f"{instr.op.name.lower()}i r{instr.reg}, {instr.imm}"
	def visit_AluReg(self, instr: AluReg, _) -> str:
		return f"{instr.op.name.lower()} r{instr.reg}"
	def visit_Skip(self, instr: Skip, _) -> str:
		return f"sbr{'s' if instr.bit_is_one else 'c'} r{instr.reg}, {instr.bit}"
	def visit_Mem(self, instr: Mem, _) -> str:
		if instr.is_store: return f"st Z+{instr.offset}, r{instr.reg}"
		else:              return f"ld r{instr.reg}, Z+{instr.offset}"
	def visit_Branch(self, instr: Branch, addr: Optional[int] = None) -> str:
		if addr is None: return f"br{instr.cond.name.lower()} 0x{instr.offset:04x}"
		else:            return f"br{instr.cond.name.lower()} 0x{addr + 1 + instr.offset:04x}"
	def visit_Jump(self, instr: Jump, addr: Optional[int] = None) -> str:
			if addr is None: return f"rjmp 0x{instr.offset:04x}"
			else:            return f"rjmp 0x{addr + 1 + instr.offset:04x}"
	def visit_ResolvedBranch(self, instr: ResolvedBranch, _) -> str:
		return f"{self.visit(instr.branch)} ; {' '.join(tt.name for tt in instr.targets)}"
		#if isinstance(instr.branch, Skip):
		#	return f"br{'s' if instr.branch.bit_is_one else 'c'} r{instr.branch.reg}, {instr.branch.bit}, {instr.targets[1].name}"

def find_basic_blocks(program: List[Instruction]):
	# identify branch targets and sources
	targets = defaultdict(list)
	branches = defaultdict(list)
	def add_transition(src, offset):
		dst = src + 1 + offset
		targets[dst].append(src)
		branches[src].append(dst)
	for addr, instr in enumerate(program):
		if isinstance(instr, Jump):
			add_transition(addr, instr.offset)
		elif isinstance(instr, Skip):
			add_transition(addr, 0)
			add_transition(addr, 1)
		elif isinstance(instr, Branch):
			add_transition(addr, 0)
			add_transition(addr, instr.offset)
	# create basic blocks
	bbs = defaultdict(lambda : BasicBlock("bb_na"))
	bb = bbs[0]
	bb.name = "entry"
	ii = 0
	for addr, instr in enumerate(program):
		if addr in targets:
			if len(bb.next) == 0: # bbs that are fall through
				bb.next = [bbs[addr]]
			bb = bbs[addr]
			bb.name = f"bb{ii}"
			ii += 1
		if addr in branches:
			tts = [bbs[dst] for dst in branches[addr]]
			bb.instrs.append(ResolvedBranch(branch=instr, targets=tts))
			bb.next = tts
		else:
			bb.instrs.append(instr)
	blocks = [ii[1] for ii in sorted(bbs.items(), key=lambda ii: ii[0]) if len(ii[1].instrs) > 0]
	# sanity check blocks:
	for ii, block in enumerate(blocks):
		last = block.instrs[-1]
		if isinstance(last, ResolvedBranch):
			assert last.targets == block.next
		else:
			assert block.next == [blocks[ii+1]]
	return blocks

def topo_sort_bbs(entry: BasicBlock):
	seen = set()
	res = []
	def visit(node):
		if node in seen or node in res: return
		seen.add(node)
		for bb in node.next: visit(bb)
		res.append(node)
	visit(entry)
	for ii, bb in enumerate(list(reversed(res))):
		bb.priority = ii

def load_program(filename) -> Tuple[List[Instruction], List[BasicBlock]]:
	with open(filename) as mem:
		program = []
		for addr, line in enumerate(mem):
			instr = BitVector(16, int(line.strip(), 16))
			# program.append(disasm(instr))
			program.append(dbg_disasm(instr, addr))
	bbs = find_basic_blocks(program)
	topo_sort_bbs(bbs[0])
	return program, bbs

# TODO: this currently implements AVR semantics ... we might need to adjust this model as we learn more about
#       the correct MF8 semantics
# TODO: for now this will only support 100% concrete instructions!
#       only state can be symbolic!

# machine state

class MachineState:
	def __init__(self):
		self._pc = BitVector(16, 0)
		self._r = [BitVector(8, 0) for _ in range(32)]
		self._mem = [BitVector(8, 0) for _ in range(1 << 16)]
		self._c = BitVector(1, 0)
		self._z = BitVector(1, 0)

	@property
	def PC(self): return self._pc
	@property
	def R(self): return self._r
	@property
	def MEM(self): return self._mem
	@property
	def C(self): return self._c
	@property
	def Z(self): return self._z
	@property
	def SREG(self): return zext(cat(self._z, self._c), 6)
	def update(self, **kwars) -> "MachineState":
		arg_names = {'PC', 'R', 'MEM', 'C', 'Z'}
		for name in kwars.keys():
			assert name in arg_names
		st = MachineState()
		for name in arg_names:
			attr = f"_{name.lower()}"
			val = kwars.get(name, self.__getattribute__(attr))
			st.__setattr__(attr, val)
		return st
	def diff(self, other: "MachineState"):
		assert isinstance(other, MachineState)
		delta = [r1 for r1, r0 in zip(other._r, self._r) if r1 != r0]
		if self.PC != other.PC: delta += [other.PC]
		if self.Z != other.Z: delta += [other.Z]
		if self.C != other.C: delta += [other.C]
		return delta


	def __str__(self):
		# TODO: nicer output with register table
		lines = [
			"MF8 Machine State:",
			f"PC: {self.PC}",
			*[f"R{ii: 2}: {reg}" for ii, reg in enumerate(self.R)],
			f"Z: {self.Z}, C: {self.C}",
			f"MEM: {self.MEM}"
		]
		return "\n".join(lines)
	def __repr__(self): return str(self)

class Exec:
	def __init__(self, pc_inc: int = 1):
		self.pc_width = 16
		self.pc_inc = BitVector(self.pc_width, pc_inc)
		self.taint = {}
		self.track_taint = True

	def taint_diff(self, st, st_next, instr):
		for dd in st.diff(st_next):
			self.taint[dd] = instr


	def exec(self, instr: Instruction, state):
		method = 'exec_' + instr.__class__.__name__
		ret = getattr(self, method)(instr, state)
		assert isinstance(ret, MachineState)
		st_next = ret
		pc_next = ret.PC + self.pc_inc
		return st_next, pc_next

	def visit_IO(self, instr: IO, _):
		raise RuntimeError(f"IO instructions not supported! {instr}")
	@staticmethod
	def _arith(op, a, b, c):
		a9, b9, c9 = zext(a, 1), zext(b, 1), zext(c, 8)
		op = {AluImmOp.Sub: AluOp.Sub}.get(op, op)
		res = {
			AluOp.Adc: lambda: (a9 + b9) + c9,
			AluOp.Add: lambda: a9 + b9,
			AluOp.Sbc: lambda: (a9 - b9) - c9,
			AluOp.Sub: lambda: a9 - b9,
		}[op]()
		res8 = res[0:7]
		z = res8 == BitVector(8, 0)
		c = res[8]
		return res8, z, c