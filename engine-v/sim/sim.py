#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, tempfile, subprocess
import kast
from enum import Enum
from typing import Optional, List, Union
from collections import defaultdict

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
	def __str__(self):
		to_str = ToString()
		prog = "\n".join(to_str.visit(instr) for instr in self.instrs)
		return f"{self.name}:\n{prog}"
class ResolvedBranch(Instruction):
	branch = Union[Skip, Jump, Branch]
	targets = List[BasicBlock]

# machine state

class MachineState:
	pass
	# FPC : bv<16>
	# Frunning : bool
	# REG : bv<8> [32]
	# RAM : bv<8> [0xffff]



class BitVector:
	def __init__(self, bits, value):
		self.bits = bits
		self.mask = (2 ** self.bits) - 1
		self.value = value
		if self.value is not None:
			assert self.mask & self.value == self.value

	def __getitem__(self, index):
		assert self.value is not None, "this bit vector is symbolic!"
		if isinstance(index, int):
			upper, lower = index, index
		elif isinstance(index, slice):
			upper, lower = index.start, index.stop
		else:
			assert False, f"unsupported index type: {type(index)} ({index})"
		assert self.bits > upper >= 0, f"upper index {upper} out of bounds"
		assert self.bits > lower >= 0, f"lower index {lower} out of bounds"
		assert upper >= lower, "upper bound needs to be >= lower"
		bits = upper - lower + 1
		mask = (2 ** bits) - 1
		value = (self.value >> lower) & mask
		return BitVector(bits=bits,value=value)

	def __eq__(self, other):
		if isinstance(other, BitVector):
			assert other.bits == self.bits
			assert other.value is not None
			return other.value == self.value
		if isinstance(other, int):
			return other == self.value
		assert False, f"unsupported comparison with {other} : {type(other)}"

	def __add__(self, other):
		if isinstance(other, BitVector):
			assert other.bits == self.bits
			assert other.value is not None
			return (other.value + self.value) & self.mask
		if isinstance(other, int):
			return other + self.value
		assert False, f"unsupported comparison with {other} : {type(other)}"

	def __invert__(self):
		assert self.value is not None
		value = (~self.value) & self.mask
		return BitVector(bits=self.bits, value=value)

	def __str__(self):
		figs = (self.bits + 3) // 4
		fmt_string = f"{{:0{figs}x}}"
		return fmt_string.format(self.value)

def cat(a: BitVector, b:BitVector) -> BitVector:
	bits = a.bits + b.bits
	value = a.value << b.bits | b.value
	return BitVector(bits=bits, value=value)

def bv(bits: int, value: int) -> BitVector: return BitVector(bits=bits, value=value)

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
		return Mem(is_store = (instr[8] == 1), reg = instr[8:4] + 0, offset=offset)
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

def dot_cfg(blocks: List[BasicBlock]) -> str:
	bb_names = { bb.name for bb in blocks}
	assert len(bb_names) == len(blocks), "requires unique names"
	def mk_node(bb: BasicBlock) -> str:
		return f'\t{bb.name} [label="{bb.name}"];'
	def mk_edges(bb : BasicBlock) -> List[str]:
		return [f'{bb.name} -> {dst.name};'
				for dst in bb.next]
	dot = ["digraph g {"]
	dot += [mk_node(bb) for bb in blocks]
	for bb in blocks: dot += mk_edges(bb)
	dot += ["}"]
	return "\n".join(dot)

def mk_dot(dot: str, filename: str, fmt=None):
	if fmt is None:
		fmt = os.path.splitext(filename)[1][1:]
	with tempfile.NamedTemporaryFile('w', suffix='.dot', delete=False) as out:
		out.write(dot)
		dotfile = out.name
	cmd = ['dot', '-T' + fmt, dotfile, '-o', filename]
	#cmd = ['sfdp', '-x', '-Goverlap=scale', '-Gdpi=200', '-T' + fmt, dotfile, '-o', filename]
	subprocess.run(cmd, check=True)
	#subprocess.run(['cat', dotfile], check=True)

def load_program(filename) -> List[BasicBlock]:
	with open(filename) as mem:
		program = []
		for addr, line in enumerate(mem):
			instr = BitVector(16, int(line.strip(), 16))
			# program.append(disasm(instr))
			program.append(dbg_disasm(instr, addr))
	bbs = find_basic_blocks(program)
	return bbs

def load_rv32_interpreter() -> List[BasicBlock]:
	program = load_program("rv32i.mem")

	# skip spi boot code
	program = [program[0]] + program[11:]  # remove bb0 .. bb9
	program[0].next = [program[1]]
	program[0].instrs = program[0].instrs[0:4]  # keep init code
	program[1].instrs = program[1].instrs[1:]  # remove some SPI code

	return program


def analyze_rv32_interpreter(program: List[BasicBlock]):
	print("analyzing rv32 interpreter ...")

	mk_dot(dot_cfg(program), filename="cfg.pdf")
	for bb in program: print(bb)

	return

if __name__ == '__main__':
	pp = load_rv32_interpreter()
	analyze_rv32_interpreter(pp)