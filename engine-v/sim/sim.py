#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, tempfile, subprocess
from typing import Optional, List, Union, Tuple

from mf8 import BasicBlock, load_program, MachineState, SymExec, Instruction, BitVecVal
from pysmt.shortcuts import Symbol, BVType, BVExtract, BVConcat, Bool, And, Solver, Not
from pysmt.logics import QF_AUFBV
from sym import simplify

from functools import reduce



def cat(*vargs):
	return reduce(BVConcat, vargs)

def dot_cfg(blocks: List[BasicBlock]) -> str:
	bb_names = { bb.name for bb in blocks}
	assert len(bb_names) == len(blocks), "requires unique names"
	def mk_node(bb: BasicBlock) -> str:
		return f'\t{bb.name} [label="{bb.name} ({bb.priority})"];'
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

def load_rv32_interpreter() -> Tuple[List[Instruction], List[BasicBlock]]:
	program, bbs = load_program("rv32i.mem")

	# skip spi boot code
	#program = [program[0]] + program[11:]  # remove bb0 .. bb9
	#program[0].next = [program[1]]
	#program[0].instrs = program[0].instrs[0:4]  # keep init code
	#program[1].instrs = program[1].instrs[1:]  # remove some SPI code

	return program, bbs


class SymbolicExecutionEngine:
	def __init__(self, program, start_state, exec):
		self.start = start_state.update(PC=simplify(start_state.PC))
		self.st = self.start
		self.program = program
		self.exec = exec
		self.path_conditions = []
		self.taken = []
		self.solver = None

	@property
	def path_condition(self):
		if len(self.path_conditions) == 0:
			return Bool(True)
		else:
			return reduce(And, self.path_conditions)

	def is_feasible(self, cond):
		return self.solver.is_sat(cond)

	def pick_next_pc(self, next_pc):
		cond, tru, fal = next_pc
		cond = simplify(cond)
		if cond.is_true(): taken = True
		elif cond.is_false(): taken = False
		elif self.is_feasible(cond): taken = True
		elif self.is_feasible(Not(cond)): taken = False
		else: raise RuntimeError(f"Infeasible condition: {cond}")
		self.solver.push()
		self.taken.append(taken)
		path_cond = cond if taken else simplify(Not(cond))
		self.solver.add_assertion(path_cond)
		self.path_conditions.append(path_cond)
		return tru if taken else fal

	def step(self):
		assert self.st.PC.is_constant(), f"PC: {self.st.PC.serialize()}"
		pc_concrete = self.st.PC.bv_unsigned_value()
		instr = self.program[pc_concrete]
		print(f"Step: {pc_concrete:04x} {instr}")
		next_st, next_pc = self.exec(instr, self.st)
		return next_st.update(PC=simplify(self.pick_next_pc(next_pc)))

	def run(self, max_steps = 100):
		self.st = self.start
		self.path_conditions = []
		self.taken = []
		self.solver = Solver(logic=QF_AUFBV)
		start_pc = self.start.PC.bv_unsigned_value()
		for ii in range(max_steps):
			self.st = self.step()
			if self.st.PC.bv_unsigned_value() == start_pc:
				return True
		return False

	def print_state(self):
		print(f"PC: {self.st.PC.bv_unsigned_value()}")
		print(self.st.simplify())

	def print_mem(self):
		print("MEM:")
		for index, val in self.st._mem._data:
			print(f"{index} -> {val}")

	def print_path(self):
		print("Path Conditons:")
		for cond, taken in zip(self.path_conditions, self.taken):
			if cond.is_true(): continue
			print(f"{cond.serialize()}")

def analyze_rv32_interpreter(program: List[Instruction], bbs: List[BasicBlock]):
	print("analyzing rv32 interpreter ...")


	mk_dot(dot_cfg(bbs), filename="cfg.pdf")
	for bb in program: print(bb)

	# start at MainStart @ 0x0056
	start_pc = 0x56
	# symbolic instruction: ADD rs2, rs1, rd
	funct7 = BitVecVal(0, 7)
	rs2 = Symbol("RV32I_ADD_rs2", BVType(5))
	rs1 = Symbol("RV32I_ADD_rs1", BVType(5))
	funct3 = BitVecVal(0b00, 3) # ADD
	rd = Symbol("RV32I_ADD_rd", BVType(5))
	opcode = BitVecVal(0b0110011, 7) # OP
	#RV32I_instr = Symbol("RV32IInstruction", BVType(32))
	RV32I_instr = cat(funct7, rs2, rs1, funct3, rd, opcode)
	print(f"Symbolically executing: {RV32I_instr}")

	# interpreter
	orig_state = MachineState().update(PC=BitVecVal(start_pc, 16))
	def place_instr(loc, instr, st) -> MachineState:
		# make sure PC fits into two registers
		assert loc & 0xffff == loc
		msb, lsb = BitVecVal(loc >> 8, 8), BitVecVal(loc & 0xff, 8)
		st = st.update(R=st.R.update(10, lsb).update(11, msb))
		instr_parts = [BVExtract(instr, *jj) for jj in ((jj*8, jj*8+7) for jj in range(4))]
		if isinstance(loc, int):
			instr_locs = [loc+ii for ii in range(4)]
		else:
			assert False, "TODO: support symbolic address"
		mem = st.MEM
		for loc, val in zip(instr_locs, instr_parts):
			mem = mem.update(loc, val)
		return st.update(MEM = mem)
	orig_state = place_instr(loc=0, instr=RV32I_instr, st=orig_state)

	mf8_ex = SymExec()
	ex = SymbolicExecutionEngine(program=program, start_state=orig_state, exec=mf8_ex.exec)

	print()
	print()
	print("SYM EXEC")
	print("--------")
	ex.run()
	ex.print_state()
	ex.print_mem()
	ex.print_path()



	return

if __name__ == '__main__':
	pp = load_rv32_interpreter()
	analyze_rv32_interpreter(*pp)
