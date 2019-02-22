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
	# WARNING: CVC4 seems to have trouble with incremental solving
	def __init__(self, program, start_state, semantics, smt_engine="z3"):
		self.start = start_state.update(PC=simplify(start_state.PC))
		self.st = self.start
		self.program = program
		self.semantics = semantics
		self.path_conditions = []
		self.taken = []
		self.solver = None
		self.branch_count = 0
		self.smt_engine = smt_engine

	def _push_path_condition(self, taken, cond):
		self.taken.append(taken)
		self.path_conditions.append(cond)
		self.solver.push()
		self.solver.add_assertion(cond)
	def _pop_path_condition(self):
		self.solver.pop()
		return self.taken.pop(), self.path_conditions.pop()


	@property
	def path_condition(self):
		pcs = [cond for cond in self.path_conditions if not cond.is_constant()]
		if len(pcs) == 0:
			return Bool(True)
		else:
			return reduce(And, pcs)

	def is_feasible(self, cond):
		is_sat = self.solver.is_sat(self.path_condition)
		#print("feasible?")
		#print(cond.serialize())
		#print("assuming:")
		#print(self.path_condition)
		#print(f"-> {is_sat}")
		return is_sat

	def pick_next_pc(self, next_pc):
		cond, tru, fal = next_pc
		if len(self.taken) > self.branch_count:
			ret = tru if self.taken[self.branch_count] else fal
			self.branch_count += 1
			return ret
		cond = simplify(cond)
		if cond.is_true(): taken = True
		elif cond.is_false(): taken = False
		elif self.is_feasible(cond): taken = True
		elif self.is_feasible(Not(cond)): taken = False
		else: raise RuntimeError(f"Infeasible condition: {cond}")
		self._push_path_condition(taken, cond if taken else simplify(Not(cond)))
		self.branch_count += 1
		return tru if taken else fal

	def backtrack(self):
		found_branch = False
		for _ in reversed(range(len(self.taken))):
			taken, cond = self._pop_path_condition()
			#self.solver.pop()
			# if the cond is constant, then there is no other way to take that branch under current assumptions
			if cond.is_constant(): continue
			# if taken is False, we already explored all feasible directions
			if not taken: continue
			# if inverted condition is not feasible, then there is not other way to take that branch under current assumptions
			if not self.is_feasible(Not(cond)): continue
			# if we get here, we have found a feasible invertible branch!
			found_branch = True
			break
		if not found_branch: return False
		self._push_path_condition(False, simplify(Not(cond)))
		self.branch_count = 0
		self.st = self.start
		return True

	def step(self):
		assert self.st.PC.is_constant(), f"PC: {self.st.PC.serialize()}"
		pc_concrete = self.st.PC.bv_unsigned_value()
		instr = self.program[pc_concrete]
		print(f"Step: {pc_concrete:04x} {instr}")
		next_st, next_pc = self.semantics.exec(instr, self.st)
		return next_st.update(PC=simplify(self.pick_next_pc(next_pc)))

	def run(self, max_steps = 100):
		self.st = self.start
		self.path_conditions = []
		self.taken = []
		self.solver = Solver(name=self.smt_engine, logic=QF_AUFBV)
		start_pc = self.start.PC.bv_unsigned_value()
		end_states = []
		for ii in range(max_steps):
			self.st = self.step()
			if self.st.PC.bv_unsigned_value() == start_pc:
				end_states.append((self.path_condition, self.st))
				if not self.backtrack():
					return True, end_states
		return False, end_states

	def print_state(self):
		print(f"PC: {self.st.PC.bv_unsigned_value()}")
		print(self.st.simplify())

	def print_mem(self, st):
		print("MEM:")
		taint = lambda x: self.semantics.taint.get(x, "")
		for index, val in st._mem._data:
			print(f"{index.serialize()} -> {val.serialize()}")
			print(f"{taint(index)} -> {taint(val)}")


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
	ex = SymbolicExecutionEngine(program=program, start_state=orig_state, semantics=mf8_ex)

	print()
	print()
	print("SYM EXEC")
	print("--------")
	# execute all 16 paths:
	#max_steps = 20 * 100
	# execute ~2 paths:
	max_steps = 2 * 100
	done, end_state = ex.run(max_steps=max_steps)
	ex.print_state()
	ex.print_mem(ex.st)
	ex.print_path()
	print(ex.taken)
	print(f"DONE? {done}")
	print("PATHS:")
	for ii, (cond, st) in enumerate(end_state):
		print(str(ii) + ") " + cond.serialize())
		ex.print_mem(st)



	return

if __name__ == '__main__':
	pp = load_rv32_interpreter()
	analyze_rv32_interpreter(*pp)
