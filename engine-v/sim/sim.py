#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, tempfile, subprocess
from typing import Optional, List, Union, Tuple

from mf8 import BasicBlock, load_program, MachineState, SymExec, Instruction, BitVecVal
from pysmt.shortcuts import Symbol, BVType, BVExtract, BVConcat, Bool, And, Solver, Not, Or, Ite, Equals, Store, Select, BVAdd, ArrayType, Implies
from pysmt.logics import QF_AUFBV
from sym import simplify

from functools import reduce
import operator


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

def sym_exec_rsicv_add(rs1, rs2, rd, regs):
	res = BVAdd(Select(regs, rs1), Select(regs, rs2))
	regs_n = Store(regs, rd, res)
	return Ite(Equals(rd, BitVecVal(0, 5)), regs, regs_n)

class ArrayValue:
	def __init__(self, array):
		assert array.is_array_value()
		self.default = array.array_value_default().bv_unsigned_value()
		vs = array.array_value_assigned_values_map()
		self.values = { v[0].bv_unsigned_value(): v[1].bv_unsigned_value() for v in vs.items()}
	def __getitem__(self, item):
		return self.values.get(item, self.default)

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
	max_steps = 20 * 100
	# execute ~2 paths:
	#max_steps = 2 * 100
	done, end_state = ex.run(max_steps=max_steps)
	ex.print_state()
	ex.print_mem(ex.st)
	ex.print_path()
	print(ex.taken)
	print(f"DONE? {done}")
	#print("PATHS:")
	#for ii, (cond, st) in enumerate(end_state):
	#	print(str(ii) + ") " + cond.serialize())
	#	ex.print_mem(st)

	solver = Solver(name="z3", logic=QF_AUFBV)

	# check for completeness
	conds = reduce(Or, (cond for cond, st in end_state))
	complete = not solver.is_sat(Not(conds))
	print(f"Complete? {complete}")

	# check result of every path:
	def to_mem_addrs(reg_index):
		return reversed([0xf100 + reg_index*4 + jj for jj in range(4)])

	def relate_regs(mem, regs):
		def relate_loc(ii):
			mem_locs = [Select(mem, BitVecVal(addr, 16)) for addr in to_mem_addrs(ii)]
			return Equals(cat(*mem_locs), Select(regs, BitVecVal(ii, 5)))
		return reduce(And, [relate_loc(ii) for ii in range(32)])


	def name_value(solver, name, val):
		sym = Symbol(name, val.get_type())
		solver.add_assertion(Equals(sym, val))

	def locs_to_str(name, array, locs):
		return "; ".join(f"{name}[{ii:04x}] = 0x{array[ii]:02x}" for ii in sorted(list(set(locs))))

	for cond, end_st in end_state:
		# create clean slate solver
		solver = Solver(name="z3", logic=QF_AUFBV, generate_models=True)
		# symbolically execute the RISC-V add
		regs = Symbol('RV32I_REGS', ArrayType(BVType(5), BVType(32)))
		regs_n = sym_exec_rsicv_add(rs1=rs1, rs2=rs2, rd=rd, regs=regs)
		name_value(solver, "DBG_RV32I_REGS_N", regs_n)
		# add mem to regs relation
		mem_orig = orig_state.MEM.array()
		pre = And(And(cond, relate_regs(mem_orig, regs)), Equals(Select(regs, BitVecVal(0, 5)), BitVecVal(0, 32)))
		mem_n = end_st.MEM.array()
		post = relate_regs(mem_n, regs_n)
		# DEBUG: add symbols for every memory write
		mem_data = end_st._mem._data
		mem_write_locs = [Symbol(f"DBG_MF8_MEM_WRITE_LOC_{ii}", BVType(16)) for ii in range(len(mem_data))]
		for sym, (expr, _) in zip(mem_write_locs, mem_data):
			solver.add_assertion(Equals(sym, expr))
		# now check for validity
		formula = Implies(pre, post)
		correct = solver.is_valid(formula)
		print(f"Correct? {correct}")
		if not correct:
			print("Model:")
			rs1_val = solver.get_value(rs1).bv_unsigned_value()
			rs2_val = solver.get_value(rs2).bv_unsigned_value()
			rd_val = solver.get_value(rd).bv_unsigned_value()
			regs_val = ArrayValue(solver.get_value(regs))
			regs_n_val = ArrayValue(solver.get_value(regs_n))
			mem_val = ArrayValue(solver.get_value(mem_orig))
			mem_n_val = ArrayValue(solver.get_value(mem_n))
			reg_addrs = [rd_val, rs1_val, rs2_val]
			mem_write_locs_vals = [solver.get_value(ll).bv_unsigned_value() for ll in mem_write_locs]
			mem_addrs = reduce(operator.add, [list(to_mem_addrs(ii)) for ii in reg_addrs]) + mem_write_locs_vals
			print(f"R[{rd_val}] <- R[{rs1_val}] + R[{rs2_val}]")
			print(f"Pre:  {locs_to_str('R', regs_val, reg_addrs)}")
			print(f"      {locs_to_str('M',  mem_val, mem_addrs)}")
			print(f"Post: {locs_to_str('R', regs_n_val, reg_addrs)}")
			print(f"      {locs_to_str('M',  mem_n_val, mem_addrs)}")
			print(f"MEM write addresses: {[f'0x{loc:04x}' for loc in mem_write_locs_vals]}")
			#print(regs_n_val)
			#print(mem_val)
			break







	return

if __name__ == '__main__':
	pp = load_rv32_interpreter()
	analyze_rv32_interpreter(*pp)
