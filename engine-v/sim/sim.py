#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, tempfile, subprocess
from typing import Optional, List, Union

from mf8 import BasicBlock, load_program

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