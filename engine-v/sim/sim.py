#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os

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

def fsr(addr: BitVector) -> str:
	map = {
		0x00: 'UART_TX',
		0x08: 'SPI_CS',
		0x10: 'SPI_SCK',
		0x18: 'SPI_IO',
		0x3f: 'FLAGS'
	}
	assert addr.value in map
	return map[addr.value]

def signed(val: BitVector) -> int:
	if val.bits < 2: return 0
	sign, mag = val[val.bits-1], val[val.bits-2:0]
	return mag + 0 if sign == 0 else -(~mag + 1)

# funny: instruction set is very similar to AVR, some of the encoding is almost (?) the same
# checkout https://www.microchip.com/webdoc/avrassembler/avrassembler.wb_instruction_list.html
def disasm(instr: BitVector, addr: int) -> str:
	# RJMP
	if instr[15:12] == 0xC:
		rel = signed(instr[11:0])
		return f"rjmp 0x{addr + 1 + rel:04x}"
	if instr[15:12] == 0xb:

	if instr[15:12] == 0xb:
		name = "out" if instr[11] == 1 else "in"
		reg = instr[8:4] + 0
		fsr_addr = cat(instr[9], instr[3:0])
		return f"{name} r{reg}, {fsr(fsr_addr)}"
	# ALU REG
	alu_ops = {
		0x2: 'sbc', 0x3: 'add', 0x6: 'sub', 0x7: 'adc', 0x8: 'and', 0x9: 'xor', 0xa: 'or', 0xb: 'mov'
	}
	if instr[15:10].value in alu_ops:
		name = alu_ops[instr[15:10].value]
		dst = instr[8:4] + 0
		src = cat(instr[9], instr[3:0]) + 0
		return f"{name} r{dst}, r{src}"
	alu_imm_ops = {
		0x7: 'andi', 0x6: 'ori', 0x5: 'subi', 0xe: 'ldi'
	}
	# ALU IMM
	if instr[15:12].value in alu_imm_ops:
		name = alu_imm_ops[instr[15:12].value]
		reg = instr[7:4] + 16
		imm = cat(instr[11:8], instr[3:0]) + 0
		return f"{name} r{reg}, {imm}"
	# SKIP
	if instr[15:10] == 0x3f:
		name = "sbrs" if instr[9] == 1 else "sbrc"
		reg = instr[8:4] + 0
		bit = instr[2:0] + 0
		return f"{name} r{reg}, {bit}"
	# LD/ST
	if instr[15:8].value & 0xd2 in [0x80, 0x82]:
		reg = instr[8:4] + 0
		is_st_not_ld = instr[8] == 1
		offset = instr[1:0] + 0 # TODO: is this correct? what about xor?
		if is_st_not_ld: return f"st Z+{offset}, r{reg}"
		else:            return f"ld r{reg}, Z+{offset}"
	# UOP
	if instr[15:9] == 0x4a:
		ops = {0x2: 'swap', 0x3: 'inc', 0x5: 'asr', 0x6: 'lsr', 0x7: 'ror', 0xa: 'dec'}
		reg = instr[8:4] + 0
		name = ops[instr[3:0] + 0]
		return f"{name} r{reg}"
	# BRANCH
	if instr[15:11] == 0x1e and instr[2:1] == 0:
		conds = { 0b00 : 'cs', 0b01: 'eq', 0b10: 'cc', 0b11: 'ne' }
		cond = conds[cat(instr[10], instr[0]).value]
		rel = signed(instr[10:3])
		return f"br{cond} 0x{addr + 1 + rel:04x}"



	assert False, f"unknown instruction: {instr}"

def main():
	if len(sys.argv) > 2:
		print(f"{sys.argv[0]} [image.mem]")
		sys.exit(1)
	elif len(sys.argv) == 2:
		mem_file = sys.argv[1]
	else:
		mem_file = "../rv32i.mem"
	with open(mem_file) as mem:
		addr = 0
		for line in mem:
			value = int(line.strip(), 16)
			mnemonic = disasm(BitVector(16, value), addr)
			print(f"{addr:04x}: {value:04x} {mnemonic}")
			addr += 1


if __name__ == '__main__':
	main()