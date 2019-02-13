#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

# def bv(bits: int, value: int) -> BitVector: return BitVector(bits=bits, value=value)