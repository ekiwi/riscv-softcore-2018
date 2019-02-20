#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2019, University of California

# some common classes used for symbolic execution

from pysmt.shortcuts import Symbol, BV, ArrayType, Select, Store, Equals, get_env, BVExtract
import pysmt.simplifier
from functools import reduce


class Simplifier(pysmt.simplifier.Simplifier):
	"""
	Allows us to add some custom simplifications to make symbolic execution easier.
	"""
	def __init__(self, env=None):
		super().__init__(env)

	def walk_bv_extract(self, formula, args, **kwargs):
		# TODO: is this ok? can we call our self recursively?
		def walk_ext(ext):
			return self.walk_bv_extract(ext, [ext.arg(0)])
		if args[0].is_bv_constant():
			return super().walk_bv_extract(formula, args, **kwargs)
		msb_outer, lsb_outer = formula.bv_extract_end(), formula.bv_extract_start()
		width_outer = 1 + msb_outer - lsb_outer
		if args[0].is_bv_extract():
			inner = walk_ext(args[0])
			lsb_inner = inner.bv_extract_start()
			lsb_new = lsb_inner + lsb_outer
			msb_new = lsb_new + width_outer - 1
			assert msb_new >= lsb_new
			return self.manager.BVExtract(inner.arg(0), lsb_new, msb_new)
		if args[0].is_bv_concat():
			left, right = args[0].args()
			lsb_left = right.get_type().width
			# drop left most input if it is not reflected in output
			if msb_outer < lsb_left:
				assert msb_outer >= lsb_outer
				return walk_ext(self.manager.BVExtract(right, lsb_outer, msb_outer))
			# drop right most input if it is not reflected in output
			elif lsb_outer >= lsb_left:
				assert msb_outer - lsb_left >= lsb_outer - lsb_left
				return walk_ext(self.manager.BVExtract(left, lsb_outer - lsb_left, msb_outer - lsb_left))
			# push extract into concat
			else:
				left_extract = walk_ext(self.manager.BVExtract(left, 0, msb_outer - lsb_left))
				right_extract = walk_ext(self.manager.BVExtract(right, lsb_outer, lsb_left - 1))
				return self.manager.BVConcat(left_extract, right_extract)
		return self.manager.BVExtract(args[0], lsb_outer, msb_outer)

_simplifier = Simplifier(get_env())

def simplify(formula):
	return _simplifier.simplify(formula)


class ConcreteAddrMem:
	def __init__(self, prefix, suffix, typ, size, _data=None):
		self.prefix = prefix
		if _data is None:
			self._data = [Symbol(f'{prefix}{ii}{suffix}', typ) for ii in range(size)]
		else:
			self._data = _data
	def update(self, index, value):
		assert isinstance(index, int), f"memory '{self.prefix}' requires a constant address not: `{index}`"
		assert len(self._data) > index >=0
		new_data = self._data[0:index] + [value] + self._data[index+1:]
		return ConcreteAddrMem(self.prefix, suffix='', typ=None, size=None, _data=new_data)
	def __getitem__(self, item):
		return self._data[item]

def make_bv(val, typ):
	if isinstance(val, int):
		val = BV(val, typ.width)
	assert val.get_type() == typ
	return val

def definitely_alias(a, b):
	return simplify(Equals(a, b)).is_true()
def may_alias(a, b):
	return not simplify(Equals(a, b)).is_false()

class SymbolicAddrMem:
	def __init__(self, name, addr_typ, data_typ, data=None):
		assert addr_typ.is_bv_type()
		self._addr_typ = addr_typ
		self._data_typ = data_typ
		self._name = name
		self._data = [] if data is None else data
	def update(self, index, value):
		index, value = make_bv(index, self._addr_typ), make_bv(value, self._data_typ)
		# filter all definite aliases, as they will be overwritten
		data = [dd for dd in self._data if not definitely_alias(dd[0], index)]
		data += [(index, value)]
		return SymbolicAddrMem(name=self._name, addr_typ=self._addr_typ, data_typ=self._data_typ, data=data)
	def array(self, data=None):
		data = self._data if data is None else data
		array = Symbol(self._name, ArrayType(self._addr_typ, self._data_typ))
		return reduce(lambda aa, dd: Store(aa, *dd), data, array)
	def __getitem__(self, index):
		index = make_bv(index, self._addr_typ)
		# try to find a sure alias, stop when there might be an alias
		for entry in reversed(self._data):
			if definitely_alias(entry[0], index):
				return entry[1]
			if may_alias(entry[0], index):
				break
		# collect all possible aliases, create array and return
		possible_aliases = [dd for dd in self._data if may_alias(dd[0], index)]
		return Select(self.array(possible_aliases), index)
	def __str__(self): return str(self._data)