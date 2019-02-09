#!/usr/bin/env bash

# WARN: currently (2019-02-08) only works with yosys from:
# https://github.com/ucb-bar/yosys/commits/firrtl+modules+shiftfixes+debug
# @ 365426743ace75c802861a1ad0eefcbd25fa0a07

yosys -p "read_verilog hdl/mf8_core.v ; proc ; opt ; pmuxtree ; opt ; write_firrtl mf8.fir"
