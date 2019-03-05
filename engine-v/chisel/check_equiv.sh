#!/usr/bin/env bash
DUT=addsub8


~/d/yosys-ucb/yosys -p "
      read_verilog ../hdl/${DUT}.v
      rename $DUT ref
      proc
      memory
      flatten ref
      hierarchy -top ref
      read_verilog ${DUT}.v
      rename $DUT new
      proc
      memory
      flatten new
      equiv_make ref new equiv
      hierarchy -top equiv
      clean -purge
      equiv_simple -seq 5
      equiv_status -assert
    "