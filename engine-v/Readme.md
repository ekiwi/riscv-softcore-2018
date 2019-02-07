# Engine-V

## compiling with verilator

```.sh
verilator -Wno-fatal -Ihdl/ --cc hdl/tb.v --exe hdl/tb.cc
make -j -C obj_dir/ -f Vtb.mk
```

## memory files

There are three memories that need to be initialized:

1) **SPI-Flash**: `./make_spiflash_hex.py ../../engine-V/verilator/images/I-ADD-01.bin spiflash.hex`
2) **RAM**: `cp ../../engine-V/verilator/images/I-ADD-01.mem riscv.mem`
3) **Microcode ROM**: `cp ../../engine-V/verilator/build/rv32i.mem .`

## launching the simulation

```.sh
./obj_dir/Vtb
```

## comparing the output

You can compare the output to the reference output found in
`../../engine-V/verilator/references/`.
