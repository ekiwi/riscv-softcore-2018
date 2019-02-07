#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# based on concat_up5k.py and bin2hex.py
# from engine-v sources

# use like this:
# ./make_spiflash_hex.py ../../engine-V/verilator/images/I-ADD-01.bin spiflash.hex

import sys, os


assert len(sys.argv) == 3, f"{sys.argv[0]} IN.bin OUT.bin"
_,program_bin, spiflash_bin = sys.argv
out_format = spiflash_bin.split('.')[-1]
assert out_format in ['bin', 'hex'], f"unknown suffix: {out_format}"

# load program
with open(program_bin, 'rb') as pbf:
	prog = pbf.read(32768)

MAX_PROG_SIZE = 0x7fff
BITSTREAM_SIZE = 0x20000

if out_format == 'bin':
	with open(spiflash_bin, 'wb') as spi:
		# upper 128kB are used for the bitstream
		# for simulation we just skip this part
		spi.seek(BITSTREAM_SIZE)
		spi.write(prog)

		# write a zero byte (why?)
		spi.seek(BITSTREAM_SIZE + MAX_PROG_SIZE)
		spi.write(b'\0')
else:
	with open(spiflash_bin, 'w') as spi:
		# upper 128kB are used for the bitstream
		# for simulation we just skip this part
		for i in range(BITSTREAM_SIZE): print("00", file=spi)

		assert len(prog) <= MAX_PROG_SIZE
		prog = prog + b'\0' * (MAX_PROG_SIZE - len(prog))
		for bb in prog: print(f"{bb:02x}", file=spi)
