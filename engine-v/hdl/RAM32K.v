/*
 * Copyright 2018 MicroFPGA UG
 * Apache 2.0 License
 */

module RAM32K (clk, addr, din, dout, we);

input clk;
input we;
input [14:0] addr;
input  [7:0] din;
output [7:0] dout;

//TODO: explcitily instanciate SBRAM

// RAM
reg [7:0] mem [0:32*1024-1];
reg [7:0] dout;
initial $readmemh("riscv.mem", mem);

always @(posedge clk) begin
	if (we) mem[addr] <= din;
	dout <= mem[addr];
end

endmodule