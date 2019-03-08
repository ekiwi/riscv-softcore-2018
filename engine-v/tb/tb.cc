#include "Vtb.h"
#include "verilated.h"

#if VM_TRACE
# include <verilated_vcd_c.h>	// Trace file format header
#endif

int main(int argc, char **argv, char **env)
{
	Verilated::commandArgs(argc, argv);
	Vtb* top = new Vtb;
	vluint64_t main_time = 0;

#if VM_TRACE
	Verilated::traceEverOn(true);
	VerilatedVcdC* tfp = new VerilatedVcdC;
	top->trace(tfp, 99);
	tfp->open ("dump.vcd");
#endif

	top->clk = 0;
	while (!Verilated::gotFinish()) {
		top->clk = !top->clk;
		top->eval();
		main_time++;
#if VM_TRACE
		tfp->dump(main_time);
#endif
	}

#if VM_TRACE
	if (tfp) { tfp->close(); }
#endif

	delete top;
	exit(0);
}

