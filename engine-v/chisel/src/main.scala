object main {

    def main(args: Array[String]): Unit = {
        // generate verilog and save to file
        chisel3.Driver.execute(args, () => new addsub8)
        chisel3.Driver.execute(args, () => new mf8_alu)
    }
}