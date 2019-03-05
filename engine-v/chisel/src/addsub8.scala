import chisel3._
import chisel3.util._

class addsub8 extends Module {
    val io = IO(new Bundle {
        val a = Input(UInt(8.W))
        val b = Input(UInt(8.W))
        val q = Output(UInt(8.W))
        val sub = Input(Bool())
        val cin = Input(UInt(1.W))
        val cout = Output(UInt(1.W))
    })
    
    val b : UInt = Mux(io.sub, ~io.b, io.b)
    val res = (io.a +& b) + io.cin
    io.q := res(7, 0)
    io.cout := res(8)

}