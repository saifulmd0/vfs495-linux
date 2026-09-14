import gdb, os
OUT=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/plaintext_cmds_full.txt"
open(OUT,"w").close()
class BP(gdb.Breakpoint):
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        rsi=int(f.read_register("rsi"))&0xffffffffffffffff
        ln=int(f.read_register("rdx"))&0xffffffff
        if 0<ln<=8192:
            data=bytes(inf.read_memory(rsi,ln))
            with open(OUT,"a") as fh: fh.write(data.hex()+"\n")
        return False
BP("*0x4f7bd0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
