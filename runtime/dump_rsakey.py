import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/rsakey.json"
class BP(gdb.Breakpoint):
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        bits=int(f.read_register("rdi"))&0xffffffff
        expp=int(f.read_register("rsi"))&0xffffffffffffffff
        modp=int(f.read_register("rdx"))&0xffffffffffffffff
        exp=bytes(inf.read_memory(expp,4)); mod=bytes(inf.read_memory(modp,256))
        json.dump({"bits":bits,"exp":exp.hex(),"modulus":mod.hex()},open(O,"w"))
        print("bits",bits,"exp",exp.hex(),"mod[:8]",mod[:8].hex())
        return True
BP("*0x51fac0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
