import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/wire_order.json"
st={}
class Op(gdb.Breakpoint):   # palRsaPublicKeyOperation output C_be
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        out=int(f.read_register("rcx"))&0xffffffffffffffff
        class Fin(gdb.FinishBreakpoint):
            def __init__(s): super().__init__(internal=True)
            def stop(s):
                st["C_be_out"]=bytes(inf.read_memory(out,256)).hex(); return False
        Fin(); return False
class Enc(gdb.Breakpoint):  # scsSSLRsaPublicEncrypt: param_4=RCX = final wire
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        out=int(f.read_register("rcx"))&0xffffffffffffffff
        class Fin(gdb.FinishBreakpoint):
            def __init__(s): super().__init__(internal=True)
            def stop(s):
                st["wire"]=bytes(inf.read_memory(out,256)).hex()
                json.dump(st,open(O,"w")); print("dumped wire+out"); gdb.execute("quit"); return True
        Fin(); return False
Op("*0x52b770"); Enc("*0x5161c0")
gdb.execute("run getprintwait -doinit")
