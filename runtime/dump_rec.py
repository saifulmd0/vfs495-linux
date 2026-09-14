import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/rec_vec.json"
st={}
class RP(gdb.Breakpoint):   # scsSSLRecordPack(ctx=RDI, record=RSI, type=DL, len=ECX)
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        ctx=int(f.read_register("rdi"))&0xffffffffffffffff
        rec=int(f.read_register("rsi"))&0xffffffffffffffff
        typ=int(f.read_register("rdx"))&0xff
        ln=int(f.read_register("rcx"))&0xffffffff
        if "done" in st: return False
        flag=int.from_bytes(inf.read_memory(ctx+0x13c,4),"little")
        if not (flag & 2): return False
        st["keyblock"]=bytes(inf.read_memory(ctx+0x48,136)).hex()
        st["seq"]=bytes(inf.read_memory(ctx+0x100,8)).hex()
        st["type"]=typ; st["len"]=ln
        st["plain"]=bytes(inf.read_memory(rec,ln+64)).hex()  # grab enough
        st["rec_ptr"]=rec; st["done"]=1
        class F(gdb.FinishBreakpoint):
            def __init__(s): super().__init__(internal=True)
            def stop(s):
                st["cipher"]=bytes(inf.read_memory(rec,ln+64)).hex()
                json.dump(st,open(O,"w")); print("REC dumped type",typ,"len",ln); gdb.execute("quit"); return True
        F()
        return False
RP("*0x514580")
gdb.execute("run getprintwait -doinit")
