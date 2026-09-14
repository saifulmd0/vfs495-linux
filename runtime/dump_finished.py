import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/finished_vec.json"
hs=[]
class Upd(gdb.Breakpoint):
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        data=int(f.read_register("rsi"))&0xffffffffffffffff
        n=int(f.read_register("rdx"))&0xffffffff
        if 0<n<=2048: hs.append(bytes(inf.read_memory(data,n)).hex())
        return False
class Fin(gdb.Breakpoint):   # scsSSLFinishedWrite entry: ctx=RDI, out=RSI(+4)
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        ctx=int(f.read_register("rdi"))&0xffffffffffffffff
        out=int(f.read_register("rsi"))&0xffffffffffffffff
        master=bytes(inf.read_memory(ctx+8,48)).hex()
        gdb.post_event(lambda: None)
        # let it compute: use FinishBreakpoint
        o=out
        class F(gdb.FinishBreakpoint):
            def __init__(s): super().__init__(internal=True)
            def stop(s):
                fin=bytes(inf.read_memory(o+4,36)).hex()
                json.dump({"master":master,"hs_updates":hs,"finished":fin},open(O,"w"),indent=1)
                print("MASTER",master[:16],"FIN",fin[:16],"nupd",len(hs))
                gdb.execute("quit"); return True
        F()
        return False
Upd("*0x5132b0"); Fin("*0x513920")
gdb.execute("run getprintwait -doinit")
