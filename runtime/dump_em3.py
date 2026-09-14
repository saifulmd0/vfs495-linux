import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/rsa_em3.json"
st={}
class Pre(gdb.Breakpoint):   # scsSSLRsaPublicEncrypt: premaster=RSI
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        st["premaster"]=bytes(inf.read_memory(int(f.read_register("rsi"))&0xffffffffffffffff,48)).hex()
        return False
class Op(gdb.Breakpoint):
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        st["em"]=bytes(inf.read_memory(int(f.read_register("rsi"))&0xffffffffffffffff,256)).hex()
        if "premaster" in st:
            json.dump(st,open(O,"w")); print("dumped both"); gdb.execute("quit"); return True
        return False
Pre("*0x5161c0"); Op("*0x52b770")
gdb.execute("run getprintwait -doinit")
