import gdb, os, json
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/kdf_vector.json"
def rd(inf,a,n): return bytes(inf.read_memory(a,n))
def ptr(inf,a): return int.from_bytes(rd(inf,a,8),"little")
d={}
class MSG(gdb.Breakpoint):   # scsSSLMasterSecretGenerate entry
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        ctx=int(f.read_register("rdi"))&0xffffffffffffffff
        pre=int(f.read_register("rsi"))&0xffffffffffffffff
        try:
            d["premaster"]=rd(inf,pre,48).hex()
            d["rand_0x38"]=rd(inf,ptr(inf,ctx+0x38),32).hex()
            d["rand_0x40"]=rd(inf,ptr(inf,ctx+0x40),32).hex()
            d["_ctx"]="0x%x"%ctx
        except Exception as e: d["err"]=str(e)
        return False   # keep going
class RSA(gdb.Breakpoint):   # scsSSLRsaPublicEncrypt: master+keyblock now filled
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        ctx=int(f.read_register("rdi"))&0xffffffffffffffff
        try:
            d["master"]=rd(inf,ctx+8,48).hex()
            d["keyblock"]=rd(inf,ctx+0x48,136).hex()
        except Exception as e: d["err2"]=str(e)
        open(O,"w").write(json.dumps(d,indent=1)); print("KDF vector keys:",list(d))
        return True
MSG("*0x5139c0"); RSA("*0x5161c0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
