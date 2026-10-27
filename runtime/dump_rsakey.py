import gdb, os, json
# HP sets up TWO RSA-2048 keys per session at 0x51fac0 (bits=rdi, exp=rsi, modulus=rdx). The first is NOT
# the key-exchange key; the SECOND one is (= storage id 10 in sensor flash, which tools/ssl_session.py
# reads itself, so this dump is only needed for cross-checking).
O=os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/rsakey.json"
keys=[]
class BP(gdb.Breakpoint):
    def stop(self):
        f=gdb.selected_frame(); inf=gdb.selected_inferior()
        bits=int(f.read_register("rdi"))&0xffffffff
        expp=int(f.read_register("rsi"))&0xffffffffffffffff
        modp=int(f.read_register("rdx"))&0xffffffffffffffff
        exp=bytes(inf.read_memory(expp,4)); mod=bytes(inf.read_memory(modp,256))
        keys.append({"bits":bits,"exp":exp.hex(),"modulus":mod.hex()})
        print("key",len(keys),"bits",bits,"exp",exp.hex(),"mod[:8]",mod[:8].hex())
        if len(keys)<2: return False
        json.dump({**keys[1],"all":keys},open(O,"w"))   # top level = the session key
        return True
BP("*0x51fac0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
