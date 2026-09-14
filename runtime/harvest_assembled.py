# gdb: harvest the fully-assembled (motion-compensated) image from IRqualityDetermination entry.
import gdb, os, os, struct
OUT = os.environ.get("VFS_ASM_OUT", os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/assembled.bin")
state = {"n": 0}
class BP(gdb.Breakpoint):
    def stop(self):
        f = gdb.selected_frame(); inf = gdb.selected_inferior()
        ctx = int(f.read_register("rdi")) & 0xffffffffffffffff
        try:
            img = int.from_bytes(inf.read_memory(ctx + 0xa8, 8), "little")
            if not img: return False
            a = int.from_bytes(inf.read_memory(img - 0x44, 4), "little")  # dim1
            b = int.from_bytes(inf.read_memory(img - 0x48, 4), "little")  # dim2
            if not (0 < a <= 5000 and 0 < b <= 20000 and a*b <= 4_000_000): return False
            px = bytes(inf.read_memory(img, a * b))
            with open(OUT, "wb") as fh:
                fh.write(struct.pack("<II", a, b) + px)   # header dim1,dim2 then pixels
            state["n"] += 1
            print(f"ASSEMBLED dim1={a} dim2={b} bytes={a*b}")
        except gdb.MemoryError as e:
            print("memerr", e)
        return False
BP("*0x4689b0")
gdb.execute("run getprintwait -doinit")
print("ASM_HITS", state["n"])
gdb.execute("quit")
