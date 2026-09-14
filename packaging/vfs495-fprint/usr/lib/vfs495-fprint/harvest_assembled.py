# gdb python: harvest the motion-compensated assembled fingerprint image from HP's
# validity-sensor (4.5-136) at IRqualityDetermination (0x4689b0). Writes:
#   <u32 dim1><u32 dim2><dim1*dim2 bytes>  to $VFS_ASM_OUT
import gdb, os, struct
OUT = os.environ.get("VFS_ASM_OUT", "/tmp/vfs495_asm.bin")
hit = {"n": 0}
class BP(gdb.Breakpoint):
    def stop(self):
        f = gdb.selected_frame(); inf = gdb.selected_inferior()
        ctx = int(f.read_register("rdi")) & 0xffffffffffffffff
        try:
            img = int.from_bytes(inf.read_memory(ctx + 0xa8, 8), "little")
            if not img: return False
            a = int.from_bytes(inf.read_memory(img - 0x44, 4), "little")
            b = int.from_bytes(inf.read_memory(img - 0x48, 4), "little")
            if not (0 < a <= 5000 and 0 < b <= 20000 and a * b <= 4_000_000): return False
            px = bytes(inf.read_memory(img, a * b))
            with open(OUT, "wb") as fh: fh.write(struct.pack("<II", a, b) + px)
            hit["n"] += 1
        except gdb.MemoryError: pass
        return False
BP("*0x4689b0")
gdb.execute("run getprintwait -doinit")
gdb.execute("quit")
