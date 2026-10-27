# gdb: harvest the fully-assembled (motion-compensated) image from IRqualityDetermination entry.
import gdb, os, socket, struct
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
# Finger-on: HP raises sensor event 0xd0 (idsSensorEventPerformCallback, event id in esi) when its
# wake-on-event sees a finger => it is silent while idle (0xcc = armed). Report it once to virtual_image
# as (-4, 1) so fprintd's finger-present goes true at swipe start, not after the image is assembled.
FINGER_SOCK = os.environ.get("VFS_FINGER_SOCK")
class FingerOnBP(gdb.Breakpoint):
    def stop(self):
        try:
            if int(gdb.selected_frame().read_register("rsi")) & 0xffffffff != 0xd0: return False
        except gdb.error: return False
        self.enabled = False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(1)
            s.connect(FINGER_SOCK); s.sendall(struct.pack("<ii", -4, 1)); s.close()
        except OSError: pass
        return False
if FINGER_SOCK: FingerOnBP("*0x459bf0")
gdb.execute("run getprintwait -doinit")
print("ASM_HITS", state["n"])
gdb.execute("quit")
