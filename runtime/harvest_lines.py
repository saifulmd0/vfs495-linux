# gdb python: dump every descrambled line UnpackLineRT produces, to a raw file.
import gdb
import os

OUT = os.environ.get("VFS_LINES_OUT", os.path.expanduser(os.environ.get("VFS495_HOME","~/vfs495-re"))+"/captures/lines.raw")
open(OUT, "wb").close()
state = {"prev": None, "n": 0}

class BP(gdb.Breakpoint):
    def stop(self):
        f = gdb.selected_frame()
        rdx = int(f.read_register("rdx")) & 0xffffffffffffffff  # output buffer
        rcx = int(f.read_register("rcx")) & 0xffffffffffffffff  # config
        inf = gdb.selected_inferior()
        w = int.from_bytes(inf.read_memory(rcx + 4, 4), "little")
        # one-behind: previous buffer is fully written by now
        if state["prev"] is not None:
            po, pw = state["prev"]
            if 0 < pw <= 4096:
                data = bytes(inf.read_memory(po + 8, pw))  # skip 8-byte header
                with open(OUT, "ab") as fh:
                    fh.write(pw.to_bytes(2, "little") + data)
                state["n"] += 1
        state["prev"] = (rdx, w)
        return False  # never actually stop; keep running

BP("*0x46f510")
gdb.execute("run getprintwait -doinit")
print("HARVESTED_LINES", state["n"])
gdb.execute("quit")
