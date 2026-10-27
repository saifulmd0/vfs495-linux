# gdb script: dump the SSL session key block (136 B) of one run of HP's validity-sensor, so that
# runtime/trace_to_init.py can decrypt the setup commands from the usblog trace of the same run.
# Breakpoint and offsets as in dump_kdf.py (validated against the KDF): at scsSSLRsaPublicEncrypt the
# context (RDI) already holds master (ctx+8) and key block (ctx+0x48). The process keeps running.
#   VFS495_KEYBLOCK=OUT.json gdb -batch -x dump_keyblock.py validity-sensor-unlocked
import json
import os

import gdb

OUT = os.environ["VFS495_KEYBLOCK"]


class RsaEncrypt(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        ctx = int(gdb.selected_frame().read_register("rdi")) & 0xffffffffffffffff
        kb = bytes(inf.read_memory(ctx + 0x48, 136))
        fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"keyblock": kb.hex()}, f)
        print("vfs495: session key block saved")
        return False


gdb.execute("set pagination off")
gdb.execute("set confirm off")
RsaEncrypt("*0x5161c0")
gdb.execute("run getprintwait -doinit")
