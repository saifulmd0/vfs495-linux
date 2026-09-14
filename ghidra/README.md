# Reproducing the static analysis

The reverse engineering was done by decompiling HP's `validity-sensor` binary with
[Ghidra](https://ghidra-sre.org/). This folder has the headless script; the binary itself is HP's
(get it via ../runtime/README.md) and is not included.

```bash
# Ghidra headless: import + decompile every function to one C file
$GHIDRA/support/analyzeHeadless proj vfs495 -import /path/to/validity-sensor -overwrite \
  -scriptPath . -postScript DumpDecomp.java "$PWD/validity-sensor.c"
```
`DumpDecomp.java` decompiles all functions to a single `.c` for grepping. Key functions referenced
throughout the docs: `scsSSL*` (the SSLv3 stack), `UnpackLineRT`/`ProcessTimeslotTable` (decode +
descramble), `irDliRTFalconData`/`IRreconstructImage` (image assembly), `scsSSLEstablishSession`
(RSA key from sensor storage id 10).
