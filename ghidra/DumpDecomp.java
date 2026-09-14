// Decompile every function in the current program and write them to one C file.
// Output path: first script argument.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DumpDecomp extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String out = getScriptArgs()[0];
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);
		int n = 0, failed = 0;
		try (PrintWriter w = new PrintWriter(out)) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (monitor.isCancelled()) break;
				if (f.isThunk() || f.isExternal()) continue;
				DecompileResults r = ifc.decompileFunction(f, 60, monitor);
				w.printf("// ==== %s @ %s%n", f.getName(), f.getEntryPoint());
				if (r != null && r.decompileCompleted()) {
					w.println(r.getDecompiledFunction().getC());
				} else {
					w.println("// decompile failed");
					failed++;
				}
				n++;
			}
		}
		ifc.dispose();
		println("Decompiled " + n + " functions (" + failed + " failed) -> " + out);
	}
}
