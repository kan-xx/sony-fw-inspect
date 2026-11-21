// Headless Ghidra script for MIPS32 LE codec firmware (`vcd_firmware.bin` at 0x80000000).
// Seeds $gp = 0x802f2920 (observed at startup 0x80004314) and exports C + assembly.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;

public class MipsFocused extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    Path out = Paths.get(a[0]);
    Files.createDirectories(out);
    currentProgram.getProgramContext().setValue(
      currentProgram.getRegister("gp"),
      toAddr(0x80004000L),
      toAddr(0x8016fdffL),
      new BigInteger("802f2920", 16)
    );
    List<Function> fs = new ArrayList<>();
    for (String s : Files.readAllLines(Paths.get(a[1]))) {
      if (s.isBlank() || s.startsWith("#")) continue;
      String[] f = s.trim().split("\\s+");
      Address p = toAddr(f[1]);
      disassemble(p);
      Function fn = getFunctionAt(p);
      if (fn == null) fn = createFunction(p, f[0]);
      else if (!fn.getName().equals(f[0])) fn.setName(f[0], SourceType.USER_DEFINED);
      if (fn != null) fs.add(fn);
      println("SEED " + s + " function=" + fn);
    }
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    Files.writeString(
      out.resolve("profile.txt"),
      "MIPS32 LE raw image, candidate base 0x80000000; gp 0x802f2920 from native startup.\n" +
      "Focused manually seeded functions. Target not executed.\n"
    );
    for (Function fn : fs) {
      String n = fn.getName() + "-" + fn.getEntryPoint();
      DecompileResults r = di.decompileFunction(fn, 45, monitor);
      Files.writeString(
        out.resolve(n + ".c.txt"),
        r.decompileCompleted() && r.getDecompiledFunction() != null
          ? r.getDecompiledFunction().getC()
          : "ERROR " + r.getErrorMessage()
      );
      StringBuilder b = new StringBuilder();
      InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
      while (it.hasNext()) {
        Instruction x = it.next();
        b.append(x.getAddress()).append(" ").append(x).append("\n");
      }
      Files.writeString(out.resolve(n + ".asm.txt"), b.toString());
      println("EXPORTED " + n + " complete=" + r.decompileCompleted());
    }
    di.dispose();
  }
}
