// Headless Ghidra script for raw ARM/Thumb RTOS images (`av-cam.bin`, base 0x635c6000).
// Explicitly seeds Thumb (TMode=1) function ranges and exports decompiled C + assembly.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;

public class ArmResetFocused extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    Path out = Paths.get(args[0]);
    Files.createDirectories(out);
    List<String> rows = Files.readAllLines(Paths.get(args[1]));
    Register tmode = currentProgram.getRegister("TMode");
    List<Function> functions = new ArrayList<>();
    for (String row : rows) {
      if (row.isBlank() || row.startsWith("#")) continue;
      String[] fields = row.trim().split("\\s+");
      Address lo = toAddr(Long.parseUnsignedLong(fields[1].replaceFirst("^0x", ""), 16));
      Address hi = toAddr(Long.parseUnsignedLong(fields[2].replaceFirst("^0x", ""), 16)).subtract(1);
      clearListing(lo, hi);
      currentProgram.getProgramContext().setValue(tmode, lo, hi, BigInteger.ONE);
      disassemble(lo);
      Function fn = getFunctionAt(lo);
      if (fn == null) fn = createFunction(lo, fields[0]);
      if (fn != null) {
        fn.setName(fields[0], SourceType.USER_DEFINED);
        functions.add(fn);
      }
      println("SEEDED " + row + " fn=" + (fn == null ? "null" : fn.getEntryPoint()));
    }
    DecompInterface decomp = new DecompInterface();
    decomp.toggleCCode(true);
    decomp.toggleSyntaxTree(true);
    decomp.openProgram(currentProgram);
    Files.writeString(
      out.resolve("analysis-profile.txt"),
      "Headless Ghidra focused Thumb export for raw RTOS image.\n" +
      "Image base=" + currentProgram.getImageBase() + "\n" +
      "Source raw bytes are not modified. Target is not executed.\n"
    );
    for (Function fn : functions) {
      String label = fn.getName() + "-" + fn.getEntryPoint();
      DecompileResults result = decomp.decompileFunction(fn, 40, monitor);
      String code = result.decompileCompleted() && result.getDecompiledFunction() != null
        ? result.getDecompiledFunction().getC()
        : "ERROR: " + result.getErrorMessage();
      Files.writeString(out.resolve(label + ".c.txt"), code);
      StringBuilder asm = new StringBuilder();
      InstructionIterator iterator = currentProgram.getListing().getInstructions(fn.getBody(), true);
      while (iterator.hasNext()) {
        Instruction instruction = iterator.next();
        asm.append(instruction.getAddress()).append(" ").append(instruction).append("\n");
      }
      Files.writeString(out.resolve(label + ".assembly.txt"), asm.toString());
      println("EXPORTED " + label + " complete=" + result.decompileCompleted());
    }
    decomp.dispose();
  }
}
