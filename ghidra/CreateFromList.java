//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.nio.file.*;
public class CreateFromList extends GhidraScript {
  public void run() throws Exception {
    int n=0;
    for (String l : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
      l=l.trim(); if (l.isEmpty()) continue;
      Address a = toAddr(Long.parseLong(l,16));
      disassemble(a);
      if (getFunctionAt(a)==null) { createFunction(a,null); n++; }
    }
    println("created "+n);
  }
}
