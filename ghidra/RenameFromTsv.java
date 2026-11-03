// RenameFromTsv.java <abs tsv: addr<TAB>name ...> : rename functions at addr (hex, no 0x). Creates function if missing.
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
public class RenameFromTsv extends GhidraScript {
  public void run() throws Exception {
    int n=0,bad=0;
    for (String l : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
      String[] p = l.split("\t"); if (p.length<2||p[0].startsWith("addr")) continue;
      Address a = toAddr(Long.parseLong(p[0].trim(),16));
      Function f = getFunctionAt(a);
      if (f==null) { disassemble(a); f=createFunction(a,null); }
      if (f==null) { bad++; continue; }
      if (p[1].trim().equals("NOTFUNC")) { removeFunction(f); n++; continue; }
      try { f.setName(p[1].trim(), SourceType.USER_DEFINED); n++; } catch (Exception e) { bad++; }
    }
    println("renamed "+n+" failed "+bad);
  }
}
