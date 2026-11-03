# deadoralive-pp-decomp

Names and notes for Dead or Alive ++ (Japan 1998, MAME `doapp`, Sony ZN-1 / Tecmo TPS board, MIPS R3000). Names, notes and tools only: no ROMs, no decompiled C, no game text.

## Status

- The MAIN EXECUTABLE is encrypted on the ROM; the TPS BIOS (`coh1002m`, real mg01 chip) decrypts it at boot. It was decoded by running MAME with the user's own ROMs plus that BIOS and dumping RAM; the cipher itself was not derived. No BIOS, keys or decrypted bytes are in this repo.
- Covered: exe + fight overlay, 1847 functions, all named, 0 provisional: ~456 ported from the PSX decomp (deadoralive-psx-decomp) by hash/skeleton/call evidence, the rest named by code read; all agent names re-reviewed against body and callers (45 renamed). 15 seed addresses were data (notfunc.txt).
- Globals: 1261 objects (1204 PROVEN, 57 DEAD, 0 OPEN), size + semantic name + evidence per row; PSX names ported where the PSX decomp named the matching object.
- `names.tsv`: addr, name, evidence, psx_ref. `globals.tsv`: addr, class (PROVEN / DEAD), name, size, evidence. OPEN is empty.

## Tools
`match_plain.py`, `match_fuzzy.py`, `review.py`, `port_exe.py`, `port_exe2.py`, `prep_exe.py`, `ghidra/RenameFromTsv.java` (need the user's own ROM dump and the PSX decomp ghidra exports).

MIT licensed.
