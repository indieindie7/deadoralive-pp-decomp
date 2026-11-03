# Dead or Alive ++ (JP 1998, MAME doapp) decomp notes
Board: Sony ZN-1 / Tecmo TPS, MIPS R3000. ROMs: rom/doapp.zip (never committed).

## Status (2026-11-02)
Functions named: see public/names.tsv (exact skeleton matches to PSX DOA OV00/SLUS; fuzzy rows are provisional, unreviewed). Globals PROVEN/DEAD/OPEN: 0/0/0 (not started).
BLOCKED: main exe (~0x88800 bytes at 0x80010000) is encrypted; TPS BIOS (coh1002m m534002c-61.ic353, 512 KB, CRC 69ffbcb4) is not in doapp.zip and not on this PC (drive search + MAME roms dir empty).

## ROM layout (MAME zn.cpp tecmo_zn_state, bank reg 0x1fb00006, 0x800000 banks)
- prog = doapp119 (odd bytes) + doapp120 (even bytes), 2 MB, bank offset 0 (work/prog.bin: o[1::2]=119, o[0::2]=120)
- maskroms: doapp-0.216 @0x400000, -1.217 @0x800000, -2.218 @0xc00000, -3.219 @0x1000000, -4.220 @0x1400000, -5.221 @0x1800000 (4 MB each; offset tables/archives, little code)
## prog.bin map
- 0x0-0x88800 encrypted; header "Licensed by Sony Computer Entertainment Inc.(SCEI)" at 0x4
- 0x88800-0x90000 encrypted zeros; 0x90000-0xa0000 0xFF
- 0xa0000-0x110000 PLAIN MIPS code+data, ~549 prologues; load addr = file_off + 0x7fff7e18 (0xa0000 -> 0x80097e18; 378 prologue hits)
- 0x130000-0x150000 plain code, base unknown
## Cipher findings
- Zero-sector keystream K (file 0x47800, period 0x800): (C-K[j&0x7ff])&255 decodes ~70% of bytes (PsyQ strings, lui/lw, jal visible). Second component unknown. Ruled out: pure XOR, 16/32-bit carry add, per-sector roll, ML K re-estimate, 2-layer (P^A)+B / (P+A)^B.
- Next: obtain BIOS (decrypt routine) or crack; then Ghidra import (MIPS:LE:32:default), PSX name port (psx/NOTES.md, psyq_match), DATAMAP.
- tools/fb.py: numpy jal-target vs prologue base finder.

## 2026-11-02 pass 2
- Plain region 0xa0000-0x110000 is the fight overlay: ~585 functions, equivalent of PSX OV00 (PSX names reused). Also loader at 0x107868 (file) copies banked ROM 0x1f000000+off words (plain copy, NO decrypt) -> decrypt is done by BIOS, MAME zn.cpp has none.
- tools/match_plain.py (exact normalised hash) 76 matched; tools/match_fuzzy.py opcode-skeleton ratio>=0.9 margin>=0.03 -> provisional. Results public/names.tsv.
- Encrypted exe: PSX SLUS aligns with decoded prog (delta 44340 words vote 765) so code is a near-copy of PSX SLUS; known plaintext usable for cipher recovery next. Zero-key K explains ~70% bytes; remaining noise sparse, not yet modelled.

## Known-plaintext attempt (2026-11-02)
- PSX SLUS aligns only locally (delta 44340 holds in data tables ~0x20000-0x26000, not whole exe); exact-word windows rare, so clean (C,P) pairs scarce.
- Findings: zero-plaintext groups of sectors give different keys: sectors 0x74-0x11f = K; sectors 0x63-0x68 identical but differ from K by exactly 256x(+2) and 256x(-2) (+2 mostly lane0, -2 mostly lane3). So key is NOT sector-independent; ~25% of positions carry a 2nd component that depends on sector class and likely plaintext. In a table with constant top byte 0xf0, deviations are random large values at ~20% of positions (K wrong there), small (0/1/3/ff) elsewhere = true data.
- Ruled out: constant 3x multiply, rotation of P, prev-byte carry, sector-independent 2-layer. Not tested: dependence on prev-sector C/P (CBC across sectors), LFSR seeded by sector number. tools/decrypt.py NOT written (no verified model).

## Pass 3 (11-02): provisional review, propagation, globals
- tools/review.py: fuzzy pairs kept only with ratio>=0.9, coverage>=0.9, 0 inconsistent callees; 36 dropped; call-vote propagation added 1. names.tsv: 108 named, 0 provisional. 477 plain fns unnamed (no evidence; not guessed).
- globals.tsv: 1848 PROVEN (PSX map or in-region static xrefs), 360 DEAD, 262 OPEN (all in encrypted main exe; blocker: BIOS coh1002m).
- Cipher parked until BIOS.

## Pass 4 (11-02): all 585 plain fns named
- 193 by PSX evidence (exact/fuzzy/LOOSE opcode-skeleton r>=0.85 + imm agreement + callee consistency, call-vote propagation). 392 by code read: tools/name_all.py derives role (fill/copy/get/set/dispatch/gte/calc/run...) from the body plus module prefix from callers, sandwiching named neighbours, callees or nearest named function. Names are structural (prefix_role_addr), NOT semantic; evidence per row in hand_doapp.txt / names.tsv. Review pass (body + callers, recomputed with final names) converged in 3 rounds, 0 unsure.
- globals.tsv: 1935 PROVEN / 342 DEAD / 202 OPEN (OPEN = encrypted main exe, BIOS blocker).

## Pass 6 (11-03): main exe decrypted (oracle), named, reviewed, globals closed
- Exe image: MAME run with the user's own real mg01 (coh1002m) decrypts the exe into RAM; dumped RAM 0x10000..0x98000 (work/mame/dumpt.lua, local only, never committed). Cipher itself not derived; no tools/decrypt.py. Regenerate from your own ROMs + mg01 with the same Lua dump. Combined image base 0x80010000 (exe + plain overlay at 0x97e18) = 1862 functions seeded, 15 seeds were data (public/notfunc.txt).
- Names: 456 ported from PSX SLUS/OV00 (400 hash-exact; port_exe.py, port_exe2.py = fuzzy skeleton + call-vote), 849 more named by code read (prep_exe.py batches), 28 PSX-hint ones included. Review pass: all 834 agent-named functions re-read against body + callers: 45 renamed, rest confirmed. 14 duplicate names resolved (8-byte jump thunks get _Thunk, second copies _B). 0 FUN_, 0 provisional. names.tsv 1847 rows.
- Globals: whole-image lui/addiu/load-store xref scan; the 202 OPEN resolved: 155 PROVEN (111 RW var_, 44 read-only tbl_), 47 DEAD (46 no static reference, 1 write-only). Totals 2090 PROVEN / 389 DEAD / 0 OPEN. Names are module_addr (module = most frequent referencing function prefix), not semantic.
