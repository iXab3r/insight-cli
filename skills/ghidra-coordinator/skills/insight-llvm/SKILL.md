---
name: insight-llvm
description: Inspect PE, ELF and Mach-O headers, dependencies, exports and symbols; query PDB debug information or a small instruction window with insight-cli LLVM utilities before opening a full analysis project.
---

# Insight LLVM 0.2.0

Use existing project RE rules and evidence paths. These are static reads; no Ghidra project,
program execution or shared merge is needed. Use Ghidra when the question needs recovered
control flow, decompilation or persistent annotations.

1. `insight-cli llvm status --json` checks readiness. `llvm install` prepares the pinned
   four-utility bundle from our GitHub Release; `--archive` and `--offline` support local
   installation. Managed LLVM 23.1.3 requires macOS 14+ ARM64. `--executable` selects an
   external llvm-readobj with compatible llvm-nm, llvm-objdump and llvm-pdbutil siblings.
   The whole known external family is fingerprinted; uninstall preserves external files.
2. Use `llvm headers INPUT`, `sections`, `imports`, `exports` or `symbols` for focused
   inventories. Reuse `--target` instead of INPUT for the same immutable bytes. Stripped
   images can have no ordinary symbols; that does not prove there are no functions.
   `symbols` includes local/static definitions; these are not automatically exported APIs.
   For ELF, `exports` uses the dynamic symbol table while `symbols` uses ordinary symbols.
3. For a supplied PDB, start with `llvm pdb FILE --view summary` and `--view modules`.
   Use `--view globals --symbol NAME` for a named global, `--view publics` for public
   addresses, or `--view symbols --module INDEX` for procedure/local records. `--view types`
   gives statistics until `--type-index 0xINDEX` selects a particular record. PDB symbol
   addresses are section:offset pairs: combine the corresponding image section RVA and
   image base from headers/sections; they are not file offsets. In pdbutil these padded
   section:offset numbers are decimal (an explicit `0x` elsewhere means hexadecimal).
4. `llvm disassemble IMAGE --address 0xVIRTUAL_ADDRESS --bytes 128` returns a bounded
   instruction interval. Distinguish static virtual addresses, RVAs and file offsets;
   runtime load bias is not established by these static commands. If the instructions load
   constants from a section, use `llvm section-data IMAGE --section NAME` and the section
   address/endianness to inspect their actual values. The complete section must fit the
   4-MiB native-output bound; oversized sections fail explicitly and need another focused
   binary-reading tool rather than an assumed complete result.
5. Keep useful output in the project's format. Text views page with `--limit`/`--offset`;
   `--filter` selects matching native lines and can omit surrounding context. `--output`
   writes full bounded native text to a new file, creating missing parent directories.
   Use focused PDB/module/type queries instead of asking for every symbol or instruction.

The four upstream executables supply native text inside our JSON envelope. In particular,
upstream readobj JSON output is not treated as a reliable structured COFF contract. ELF
imports show needed libraries and undefined dynamic symbols; Mach-O imports show dylibs and
undefined symbols. This is static linkage evidence, not proof of observed runtime calls.

These calls need Update permission to capture input and run tools. Generated `--help` owns
exact syntax. `tools processes --tool llvm --all` and `show <id>` retain execution diagnostics;
failed/limited output is not a complete inventory. Save completed ordinary files through
`artifacts save` when a checkpoint is useful.
