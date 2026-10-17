---
name: insight-windbg
description: Investigate Windows native user-mode minidumps using bounded stacks, threads, registers, modules, memory and disassembly through insight-cli windbg. Use on Windows x64 when a captured runtime state needs native debugger evidence.
---

# Insight WinDbg 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Keep the project's RE and evidence conventions. This facade reads a captured Windows
user-mode minidump; it does not run or attach the original application. Dump contents
can include private memory. Store evidence under the project's normal rules.

1. Check `insight-cli windbg status --json`. On Windows x64, `windbg install --vendor-direct`
   downloads Microsoft's pinned WinDbg bundle, prepares the CDB console runtime and probes it.
   Microsoft terms prohibit our redistribution; this explicit acquisition uses Microsoft,
   SHA256 and our local cache. `download --vendor-direct` stages the archive first.
   `install --archive FILE --offline` accepts the matching local MSIX bundle.
   `install --executable C:\tools\windbg\amd64\cdb.exe` selects an existing CDB 10.x family;
   adjacent runtime bytes are fingerprinted. `doctor` probes it again; uninstall removes only
   owned software and preserves research and external files.
2. `insight-cli windbg inspect crash.dmp --symbols native.pdb --json` captures immutable inputs
   and shows the dump environment, threads, current stack, registers and modules. A local
   matching PDB improves correspondence; missing/mismatched symbols remain warnings.
   Network symbol lookup and inherited debugger initialization are disabled.
3. Drill down with `--view stack --frames 32`, `--view registers`, `--view threads` or
   `--view modules`. `--thread N` selects the dump's decimal thread index. A runtime address
   from this same dump enables `--view memory --address 0xADDRESS --count 64` or
   `--view disassembly --address 0xADDRESS --count 16`. Addresses are runtime values affected
   by ASLR, not file offsets. Missing pages do not mean zero or absent behavior.
4. `--target ID` reuses a captured dump. `--limit`/`--offset` page native lines;
   `--output research/native-state.json` saves the full bounded result to a new ordinary file.
   Preserve useful evidence with `artifacts save` if appropriate. A `partial` response includes
   warnings; retain them in conclusions. One dump proves one captured state, not every path.
5. The owned debugger runs inside a Windows Job Object, bounded by `--timeout-seconds`
   (default 30, maximum 600). Owner loss or launcher termination closes its process tree.
   `tools processes --tool windbg --all` shows retained jobs. Lost or missing result receipts
   mean an unknown result; inspect diagnostics before choosing a new query. No automatic
   replay or arbitrary debugger-command gateway is exposed.

Generated `windbg inspect --help` owns exact syntax. No Ghidra session or merge is needed.
