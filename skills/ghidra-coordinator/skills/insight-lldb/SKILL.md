---
name: insight-lldb
description: Observe native runtime arguments, return values, registers, stacks and bounded memory at a selected breakpoint using an owned LLDB launch. Use insight-cli lldb on macOS ARM64 when static findings need a concrete execution check.
---

# Insight LLDB 0.2.0

Follow the project's RE and evidence conventions. This debugger runs a native input; choose
an input whose execution and application side effects are authorized. It launches a separate
owned copy, captures one breakpoint observation and terminates that launch. It does not attach
to an existing process or resume a crashed execution.

1. `insight-cli lldb status --json` checks readiness. `lldb install` obtains our pinned
   LLDB 23.1.3 bundle (debugger, debugserver and library) from GitHub Releases. Managed delivery
   requires macOS 14+ ARM64. `download`, `install --archive FILE --offline`, `doctor` and
   `uninstall` use the shared lifecycle. `install --executable /path/to/bin/lldb` selects
   an external compatible bundle with its adjacent bin/debugserver and lib directory;
   these dependencies are fingerprinted. External files and research survive uninstall.
2. Start from static evidence identifying the relevant function and a useful input.
   `insight-cli lldb inspect INPUT --breakpoint FUNCTION --step-out --json` records arguments,
   registers, backtrace and the return from that call. `--target ID` reuses a captured input.
   Only a native thin ARM64 Mach-O is supported here; a Windows PE imported into Ghidra cannot run
   on this host. An optimized/stripped binary may omit names, arguments or source variables.
   `--symbols FILE` captures a matching DWARF file from a dSYM bundle and loads it before launch.
   `--variables` explicitly requests locals when debug information is available; without it
   registers/backtraces remain useful for stripped code. Moving an executable alone does not
   retain its adjacent dSYM.
3. `--hit N` skips earlier calls; compare calls around the relevant boundary. `--arg` supplies
   literal program arguments without shell expansion. Backticks are rejected because LLDB uses them
   for expression substitution. `--registers pc,sp,x0` selects registers.
   `--memory-address '$sp' --memory-bytes 64` records a bounded memory window. A `0x` breakpoint
   is a file address; memory addresses and printed pointers are runtime addresses affected by
   ASLR. Establish correspondence before combining them with static analysis.
4. A snapshot proves one observed path and input, not all possible behavior. `--limit` and
   `--offset` page native lines. `--output research/snapshot.json` saves the full bounded
   snapshot to a new ordinary file, creating parents. Raw diagnostics remain under the
   returned process directory. Preserve useful files with `artifacts save` when appropriate.
5. The deadline (default 30 seconds, up to 600) survives owner loss. LLDB is configured to
   kill its inferior on debugger connection loss. `tools processes --tool lldb --all` shows
   history; stop/kill applies to verified owned collectors. After an owner crash a live
   recovered macOS PID may be unverified: wait for its kernel deadline, inspect retained
   records and do not replay an execution blindly. Observed exit after loss means an unknown
   result, not a completed snapshot. Init files are disabled; no arbitrary debugger script
   or expression evaluation is exposed by this facade.

Generated `lldb inspect --help` owns exact syntax. No Ghidra session or merge is required;
these are runtime observations to corroborate static research.
