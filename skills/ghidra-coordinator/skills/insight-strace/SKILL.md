---
name: insight-strace
description: Observe actual file reads, writes, process creation and network syscalls in an authorized owned native Linux launch using insight-cli strace. Use when static inference needs concrete operating-system interaction evidence.
---

# Insight strace 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Respect the project's RE and evidence format. This tool runs the supplied application;
its side effects must be authorized. It traces an owned native copy and its descendants.
A trace may contain private paths, strings or network data: retain it under project rules.

1. `insight-cli strace status --json` checks readiness. `strace install` obtains our pinned,
   source-built strace 7.2 bundle from GitHub Releases. Supported host: Linux x64 with glibc
   2.35+ and permission to ptrace an owned child. No root, global ptrace-policy change or
   arbitrary process attach is requested. `download`, `install --archive FILE --offline`,
   `doctor` and `uninstall` use the shared lifecycle. `install --executable /path/to/strace`
   selects an external compatible 7.2 executable; uninstall preserves external software.
2. `insight-cli strace trace worker --arg /absolute/settings.txt --json` captures immutable
   ELF bytes and runs a separate owned copy. Default events cover files, processes and I/O.
   `--events file,io` narrows categories; `network` is also available. The executable must
   be native x64 ELF. Adjacent executable sidecars are not copied; choose a suitable owned
   fixture/input rather than assuming another platform's EXE will run on Linux.
3. Establish the actual path and successful `openat`/`read` result, then relate returned bytes
   to application stdout. A static filename or attempted open is not a successful read.
   `--path /absolute/settings.txt` focuses a literal path and combines with categories;
   `--string-bytes N` bounds shown strings (default 128, up to 1024). Filtered or truncated
   data is unknown; syscall evidence does not prove high-level intent on other paths.
4. `--target ID` reuses captured code; `--arg` values remain literal, without shell expansion.
   `--limit`/`--offset` page trace lines. Native trace and program stderr share one stream;
   program stdout is separate. `--output research/file-read.json` saves the full bounded
   result to a new ordinary file. `artifacts save research` optionally checkpoints results.
5. `--timeout-seconds` bounds execution (default 30, maximum 600). A kernel parent-death
   guard and strace's `--kill-on-exit` bound owned tracees after owner/launcher loss.
   `tools processes --tool strace --all` retains history. Stop/kill applies to a verified
   owned launcher. A lost result remains unknown and is not automatically replayed.
   Output overflow or nonzero program termination retains diagnostics rather than a
   successful complete trace. Running the application again is a new side-effecting action.

Generated `strace trace --help` owns exact syntax. No Ghidra session or merge is required.
