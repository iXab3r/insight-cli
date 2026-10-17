---
name: insight-die
description: Classify unknown executable or container inputs by format, architecture and compiler/runtime/packer signatures with Detect It Easy before choosing managed or native analysis. Use insight-cli die for static triage and preserve scan uncertainty.
---

# Insight Detect It Easy 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Follow the project's RE instructions and evidence format. DiE provides quick static triage;
it does not execute, unpack or decompile the input. Use the classification to choose a focused
next tool, then verify important claims with that tool.

1. `insight-cli die status --json` checks readiness. `die install` obtains our pinned console
   bundle from GitHub Releases: DiE 3.21, its database and private dynamic Qt frameworks.
   Managed delivery supports macOS 13+ ARM64. `die download`, `install --archive FILE` and
   `--offline` use the ordinary managed lifecycle. No system Qt or installer is needed.
   `install --executable /path/to/MacOS/diec` selects a compatible external bundle retaining
   adjacent Resources/db, Resources/db_custom and Frameworks. The database and five required
   frameworks are fingerprinted too. Uninstall preserves external files and research.
2. `insight-cli die classify INPUT --json` reads both file information and signatures.
   `--target` reuses the captured immutable input instead of INPUT. Start with the default
   scan; use `--deep` or `--heuristic` for a reason. The input is never launched.
3. Separate the file header from signature guesses. PE/ELF/Mach-O architecture is not proof
   of the original programming language. A managed AnyCPU assembly can report an I386 PE
   header; it does not establish the process architecture on another host. A .NET runtime
   signature is a reason to inspect metadata with ILSpy. Native code, NativeAOT and unclear
   managed recovery require native inspection such as LLVM or Ghidra.
4. Inspect `complete`, `state` and `diagnostics` before interpreting findings. The pinned
   upstream scanner can append JavaScript signature errors after valid JSON and still exit
   zero. We retain the useful records but mark that classification `partial`. Errors,
   Unknown or no packer match never prove absence of packing/obfuscation/runtime code.
   Cross-check important signature claims. Do not present a partial scan as exhaustive.
5. `--limit`/`--offset` page signature findings. `--output research/triage.json` saves the
   complete bounded envelope including all findings/warnings to a new ordinary file, making
   missing parents. Raw native stdout/stderr remain in each returned process's diagnostic
   directory. The 4-MiB output bound and per-process deadline fail explicitly; limited output
   is not a completed scan. Save completed research with `artifacts save` when useful.

`die doctor` checks the selected runtime. `tools processes --tool die --all` and `show <id>`
provide owned execution history. These reads need Update permission to capture input and run
the scanner. Generated `--help` owns exact syntax. Use the private bundle by default; copied
compatible Qt frameworks can be replaced and the resulting external bundle reselected as
explained in its NOTICE.txt. No Ghidra session or merge is needed for this static classifier.
