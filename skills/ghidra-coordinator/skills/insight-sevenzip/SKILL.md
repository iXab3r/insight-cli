---
name: insight-sevenzip
description: Inventory, integrity-check and recover files from archives and supported containers with insight-cli 7-Zip, then hand recovered binaries or configuration to the appropriate research tool.
---

# Insight 7-Zip 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Use the project's existing evidence layout. Container recovery produces ordinary files;
it does not publish analysis or require a Ghidra session.

1. Check `insight-cli sevenzip status --json`. `sevenzip install` prepares the private,
   pinned 7zz runtime from our GitHub Release; `--archive` accepts a local gzip tar or zip,
   and `--offline` prevents downloads. Managed delivery is macOS universal. An external
   compatible 7zz 26.04 can be selected with `--executable` and is never deleted by uninstall.
2. Run `sevenzip list INPUT --json` for a bounded inventory. Continue with `--offset`;
   `sevenzip test INPUT --json` checks archive integrity without executing its content.
3. Recover one exact file with `sevenzip extract INPUT --entry path/from/inventory
   --output NEW_DIRECTORY --json`. Omit `--entry` only for small, trusted container trees.
   The output directory must be new; choose a different directory after a partial failure.
4. Read recovered configuration bytes before summarizing values; the inventory gives paths
   and sizes, not configuration contents. For DLLs use the managed/native skill that
   matches their format; do not execute a recovered program to identify it. Preserve the
   parent archive identity and recovered path in your notes. `artifacts save` can retain
   the completed folder using the project's format.

All research calls accept either INPUT or `--target`, and require Update permission to
capture immutable input and run the tool. Recovery is bounded to 512 entries, 64 MiB per
file and 256 MiB total. Encrypted recovery, ambiguous multiline filenames, links, special
files and colliding output paths are unsupported. It extracts file bytes through stdout
and writes validated paths itself, keeping archive-selected paths away from native writes.
Container integrity proves consistency of bytes, not safety or truth of their contents.

Use generated `--help` for syntax and `tools processes --tool sevenzip --all` for retained
execution diagnostics. A process limit/deadline is a failed operation; inspect retained
partial output before another intentional call.
