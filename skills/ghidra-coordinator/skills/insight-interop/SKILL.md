---
name: insight-interop
description: Trace a .NET P/Invoke declaration to an explicitly supplied native library export and Ghidra function through insight-cli ilspy query, binary query and scoped ghidra APIs. Use for managed/native linkage evidence while keeping static correspondence separate from observed loading or execution.
---

# Insight Interop 0.2.0

Respect project RE/evidence rules. This workflow composes existing public APIs, without
another runtime, global active binary or universal library resolver. Tokens and native
addresses identify different immutable targets; preserve both hashes in the finding.

1. Read `ilspy query managed.dll --view imports --json`. Select the exact managed signature,
   MethodDef token, declared module/entrypoint, calling convention, charset and spelling
   flags. Drill into `--view method --method TOKEN` when needed. An absent declaration
   does not exclude dynamic loading, generated interop, reflection or runtime resolvers.
2. Select candidate native files explicitly. `binary query candidate.dll --json` identifies
   format, architecture and image base. A filename match alone is insufficient. A neutral
   IL assembly does not select the eventual runtime architecture by itself.
3. Query `--view exports --filter ENTRYPOINT`, then verify the **exact** name in the returned
   row: the filter is a substring. Keep its native target/hash, ordinal, RVA and VA. Do not
   treat a forwarded PE export as code; follow its named library/export using another
   explicitly supplied candidate. Ordinal imports, name decoration, charset A/W probing,
   Mach-O leading underscores and ambiguous candidates need explicit ABI/loader evidence;
   never silently choose a winner by stripping names or comparing addresses alone.
4. `ghidra open candidate.dll --session new --json` opens an isolated native context. Match
   this returned native target identity to the file just queried. Use
   `ghidra functions get --session S --target T --address VA --json`, then
   `ghidra functions decompile --session S --target T --address VA --json` to inspect the
   exact implementation candidate. An address pointing to data or an unavailable function
   is unresolved; do not create a claimed implementation merely to finish the workflow.
5. Write ordinary project evidence linking the managed declaration, concrete native export,
   scoped Ghidra function and useful behavior. Label this **static correspondence**. It
   proves neither that this file was selected by the runtime nor that the call occurred:
   search paths, architecture, custom resolvers and marshaling can change the actual route.
   An authorized Frida/LLDB/dnSpy observation is separate evidence when execution is needed.
6. If a useful annotation belongs in the shared Ghidra model, edit the chosen session/target
   and explicitly `ghidra merge --session S --target T`. Verify it from a new context;
   other workers refresh explicitly and retain their local changes. Metadata/binary reads
   have no independent merge. Checkpoint ordinary materials with `artifacts save` as useful.

Use each tool's dedicated packaged skill for install/status, bounds and generated help.
MacOS native workflow acceptance uses static Windows PE/.NET fixtures; it does not claim
those Windows binaries execute on macOS. Project-specific formats and tools take precedence.
