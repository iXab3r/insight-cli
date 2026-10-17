---
name: insight-managed-metadata
description: Query managed assembly metadata, MethodDef tokens, P/Invoke declarations and bounded IL, or compare two C#/.NET assemblies through insight-cli ilspy query/compare. Use for structured static evidence and changed-method research without executing the target.
---

# Insight Managed Metadata 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Keep the project's RE and evidence conventions. This capability parses assembly bytes;
it never loads target code for execution, resolves ambient assemblies or loads PDBs.
dnlib is a packaged implementation library, not another application to install.

1. Use the existing `ilspy status` and `ilspy install` for its private .NET 10 runtime.
   With an external ILSpy selection, supply a compatible explicit `--dotnet-host`.
   No SDK/compiler is needed on the consumer machine.
2. `ilspy query app.dll --json` gives assembly identity, metadata runtime/framework hints,
   type/method/import counts and bounded references/resources. Metadata runtime version
   is not the required execution runtime; the framework attribute may be absent or forged.
3. `--view types`, then `--view methods --type FULLNAME` finds exact dnlib names and tokens.
   `--filter TEXT` selects a literal fullname substring. Drill down with
   `ilspy query --target TARGET --view method --method 0x06000002 --limit 50 --json`.
   Offsets are IL instruction offsets, not native addresses. Tokens belong to one exact
   module SHA and may change when unrelated methods are added.
4. `--view imports` returns actual P/Invoke module, entrypoint, flags and managed signature.
   A declaration is static evidence; it does not prove which file the runtime loaded or
   that the import was invoked. Use native exports/Ghidra for static correspondence and
   an authorized runtime observation when execution evidence is needed.
5. `ilspy compare before.dll after.dll --json` identifies added/removed signatures,
   changed normalized IL/imports and reference changes. Operand names and branch/local
   indices avoid treating metadata RID changes alone as changed code. Signature changes
   appear as removed/added methods. Equal structure is not semantic equivalence: runtime,
   dependency, configuration and environment changes can still affect behavior.
6. Inputs are bounded to 64 MiB; `--limit`/`--offset` page rows or instructions. Comparisons
   scan at most 100000 methods; narrow a large query with `--type`/`--filter`.
   `--output research/metadata.json` saves the current bounded result/page to a new file.
   Use ordinary project notes and `artifacts save` when a checkpoint is useful.

Generated `ilspy query --help` and `ilspy compare --help` own exact options. Use the
existing decompile/IL commands when a source-style explanation is more useful than metadata.
