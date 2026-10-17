---
name: insight-ilspy
description: Recover C#, inspect IL/types/metadata, extract resources or export projects from managed .NET assemblies through insight-cli ILSpy. Choose native analysis for NativeAOT or ordinary PE machine code.
---

# Insight ILSpy 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Use the project's preferred tool and evidence conventions. Use ILSpy for static managed
assemblies with CLR metadata. It does not execute the assembly, recover C# from NativeAOT,
or establish runtime behavior from pseudocode alone.

1. `insight-cli ilspy status --json` checks the selected profile. If needed,
   `insight-cli ilspy install` prepares the pinned ILSpy and private .NET runtime.
   No machine-wide SDK is required. Use generated install help for local archives,
   offline cache or an external executable; see [workflows](references/ilspy.md).
2. Start with `ilspy query <input> --json` and `--view types`, then decompile one relevant type/member,
   inspect its IL or metadata, or enumerate resources. Use returned target identity
   across calls/tools. `--target` reuses immutable bytes without opening Ghidra.
3. Text responses default to a 16000-character window. Page with `--limit-chars` and
   `--offset-chars`; combine only pages with the same `textSha256`. The hash covers observed
   native text, which may itself be incomplete. Save full bounded text with `--output`,
   or extract a selected resource into new ordinary output paths.
   Recover a full project only when the question calls for it. Distinguish recovered
   code/names from source truth. Record commands/input identity alongside findings
   according to project rules.
4. `tools processes --tool ilspy --all` shows executions and retained diagnostics.
   Inspect partial exports after failure; choose a new output path for an intentional
   retry. Close only owned executions; uninstall preserves external files and research.

Execution and preparation need Factory Update permission. `ilspy --help` supplies exact
commands/options; the [workflow reference](references/ilspy.md) covers inputs, outputs,
resource/project export and continuation. Save a completed project file/folder through
`insight-cli artifacts save` when a checkpoint is useful; it is independent of Ghidra merge.
