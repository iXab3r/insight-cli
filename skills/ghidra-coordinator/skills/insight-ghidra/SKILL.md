---
name: insight-ghidra
description: Inspect or edit native binaries with Ghidra through insight-cli; use isolated contexts, multi-agent merge/refresh, server, GUI or debugger workflows. Choose this for static native behavior and references, not C# recovery from managed IL.
---

# Insight Ghidra 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Use `ghidra status` to inspect runtime readiness; `ghidra install` delivers the pinned runtime.
For static managed C#/IL research, locate `insight-cli skill insight-ilspy`.
For owned process inventory use `tools processes`; `stop` saves Ghidra contexts, while
`kill` explicitly interrupts verified owned work and preserves its journals.
For archives, external launchers, server lifecycle or removal, read [managed runtime](references/managed-runtime.md).

This skill and its executable helper are one npm package. Run `insight-cli skill insight-ghidra` to locate
these installed resources. Use generated `--help` for syntax; read the references as needed.
Follow applicable project RE rules for tools, source of truth, evidence layout and format;
this package's walkthroughs fill gaps rather than replacing those conventions.

For coordinating a reverse-engineering investigation with ordinary files, external tools
and multiple agents, locate the RE workflow with `insight-cli skill insight-re`. When a retained checkpoint is useful, save
a completed project file or folder with
`insight-cli artifacts save <path>`; [save semantics](references/artifacts.md) describe the
ordinary saved copy and its receipt. Neither operation requires a Ghidra installation.

1. Select the configured runtime profile. Ordinary work uses a managed local server; an external
   server is optional. See [setup](references/setup.md). Factory permissions authorize changes.
2. Open the input with `ghidra open <input> --session new`. Retain the returned session and target.
   Another agent chooses `new` independently; one session can open several inputs.
3. Pass both `--session` and `--target` on research calls. Follow strings to xrefs and their
   function addresses, then inspect/decompile. Decompilation defaults to a 16000-character
   window; page with `--limit-chars`/`--offset-chars` and retain `textSha256`. Native
   truncation remains explicit even at the end of the observed text. See [research](references/research.md).
4. Rename functions or set/clear comments through ordinary commands. An `applied` result means
   verified saved private work. Other sessions keep their own views; local edits remain unpublished in the default manual mode.
5. By default, publish explicitly with `ghidra merge`; receive safe shared changes with `ghidra refresh`.
   Resolve overlapping names/comments against an explicitly observed shared value. A conflict
   prevents the whole selected merge and retains local work.
6. Continue with `ghidra open --session <id> --target <id>`. For uncertain outcomes inspect
   `sessions status <id> --target <id>` and [recovery](references/recovery.md). Supplying a stable
   optional `--request-id` lets a repeated changing intent retrieve its outcome without rerunning.

The facade exposes the pinned static research/editing catalog, merge/refresh, project/server/GUI
controls, debugger, archive exchange and supported recovery. Preserve private work
and journals while an outcome is unresolved. The CLI supplies the investigation tools; agents
choose research goals and interpret findings.
Installing this package does not register this skill in an agent's configuration.

For project files, program export/import and configured-server administration, read
[administration](references/administration.md). These operations preserve separate research views;
their external effects do not participate in program merge.

For owned GUI execution, CPU state, breakpoints and retained traces, read
[debugger](references/debugger.md). Execution side effects remain separate from program publication.

For explicit external documentation exchange and retained submission outcomes, read
[archive](references/archive.md).

For selected native SDK extensions (VT, DB differences, byte/assembly edits, formats, GDT,
FID/BSim, namespaces and typed IR), read [native workflows](references/native-workflows.md).

For managed SDK extension modules, actual language/analyzer/plugin discovery and opt-in
automatic synchronization, read [extensions and sync](references/extensions-and-sync.md).
