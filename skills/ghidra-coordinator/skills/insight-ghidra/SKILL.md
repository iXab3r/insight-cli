---
name: insight-ghidra
description: Inspect or edit native binaries with Ghidra through insight-cli; use isolated contexts, multi-agent merge/refresh, server, GUI or debugger workflows. Choose this for static native behavior and references, not C# recovery from managed IL.
---

# Insight Ghidra 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Ghidra operations can exceed the host execution tool's first wait. If it returns a running
session/cell ID, await that same execution with the host's wait/poll facility until terminal
status and read its stdout/stderr. An empty first chunk is not a lost CLI response. Do not
start another open or repeat a CPU mutation while the original command is still running.


New targets import **without automatic analysis**. Reuse existing selectors/projects before
opening another copy; `ghidra open --session <session> --target <target>` preserves its bound
load settings, including older analysis choices. `--no-analysis` makes the fast choice explicit;
`--analysis` opts into a full analysis only during the first import of a new target.
After a fast import, use scoped `ghidra analysis run` to process pending analysis, or
`ghidra analysis reanalyze` to deliberately queue full reanalysis. These are saved private
mutations; merge deliberately. For a narrow question prefer bounded function disassembly,
function creation and decompilation first; inspect help for the exact operation.

For long first opens, `ghidra progress --session <session> --target <target> --json`
reads retained progress without starting Java or repeating the operation. It reports the
current stage, elapsed time, heartbeat age and native task message/counters when available;
those counters belong to the current task, not the whole import. Human output also reports
progress through Factory; `--json` keeps one final JSON result on stdout and stays quiet.
If the execution host yields, keep its same running execution and inspect progress every
5-10 seconds when useful; relay stage changes or meaningful stalls, and do other independent
work. Do not silently extend waits to minutes or start a second import. Until selectors are
returned, use the existing `sessions list/status` and `tools processes` inventory to locate the
reserved scope. A stale heartbeat, dead worker or unknown result is not completion: inspect
`sessions status` and recovery before continuing. Pre-upgrade workers have no progress record;
null progress means unavailable, never success. Progress is observational, not a completion receipt. This command tracks first open only;
its old complete record does not describe later `analysis run`/`reanalyze` operations.
`operation: initial-model` completes after verified shared-model publication; the private
session context can still be opening. Inspect `sessions status` for context readiness.

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
2. Open the input with `ghidra open <input> --session new --json`. Retain the returned session and target.
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
7. Finish by closing each context you own with scoped `ghidra close`, preserving private work.
   If this profile's local server belongs exclusively to your investigation and all its contexts
   are closed, use `ghidra server stop`, then verify `ghidra status` has no remaining processes.
   `ipc-server stop` stops the CLI owner; it does **not** stop Ghidra's local server. Stop that
   owner last when needed. For a shared profile/server, leave server shutdown to its coordinator;
   an individual worker closes only its own contexts and never kills unrelated processes.

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

For authorized macOS local debugging, use `ghidra debugger launch --stop-at-entry`
with the returned session/target and `--json`; then inspect status, registers and stack
before resuming. The default launch runs immediately, so a short program may exit before
an interrupt. Before resuming from entry, map the selected function and set a live breakpoint at the
returned dynamic address. Resuming a short program without that breakpoint can run it to
exit before any call is observed. At the breakpoint verify PC, then read arguments/stack
and step out or over the call to inspect its actual return.
Repeat mapping and live breakpoint setup for every new launch. A saved breakpoint bookmark
does not prove placement in that new process; check its `trace_location_count` before resuming.
Use `new` only when creating a session; subsequent calls take its actual returned ID.

Long import/save budgets and stopped-worker abandonment: see [recovery](references/recovery.md) and [setup](references/setup.md). Never replay an uncertain script.
