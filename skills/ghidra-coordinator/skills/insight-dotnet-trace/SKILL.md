---
name: insight-dotnet-trace
description: Collect and inspect bounded .NET EventPipe traces to identify sampled thread work, waits or runtime activity; distinguish wall-clock samples from CPU consumption.
---

# Insight .NET Trace 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Use `insight-cli dotnet-trace collect --pid PID --duration-seconds 5 --output research/worker.nettrace`.
The default `dotnet-sampled-thread-time` profile measures sampled thread wall-clock time.
A sleeping method can rank at 100% while consuming little CPU. This API does not use the
Linux-only `cpu-sampling` kernel profile. Other declared EventPipe profiles cover common
runtime or GC events; a trace without sample events need not have a useful method ranking.

Use `report FILE --count 10` for inclusive method ranking (`--exclusive` changes the metric).
Reuse `--target ID` for captured immutable bytes. `convert FILE --format Speedscope --output
research/worker.speedscope.json` creates a new ordinary JSON export; Chromium is also supported.
Preserve the original trace, profile, duration, target identity and collection conditions.
Limited/dropped samples and startup/rundown overhead constrain inference; do not call this a
CPU speedup benchmark merely because a report contains percentages.

Use the existing project RE instructions and evidence format. `status` checks readiness;
`install` prepares the pinned tool and private .NET 10.0.13 from our GitHub Releases.
`--archive`, `--dotnet-archive` and `--offline` support local preparation; `--executable`
selects a compatible external tool, whose runtime/dependency closure remains user-managed.
Managed admission is macOS ARM64. A native compatible runtime/DAC is required for dump
inspection; a Windows dump is not promised readable on macOS.

Live commands require an explicit `--pid`. The selected process remains external: the CLI
owns its collector, not that target's lifetime. Use the PID supplied for this investigation;
process birth is checked around collection, with the reported OS identity strength. If the
process uses a custom TMPDIR, pass `--diagnostic-directory` with that directory. Do not
infer target ownership from a successful attachment or stop another agent's process.

Text views page with `--limit`/`--offset`; `--output FILE` retains complete bounded text in
a new ordinary file. Native text has a 4-MiB output bound; an output-limit error is not a
complete inventory. Save finished project files/folders with `artifacts save` when useful.
`tools processes --tool dotnet-trace --all` and `show ID` retain collector diagnostics. Update
permission is required. Generated `--help` owns exact syntax. Uninstall preserves research.
