---
name: insight-dotnet-stack
description: Inspect live managed thread stacks to identify active or waiting work in an explicitly selected .NET process without taking a dump.
---

# Insight .NET Stack 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Use `insight-cli dotnet-stack report --pid PID` for a lightweight live stack snapshot.
Inspect the managed callers around native wait/sleep frames: a wait identifies where a
thread was sampled, not by itself why an application is stalled. Keep PID/birth, capture
time and relevant frame names in the project evidence. Different snapshots may legitimately
differ. Use dotnet-dump for object/field questions and dotnet-trace for a bounded view over
time instead of presenting one stack snapshot as a performance measurement.

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
`tools processes --tool dotnet-stack --all` and `show ID` retain collector diagnostics. Update
permission is required. Generated `--help` owns exact syntax. Uninstall preserves research.
