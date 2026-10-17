---
name: insight-dotnet-dump
description: Capture a managed heap dump or inspect compatible .NET dumps with SOS to recover waiting stacks, objects, fields and retention evidence.
---

# Insight .NET Dump 0.2.0

Start with `insight-cli dotnet-dump collect --pid PID --output research/worker.dmp`.
The default Heap dump includes managed objects; Mini may lack required heap data. Collection
has a deadline and accepts only a nonempty file below 4 GiB. It does not execute dump data.

Use `analyze FILE --command clrthreads` or `--command clrstack` for thread context, then
`--command 'dumpheap -type TYPE'` to locate objects and `--command 'dumpobj ADDRESS'` for
fields. Reuse the returned `--target ID` instead of a file. `gcroot ADDRESS` can investigate
retention. Interpret the actual output: an empty type selection, unavailable DAC or SOS error
is not evidence that the requested object was found. Addresses belong to that dump only.
Use `--command 'help dumpheap'` for native SOS query syntax.
The API accepts one supported inspection command; it does not expose arbitrary debugger
scripts, chaining, symbol-server configuration or execution. Keep static object snapshots
separate from claims about current live state.

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
`tools processes --tool dotnet-dump --all` and `show ID` retain collector diagnostics. Update
permission is required. Generated `--help` owns exact syntax. Uninstall preserves research.
