# Performance and opt-in timing

Use the existing persistent `--json-rpc` entry point with `cli.execute` for repeated
commands. It preserves ordinary command permissions, errors, explicit session/target
selectors and durable request IDs. A one-shot process additionally loads the CLI and
verifies its deployed package bytes. Bounded `functions inspect` already supports
multiple functions; batching does not relax view or result-completeness checks.

For local diagnosis, create a private directory and set `CLI_FACTORY_TRACE_DIRECTORY`
to its absolute path **before starting the CLI and its ordinary IPC owner**. An existing
owner keeps its startup environment; wait for its normal idle exit before changing
instrumentation. Do not stop another researcher's owner to enable tracing.

Each participating Node process writes an exclusive mode-0600 `pid-UUID.jsonl` file.
Records contain a schema version, PID, random request ID, span ID/parent, optional
hashed logical scope, static stage, monotonic nanosecond start/duration and success.
There are no arguments, paths, endpoint URLs, credentials, program text or result
bodies. The limit is 200,000 records per process; filesystem failure disables the
sink without changing command outcomes. Relative/nonexistent destinations produce
no usable trace. Retain the directory privately and inspect before sharing.

Stages cover module/schema preparation, deployed-byte verification, owner discovery
and IPC, permissions/profile validation, command/context queue waits, authenticated
backend calls, native helper processes, save/export, snapshot copy/verification,
saved-effect inspection, journal transactions, publication and output serialization.
`backend.dispatch` includes network and native execution until response headers;
`backend.response-read/decode` cover body transfer/decoding. A Java helper span covers
its entire child process, including Ghidra initialization and execution. These are
boundary timings, not CPU profiling inside the Ghidra decompiler.

Spans are inclusive and can overlap. Never add client roundtrip, owner command,
handler and backend durations into one critical path. The repository's
`scripts/performance/trace-report.mjs` subtracts the union of immediate child intervals
for exclusive durations and keeps process/request trees separate. Bootstrap spans
can precede the first command. Cross-process random request IDs are not a distributed
causality identifier; correlate an isolated serial reproduction by its time window.

Tracing is off by default. Measure its cost for the actual workload before using a
traced run as a performance baseline. The repository includes an alternating on/off
sink-cost experiment and separate traced native diagnostics. Full native benchmark
protocol, owned fixture builder and regression jobs are in `docs/NATIVE-PERFORMANCE.md`
in the source repository. Snapshot publication, saved-state verification and authority
checks remain part of the normal contract; a raw stock save performs less work than
an insight merge and must be reported separately.
