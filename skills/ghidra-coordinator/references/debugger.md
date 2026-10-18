# Debug an input in its private context

Use the same `--session` and `--target` as static research. `debugger launch-offers` lists
available launchers and starts the owned GUI services when needed. `debugger launch` executes a
verified copy of the selected immutable input in an owned run directory. It accepts `--offer`,
`--args`, `--cwd`, a bounded launch timeout and the optional request ID. A second live process
uses another session; it does not replace this context's current process.

For local macOS `lldb`, `--stop-at-entry` launches stopped before normal program startup.
The response verifies a live `STOPPED` target and reports `stoppedAtEntry: true`. This is
useful for short programs: inspect/map/set breakpoints, then explicitly resume. Without the
flag, the existing immediate-run behavior is unchanged. Other offers reject this flag before
a CPU intent is reserved. An unknown stopped launch still requires ordinary request recovery.

Read `debugger status`, `modules`, `registers`, `stack-trace` and `traces`. Address conversion
uses `static-to-dynamic` and `dynamic-to-static`; memory and breakpoint commands take dynamic
addresses. Lists are paged. Read results identify the logical context and current trace, and
report whether the trace is connected or retained after disconnection. `--trace` selects a
saved trace within this context; IDs from another context are rejected.

Changing commands include interrupt, resume, step into/over/out and breakpoint set/remove.
Their optional request ID retrieves the recorded result without executing again. A genuinely
unknown CPU action remains uncertain; a later program counter alone does not prove how many
instructions executed. Read-only observation remains available for uncertain debugger actions.
Program merge does not roll back execution, debugger I/O or other process side effects.

Trace databases are checkpointed separately from the private program and verified by independent
packed-database readback before acknowledgment. Reopening after process replacement restores
saved trace data as disconnected. It does not restart the debuggee or reconstruct CPU execution.
Ordinary static program edits remain private and retain the usual merge/refresh behavior.
Static breakpoint bookmarks created by debugger actions also count as pending program changes.
They follow explicit merge/refresh and complex-change conflict rules; CPU execution does not
wait for publication, and publishing a program never resumes another session's process.

On macOS, launch enforces the selected working directory, including paths with spaces and
quotes. A GUI backend crash ends the owned live debuggee through its debugger controller.
Verified trace data retained before a lost action response is adopted on disconnected continuation,
unless a later observation already saved a newer view. The CPU action itself remains uncertain.

On macOS, use an installed local LLDB and an executable supported by that host. GUI startup
prepares the Python wheels already supplied with Ghidra in owned storage; it does not install
packages into system Python. A launcher's optional Python executable and Windows debugger
directory are Factory profile settings. Native Windows/Linux acceptance remains deferred.

Use generated help for exact flags. A retained static breakpoint bookmark may remain after its live trace placement is
removed; `trace_location_count` distinguishes current placements from that static metadata.

For a call observation, set the mapped function breakpoint **before** resuming from entry.
After the stop, check the PC against that address, then capture arguments and stack before
stepping. Step-out verifies return to the native caller in the same thread and stack;
return registers are observed without being modified. A competing stop or unavailable caller
does not count as a verified return. A requested step whose reply
or observed completion is unknown remains journaled; do not issue another CPU action to
try to recover a missing return. Retain its diagnostics and use request/status recovery.

For another intentional run, close and reopen the same owned context first: this disconnects
and retains the previous trace without relaunching it. Then launch with a distinct request ID
and desired arguments. A connected debugger remains busy even after its subject has exited;
selecting or reading its old trace is not a request to execute the subject again.
Map the new process and explicitly set/check its live breakpoints before each resume from
entry. Old static bookmarks do not establish new trace placements. Reopening restores each
trace's saved snap/thread, including inactive traces; choose its returned ID with `--trace`.
