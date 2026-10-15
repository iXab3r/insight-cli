# Debug an input in its private context

Use the same `--session` and `--target` as static research. `debugger launch-offers` lists
available launchers and starts the owned GUI services when needed. `debugger launch` executes a
verified copy of the selected immutable input in an owned run directory. It accepts `--offer`,
`--args`, `--cwd`, a bounded launch timeout and the optional request ID. A second live process
uses another session; it does not replace this context's current process.

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

On macOS, use an installed local LLDB and an executable supported by that host. GUI startup
prepares the Python wheels already supplied with Ghidra in owned storage; it does not install
packages into system Python. A launcher's optional Python executable and Windows debugger
directory are Factory profile settings. Native Windows/Linux acceptance remains deferred.

The sixteen operations and disconnected trace restoration have a macOS native checkpoint.
The full installed crash matrix and combined delivery gate remain open. Use generated help for
exact flags. A retained static breakpoint bookmark may remain after its live trace placement is
removed; `trace_location_count` distinguishes current placements from that static metadata.
