# Agent host execution permissions

Keep the user/project host policy and the selected profile. A sandbox can deny writes
to runtime AppData or access to the local IPC endpoint, including during local help.
This is a host execution boundary, not evidence that the tool or its inputs are absent.

First retry only `insight-cli --help`, `tools list`, `skill`, or the selected application's
read-only `status` using the host's normal permission escalation. In Codex, use the
execution tool's `sandbox_permissions: "require_escalated"` with a scoped explanation
that the installed CLI needs its existing profile storage/local IPC. Automatic approval
review or the user decides that request; do not disable the sandbox or approval policy.

Do not work around this by changing HOME/AppData/profile paths, creating another host,
deleting owner/endpoint files, killing unrelated processes or claiming a missing runtime.
After the read-only probe succeeds, use the approved execution route for the intended
public CLI commands. An access refusal explicitly stating **no command was sent** is
known not dispatched; it is safe to submit that authorized command through the approved
route. This includes a mutation refused before dispatch. Do not mistake that definite
pre-dispatch refusal for an unknown execution outcome. Downloads still require their explicit
network access.

A lost mutation response is different from a denied startup probe: inspect retained
request/status/recovery evidence and use its request ID when supported. Never blindly
repeat a publication, script or program run whose outcome is unknown. External-tool
fallback is allowed by project rules, but record that the intended facade was not used
and do not invent a successful checkpoint or native result.

## Wait for the original execution

A tool operation may outlast the host execution tool's initial wait. A returned running
session/cell ID means that command is still in progress, not that the CLI returned no data.
Use the host's session poll/wait facility until terminal exit and consume stdout/stderr
before issuing a dependent command. In Codex, an `exec_command` session is continued with
`write_stdin`; a yielded execution cell uses that host's cell wait. Do not launch a second
open/install or repeat a CPU action just because the first chunk was empty. If the execution
really loses its terminal result, use the CLI's request/status recovery as described above.
