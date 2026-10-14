# Continue saved work

Retain the session/target returned by initial open. Continue the tuple through
`insight-cli ghidra open --session <id> --target <id> --json`. Saved private snapshots and
pending scalar comparisons persist independently of a backend process. Reopening preserves
private work; it does not silently receive a newer shared version.

If a response was lost, inspect `sessions status <session> --target <target>`. Never infer
`applied` from a connection failure. A changing command's optional request ID binds one effective
intent inside the profile. Repeating the same ID/input retrieves its recorded outcome or
unresolved state; changing input under that ID fails. Without an ID, calls are new intentions.

An unknown or partial effect retains its request intent, snapshots and native stage. This
checkpoint reports those unresolved states and blocks conflicting work; complete automatic
reconciliation and merge/refresh remain under implementation. Preserve the profile storage and
credential store. Do not delete another session's project, stop a process by guessed PID/port,
or blindly repeat a script/external action to turn uncertainty into success.

The older prototype's `workers`, `findings`, `integrate` and batch `recover` commands are not the
public facade API. Its coordinator journals remain separate and are never silently migrated.
