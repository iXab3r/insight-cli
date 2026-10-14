# Continue saved work

Retain the session/target returned by initial open. Continue the tuple through
`insight-cli ghidra open --session <id> --target <id> --json`. Saved private snapshots and
pending scalar comparisons persist independently of a backend process. Reopening preserves
private work; it does not silently receive a newer shared version.

If a response was lost, inspect `sessions status <session> --target <target>`. Never infer
`applied` from a connection failure. A changing command's optional request ID binds one effective
intent inside the profile. Repeating the same ID/input retrieves its recorded outcome or
unresolved state; changing input under that ID fails. Without an ID, calls are new intentions.

An unknown or partial effect retains its request intent, snapshots and native stage. Open the
same tuple to reconcile supported outcomes. A committed merge is verified against its recorded
server version and complete saved buffers through independent read authority; it is never
checked in again merely because its response was lost. Until verification succeeds, publication
for this shared target is blocked across sessions. Saved private work remains retained.

Scalar reconciliation observes and saves an already present effect; it does not execute the
setter again. Supported structural/function edits retain a candidate snapshot after an incomplete
response; continuation can verify every requested effect in that immutable snapshot and adopt it
without replay. If the complete result cannot be established, the candidate and previous saved
private view remain retained. An unproved program/script/external outcome remains unresolved. Preserve the profile
storage and credential store. Do not delete another session's project, stop a process by guessed
PID/port, or blindly repeat a script/external action to turn uncertainty into success.

The older prototype's `workers`, `findings`, `integrate` and batch `recover` commands are not the
public facade API. Its coordinator journals remain separate and are never silently migrated.
