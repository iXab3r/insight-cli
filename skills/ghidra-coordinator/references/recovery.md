# Continue saved work

Retain the session/target returned by initial open. Continue the tuple through
`insight-cli ghidra open --session <id> --target <id> --json`. Saved private snapshots and
pending scalar comparisons persist independently of a backend process. Reopening preserves
private work; it does not silently receive a newer shared version.

First-import recovery uses the same scoped `ghidra open` or the original request ID/input.
Import/analysis writes a private snapshot and completion receipt before any initial publication.
If its worker is still running, continuation reports busy; wait and continue the same scope.
If that worker stopped before completing its receipt, continuation can repeat private analysis
from the immutable input while retaining previous attempts. A completed snapshot is reused.
Initial publication first creates a uniquely named staging object. A separate read-only process
verifies its complete saved DB buffers before a conditional server move to the absent canonical
path. It never checks in a new version of an existing canonical item. Lost promotion replies
are reconciled against the retained identity, one-version history and complete saved buffers.
Interrupted staging objects remain retained and can be replaced by another private stage;
they are not adopted as the canonical model. Foreign or mismatched canonical state stays blocked.
An older direct create that is provably owned and left only an incomplete `<Recovered>` entry
can be moved aside without deletion; its bytes and original receipt remain preserved.

Legacy first-import failures are also recoverable in the original profile. Continuation first
establishes that the old owned bootstrap worker has ended, then uses an authoritative repository
probe. An absent canonical item permits private preparation; an existing first version requires
independent readback. The old project, intent and original session/target remain preserved.

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

A lost UI navigation response can be verified from the live authenticated cursor without another
goto. If its original owned GUI process has exited, continuation reports the uncertain UI action
as disconnected and retains saved program work. It does not recreate the old cursor or re-enable
a previous prompt policy. Other unproved live UI effects remain retained until their outcome is
established or the original process is known to have ended.

## Abandon an uncertain private program attempt

A post-mutation save timeout does not repeat the script or issue another save in the
error handler. Status exposes the original request identity and retained phase/budget.
Arbitrary script effects are never inferred from metadata or from an unverified DB.
After inspecting the retained attempt, explicitly stop only its verified owned worker
(`tools processes`, then `tools processes kill <process>` if required). Resume the
last acknowledged private snapshot with:

```sh
insight-cli permissions grant Destructive
insight-cli ghidra abandon --session <session> --target <target> \
  --request-id <original-request> --acknowledge-unknown-effects --json
insight-cli ghidra open --session <session> --target <target> --json
```

Abandon requires exactly one unresolved private program operation, an unchanged verified
previous snapshot/generation, a stopped original worker and no active publication or live
debugger. It retains the native project, candidate artifacts, original intent/execution and
previous diagnostic result. Its terminal request is `failed` / `state: abandoned` with
`outcome: unknown`; no effect is marked applied. Repeating abandonment retrieves the same
result. Earlier saved private edits remain pending. The original changing request ID cannot
execute again. Abandoning never undoes external effects or establishes what an arbitrary
script did; the acknowledgement explicitly accepts that uncertainty. Publication recovery,
initial import, UI and debugger attempts use their own protocols and cannot use this command.
