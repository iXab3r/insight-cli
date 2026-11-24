# Shared Ghidra investigation: executable business expectations

This follow-up checks what independent agents can accomplish through the installed
public CLI against a real, disposable Ghidra Server. It supplements the stable
[BS-01–BS-25 catalogue](BUSINESS-SCENARIOS.md); it does not replace that catalogue,
rerun its performance benchmark or claim coverage of every Ghidra facility.

The [collaboration feature](../tests/acceptance/Features/ServerCollaboration.feature)
and [rich findings feature](../tests/acceptance/Features/ServerRichCollaboration.feature)
contain separately reported GS-01–GS-32 scenarios. EyeAuras.Automation owns execution,
deadlines, process supervision and TRX. Consumer-side
[bindings](../tests/acceptance/Bindings/ServerBusinessSteps.cs) select individual
[workflows](../scripts/server-business/workflows.mjs), rather than wrap the earlier
technical prototype in a passing business step.

## What must be observable

| Agent expectation | Scenarios | Relation to the existing catalogue |
| --- | --- | --- |
| Investigate independently and deliberately deliver complementary findings | GS-01–GS-04, GS-20 | BS-04–BS-05, BS-10–BS-11, BS-16 |
| Preserve exact numeric return types when combining findings | GS-05–GS-06 | BS-11–BS-12, extended type regression |
| Receive another agent's work and continue the investigation | GS-07–GS-08, GS-10 | BS-12 |
| Resume the same saved private work after restarting the service | GS-09, GS-19 | BS-09, BS-18 |
| Recognize agreement without a false conflict | GS-11 | BS-13 |
| Preserve the entire private set when part of it conflicts | GS-12 | BS-15 |
| Inspect the affected function/type and original, private and shared alternatives | GS-13, GS-18 | BS-14; a useful disagreement, not merely an error message |
| Deliberately transfer the chosen finding, retain unrelated findings and continue with both original agents | GS-14–GS-15 | The accepted public-transfer route of BS-14 |
| Establish delivery after a lost reply without another publication | GS-16 | BS-20; client-boundary reply loss, not an owner crash during check-in |
| Release a delivered copy and start a fresh contribution | GS-17 | Current working-copy lifecycle expectation |
| Retain a reconstructed data model and its use by the executable | GS-21 | Enum/union/typedef definitions, dependent structures, defined data and function type bindings |
| Retain navigable evidence and investigation annotations | GS-22 | Namespaces, labels, references, comments, bookmarks, equates, properties, options, trees and tags |
| Retain code corrections and execution assumptions | GS-23 | Bytes, instructions, function creation/deletion, memory region attributes, register context and external bindings |
| Preserve contradictory byte corrections and region descriptions | GS-24–GS-26 | Real native conflicts; both directions of description deletion/revision |
| Combine complementary work on one function by three agents | GS-27 | Name, result type and exact local-variable type/stack storage |
| Deliver at the same time without losing either contribution | GS-28 | Concurrent public clients, serialized publication and independently verified result |
| Avoid accumulating complete copies during repeated saves/reopens | GS-29 | Same checkout, stable physical project/packed-file inventory and verified project removal |
| Inspect attributable contributions and active investigations | GS-30 | Public history, checkouts and distinct repository ACL roles |
| Preserve first-time float/double disagreements in both directions | GS-31–GS-32 | No silent winner or publication when result types conflict |

Function and type disagreements use different fixtures. A real conflicting Update
must occur before preservation or settlement can pass. Fresh sessions verify shared
results; reads from an already edited private copy cannot establish delivery.
GS-14 and GS-15 explicitly choose the second agent's conflicting finding and retain
unrelated notes from both agents. They apply that choice to a fresh current context
through public edits, deliver it, then explicitly discard the superseded private set
and verify that both original agents can continue. This is deliberate transfer by an
agent, not an automatic coordinator merge or native in-place conflict continuation.

Detailed native conflict choice/resume remains a separate missing capability. Passing
the transfer route would not prove that capability. Safe refusal alone cannot pass
settlement. Failures in the new expectations remain failures, with their observed
values and complete command transcripts retained.

## Observed gaps in installed 0.5.9

The complete development attempt on the same installed artifact exposed these gaps.
The corrected full run and diagnostic selections retain their own actual outcomes and
failure phases; an earlier observation cannot replace an assertion they did not reach.

| Scenario | Expected result | Observed result |
| --- | --- | --- |
| GS-11 | Independently choosing the same name completes without a false disagreement. | A publishes `agreed`; B's Update returns `coordinator.unknown`. Native stderr records `java.io.IOException: Concurrent database modification error (4)`. B's ordinary close is blocked; the project and unresolved journal remain retained. B's final saved contents were not established by this case. |
| GS-13 | The agent can inspect the affected function and original/private/shared names. | Status supplies only the native `listing` conflict message, without the address or three alternatives. Preservation passed before this assertion failed. |
| GS-15, GS-18 | Contradictory structure definitions require a decision and inspectable alternatives before the chosen result is delivered. | Both Updates report success without a conflict. Supplemental GS-15 reads find the incoming `float` definition in the private copy. Settlement in GS-15 and the three-way detail assertion in GS-18 are not reached. |

A separate minimal disposable control for GS-15 reads both definitions before receiving:
`Record0.count` is `float`/4 bytes in A and `double`/8 bytes in B. After A publishes,
B still reads `double` immediately before Update. Update returns `updated`, no conflicts,
and `preservedLocalChanges: 1`; B then reads `float`/4 bytes. A public enumeration finds
only that `Record0` definition. History gains no additional publication, and all control
workers close successfully. These supplementary receipts are separate from the 32 case
outcomes. Backup recovery and attribution to Ghidra or the adapter remain unverified.
The passing GS-05/06 checks concern function return types, a different case.
The inspection scripts contain no explicit data edits but still append ordinary CLI
mutation bookkeeping. Their receipts are post-failure observations; they are not
untouched forensic snapshots.

## Fixture and evidence boundary

Each scenario owns separate application/control directories, a local server and a
repository. Its agents share that repository; failures and frozen copies cannot consume
another scenario's context capacity. The same installed CLI artifact serves the full run.
Most fixtures are different immutable raw x64 programs. GS-23/25/26 use deterministic
PE32+ images whose loader establishes code at `1000` and data regions at `2000`/`3000`.
The address oracle is declared in the fixture generator and checked by public reads.
Public inline scripts
prepare the known function/type baseline and perform type edits not covered by a
convenience command. Normal public CLI processes perform all research, edits, Update,
publication, history reads, continuation and cleanup. There are no product imports,
custom product entrypoints, direct MCP requests or replacement merge implementation.

These constructed Program fixtures isolate collaboration over Ghidra's data model.
They do not satisfy the original catalogue's compiled-EXE research corpus, target-version
comparison or performance acceptance. Those BS scenarios retain their own prerequisites
and require a separate native rerun before their historical results can be renewed.

The actual installed package must match every payload file in the supplied archive
before and after the run. The runner records hashes for the business sources, verifies
they remain unchanged, retains TRX and emits a report even when scenarios fail. A full
run requires all 32 distinct outcomes; an absent scenario is not a pass. Every scenario
attempts to close its own active workers and records a failed close separately. A frozen
unknown operation must retain its project and journal; it cannot be counted as successful
scenario cleanup. Every driver additionally disconnects its own server and stops its
own IPC owner, recording service cleanup separately from context closure. The outer
runner retries only teardown for owned interrupted drivers. Saved projects, failed work and server history remain
available for diagnosis; GC and migration of old contexts are excluded.

GS-20 checks cooperative credential separation: the actual private worker has no
publication password environment variable and its repository is disconnected. It is
not an OS sandbox or a hostile-code security test. GS-29 additionally observes the
owned workspace's physical project/packed-file inventory. It does not establish disk
scaling for large production databases or GC. Full DB fingerprint verification retains
the separate technical integration evidence. Rich readback uses a fresh agent's public
inline script with explicit golden assertions; no internal server SDK is used by the driver.
Memory scenarios edit existing regions. New memory-layout operations require Ghidra's
exclusive access and are outside these ordinary-checkout workflows.

This gate covers the declared multi-agent investigation outcomes, not every Ghidra
Server facility. It does not establish joining the same existing item from independent
machines/workspaces, exclusive memory-layout or language changes, native in-place
conflict choice/resume, or abrupt process failure inside check-in. Repository account
administration and destructive history management are not comprehensively exercised.
Program user-data, external files and tool preferences are not claimed as shared program
findings. The recorded red cases and these boundaries prevent a full-parity claim.

`ec2-native` and existing product profiles are excluded. Explicit fixture authorization
and paths are required; no fallback to an ordinary user profile is allowed.

## Run

Development attempts are retained separately. A four-case selection passed before
the suite was expanded. The first full attempt was stopped after GS-05 incorrectly
expected a prototype edit to rename its function: its actual result was
`float baseline_0(void)`, so this was not float loss. GS-05/06 now use the existing
function names and still compare exact numeric signatures after Update and published
readback. That stopped attempt has no final TRX and is not complete acceptance.
A subsequent complete shared-profile attempt executed all 32 cases: 19 passed and 13
failed, with no skips. Four failed cases exposed the product behavior described above;
GS-23/25/26 stopped during unnecessary memory-layout setup, and GS-27–GS-32 were blocked
by the capacity occupied by earlier frozen copies. Its original report, TRX, unchanged
source/payload checks and independent process-exit verification remain retained. That
attempt is development evidence, not acceptance of the corrected fixtures or isolation.
A later isolated attempt was stopped with 17 recorded outcomes (14 passed, 3 failed)
and GS-18 in progress, before reaching invalid checkout comparisons in GS-29/30.
Session status uses numeric IDs while repository listings use decimal strings: the
old release predicate could pass even with a checkout still listed. The corrected
predicate normalizes that boundary and proves initial presence before testing release;
negative controls reject a still-listed checkout. That stopped attempt has no final
TRX. Its frozen source copies, unchanged installed payload and independent process-exit
verification remain retained. Its GS-13 failed during CLI-host startup, before any
conflict assertion; it is not another observation of missing conflict details.
The corrected candidate must run from new fixtures; successful prefix results cannot
substitute for its complete run. Windows runs use short owned paths; longer-prefix
bootstrap pilots failed in Java keytool's `NUL` handling before program import.

Initialize the pinned dependency and SDK prerequisites as described in
[Automation setup](ACCEPTANCE-AUTOMATION.md). Set these environment variables:

- `INSIGHT_NATIVE_DISPOSABLE=1`
- `INSIGHT_SERVER_BUSINESS_OUTPUT`: an existing disposable output parent outside the checkout
- `INSIGHT_GLOBAL_CLI`: the installed package's actual `dist/src/bin.js`
- `INSIGHT_SERVER_BUSINESS_ARCHIVE`: the matching CLI archive
- `INSIGHT_JAVA` and `INSIGHT_GHIDRA_HOME`: Java 21 and Ghidra 12.1.2

This follow-up currently runs on Windows. Run `npm run test:business:server`. To narrow development, append a normal Automation
filter, for example `-- --filter 'Name~GS-14'`. A selection is reported as a selection,
not a complete run. Local paths and raw logs belong in the private output directory;
only a sanitized report is suitable for source control.
