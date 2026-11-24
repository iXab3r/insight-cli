# Agent business acceptance scenarios

The owner accepted these five branches and 25 scenarios on 2026-10-16. This document
owns the scenario hierarchy and acceptance criteria. All 25 scenarios now have
[individual Gherkin workflows and a frozen benchmark](BUSINESS-ACCEPTANCE.md). That
execution report records the historical **25/25 passed on real Ghidra**, including all six prepared-base
speedup pairs, separately from this agreed contract.
Existing technical checks and historical receipts do not establish acceptance of this
catalogue. [Automation setup](ACCEPTANCE-AUTOMATION.md) describes the current runner
and technical bridge; [CLI scenarios](CLI-SCENARIOS.md) describe the public contract.

The agent chooses the investigation, interprets evidence and resolves disagreements.
insight-cli supplies target/session context, tool operations and shared publication.
Acceptance concerns what the agent can accomplish through the installed public CLI.

## Current native collaboration expectations

The separately executable [Ghidra Server business follow-up](SERVER-BUSINESS-ACCEPTANCE.md)
adds GS-01–GS-32 without reassigning the historical BS IDs. Its current run results
must be read separately from the original 25-scenario acceptance.

For the native follow-up, describe the agent's goal and expected observable result before
implementation details. Keep BS-01–BS-25 stable. The historical 25/25 run is evidence for its
recorded artifact, not acceptance of the local native 0.5.9 build. The
[global native delivery](verification/native-global-cli-delivery.json) supplies supporting
technical evidence. GS-01–GS-32 are new Windows public-CLI workflows for that installed
artifact; the historical BS corpus and benchmark have not been rerun on it.

| Business expectation | Current native acceptance boundary |
| --- | --- |
| Two agents investigate independently, then deliver both contributions (BS-10–BS-11). | GS-01–GS-06 and GS-21–GS-23 check private work and fresh readback of names, exact types, related data models, navigation and code corrections. |
| An agent receives a colleague's findings and continues its own work (BS-12). | GS-07–GS-10 require stable private reads, explicit receive, retained local work and a subsequently delivered result. |
| Agents settle contradictory findings and deliver their agreed result (BS-14). | GS-14 requires deliberate public transfer of a chosen name, fresh readback, both notes and continued work by both original agents. GS-15 requires the same for a type; its observed silent replacement is a failure. Native in-place decision/resume remains missing. |
| A disagreement cannot silently lose findings or deliver only part of a selected result (BS-15). | GS-12–GS-13 and GS-18 check saved private/shared values and usable conflict details. GS-24–GS-26 and GS-31–GS-32 require preservation for byte, region-description and numeric-signature disagreements. An error code alone cannot pass them. |
| An interrupted agent resumes and establishes whether its result was delivered (BS-18–BS-20). | GS-09/GS-19 check graceful owner/server restart and continuation; GS-16 checks a lost completed client reply and original-request retry. These do not establish abrupt worker/check-in crash recovery. |

BS-14 must express the complete outcome, for example:

```gherkin
Scenario: Two agents settle contradictory findings and continue investigating
  Given two agents have independent findings about the same program
  And they disagree about a function name or a type definition
  When the first agent delivers its findings
  And the second agent requests incoming findings
  Then the second agent can inspect the disagreement without losing private work
  And no part of its conflicting finding set is delivered silently
  When the second agent explicitly chooses the intended result and delivers it
  Then a fresh agent reads the chosen name or type definition
  And unrelated findings from both agents are retained
  And both agents can continue their investigation from the accepted result
```

Use separate function-name and type-definition fixtures with explicit expected values.
The agent makes the decision; Ghidra applies its native merge semantics. This contract
does not select an automatic winner or authorize a coordinator merge algorithm. The example
is the acceptance expectation; GS-14 and GS-15 implement its distinct name/type cases.
The accepted BS-14 permits an intentional transfer through public operations. It does not
require a particular resolution command or UI. The name-transfer workflow has passed in
the follow-up; that result does not establish type settlement or native in-place
decision/continuation. The follow-up report owns exact outcomes and artifact identity.

For working-copy lifecycle, the observable expectations are that saved private findings
survive a restart, ordinary commands do not accumulate complete program copies, successful
delivery releases the verified private copy, and disagreements/uncertain delivery preserve
work. GC and migration of existing data remain outside this follow-up.

Delivery reports should lead with the scenario, expected result, observed result and any
remaining gap. Command transcripts, checkout IDs, fingerprints and process evidence support
that account; they do not replace the business outcome.

## Shared acceptance rules

- Use versioned, disposable EXE inputs with recorded hashes and independently prepared
  expected findings. Expected facts include enough identity, addresses, references and
  values to distinguish a correct result from merely successful commands.
- Drive research, edits, status, merge, refresh and result verification through the public
  CLI. Product assertions must not depend on direct MCP/SDK calls, internal database reads,
  a test-only command tree or runtime overrides. Harness-only fault injection and native
  process identity/timing observations are permitted and reported separately.
- Identify every CLI actor by its session and target. Separate actors use separate CLI
  processes and private contexts. Multiple CLI processes alone do not establish multiple
  Ghidra workers or parallel execution.
- Check result content and ownership: the expected target receives the intended findings,
  another target is unaffected, and another session sees only published changes. Confirm
  published outcomes through fresh independent public-CLI reads.
- Exercise explicit merge/refresh as the baseline. Automatically selected publication or
  conflict resolution must not change these scenarios' meaning.
- Record executed scenario IDs, input/build/runtime identity, outcome, assertion evidence
  and cleanup result. Missing prerequisites, empty selections, all-skipped scenarios and
  incomplete findings cannot count as acceptance. Existing technical evidence can be
  referenced as supporting evidence without marking a planned business scenario passed.

## 1. One agent investigates one EXE

| ID | Agent goal | Acceptance criteria |
| --- | --- | --- |
| BS-01 | Start an investigation | Opening the EXE returns unambiguous target/session identifiers. Subsequent public reads with those selectors inspect the expected input and report usable context. |
| BS-02 | Find a point of interest | Starting from a known string, import or other declared clue, the agent locates the expected program locations. Validate relevant addresses and values against the fixture oracle. |
| BS-03 | Trace behavior | From the clue, the agent follows references, containing/calling functions and decompilation to obtain the evidence needed to answer a predefined research question. Required relationships and findings are checked explicitly. |
| BS-04 | Record a finding privately | The agent renames a function, adds a comment or refines a supported type. Subsequent reads in the same context show the intended edits; an independent session does not see them before publication. |
| BS-05 | Deliver a completed result | The agent explicitly merges the findings. A fresh independent session reads the expected accepted names, comments and supported types from the shared base. |

## 2. One agent investigates several EXEs

| ID | Agent goal | Acceptance criteria |
| --- | --- | --- |
| BS-06 | Alternate between two EXEs | The agent reads and edits both targets in one investigation. Switching targets retains each target's findings and private work with no cross-target effects. |
| BS-07 | Distinguish identical file names | Two different EXEs have the same basename and overlapping function addresses. Reads, edits and publication consistently affect the selected target; content verifies that the other EXE remains unchanged. |
| BS-08 | Compare two program versions | The agent investigates the same declared behavior in two builds and obtains the expected differences, with evidence tied to each build's target and locations. The agent performs the comparison using available operations; automatic semantic matching is not assumed. |
| BS-09 | Return to an earlier EXE | After working on a different target, the agent resumes the original target/session and finds its prior observations, published state and retained private edits. |

## 3. Several CLIs investigate the same EXE

A and B are independent CLI actors with distinct sessions and private tool contexts
for the same target. Start them from a known shared revision and record which findings
each actor is expected to contribute.

| ID | Agent goal | Acceptance criteria |
| --- | --- | --- |
| BS-10 | Divide an investigation | A and B perform overlapping-in-time work on different parts of the EXE. Each can read the program and its own private edits; neither sees the other's unpublished edits. |
| BS-11 | Combine independent findings | A and B make disjoint supported changes and explicitly merge them. A fresh session reads both contributions in the shared result without losing either. |
| BS-12 | Continue after a colleague publishes | A merges while B retains private edits. B's context remains stable until explicit refresh; refresh adds safe incoming findings from A while preserving B's local work. B can then publish the combined result. |
| BS-13 | Agree independently | A and B assign the same value to the same object. Their publication/refresh sequence produces the agreed shared value without an artificial conflict. |
| BS-14 | Resolve contradictory findings | A and B propose different values for one field. After A publishes, B receives an explicit conflict with both local and shared versions available. B deliberately chooses/transfers the expected result and publishes it; independent readback confirms the choice. |
| BS-15 | Keep a finding set intact | B's selected merge contains both conflicting and safe edits. Any conflict prevents the whole merge from publishing. All B's local work survives, and independent shared reads show none of B's selected edits until a later successful merge. |
| BS-16 | Transfer a complex finding to the current base | A shared-base change conflicts with B's structural work. Preserve both versions; B uses the available public operations to transfer the intended work onto the current base and publish it. Validate the transferred finding and retained shared findings. Universal automatic database merging and force replacement are not acceptance requirements. |

## 4. Continue an interrupted investigation

Choose and record a concrete interruption point for each scenario during test design.
The business assertion is recoverable work and an established outcome. Detailed crash
phase matrices remain supporting technical integration tests.

| ID | Agent goal | Acceptance criteria |
| --- | --- | --- |
| BS-17 | Continue the first import | Interrupt the initial EXE opening after the original scope/request is established. The agent continues in the same profile with the original target/session/request, obtains one valid canonical initial publication and can investigate and merge a subsequent finding. No profile reset or blind publication retry is needed. |
| BS-18 | Recover an active investigation | Interrupt an owned tool process after acknowledged private edits and published findings exist. The agent reopens the original context and reads the expected published findings and acknowledged saved local edits, then completes the investigation. |
| BS-19 | Establish an edit outcome after losing its reply | An edit request's reply is lost after dispatch. Public status/recovery and the original request identity establish whether it applied. The agent continues with the expected local result, without applying the same effect twice. |
| BS-20 | Establish a merge outcome after losing its reply | A merge reply is lost after publication may have occurred. The agent establishes its outcome through the public interface and independent readback. Accepted findings appear once, local work remains available as appropriate, and continuation does not blindly repeat publication. |

## 5. Complete a shared task and measure acceleration

Use one fixed research task with deterministic expected findings that can be divided
into three useful complementary parts. A candidate is tracing an input-processing path:
format recognition, validation and content processing, with required functions and links.
The exact real EXE, task and oracle must be frozen before measurement. Each mode must
perform the same total useful work and produce an equivalent verified shared result.

| ID | Agent goal | Acceptance criteria |
| --- | --- | --- |
| BS-21 | Complete the task with one worker | One CLI actor and one Ghidra worker complete every part, publish the required findings and pass fresh-session readback. This establishes the serial correctness baseline and timing. |
| BS-22 | Complete the same task with three workers | Three independent CLI actors use three distinct native Ghidra workers with overlapping active task execution. Each contributes its assigned part; coordination and merge yield the same required shared result as BS-21. Record worker/context identity and overlap evidence. |
| BS-23 | Accelerate work on a prepared base | Paired one-worker/three-worker runs satisfy the measurement protocol below and all correctness assertions. The three-worker mode must demonstrate repeatable lower time to the verified shared result on the declared task. This is the required acceleration acceptance gate. |
| BS-24 | Measure the task from a cold start | Run the same task from declared clean initial state and report end-to-end time, including import, analysis, context startup and publication, for one and three workers. Correctness remains mandatory; cold-start acceleration is measured separately and is not a required speedup gate. |
| BS-25 | Complete a task with uneven work distribution | Use a declared task variant where one part is substantially heavier. All required findings must still be correctly combined. Measure the actual time, waiting/coordination costs and observed speedup or slowdown; disclose scaling limits. This case does not replace BS-23 or imply that all task distributions must accelerate. |

### Prepared-base measurement boundary

The owner requires acceleration on the prepared base and separate cold-start reporting.
For BS-23, canonical import and initial analysis are complete, the required one or three
worker contexts are ready, and no measured task findings have been precomputed. Record
the setup duration separately. Use equivalent baseline state and a declared cache policy
for both modes; results from a previous trial must not leak into a subsequent trial.

Start a monotonic clock immediately before dispatching the first measured task command.
Stop it only when all required findings have been merged and fresh independent public-CLI
readback validates the common result. Include CLI invocation overhead, work dispatch,
research, waiting, coordination, refresh, merge, retries and final readback. Test-runner
build/restore, fixture preparation and cleanup outside that task boundary are reported
separately. The duration of the entire test process cannot replace this task measurement.

For BS-24, begin the task clock before the first opening/import operation in the declared
cold state. Include required worker creation and all subsequent work through the same
verified result. State whether the cold policy covers application data, tool caches and
OS caches; do not imply cache control that the harness has not established.

### Comparative acceptance and evidence

- Freeze the EXE hash, build/runtime versions, expected findings, work partition, command
  workload, machine/resource allocation, cache/reset policy, repetition count, comparison
  method and any quantitative margin before collecting acceptance measurements.
- Use repeated paired trials with alternating or randomized mode order. Retain every
  trial's timings, outcome and environment. Report variability and the predeclared
  comparison, so one favorable run cannot establish acceleration.
- Require successful and equivalent business results in both modes. A failed, skipped,
  interrupted or incomplete trial cannot be counted as a faster success or silently
  discarded. Document any externally invalid trial and the declared rerun policy.
- Report raw task times, `speedup = T1 / T3` and `efficiency = T1 / (3 * T3)`, with setup,
  research and completion phases distinguishable. Prepared and cold results remain separate.
- BS-23 passes only with demonstrated repeatable improvement under the frozen comparison
  method, in addition to functional correctness. A quantitative target such as **1.5x has
  not been agreed** and must not be presented as an approved threshold. The exact workload,
  repetition count and statistical comparison are still to be specified before execution.
- Three Ghidra workers must be real, distinct and doing useful concurrent work. Three CLI
  clients routed into serialized native execution cannot establish the required result.

Fixed CLI workloads measure acceleration of tool-assisted investigation execution. They
do not establish the reasoning speed of live AI agents. A future live-agent benchmark
would need its own model/prompt/budget and variability controls. The accepted speedup claim
is limited to the declared workload and environment; neither linear scaling nor general
acceleration of every investigation is promised.

## Delivery and acceptance status

The hierarchy and prepared-versus-cold decision are agreed. Executable business features,
public-CLI bindings, versioned PE fixtures/oracles and the comparative benchmark now map
to these stable IDs. [Business acceptance](BUSINESS-ACCEPTANCE.md) records the execution
result (25/25 passed), exact artifact/input identity, raw timings and limits. Earlier
technical gates do not substitute for this separate business gate.
