# Agent walkthrough on a real Windows EXE

Follow-up: [interrupted first-import recovery](INITIAL-IMPORT-RECOVERY.md) closes the bootstrap
limit found in this walkthrough, including the same retained profile. The evidence and limits
below describe this earlier build.

The 2026-10-16 walkthrough uses the installed `insight-cli` executable, its ordinary Factory
IPC owner and a separate disposable profile. Every research, edit, publication and continuation
action uses public CLI commands. There are no in-process fixtures, custom entry points, runtime
patches, direct bridge requests or SDK calls in this investigation. Native logs were read only
to diagnose the failed first import. [Evidence](verification/agent-cli-7zip.json) identifies the
input, installed artifact, source hashes, observed results and separately run regressions.

## Input and research question

The input is the official [7-Zip standalone console executable](https://www.7-zip.org/download.html),
downloaded from `https://www.7-zip.org/a/7zr.exe`: 602624 bytes, SHA256
`256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282`.
It is a production PE32 x86 executable, rather than a generated acceptance fixture. The URL can
change its contents; compare the digest before expecting the same addresses. The input is
analyzed statically and is never executed. Neither the EXE nor profile data belongs in this repo.

Question: locate the handling of an unknown command-line switch and publish a supported
function name and explanatory annotation. Use Node 24, Java 21 and Ghidra 12.1.2 on macOS.

## Public commands

Create a fresh profile with the installed tool paths, then use it on every command below:

```sh
insight-cli profile create agent-review --java "$INSIGHT_JAVA" --ghidra-home "$INSIGHT_GHIDRA_HOME" --json
insight-cli --profile agent-review permissions grant Update --json
insight-cli --profile agent-review ghidra open ./7zr.exe --session new --request-id open-A --json
insight-cli --profile agent-review ghidra open ./7zr.exe --session new --request-id open-B --json
```

Retain A's and B's returned session IDs as `$A` and `$B`, and their equal target ID as `$T`.
Both report `ready`, R1 and zero pending changes. An ordinary shell wrapper can prepend
`insight-cli --profile agent-review`; the examples spell it out to keep profile scope explicit.

```sh
insight-cli --profile agent-review ghidra strings search --session "$A" --target "$T" --contains Unknown --limit 10 --json
insight-cli --profile agent-review ghidra xrefs to --session "$A" --target "$T" --address 0x47c2ac --limit 10 --json
insight-cli --profile agent-review ghidra functions get --session "$A" --target "$T" --address 0x40125a --json
insight-cli --profile agent-review ghidra functions decompile --session "$A" --target "$T" --address 0x40125a --json
```

String search returns six matches with complete scanning; `Unknown switch:` is at `0x47c2ac`.
Its one incoming reference is at `0x4012e5`, in `FUN_0040125a` at `0x40125a`. Decompilation
shows a leading `0x2d` test, matching against a switch table and diagnostics for duplicate use,
long/short switches and incorrect postfixes. This supports the inferred name
`ParseSwitchArgument`. The recovered prototype remains uncertain and is left unchanged.

```sh
A_EVIDENCE='Inferred switch-argument parser: matches a leading dash against a switch table and validates duplicate use and postfix length/content. Evidence: xref from Unknown switch: at 0x47c2ac and decompiled diagnostics Multiple instances for switch:, Too long switch:, Incorrect switch postfix:, Too short switch:. Recovered prototype is uncertain.'
B_REVIEW='Independent review B: decompilation uses a leading 0x2d test and switch-table matching. Argument types and recovered calling convention remain unverified.'
insight-cli --profile agent-review ghidra functions rename --session "$A" --target "$T" --address 0x40125a --name ParseSwitchArgument --request-id name-A --json
insight-cli --profile agent-review ghidra comments set --session "$A" --target "$T" --address 0x40125a --kind plate --text "$A_EVIDENCE" --request-id note-A --json
insight-cli --profile agent-review ghidra comments set --session "$B" --target "$T" --address 0x40125a --kind pre --text "$B_REVIEW" --request-id note-B --json
insight-cli --profile agent-review ghidra functions get --session "$B" --target "$T" --address 0x40125a --json
insight-cli --profile agent-review ghidra merge --session "$A" --target "$T" --request-id merge-A --json
insight-cli --profile agent-review ghidra functions get --session "$B" --target "$T" --address 0x40125a --json
insight-cli --profile agent-review ghidra refresh --session "$B" --target "$T" --request-id refresh-B --json
insight-cli --profile agent-review ghidra functions get --session "$B" --target "$T" --address 0x40125a --json
insight-cli --profile agent-review ghidra merge --session "$B" --target "$T" --request-id merge-B --json
```

`$A_EVIDENCE` records the string/xref addresses and diagnostics above, labels the interpretation
as inferred and notes the uncertain prototype. `$B_REVIEW` independently records the leading
dash and table comparison, leaving argument types/calling convention unverified. These are
different comment fields, so the refresh can preserve B's private review while receiving A's
annotation. The exact tested texts are retained in the sanitized evidence.

A's two edits report `applied` and `sharedState: pending`. B still reads the original function
name and its own pre-comment before and after A's merge. A's merge publishes two fields as R2.
B's refresh reports two received changes, one preserved local change and no conflicts. B then
reads A's name/plate comment together with its own pre-comment, and publishes that review as R3.
A new third session reads all three published fields from R3. Closing/reopening the saved
context and replacing the IPC owner preserve the result. The input digest remains unchanged.

For ordinary continuation and resource release:

```sh
insight-cli --profile agent-review ghidra close --session "$B" --target "$T" --json
insight-cli --profile agent-review ghidra open --session "$B" --target "$T" --json
```

Close all owned contexts before disconnecting this disposable profile's server with
`ghidra server disconnect`. `ipc-server stop` drains the common CLI owner; only use it when
other work sharing that owner has finished. Profiles retain their saved work after shutdown.

## Problems found and fixed

The old HTTP budget was 30 seconds for every request. The first real import took 32.079 seconds,
including 26 seconds of native analysis, so the client discarded its successful late reply.
The shared initialization and open intent correctly remained unknown, but the error omitted
the session/target, and retry returned exit zero with `state: unknown`.

Initial import now has a bounded 600-second budget. Discovery and ordinary calls retain their
30-second budget; caller cancellation and explicit debugger budgets still apply. Transport
errors identify the operation and distinguish timeout, cancellation and connection/body failure
without exposing the bridge address or credentials. Failed opening returns its retained scope
and Factory follow-up argv for `sessions status` and scoped `ghidra open`. An unresolved open
retry returns nonzero, retaining the same session and intent without reimporting.

The original unknown import is preserved, not reset or republished. Initial-model reconciliation
requires independent proof of its first canonical version. If import completed before version
control was reached, that proof is unavailable and the stage stays blocked. Prevention by a
larger bounded import budget does not claim arbitrary interrupted bootstrap recovery. The full
successful investigation used a fresh disposable profile.

Focused verification passed 122 offline tests, isolated package checks and a separate
[installed native regression](verification/agent-cli-regression.json) on the same artifact.
That fixture uses two agents, two EXEs and four contexts, checks conflicts and owner/server
restart, and kills its owner at automatic `local_ack` and `verified` phases. Its test-only
barriers and isolated application identity are separate from the public-CLI investigation
above. All 153 bound runtime inputs and three harness inputs match at completion.

The walkthrough tests this one real EXE and normal headless research/publication. It does not
repeat the earlier 33-group GUI/debugger/archive gate or establish arbitrary input capacity.
