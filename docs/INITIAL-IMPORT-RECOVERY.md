# Interrupted first import

Continue the original session and target. No profile reset, new session or manual check-in is
required. The same commands handle interruption during analysis, staging or initial publication:

```sh
insight-cli --profile research sessions status "$SESSION" --target "$TARGET" --json
insight-cli --profile research ghidra open --session "$SESSION" --target "$TARGET" --json
```

If the initial call used `--request-id open-A`, repeating its original input and arguments
also retrieves/reconciles that same intent:

```sh
insight-cli --profile research ghidra open ./7zr.exe --session new --request-id open-A --json
```

After recovery the ordinary public result is `ready`, with the original identifiers, R1 and
zero pending changes. The native worker may still be completing a prior attempt after its
CLI owner exited. In that case continuation reports busy, retains scope and follow-up commands,
and can be repeated after the worker finishes. It does not start a second concurrent import.
If the profile was explicitly disconnected, use `ghidra server connect` first as usual.

## What establishes recovery

| Interruption | Retained evidence and continuation |
| --- | --- |
| Import/analysis worker exits | Immutable input, load settings and per-attempt receipts survive. Once the OS file lock is free, a new private analysis attempt can run. Existing attempts remain retained. No repository connection exists in this worker. |
| Owner exits after analysis | The completed, synced packed snapshot and its SHA256 are reused. Analysis is not repeated. |
| Writer exits during staging | The incomplete uniquely named repository object stays unpublished. Recovery retains it and can create a new staging object from the same verified snapshot. |
| Owner exits before promotion | A separate read-only process verifies every saved DB buffer and database identity before a conditional server move to the absent canonical path. |
| Promotion succeeds but its reply is lost | The original item identity, one-version history, source digest and complete saved buffers establish R1 through independent read-only authority. Existing canonical content is never checked in again. |

Import intent binds input bytes, settings, runtime and reader/publisher repository authority.
Native processes hold a per-target OS file lock across each phase, including after owner loss.
A partially written snapshot without its completed receipt cannot be published. Its immutable
captured artifact is checked again before staging, during read-only staging verification and
after promotion. Each native read-only verification uses a separate JVM/connection; Ghidra's
in-process connection cache must not turn it into a publisher observation.

Ghidra can represent an interrupted initial `createDatabase` as a synthetic version 1 whose
history says `<Recovered>` even when its buffers are incomplete. That version number alone is
not publication proof. New initialization creates under a unique staging name, verifies the
whole saved snapshot, releases its owned checkout and only then promotes it. Server move rejects
an existing destination. No canonical overwrite, versioned save or repeated check-in is used.
Unfinished stages and their creation receipts remain available for diagnosis.

Older profiles without the new receipt first require their legacy bootstrap worker to be
stopped or authenticated and safely released. Only an authoritative repository response can
establish absence; a failed connection never does. Completed legacy R1 is independently read
back. A proven-owned incomplete direct create with synthetic `<Recovered>` history can be
moved to quarantine without deletion before staging a complete result. A foreign identity,
ordinary conflicting history, active check-in or changed input/settings remains blocked.

## Long initial analysis

Initial import/analysis defaults to 3600 seconds. Set the profile's
`--initial-import-seconds <seconds>` (1–86400) before opening a long input, or after a
failed worker has stopped, then continue the original session/target. For example:

```sh
insight-cli profile set research --initial-import-seconds 7200
insight-cli --profile research ghidra open --session <session> --target <target> --json
```

The budget is execution policy, separate from immutable auto-analysis/load settings.
Existing profiles need no new target or profile to raise it. Timeout diagnostics retain
phase, effective milliseconds, setting name and process diagnostics. An incomplete attempt
still restarts private analysis from the retained immutable input; there is no partial-analysis
checkpoint. Only the existing complete, hashed receipt and independent full-buffer readback
permit initial publication. A longer deadline does not make an incomplete snapshot valid.

## Real CLI acceptance

[Evidence](verification/initial-import-recovery.json) records recovery of the actual earlier
blocked `7zr.exe` profile with its original session/target/request ID, plus recovery of an
interrupted partial direct create in its original profile. Old projects and journals remain.
The production input SHA256 is
`256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282` (602624 bytes), from the
[official 7-Zip download](https://www.7-zip.org/download.html).

The installed-entry acceptance runner executes public CLI commands with normal AppData,
Factory owner and OS keyring. It uses OS signals against receipt/command-line-verified owned
processes to simulate failures during analysis, after private preparation, during staging and
after promotion. Receipt/log observation is limited to timing those crashes; research,
continuation, history checks, edits and merge use the public CLI. There are no SDK imports,
custom entry points, runtime fault hooks, direct bridge calls or database edits in that workflow.

```sh
node scripts/acceptance-initial-import.mjs --ack-disposable \
  --cli "$INSTALLED_INSIGHT_BIN_JS" --artifact "$INSTALLED_INSIGHT_TGZ" \
  --input ./7zr.exe --java "$INSIGHT_JAVA" --ghidra-home "$INSIGHT_GHIDRA_HOME"
```

Each case requires R1 with exactly one canonical history entry, the same initial scope/intent,
usable string research, stable replay without another creation, and a subsequent annotation
merged as R2 and read from a new independent session. A killed staging writer can require
another staging creation; this does not produce another canonical version. The runner requires
the recorded EXE digest and macOS, and starts only when other work sharing the normal owner has
finished. It retains private diagnostics/profiles outside the repo and shuts down owned contexts,
servers and owners. The earlier 33-group gate keeps its original build identity.

To verify an upgrade from the earlier installed build, add `--scenario legacy` and
`--legacy-cli "$PREVIOUS_INSTALLED_BIN_JS"`. This starts the old bootstrap, kills only its
identified native worker during analysis, stops its owner and continues with the new installed
CLI using the original request. The legacy project/process receipt must remain unchanged.

The accepted artifact also passes 128 offline tests, the
[installed facade regression](verification/initial-import-regression.json) with two agents,
two EXEs, four contexts and two automatic owner SIGKILL phases, plus nine
[managed extension/synchronization cases](verification/initial-import-p3.json). Those regressions
use separately isolated fixtures; the first-import investigation and upgrade above use the
ordinary installed public entry point.
