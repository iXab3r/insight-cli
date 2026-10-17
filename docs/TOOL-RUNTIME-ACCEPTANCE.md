# Shared tool runtime acceptance

TR-01–TR-10 are implemented and accepted on macOS ARM64. The
[receipt](verification/tool-runtime.json) records source `b28ec62a2bd86b93f1050a22c9bf4a17b35f8bae`,
package SHA256 `90ad871601e0a391ac9d7273223be918730498dac15595f02aa401e8fc1d7ab5` and installed Factory build identity
`13738de9d5993d769d2f34c4ad7e0cf90fd59f9aaf03c7ca6d0d50c7e04238d2`. All 200 packaged files were compared byte for byte
with the ordinary global npm installation. This is a source-built candidate; npm registry
publication remains the separate manual release workflow.

## Executed gates

| Gate | Result |
| --- | --- |
| Portable application tests | 172 pass; two host-dependent LLDB checks are opt-in |
| Release/catalog tests | 15 pass; 14 binary assets pinned |
| Isolated pack/install | Skill/resources, CLI/JSON/RPC, permissions, spaces/Unicode pass |
| Offline Gherkin | 2 scenarios pass |
| Native LLDB startup faults | 2 pass: early child exit and stop during startup |
| Combined native Gherkin | 1 pass; 73 managed-Ghidra calls plus 73 combined calls |
| Global file verification | 200/200 exact matches |

The native gates use only the public globally installed CLI for product workflows. Fixture
preparation and intentional owner SIGKILL are test-side operations. The supporting LLDB
fault checks use a fixture identity endpoint and real LLDB without executing a target;
the Gherkin scenario separately uses real Ghidra GUI and a native debuggee.

## What was demonstrated

- Fresh profile without Java/Ghidra paths: download from our immutable GitHub Releases,
  offline cache reuse, staged installation, real decompiler/server/permission probes and
  local server start. Official zip plus macOS native supplementation is verified separately.
- Two independent CLI clients investigate real `7zr.exe`, retain private views, publish and
  refresh. An overlapping merge publishes nothing, including disjoint changes; explicit
  resolution publishes the preserved local decision.
- Generic process inventory includes roles and scope. Graceful stop saves a context;
  force-killed GUI and headless contexts retain acknowledged private work. A replacement
  owner authenticates a surviving process, and server failure preserves work through restart
  and a later verified merge. No script/publication/debuggee execution is blindly replayed.
- ILSpy and private .NET are delivered without a global SDK/runtime on the tool PATH.
  Type/C#/member/IL/resource/project/metadata operations produce useful findings from a real
  managed assembly: tiered cost arithmetic, XOR decoding, P/Invoke and embedded settings.
  Ghidra opens the same immutable managed target in the existing research session.
- Ordinary output files/folders can be saved explicitly. Local archive reinstall and an
  external ILSpy executable work; removing either tool preserves targets, research, materials
  and external code. At the end no owned tool process remains live and inputs are unchanged.

CLI call timings sum to **758.8 seconds**; individual monotonic durations and phase
boundaries are in the receipt. This includes delivery, installation and repeated recovery;
it is not a one-versus-three research-speedup measurement. Historical benchmark evidence
keeps its original source and scope.

## Reproduce

Use Node 24+, the pinned Automation submodule/.NET SDK for development, macOS display/keychain
access and host LLDB/developer authorization. Build the managed fixture into a disposable directory.
Prepare and globally install the tarball, then use `scripts/verify-global-package.mjs` to compare
it with the installed package. The exact source/fixture/runtime inputs are retained in the receipt
and [distribution receipt](verification/tool-distributions.json).

Set `INSIGHT_NATIVE_DISPOSABLE=1`, `INSIGHT_GLOBAL_CLI`, `INSIGHT_RUNTIME_EXE`,
`INSIGHT_MANAGED_ASSEMBLY`, `INSIGHT_EXTERNAL_GHIDRA`, `INSIGHT_GHIDRA_ARCHIVE`,
`INSIGHT_ILSPY_ARCHIVE` and `INSIGHT_DOTNET_ARCHIVE` as described in
[Gherkin acceptance](ACCEPTANCE-AUTOMATION.md#shared-tool-runtime-gate), then run:

```sh
npm run automation -- test --suite acceptance --tag tool-runtime --property RestoreLockedMode=true --timeout-seconds 3600
```

Inspect the TRX and `tool-runtime-result.json`; every named check must pass. Export only
bounded public facts with `scripts/export-tool-runtime.mjs`, supplying the raw result, tarball,
TRX, output receipt, global file-verification receipt and LLDB fault-test log in that order.
Keep raw logs, private paths, profiles and credentials outside committed evidence.

## Limits

Native acceptance is macOS ARM64. Linux CI verifies portable code and real generic process
fixtures; native Windows/Linux Ghidra/ILSpy acceptance remains future work. Process ownership
is not an OS security sandbox. Escaped descendants need tool-specific identity/cleanup;
ambiguous recovered processes are not signalled. OS debugger tools/authorization remain host
prerequisites. [Adding tools](ADDING-TOOLS.md) covers the supported adapter and mirror workflow.
