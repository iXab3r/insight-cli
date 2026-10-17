# Adding a managed research tool

The internal CORE is `skills/ghidra-coordinator/src/tool-runtime`. Factory remains the
parser, permission authority, profile/secret store and IPC owner. A tool definition
contributes ordinary Factory commands; no extra daemon, CLI parser or plugin SDK is needed.
ILSpy (`src/ilspy.ts`) is the small one-shot example. Ghidra uses the same primitives with
additional repository, GUI and debugger invariants.

1. Inventory the real executable and runtime dependencies on each supported OS/architecture.
   Pin exact distributions and redistribution materials in `scripts/tool-distributions/`.
   Review licenses, embedded notices and corresponding source/build materials, including
   transitive packages. Supply the manifest/asset recipe to the manual `tool-release` workflow.
   It verifies draft assets by download before publishing an immutable non-latest tool release.
   Use a new `-rN` identity when any byte changes; do not replace published assets.
2. Regenerate `runtime/tool-catalog.json` with `node scripts/tool-catalog.mjs` after publication.
   The installed catalog owns expected bytes. Runtime never resolves upstream/latest or trusts
   a downloaded manifest to redefine hashes. Local archives and verified cache cover offline use.
3. Define the tool's components and dependency edges with `defineTool`. Use `ToolInstaller`
   for standard archive layouts: select platform components, return executable/argv/environment
   from installed roots, and provide a bounded real version/capability probe. Dependency archive
   options are `<component>-archive`; the primary archive uses `--archive`. Declare matching
   Factory options in `installOptions`, then register `lifecycleCommands(definition)`.
4. Run one-shot operations with `installer.use(selected => runTool(context, ...))`. The reservation
   covers selection verification through launch/completion; uninstall cannot delete the installation
   in that gap. Pass a concrete executable and argv, controlled environment/cwd, deadline/output
   bounds, accepted exit codes and optional session/target. Secrets belong in environment/stdin,
   not argv or metadata. CORE stores redacted bounded logs, exit state, timing and diagnostic paths.
   Keep target/session validation and output parsing in the adapter. Outputs remain ordinary files.
5. Persistent tools use `launchProcess` with a role, installation and non-secret resource metadata.
   The POSIX launch gate records intent and OS identity before authorizing exec.
   An async `onSpawn` hook may durably bind adapter PID/identity/secret references before that grant;
   use it when reconnecting requires more than the common process record. Await `toolClosed`
   before deleting execution storage: persistent close includes its durable terminal receipt. Supply readiness
   checks and authenticated identity verification through `ToolProcessHooks`. On macOS birth times
   have one-second resolution; a recovered process requires authenticated tool proof. Register only
   previously owned, authenticated resources through `registerExistingProcess`. Never adopt a process
   by basename, matching port or PID existence. `tools processes` uses these same hooks for listing,
   save-aware stop and explicit force kill. Refuse shutdown when domain ownership is ambiguous.
6. Reuse common `installationStage`, `consumeArchive`, `extractArchive`, `atomicWrite`, locks and
   removal helpers for exceptional layouts. Ghidra is this example: native overlays, real server
   authorization/decompiler probes and legacy receipts stay in its adapter. Preserve existing paths,
   working selections, journals and research on failure. Do not remove a shared cache wholesale.
7. Add offline executable fixture tests for failure/permission/ownership paths and a public installed
   CLI acceptance with a real input. Prove useful results, dependency isolation, external-path
   retention, offline continuation, concurrent clients and safe uninstall. Record exact package/source
   hashes and timings. Check generated help, packaged skill/reference links and isolated pack/install.

## Process and platform limits

This is process ownership and lifecycle management, not an OS security sandbox. Controlled tools
can still access host files. POSIX process groups cover children that remain in the owned group;
escaped/detached descendants need adapter-specific identity and cleanup. Ghidra's LLDB helper
retains its original child handle, authenticates its control identity and verifies inferior termination
through LLDB. Generic kill refuses an independently running debugger; close its owning GUI context.

Linux birth identity uses boot ID plus start ticks. macOS combines local child handles with a
process birth timestamp and authenticated tool endpoints after owner replacement. Windows has
no POSIX exec gate: direct-child startup and creation identity are implemented, but native Windows
and Linux tool lifecycles remain unaccepted until their own native gates run. An ambiguous recovered
process remains visible as `unverified`; there is no automatic execution/publication replay.

Installation mutations serialize in Factory's elected owner; CORE does not add a second interprocess
lock service. Runtime state derives from profile AppData. Existing Ghidra paths remain unchanged;
additional selections live under `runtime/tools/<tool>`, shared cache under `runtime/cache`, process
records under `runtime/processes`, and bounded run diagnostics under `runtime/runs`. Changing a
runtime does not change the RE finding format or promote saved output into a source of truth.

Two opt-in macOS LLDB lifetime fault tests exercise exit-before-readiness and stop-during-startup:
`INSIGHT_NATIVE_LLDB=1 node --test skills/ghidra-coordinator/dist/tests/debugger-owner.test.js`.
They use a fixture identity endpoint and real LLDB without executing a target; the combined
Gherkin gate independently uses real Ghidra GUI and a native debuggee. Default offline CI
skips these host-dependent checks.

Before native acceptance, verify the global installation against the exact tarball with
`node scripts/verify-global-package.mjs <tarball> <installed-package-root-or-POSIX-executable> <receipt.json>`.
It compares every packaged file, retaining only the count, package SHA256 and build identity.

For managed helpers, reuse `dotnetArtifact` and `dotnetLaunch` from `tool-runtime/dotnet.ts`;
do not introduce another runtime resolver. `InstallDescriptor.noticeFiles` copies full
retained notice text from packaged resources into owned installation storage. Its digest is
part of the installation identity and its installed text is checked before use, including
external selections. This complements upstream embedded notices and release companions.
