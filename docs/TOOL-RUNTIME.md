# Shared tool runtime: contract and delivery plan

Status: planned. The owner requested a shared CORE, a task hierarchy and sequential
implementation, with tool distributions retained in our GitHub Releases. This document
does not claim that the shared runtime, mirrors or ILSpy integration are implemented.
The existing [Ghidra runtime](MANAGED-GHIDRA-RUNTIME.md) remains the delivered baseline.

## Ownership and first consumers

CORE means an internal `tool-runtime` module in the existing insight-cli npm workspace.
Factory continues to own command parsing, output, profiles, secrets, permissions and the
CLI/IPC owner. No second daemon, public SDK, plugin loader, generator or Factory fork is needed.
Extract mechanisms from the current Ghidra implementation and validate them against two
consumers: Ghidra (multiple persistent processes and server) and ILSpy (one-shot CLI).
Adding the remaining tools from the candidate list is outside this first slice.

| Common runtime owns | Tool adapter owns |
| --- | --- |
| Platform selection, pinned acquisition, cache and archive handling | Supported versions/platforms and component inventory |
| Staging, installation receipts, activation and external selection | Layout discovery, exceptional preparation and capability probes |
| Dependency preparation and installation-use guards | Required runtime components and compatibility rules |
| One-shot execution, deadlines, cancellation and output bounds | Executable, argv, accepted exit codes and result parsing |
| Persistent process records, ownership checks, stop/kill and reconciliation | Readiness, authenticated identity where available and graceful shutdown |
| Standard lifecycle command registration and profile storage | Research commands and operation-specific effects |

An installation is software; a process is a live execution; a tool context is research state.
One Ghidra installation can serve a server and several headless/GUI processes. The supervisor
records their roles separately. Targets/sessions remain above tools, and Ghidra continues to
own private state, publication, merge/refresh, conflict handling and unknown-outcome recovery.
Stateless tools need no artificial persistent context or merge implementation.

The author's minimum input is an ordinary typed definition plus tool-specific hooks. Standard
archives use a default installer; one-shot tools need no service hooks. Dependencies are explicit
pinned components, such as Ghidra plus JDK or ILSpy plus the required .NET runtime. Keep the
dependency model to these real compositions, including cycle rejection and same-profile reuse.
Do not introduce an ecosystem-wide package solver.

## Agent-facing lifecycle

These are planned shared commands, inherited under each tool namespace:

```text
insight-cli <tool> download [--offline]
insight-cli <tool> install [--archive PATH | --executable PATH] [--offline]
insight-cli <tool> status
insight-cli <tool> doctor
insight-cli <tool> uninstall [--purge-cache]
insight-cli tools processes [--tool NAME] [--session ID] [--target ID]
insight-cli tools processes stop <process-id>
insight-cli tools processes kill <process-id>
```

Reuse the delivered Ghidra dependency-specific options, including Java/archive paths. A single
`--archive` does not imply that a tool's other dependencies are bundled. Status reports installed
selection, capabilities, retained failures and processes without starting/downloading anything.
Doctor runs bounded declared probes and distinguishes installed, functional and unavailable
capabilities. Handlers return ordinary Factory data/errors for CLI JSON and API alike.
Install/download/start/stop use Update; uninstall and force kill use Destructive. Read-only
status/process inventory use ReadOnly. Doctor probes declare their effects and use Update
when they launch a process or write files. No generic restart or arbitrary shell command surface
is added. Tool-specific commands may expose supported lifecycle equivalents.

`stop` requests tool-aware graceful shutdown. Ghidra must save/close/reconcile according to its
existing semantics before termination. `kill` is an explicit forceful action on a verified owned
process; it reports interrupted/unknown work and preserves journals. Neither path treats process
exit as successful save, merge or completion of an arbitrary research operation.

## Distributions retained in our releases

Runtime delivery reads exact assets from public releases in `iXab3r/insight-cli`. CLI/npm versions
and tool-distribution versions are independent. Example tag: `tool-ghidra-12.1.2-r1`; the revision
changes if packaging or any retained byte changes. Ghidra, JDK and .NET component releases can be
reused across compatible tool definitions without copying them into every CLI release.

The committed catalog pins repository, release tag, asset name, byte size and SHA256 for each
supported platform/component, including license/source companion assets. A tool release has a
manifest describing this same inventory and upstream provenance. Installed CLI downloads must
not trust a replacement manifest fetched from the same release to redefine their expected hashes.
No `latest` resolution or automatic upstream fallback occurs during installation. Upstream URLs
are acquisition provenance for the release workflow, not runtime dependencies.

The release workflow performs this sequence:

1. Read a reviewed, committed component recipe with exact upstream version, URLs and digests.
2. Acquire bytes and verify independent pinned digests; record whether each asset is an original
   archive or our derived package. Derived packages retain source digests and preparation steps.
3. Retain licenses, notices and corresponding source/build materials required for redistribution,
   including transitive components. An unresolved distribution right blocks mirroring that
   component; external-path use remains possible. A license label or upstream link alone is not
   considered fulfillment of a source-distribution requirement.
4. Create a draft, attach the complete manifest, binaries and required companion assets, then
   download/read back and verify every uploaded asset before publishing. Never overwrite an
   existing published asset or tag with different bytes. A matching retained draft can continue;
   unknown upload/publish responses require readback before retry.
5. Publish with GitHub immutable releases enabled and verify the resulting release/asset identity.
   Update the installer catalog only after publication and independent download verification.

One-time setup enables immutable releases through an administrator and sets the repository variable
`TOOL_RELEASE_IMMUTABLE_READY=true`. GitHub Actions cannot read that administrative setting with
its ordinary token. Publication checks the explicit setup flag and verifies the actual published
release is immutable; it does not store or request an administrative token. Existing published
releases are verified against the recipe without requiring upstream availability again.

The workflow is manually dispatched, serialized per distribution identity and uses repository
permissions scoped to its release job. Pull-request validation cannot publish tool assets.
It does not execute downloaded installer scripts, add binaries to Git/npm, grant new npm publishing
rights, or alter the existing manual npm auto-version pipeline. Mirror releases use `--latest=false`
so they do not become the application's latest release.

GitHub currently requires each release asset to be below 2 GiB. Oversized distributions need an
explicit supported packaging strategy before admission; silently splitting an archive is excluded.
Releases protect against upstream removal, not a GitHub outage: verified cache and explicit local
archives remain required. Each admitted tool's transitive delivery must be inventoried, including
Ghidra macOS native components and debugger wheels; host developer tools/OS debugger authorization
remain reported prerequisites where redistribution/automatic installation is unavailable.

## Execution and storage guarantees

- All mutable files derive from profile AppData. Installations, cache, process records/logs and
  research data have distinct ownership. Existing Ghidra paths and receipts are inventoried before
  migration; no profile reset, lost selection or deletion of pending work is acceptable.
- Install from an owned staged copy, validate it and activate atomically. A failed or cancelled
  install retains useful diagnostics and the prior selection. Coordinate concurrent lifecycle calls
  across CLI clients. Installation-use reservations prevent deletion between resolve and launch;
  failed launches and crashed owners reconcile reservations conservatively.
- Launch an executable with argv and a controlled per-invocation environment/cwd. Secrets stay
  out of records and printed argv. Bounded output captures exit code, signal, elapsed time and
  truncation; raw logs receive the same secret handling as other tool diagnostics.
- A persistent process record binds profile, installation, role, executable and verified OS process
  identity; optional session/target associate research scope. PID existence is not ownership. Use
  retained OS handles/start identity or authenticated tool identity, with platform-specific proof.
- Track spawning/readiness failures as well as ready processes. The spawn-to-record crash window,
  child descendants, detached processes and owner death need an explicit supervision strategy and
  executable tests. Process groups alone do not establish cross-platform ownership or containment.
- Stop uses graceful shutdown and a bounded wait; kill uses explicit escalation only after ownership
  checks. Terminate owned descendants only where ownership can be proved. A reused PID or ambiguous
  orphan is reported as unverified, never adopted or killed. Windows and Unix guarantees have
  separate acceptance evidence; an unsupported guarantee is a visible limitation.
- After restart, reconcile records without automatically replaying scripts, publication or debuggee
  execution. External installations are never deleted. External running servers/processes are not
  adopted as owned merely because their path or port matches.
- Retain runtime version, installation/process identity and timings for diagnosis. This does not add
  an evidence database, automatic research capture, a new finding format or an OS security sandbox.

## Ordered work and acceptance

[Delivery epic #6](https://github.com/iXab3r/insight-cli/issues/6) is the execution tracker. Each item is a native GitHub sub-issue with
dependencies and concrete acceptance. Implement one item at a time; the next starts after the
previous item's affected checks pass. Documentation of a contract does not close an implementation
item. Each implementation PR references its issue and records exact tested source/artifact identity.

| Order | Item | Deliverable and acceptance |
| --- | --- | --- |
| [TR-01](https://github.com/iXab3r/insight-cli/issues/7) | CORE definitions and shared lifecycle registration | Typed component/tool/installation/process contracts, adapter hooks, Factory command registration and common error/result rules. Ghidra and one-shot fixtures demonstrate the same authoring surface; no custom CLI renderer or host. |
| [TR-02](https://github.com/iXab3r/insight-cli/issues/8) | Mirrored tool release workflow | Reviewed recipes, provenance/licenses/source companions, draft/upload/readback/publish/recovery, immutable release verification and non-latest tags. Mirror exact Ghidra/JDK/macOS components and ILSpy/runtime inputs; a fresh download matches pinned digests. |
| [TR-03](https://github.com/iXab3r/insight-cli/issues/9) | Shared download/cache/archive helpers | Extract current verified acquisition and local archive handling; remove Ghidra-specific registry authorization from common code. Offline, corrupt/truncated archive, traversal/link/size bounds, cancellation and concurrent clients pass offline checks. Normal runtime acquisition uses only our pinned releases. |
| [TR-04](https://github.com/iXab3r/insight-cli/issues/10) | Shared installation/dependency/selection lifecycle | Staging, probes, activation, external paths and safe uninstall with installation-use reservations. Concurrent install/uninstall/launch, interrupted activation, missing dependency and external-file retention pass; previous working selection survives failure. |
| [TR-05](https://github.com/iXab3r/insight-cli/issues/11) | One-shot execution helper | argv/env/cwd, bounded output, timing, exit codes, timeout/cancellation and tracked execution. Tests use real disposable child processes; secrets are excluded from output and detached descendants have defined behavior. |
| [TR-06](https://github.com/iXab3r/insight-cli/issues/12) | Persistent process supervision | Durable inventory, readiness/identity hooks, scoped stop/kill, owner-crash reconciliation and process-tree policy. Exercise startup crash windows, PID reuse, unresponsive tool, foreign process refusal and multi-client ordering on supported OSes. |
| [TR-07](https://github.com/iXab3r/insight-cli/issues/13) | Migrate Ghidra delivery | Route existing lifecycle commands through CORE and mirrored catalog. Preserve managed/external selection, caches where valid, repositories, sessions and pending work. Installed CLI completes real headless import/decompile with upstream acquisition blocked. |
| [TR-08](https://github.com/iXab3r/insight-cli/issues/14) | Migrate Ghidra server/context/debugger processes | Use shared supervision for all owned Ghidra roles while retaining tool-aware save, authentication and recovery. Real concurrent contexts/server/GUI, stop/kill, failed readiness and owner/backend crashes preserve acknowledged changes and unknown publication guards. |
| [TR-09](https://github.com/iXab3r/insight-cli/issues/15) | ILSpy first additional tool | Deliver pinned ILSpy and runtime, lifecycle commands and focused decompile/IL/type/resource operations through the public CLI/API. Real fixture assembly, external executable, offline reuse, parallel CLI callers and saved ordinary output work without a global dotnet installation. Compare authoring code against Ghidra and remove duplicated mechanisms. |
| [TR-10](https://github.com/iXab3r/insight-cli/issues/16) | Combined global-install gate and author guide | Exact packed/global-installed build: real EXE plus .NET assembly, several CLI clients, process inventory/stop/kill, failures, offline/local/external delivery and uninstall preserving research. Add the minimal new-tool recipe/hooks guide and timings. Keep portable CI and macOS native evidence distinct; unsupported Windows/Linux capabilities remain explicit. |

TR-01 through TR-10 execute in listed order. TR-02 gathers both consumer inventories before CORE
is expanded for them; it does not require the research API to exist yet. Per-tool API choices in
TR-09 are bounded by these concrete capabilities and must be documented before implementation.
The first completed slice ends after TR-10; additional candidate tools receive separate tasks.

## Sources

- [GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
- [Immutable releases and draft-first publication](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
- [Ghidra distribution notices](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE).

## ILSpy command contract (TR-09)

ILSpy consumes the same immutable targets as Ghidra. It does not create a Ghidra context,
require a session or merge a decompilation. Supply exactly one file or `--target ID`.
An optional `--session ID` validates and associates an existing research session with the run.
The selected managed distribution supplies ILSpy 11.1.0.9782 and private .NET 10.0.13;
`--dotnet-archive PATH` supplies the runtime archive during offline installation.
An external `--executable PATH` must expose the same pinned ilspycmd CLI version.

```text
insight-cli ilspy types [input] [--target ID] [--kind c,i,s,d,e]
insight-cli ilspy decompile [input] [--target ID] [--type FULL_NAME | --member XML_ID_OR_TOKEN]
insight-cli ilspy il [input] [--target ID] [--type FULL_NAME]
insight-cli ilspy resources [input] [--target ID]
insight-cli ilspy resource [input] --name NAME --output DIRECTORY
insight-cli ilspy project [input] --output DIRECTORY
insight-cli ilspy metadata [input] --table NAME_OR_NUMBER
```

Text operations return content with immutable target SHA, process identity, elapsed time and
diagnostics. `--output PATH` on text operations writes one new ordinary file; directory operations
require a new output directory. Existing output is never overwritten. These commands use Update
because they capture immutable input and start a tool. They perform static analysis; they do not
execute the analyzed assembly. Tool update checks are disabled. Output remains ordinary files that
agents may keep according to project conventions or explicitly save with `artifacts save`.
