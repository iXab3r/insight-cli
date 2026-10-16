# Complete Ghidra runtime delivery

The owner authorized this slice on 2026-10-16. The maintained agent contract is the packaged
[managed runtime reference](../skills/ghidra-coordinator/references/managed-runtime.md).

The public CLI now delivers and manages Ghidra, JDK, host native components, the pinned bridge
and Ghidra Server together. One selected installation serves isolated research JVMs. Repository
data, sessions, pending changes and artifacts remain separate from installation files. An explicit
external Ghidra launcher/directory is also supported, including Homebrew wrappers; its files are
never owned by uninstall. Existing explicit profile paths and externally operated servers remain
supported. These commands supplement the pinned Ghidra/MCP functionality rather than changing its
210-operation accounting.

## Agent workflow

```sh
npm install --global @eyeauras/insight-cli
insight-cli profile create local
insight-cli --profile local permissions grant Update
insight-cli --profile local ghidra install
insight-cli --profile local ghidra status
insight-cli --profile local ghidra open ./client.exe --session new --json
```

For advance acquisition, run `ghidra download`; later `ghidra install --offline` uses only the
cache. Local Ghidra/JDK archives and external executable paths are documented in the packaged
reference. Local archives are copied into owned, hash-addressed storage before extraction.
Installation stages validate the runtime and run real decompiler/server probes before activation.
A failed/aborted stage does not replace the selection. A later installer/doctor authenticates and
stops a leftover disposable probe server; it does not stop arbitrary PIDs or recover research by
repeating publication.

`ghidra server start/stop/status` exposes local lifecycle. Ordinary research starts the local server
when required. Stop refuses active contexts and preserves automatic startup; `disconnect` retains
its explicit connection-disable behavior. An external server can be disconnected, but not stopped.
Profile reconfiguration/deletion is blocked while runtime preparation is executing.

`ghidra uninstall` needs Destructive, refuses live processes, removes owned installation files and
keeps the selected identity as an uninstalled receipt. `--purge-cache` also removes downloaded
archives. Reinstalling does not reset the profile, clear a repository or drop session/private state.
Side-by-side installation files are activated explicitly, with no floating upstream upgrade or
implicit database-version migration.

## Verified result

[Exact artifact and native results](verification/managed-ghidra-runtime.json) record the passing
0.2.0 gate: **154/154 offline tests**, isolated offline npm installation, two validated skills,
and **1/1 Gherkin scenario / 73 public CLI calls / 13 native checks**. The final run takes about
11 minutes; measured CLI calls sum to 669.518 s. This includes runtime acquisition, repeated
installation, analysis, publications and cleanup; it is not a parallel-speedup benchmark.

All **174 installed package files** match the source-prepared artifact. An independent repack
is byte-identical. Artifact SHA256:
`ac24a6fa06bacf0f48d6472ebe26b2f6efe68966b47990466494bc5f52c70dab`.
The runner uses Node 24.21.0; the public PATH executable runs Node 26.4.0. The native gate covers
Ghidra 12.1.2, Temurin 21.0.11+10 and the ordinary external Homebrew `ghidraRun` wrapper.
Both profiles finish with closed contexts/stopped servers; research and saved artifacts remain.

A lifecycle issue found in development was corrected: local `server stop` now preserves later
automatic startup, while explicit `disconnect` disables shared operations until reconnected.
Archive paths are consumed into owned copies, and enabled profile extensions are fingerprinted
separately from the verified base installation.

## Acceptance and limits

The opt-in `@runtime` Gherkin scenario runs `scripts/proof-managed-runtime.mjs` through the actual
global executable, with ordinary Factory IPC, permissions and OS secrets. It creates fresh profiles
without configured Java/Ghidra and clears inherited Java/Ghidra environment overrides. This is a
clean application-profile acceptance on a real macOS machine, not a newly imaged OS/VM. Product
operations use public CLI commands; the runner reads their ordinary output/metadata and builds one
owned native debugger fixture using the host compiler. It never executes the Windows 7zr.exe.

The gate covers pinned public downloads, offline reuse, native installation/doctor, managed server,
real 7zr string → xref → decompilation, two private clients, R2/R3 merge/refresh, deletion refusal
under live clients, artifact retention, archive reinstall/continuation, official ZIP plus delivered
macOS natives, owned GUI/live LLDB, a profile extension, external launcher research/publication and
safe uninstall. A fresh external-profile session independently reads back its R2 annotation.

The verification receipt records the exact installed package build, archive/input identities,
command times and executed assertions. Earlier full-facade/P0–P3 evidence retains its own source
identity; this focused delivery does not rebind the old 33-group acceptance or benchmark timings.
Normal CI remains offline. The new runtime scenario is separate from the historical 25 business
IDs, and current Automation discovery has 30 scenarios.

Node/npm, OS GUI/keychain frameworks and native debugging authorization are host prerequisites.
macOS LLDB/embedded Python are supplied by Apple developer tools; the product neither redistributes
Apple tools nor silently installs administrative OS components. Doctor reports missing debugger
support as a partial failure. Ghidra debugger wheels come from the delivered SDK and are prepared
in private GUI storage. The default runtime requires no installed Homebrew, Gradle, external Java,
external Ghidra or Python MCP bridge. Native acceptance here is macOS ARM64; Windows/Linux x64
catalog entries and portable extraction do not imply native GUI/debugger acceptance there.

Version 0.2.0 is now published on npm as `latest` through the manual GitHub Actions workflow.
[Registry release verification](verification/npm-release-0.2.0.json) confirms the archive is
byte-identical to this native-tested candidate, with matching provenance source, a clean Linux
global-install smoke test and an actual macOS global registry installation.
