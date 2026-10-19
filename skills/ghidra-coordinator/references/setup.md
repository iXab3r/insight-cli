# Setup

Inspect `storage show --json` and read [analysis storage](storage.md) before moving databases.
Use `storage configure` for an empty profile or `storage migrate` for existing work. Factory
control metadata and keyring identity stay in their original locations.

Use Node 24+ and `ghidra install` to deliver Ghidra 12.1.2, JDK 21, native components and
server support. See [managed runtime](managed-runtime.md) for download/install/offline archives,
external executable paths, status/doctor and safe removal. Existing Factory profile `java` and
`ghidraHome` paths remain supported when no managed/external selection exists.
The package contains the verified GhidraMCP 7.0.0 bridge, its Apache-2.0 license/notice and
artifact provenance. Its pinned functionality catalog is from source
`57e37a8bf388b1279cff46378f85be1554548f61`, with SHA256
`7084e2fda16dc779dd05398e48821ff3f9ace4d32757ea143b257b39689e5fbd`.
`mcpJar` optionally selects another copy of those exact verified bytes. Runtime startup needs no
bridge/Factory source checkout or Python MCP bridge. Packaged native helper sources compile
against the installed Ghidra/JDK.

Omitting `server` enables owned local startup. The facade creates profile storage, a private
repository and distinct read-only/publisher accounts with random credentials in Factory's secret
store. It manages isolated headless contexts and introduces GUI mode on demand.

For an external server profile, configure `server` (`ghidra://host:port`), `repository`,
`readerUser` and `publisherUser`. They are distinct accounts with actual read-only and write
permissions respectively. Store each password using `auth login --role reader|publisher
--password-stdin`. Passwords are stdin/secret-store values, never profile JSON or argv values.
Connecting does not transfer ownership of that external server or allow the facade to stop it.

Factory's Update permission is initially disabled. Enable it through `permissions grant Update`
in the selected profile before creating contexts or editing. Research scope is explicit; local
skill discovery and help require no authentication or native process startup.
Deletion and replacement commands also require `permissions grant Destructive`.

All target bytes, snapshots, journals, projects and process receipts derive from the selected
profile's AppData. Stop the owner through `ipc-server stop` before changing its code/runtime
configuration. Restoring a saved context preserves its private view. Server settings and initial
loader settings remain bound to the target/workspace, so changing those cannot silently replace
retained work. This revision conservatively protects retained profile research state from deletion.
Runtime identity covers installed Ghidra code, language/compiler data, native modules and Python
inputs together with JDK tools, modules and configuration. Generated Python caches are isolated.
Changing those runtime inputs requires stopping the old owner before continuing with the new build.

Native acceptance separates macOS GUI/LLDB workflows from selected headless Windows/Linux
SDK, Version Tracking and FID/BSim workflows. Native Windows/Linux debugger/GUI acceptance
remains deferred. The ordinary CI lane stays offline; disposable native CI is explicit.

On macOS 15+ ARM64, `ghidra install` delivers an owned LLDB/Python debugger backend;
OS debugger authorization remains required. Other host profiles need their supported debugger. Its
Ghidra Python dependencies are prepared from the installed SDK wheels into owned GUI storage.
`debuggerPython` optionally configures a Python-backed offer; `windbgDir` configures the Windows
debugger runtime directory when relevant. These are runtime profile settings, not research scope.

Archive exchange is opt-in through `archiveUrl`; its optional token uses Factory secrets.
See [archive](archive.md) for the service contract and submission recovery behavior.

## Native operation budgets

Profile `initialImportSeconds` defaults to 3600 (1–86400 seconds); `saveSeconds`
defaults to 120 (1–3600 seconds). Configure them with `ghidra budgets set
--initial-import-seconds 7200 --save-seconds 300`; `ghidra budgets show` reads effective values.
This uses Factory ProfileStore without invalidating research or stopping native contexts.
Active requests retain their original budget. Generic `profile set` remains guarded for
profiles containing research; initial profile creation also accepts these fields. Both are execution policy, independent
of immutable target/load identity. Save and packed snapshot export use the save budget;
discovery and ordinary HTTP queries keep their 30-second budget. Each native request has
its own budget, not a total command deadline. Cancellation remains independent.

After an import timeout, wait for the original worker to end, raise its budget and continue
the original scope. Incomplete private analysis restarts; a completed receipt is reused.
A save timeout reports `phase: save`, the effective budget and `saveSeconds`. Inspect
`sessions status`; a native log or broken response stream cannot prove a saved snapshot.
