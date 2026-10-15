# Setup

Use Node 24+, Ghidra 12.1.2 and a Java 21 JDK. Configure the runtime with Factory's profile
commands and generated help: `java` and `ghidraHome` select installed dependencies.
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

The current native acceptance is macOS. Portable CLI/CI remains required; native Windows/Linux
acceptance is deferred. The combined full-artifact delivery gate remains in progress.

Debugger execution additionally needs a supported host debugger (local LLDB on macOS). Its
Ghidra Python dependencies are prepared from the installed SDK wheels into owned GUI storage.
`debuggerPython` optionally configures a Python-backed offer; `windbgDir` configures the Windows
debugger runtime directory when relevant. These are runtime profile settings, not research scope.

Archive exchange is opt-in through `archiveUrl`; its optional token uses Factory secrets.
See [archive](archive.md) for the service contract and submission recovery behavior.
