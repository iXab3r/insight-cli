# Managed Ghidra runtime

Use `ghidra install` for a complete compatible installation. Node 24+ is the bootstrap dependency;
no existing Java, Ghidra, Homebrew, Gradle, compiler or Python MCP bridge is required. Factory
profiles, permissions and OS secret storage remain in use. Follow the project's tool rules when
it specifies an external installation or server.

```sh
insight-cli profile create local
insight-cli --profile local permissions grant Update
insight-cli --profile local ghidra install
insight-cli --profile local ghidra status
insight-cli --profile local ghidra open ./client.exe --session new --json
```

`download` caches the complete pinned Ghidra/JDK archives, without selecting or starting a runtime.
`install` uses that cache or downloads missing archives, unpacks to a new stage, checks JDK 21 and
Ghidra 12.1.2, decompiles a known x86 function and starts a disposable local Ghidra Server. The
server probe authenticates its identity and reader/publisher permissions. Selection changes only
after all checks pass. The bridge and helper sources come from the version-matched npm package.
A failed install preserves its stage/diagnostics and the old selection. Retrying uses a fresh stage;
completed cached archives are reused. A later install/doctor/uninstall authenticates and stops
any leftover disposable probe server before proceeding; an unverified live identity blocks recovery. Interrupted partial downloads are never used as complete files.

`status` without scope is passive: selection, paths, missing components, installations, retained
stages, recorded checks and live process receipts. It works before installation. It does not start
Java or create a research workspace. `status --session S --target T` retains the scoped live health
check. `server status` also works without an installed runtime and explains missing prerequisites.
`doctor` explicitly runs disposable native decompiler/server probes and checks macOS LLDB Python.
It never imports a research target or publishes research changes. Readiness recorded by a doctor
run includes its runtime fingerprint; status identifies whether that record matches the selection.

## Local archives and external installations

```sh
insight-cli --profile local ghidra download
insight-cli --profile local ghidra install --offline
insight-cli --profile local ghidra install --archive ./ghidra.zip
insight-cli --profile local ghidra install --archive ./ghidra.zip \
  --java-archive ./jdk.tar.gz --offline
insight-cli --profile local ghidra install --executable /tools/ghidra/ghidraRun
insight-cli --profile local ghidra install --executable /tools/ghidra \
  --java /tools/jdk/bin/java --offline
```

`--executable` accepts the actual Ghidra launcher (`ghidraRun[.bat]`, or
`support/analyzeHeadless[.bat]`) or installation directory. It needs the complete compatible
installation, including host native components. A target EXE is not a Ghidra launcher.
Common Homebrew launcher wrappers are resolved through the adjacent complete `libexec` tree.
The external Ghidra tree is never modified or deleted. Java is delivered automatically unless
`--java` or `--java-archive` is supplied. Legacy profile `java`/`ghidraHome` configuration still works
when no explicit selection exists; an explicit selection takes precedence and never silently
falls back to profile paths after failure or uninstall.

Local archives are caller-selected inputs, consumed into owned hash-addressed copies before
extraction so later source edits cannot change the installed bytes. Optional `--archive-sha256` and
`--java-archive-sha256` check the expected bytes; the actual digests are recorded in the installation
identity. `--offline` prohibits network acquisition: provide/cache every required archive. On macOS,
an official Ghidra zip also needs the pinned prebuilt native archive in cache. The managed macOS
distribution already includes these natives. Executable modes are preserved; paths, links and
expanded sizes are checked during portable Node extraction. Downloads use exact assets retained
in `iXab3r/insight-cli` GitHub Releases, with hashes and sizes pinned in the installed package.
There is no runtime upstream/latest fallback; supplied archives and verified cache support offline use.
No external unzip, tar or Python executable is needed for extraction.

## Server, process and data ownership

The Ghidra distribution includes Ghidra Server. It uses the selected JDK and immutable tool code;
its repository, certificates, credentials and process settings are separate profile data.
Ordinary `open` starts it automatically. `server start` explicitly starts/enables it, and
`server stop` stops the identified owned server after all contexts are closed. It refuses to stop
a server under live clients. A later open can start it again; explicit `disconnect` disables shared
operations until `connect`/`start`. `server connect/disconnect` retain their connection-management API.
An external server remains configured through profile server/repository/account fields and Factory
secrets; `server stop` cannot stop that external service.

Code/cache/installation receipts live under profile AppData `runtime/`; research remains under
`workspace/`, and saved files under `materials/`. One selected immutable installation serves many
isolated JVM contexts; each has its own projects, home, settings, cache/temp and authenticated
endpoint. No per-agent copy of the Ghidra code distribution is required. This is process and data
isolation; it does not restrict arbitrary user scripts to an OS security sandbox.

Close scoped contexts and stop the owned server before selecting/reinstalling/removing a runtime.
A live receipt conservatively blocks these operations; it never authorizes killing a PID.
Download and doctor can run without switching the current runtime. Runtime commands serialize
within the Factory owner. Changing a selected runtime invalidates cached backend handles, without
removing saved research. There is no automatic version migration or floating upstream upgrade.

```sh
insight-cli --profile local ghidra close --session S --target T
insight-cli --profile local ghidra server stop
insight-cli --profile local permissions grant Destructive
insight-cli --profile local ghidra uninstall
# Optional cache deletion; research and external installations remain preserved:
insight-cli --profile local ghidra uninstall --purge-cache
```

Uninstall removes only selected owned installation files. It preserves the selection as an
uninstalled receipt, so later research reports a missing runtime instead of changing bindings.
Archives remain reusable unless `--purge-cache` is selected. It removes recorded archives for
this installation, preserving other tools' cache and unrecorded legacy entries. Reinstalling the same archives restores
the same runtime identity. Sessions, private snapshots, unresolved publication journals, server
repositories and artifacts survive. Uninstall does not resolve an uncertain merge or replay it.

## Process inventory and recovery

```sh
insight-cli --profile local tools processes --tool ghidra
insight-cli --profile local tools processes show <process-id>
insight-cli --profile local tools processes stop <process-id>
insight-cli --profile local tools processes kill <process-id>
```

These IDs describe executions, not new research selectors. Context records include the existing
session/target; server, GUI, debugger and helper roles remain separate. `stop` saves a selected
Ghidra context through its ordinary close path. Stopping a server requires closed contexts.
`kill` requires Destructive and explicitly interrupts verified owned work; it does not prove a
merge/save completed. Live debugger cleanup goes through the owning GUI so inferior termination
can be verified. Research and unknown journals are retained.

After an owner crash, inventory reconnects to authenticated owned endpoints without re-executing
research. macOS process birth times alone cannot prove recovered ownership; an ambiguous process
stays `unverified` and is not signalled. Original child handles and authenticated tool identities
provide the supported stop/kill authority. This is lifecycle management, not an OS security sandbox.

## Sources and host boundary

The catalog pins Ghidra 12.1.2 and Temurin JDK 21.0.11+10. macOS uses public Homebrew-built Ghidra
bottles with native components (macOS 14+, ARM64 or x64); no installed Homebrew is used. Linux x64
and Windows x64 use the official Ghidra zip and Temurin archive. The installed `runtime/tool-catalog.json` pins mirror assets; repository
`scripts/tool-distributions/` recipes retain upstream provenance. Published tool releases include
original licenses/notices and required source/build companions, independent of CLI releases.
Unsupported platforms fail explicitly and may use compatible external profile paths. Native
acceptance for this delivery is macOS ARM64; catalog availability is not Windows/Linux native proof.

The host provides Node/npm, OS frameworks, display/keychain access and debugger authorization.
macOS LLDB and its embedded Python come from Apple's developer tools; they are OS prerequisites,
not downloaded third-party Python dependencies. `doctor` reports a missing host debugger as a partial
failure even when static analysis/server pass. No root installation, developer-tools installer,
Gatekeeper disabling, shell-profile edit or global Java/Python selection is performed. Ghidra GUI
agents receive private copies of the Ghidra SDK's pinned debugger Python wheels.
