# Setup

Use Node 24+, Ghidra 12.1.2 / Java 21 and a matching GhidraMCP build. The transport contract is
based on GhidraMCP source 57e37a8bf388b1279cff46378f85be1554548f61 / artifact 7.0.0. Rebuild it
against your Ghidra installation; configure and verify its jar SHA256. Ghidra and Python bridge
are external dependencies, not bundled binaries. Configure `java`, `ghidraHome`, `mcpJar`,
`mcpJarSha256`, `python` and `bridgeDirectory` (the directory containing bridge_mcp_ghidra).
Runtime scripts are disabled. The official MCP TypeScript SDK drives one stdio bridge per reader.

A profile names a connection realm, with `server` as ghidra://host:port, `readerUser` and
`publisherUser`. They must be distinct server accounts. Provision read-only access for readers
and write access for the publisher in each repository. The CLI's Update gate is disabled by
 default; it does not grant server rights and cannot isolate hostile code under the same OS user.
The publisher account/secret must not be supplied to investigator processes or tool sessions.
Publisher endpoints require a fresh private bridge token held in the Factory secret store, so
knowing a PID/port from status does not admit direct write calls. Per-process program scope is
set to the exact registered path; no publisher token is passed to investigator bridges.
Ghidra's read-only proxy may accept transient in-memory comment edits through native MCP.
Those edits are private to that reader snapshot: its server account cannot obtain a writable
checkout or check in. They are not proposals or published findings. This CLI exposes only
inspection and journal submission to investigators; fresh publisher preconditions and independent
readback use the canonical server version, never the reader's modified memory.

Example setup (substitute your local runtime paths):

```text
insight-ghidra profile configure lab --server ghidra://127.0.0.1:14100 --reader-user investigator --publisher-user coordinator
insight-ghidra auth login --role reader --password-stdin --profile lab
insight-ghidra auth login --role publisher --password-stdin --profile lab
insight-ghidra permissions grant Update --profile lab
```

The corresponding password is stdin input, never an argv/profile field. Credentials reside in
Factory's secret store. Queries/local discovery do not require credentials; launch/remote reads
require reader credentials, publication also requires publisher credentials.

SQLite, process registry, per-worker projects, logs and retained stage backups all derive from
that profile's Factory AppDataDirectory. Unix permissions protect local state; no portable data
flag exists. The pinned Ghidra project locator rejects hidden path components. On Linux configure
the OS XDG_DATA_HOME to a non-hidden path if its default .local path is rejected. IPC AppData
must also fit the platform Unix-socket path limit. No existing Ghidra config is rewritten.

A changed packaged CLI requires `ipc-server stop` before using the new build. Keep unresolved
journals and stage directories; ordinary installation and build preparation contain no user state.
