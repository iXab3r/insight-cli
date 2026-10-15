# Projects, files and server administration

Research uses root session/target scope. `ghidra projects` manages separate projects inside the
selected profile; these projects do not select or replace an agent's private context. Use an
explicit `--project` for create/open/close/info/files and file operations. Closing releases the
native handle and preserves files; deletion requires Destructive. File listings are paged.
Moves select a source `--path` and an existing `--destination` folder. Existing names are preserved.

`ghidra program export --session <id> --target <id> --output <file>` saves the selected private
program as GZF without publishing. `ghidra program import --project <name> --input <gzf>
--path /folder/program` adds that saved program to a managed project. Importing files does not
change the immutable target's input identity. Export requires a new output file.

`ghidra projects archive --project <name> --output <gar>` exports a native Ghidra project archive.
`ghidra projects restore --project <new-name> --input <gar>` restores into a new independent owned
project. Archive entries cannot escape their destination; restoration accepts at most 100,000
entries and 4 GiB of declared uncompressed data. Research contexts and pending work remain separate.

Changing operations accept `--request-id`. A verified native completion journal can recover a
lost project response without executing that operation again. If no complete journal exists,
changing that project stays blocked; read-only inspection remains available. Partial or different
export output does not prove success and is preserved. Retain receipts for continuation.

`ghidra server` operates on the configured local or external server. `status` reports connection
state; `connect` enables shared operations; `disconnect` releases the owned local server or the
external connection. Reconnect preserves repositories. Repository/file/history/checkout commands
require the explicit repository and relevant path. Admin actions require actual server authority
alongside Factory permissions. Changing ACLs preserves other users and anonymous access.
Facade reader/publisher authority and canonical publication checkouts remain protected.

Unknown server administration outcomes are retained without blind replay. Server/file effects
are independent of program merge. Use generated help for flags and Factory profile/secret commands
for connection configuration.
