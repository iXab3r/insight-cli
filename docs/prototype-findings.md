# Historical prototype findings and bindings

This is the earlier publication fixture's contract. It is not the public `insight-cli` API.

Register an identity JSON object with exactly the active `profile` and `server`, `repository`,
absolute `programPath`, 64-character `binarySha256`, `language`, `compilerSpec` and hexadecimal
`imageBase`. Registering another binary for the same lane rejects; this version does not migrate
an existing target across builds. Target IDs are content-derived; the lane excludes binary SHA
so a different build cannot silently create a second publisher of the same database.

A proposal JSON object requires `requestId`, `findingId`, `targetId`, the full `identity`, a
registered `workerId`, `baselineVersion`, an explicit hexadecimal `address`, `kind` (eol, pre,
post, plate, repeatable), `before`, `after` and `evidence`. Use null for an absent original
comment; proposed `after` is a non-empty string. Clearing comments is outside this verified slice. No function-name selector
is accepted for mutations. Evidence is a bounded explanation, not a raw private log.

The worker must have read the same program and baseline. A read-only Ghidra proxy may omit
file_version or report its latest-version sentinel (-1). The reader captures matching native
server versions before/after opening and binds the read epoch across direct HTTP and its MCP
bridge; a reopen or positive version mismatch rejects. CLI bindings contain actual PID,
loopback endpoint, distinct AppData project directory, complete program identity and version.
Missing/wrong selectors, SHA, profile or program reject. Every remote read checks content and
requested selectors; an HTTP/MCP success envelope alone is insufficient.

The same request and identical content returns the durable original finding, including its
current state. Reusing either ID with different content fails. Concurrent proposals for the
same address/kind with different values conflict, even if both workers began from an empty
comment. No last-write-wins behavior is used. Old baseline versions may integrate when the
exact before value still matches a freshly checked-out version; future versions reject.

To resolve a quarantined proposal, inspect the current published value, submit a new proposal
with fresh IDs/baseline and `resolves` naming the conflict. The old proposal, peer and observed
values remain in the journal. Resolution never edits the old finding or silently applies it.
Lists return at most 100 records; `show` returns a selected record. Inspect accepts up to eight
explicit function references and caps remote content at one MiB.
