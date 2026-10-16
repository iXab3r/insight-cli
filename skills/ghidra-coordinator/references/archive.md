# Exchange private documentation with an archive

Archive exchange is disabled until the selected Factory profile has an explicit `archiveUrl`.
Use HTTPS for a remote service; local HTTP is supported for local services. URLs cannot contain
credentials, query parameters or fragments. An optional bearer token is stored with
`auth login --role archive --password-stdin`; it is a Factory secret and is never passed to
Ghidra or the debuggee. `auth logout` clears this token as well as external server credentials.

Use `ghidra archive ingest-function --address <entry>` or `ingest-program`, with the usual
`--session` and `--target`. Both export the selected private view. `--version-label` supplies
the archive version; its default is `unknown`. Internal project directories are not used as
version labels. Bulk selection skips default function names unless `--include-default-named`
is set; `--limit` bounds visited functions. Zero selects all, subject to the documented bound.
`--dry-run` validates payloads and returns would-be counts without a network request.

The service contract is `POST <archiveUrl>/v1/doc_archive/upsert` with JSON and an optional
`Authorization: Bearer ...` header. The payload matches the pinned GhidraMCP builder: binary
name, explicit version, function address, run/tool identity, name/prototype, calling convention,
flags, matching hash/shape metadata, tags, named locals and instruction comments when present.
The binary name is the logical target name. Each successful JSON response must contain a
boolean `created` and a nonnegative integer `conflicts_enqueued`. Redirects are refused.

Results retain created, updated, conflict, skipped and error counts. Archive conflict counts
describe the external service's decisions; they do not resolve program merge conflicts.
Use an optional stable `--request-id` when a response might be lost. A repeated ID returns
the saved successful result or the retained uncertain outcome, without sending again.
Each outbound payload identity and the source snapshot are retained before dispatch. Unknown
external outcomes stay observable and do not block unrelated private research. A new request ID
expresses another explicit submission; the facade does not assume the service can deduplicate it.

Archive requests do not publish the program or alter another session. Developing or deploying
the external archive service is outside this package; acceptance uses an owned contract fixture.
