# Agent CLI scenarios

These are the intended `insight-cli` commands and illustrative responses agreed during product
design. They are not executable in the existing `insight-ghidra` prototype. The scenarios specify
observable behavior; exact schemas and remaining edge cases are tracked in [the plan](PLAN.md).
The [design](DESIGN.md#agreed-product-model) owns the model. Factory supplies the same command
tree for CLI help, human/JSON output and API execution; no separate product RPC methods are invented.

## Command baseline

| Command | Purpose |
| --- | --- |
| `ghidra open <input> --session new` | Determine target identity and start independent work |
| `ghidra open <input> --session <id>` | Open another input in the same session |
| `ghidra open --session <id> --target <id>` | Continue the saved context, including after a failure |
| `ghidra strings search` | Find bounded string results |
| `ghidra xrefs to` | Locate references and their containing functions |
| `ghidra functions get/decompile/rename` | Inspect and update a function |
| `ghidra comments get/set` | Read and change a scoped comment |
| `ghidra refresh` | Receive shared changes while preserving local work |
| `ghidra merge` | Publish supported local changes with precondition/outcome checks |
| `sessions status <session> --target <id>` | Inspect context/publication status without replaying a write |

Research operations require both `--session` and `--target`, including when a session has only
one input. Input-opening calls may derive target identity from the supplied path. Scoped JSON
results echo both identifiers. Counts describe the selected context. Missing selectors fail
with a nonzero exit status rather than guessing an active input.

The owner selected explicit merge/refresh for the complete delivery; automatic strategies are deferred.
Target source bytes are immutable; publishing analysis does not patch the EXE.

## Research one input

A opens the EXE; B independently runs the same command:

```sh
insight-cli ghidra open ./client.exe --session new --json
```

```json
{"session":"s_a","target":"t_client","state":"ready"}
```

B receives `s_b` and the same `t_client`. Both initially see the shared analysis at R1.

A searches for a string, then follows its address to references:

```sh
insight-cli ghidra strings search --session s_a --target t_client --contains "config.json" --limit 10 --json
```

```json
{
  "session":"s_a","target":"t_client",
  "items":[{"address":"0x140008040","text":"config.json"}],
  "truncated":false
}
```

```sh
insight-cli ghidra xrefs to --session s_a --target t_client --address 0x140008040 --json
```

```json
{
  "session":"s_a","target":"t_client",
  "items":[{
    "from":"0x140001027","to":"0x140008040","kind":"data",
    "function":{"address":"0x140001000","name":"LoadConfig"}
  }],
  "truncated":false
}
```

The containing function is directly usable in the next call:

```sh
insight-cli ghidra functions decompile --session s_a --target t_client --address 0x140001000 --json
```

```json
{
  "session":"s_a","target":"t_client",
  "address":"0x140001000","name":"LoadConfig",
  "code":"int LoadConfig(void) {\n  return read_settings_file(\"config.json\");\n}"
}
```

A interprets this evidence and chooses the new name and comment:

```sh
insight-cli ghidra functions rename --session s_a --target t_client --address 0x140001000 --name LoadConfigFile --json
insight-cli ghidra comments set --session s_a --target t_client --address 0x140001000 --kind eol --text "Reads settings from config.json" --json
```

Each returns:

```json
{"session":"s_a","target":"t_client","state":"applied","sharedState":"pending"}
```

```sh
insight-cli ghidra functions get --session s_a --target t_client --address 0x140001000 --json
```

```json
{
  "session":"s_a","target":"t_client",
  "address":"0x140001000","name":"LoadConfigFile",
  "comments":{"eol":"Reads settings from config.json"}
}
```

The edit acknowledgments mean the local work is recorded for recovery. B still sees the original
name/comment in its own context; publication by A will not silently replace B's view.

## Two inputs in one session

A opens another input without replacing the client context:

```sh
insight-cli ghidra open ./helper.exe --session s_a --json
```

```json
{"session":"s_a","target":"t_helper","state":"ready"}
```

The address `0x140001000` in helper is an unrelated function. A records a helper comment:

```sh
insight-cli ghidra comments set --session s_a --target t_helper --address 0x140001000 --kind eol --text "Initializes the worker" --json
```

```json
{"session":"s_a","target":"t_helper","state":"applied","sharedState":"pending"}
```

Calls selecting `t_client` still address client. Merge/refresh on client never include or reset
helper changes; pending counts in their replies are not session-wide totals.

## Disjoint changes and incoming updates

B changes a different function in client:

```sh
insight-cli ghidra comments set --session s_b --target t_client --address 0x140001100 --kind eol --text "Checks record count" --json
```

```json
{"session":"s_b","target":"t_client","state":"applied","sharedState":"pending"}
```

A publishes its two client changes:

```sh
insight-cli ghidra merge --session s_a --target t_client --json
```

```json
{"session":"s_a","target":"t_client","state":"merged","sharedRevision":"R2","applied":2,"pendingChanges":0}
```

A's helper comment remains pending. B explicitly receives the client updates:

```sh
insight-cli ghidra refresh --session s_b --target t_client --json
```

```json
{
  "session":"s_b","target":"t_client","state":"updated","sharedRevision":"R2",
  "receivedChanges":2,"preservedLocalChanges":1,"conflicts":[]
}
```

B now sees A's name/comment and its own record-count comment. B publishes the latter:

```sh
insight-cli ghidra merge --session s_b --target t_client --json
```

```json
{"session":"s_b","target":"t_client","state":"merged","sharedRevision":"R3","applied":1,"pendingChanges":0}
```

## Conflict and explicit resolution

A refreshes client to R3. A and B now make different changes to the same existing comment:

```sh
insight-cli ghidra refresh --session s_a --target t_client --json
insight-cli ghidra comments set --session s_a --target t_client --address 0x140001000 --kind eol --text "Loads settings from a file" --json
insight-cli ghidra comments set --session s_b --target t_client --address 0x140001000 --kind eol --text "Loads settings from embedded data" --json
insight-cli ghidra merge --session s_a --target t_client --json
insight-cli ghidra merge --session s_b --target t_client --json
```

A's merge produces R4. B's merge fails with nonzero exit status:

```json
{
  "session":"s_b","target":"t_client","state":"conflict","applied":0,
  "conflicts":[{
    "address":"0x140001000","field":"comment.eol",
    "original":"Reads settings from config.json",
    "shared":"Loads settings from a file",
    "local":"Loads settings from embedded data"
  }]
}
```

The common value remains A's; B's local value and conflict remain available. The caller chooses
the meaning of the resolution. The service does not infer a winner from the text.

B can keep either existing value or choose another through the same setter. For example, if
further investigation supports a fallback path:

```sh
insight-cli ghidra comments set --session s_b --target t_client --address 0x140001000 --kind eol --text "Loads settings from a file; falls back to embedded defaults" --resolve-conflict --expect-shared "Loads settings from a file" --json
```

```json
{"session":"s_b","target":"t_client","state":"applied","conflict":"resolved","sharedState":"pending"}
```

This records a local decision against the observed shared base. B then uses ordinary merge.
If the shared value has already changed, resolution fails with `state: conflict` and
`reason: shared_changed`, retaining the local work and returning expected/shared/local values.
If it changes later, merge compares against that acknowledged base and checks for another conflict.
The typed implementation defines null/absent values consistently. The owner selected no partial
publication: any conflict prevents publication of the whole selected merge, preserving all work.
Refresh still applies incoming changes proven safe to combine and retains local/shared conflicts.

## Failure and continuation

For this branch of the walkthrough, B leaves its R4 conflict unresolved. A edits the other
client function and publishes, but the service stops after publication commits and before the
successful response reaches A:

```sh
insight-cli ghidra comments set --session s_a --target t_client --address 0x140001100 --kind eol --text "Rejects invalid record counts" --json
insight-cli ghidra merge --session s_a --target t_client --json
```

A received `applied` for the local edit, then a connection failure for merge. A cannot infer
publication success or failure from that connection failure. After service restoration:

```sh
insight-cli sessions status s_a --target t_client --json
```

```json
{"session":"s_a","target":"t_client","ghidra":{"mergeState":"unknown"}}
```

```sh
insight-cli ghidra open --session s_a --target t_client --json
```

If durable evidence establishes that publication completed:

```json
{
  "session":"s_a","target":"t_client","state":"ready",
  "mergeState":"merged","sharedRevision":"R5","pendingChanges":0
}
```

The publication is not repeated. If evidence cannot establish the result, it remains unknown;
further publication affecting that shared model stays blocked rather than guessing or blindly
checking in again. The precise unknown/error envelope is an implementation-planning decision.

B reopens its own context and still reads its unresolved local value:

```sh
insight-cli ghidra open --session s_b --target t_client --json
insight-cli ghidra comments get --session s_b --target t_client --address 0x140001000 --kind eol --json
```

```json
{
  "session":"s_b","target":"t_client","address":"0x140001000","kind":"eol",
  "text":"Loads settings from embedded data","sharedState":"conflict"
}
```

A can independently reopen `s_a / t_helper` and recover its unpublished worker comment. Reopening
either context does not replace the private view with the latest shared version.

## Several CLI processes

Different processes selecting `s_a / t_client` share its local work. Processes selecting
`s_b / t_client` or `s_a / t_helper` select separate contexts. Changing calls on the same context,
including merge/refresh, execute sequentially; simultaneous submission has no promised order.

For a concurrent setter and merge: if the setter executes first, its change is included; if
merge executes first, the later edit remains pending. A caller requiring inclusion waits for
the setter's `applied` response and then invokes merge. No process selector or manual lock is
added to the research API. The ordering rule does not claim atomic multi-call database updates.

## Optional request identity

An agent that needs to retry initial open after losing its response can supply a stable request ID:

```sh
insight-cli ghidra open ./client.exe --session new --request-id open-A-001 --json
```

```json
{"session":"s_a","target":"t_client","state":"ready"}
```

Repeating the same intent with `open-A-001` retrieves the same session/result or the request's
unresolved state; it does not create another session. Reusing it with changed effective input
fails. Without a supplied ID, each invocation is a new intent.

The same option is available for setters, merge, scripts, batches and other changing commands:

```sh
insight-cli ghidra merge --session s_a --target t_client --request-id merge-A-001 --json
```

If the response is lost, retrying with that ID observes/reconciles the original publication,
without submitting another check-in. Unknown/partial outcomes are not transformed into success.
Script/debugger/external actions are never blindly repeated under an unresolved request ID.

API execution uses the existing Factory method and command arguments, for example:

```json
{
  "method":"cli.execute",
  "params":{
    "argv":["ghidra","merge","--session","s_a","--target","t_client","--request-id","merge-A-001","--json"]
  }
}
```

This shows method/params only, not the full transport envelope. No separate product RPC method
or required agent-visible job entity is introduced.

## Complex changes and a diverged base

An agent can edit types, signatures, structures or analysis through the facade. If the shared
model is unchanged, a verified saved private result can be published. If another session advances
the model, changes outside verified merge categories remain explicit conflicts. Both versions
remain available; the service does not force-replace the shared version or replay the agent's script.

To transfer desired work onto the latest model, the agent can open the existing target in a new
session while retaining its previous context:

```sh
insight-cli ghidra open --session new --target t_client --json
```

```json
{"session":"s_b_current","target":"t_client","state":"ready"}
```

The agent reads its old work through `s_b`, applies the desired changes through `s_b_current`
against that current base, then merges normally. This uses the existing session/target model;
no automatic whole-version overwrite or new rebase entity is required.
