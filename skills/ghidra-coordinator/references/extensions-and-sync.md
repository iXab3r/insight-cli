# Managed extensions and synchronization

`insight-cli` keeps targets/sessions above tools. Both features below belong to the Ghidra
context/runtime selected by the existing profile; they introduce no new agent/session objects.
The Factory API uses the same command paths and options as these CLI examples.

## Consume a ready-built SDK extension

Use an unpacked standard Ghidra 12.1.2 extension module, with `Module.manifest` and
`extension.properties` at its root. Directory basename and property `name` must agree.
The module can contain compiled `lib/*.jar`, `data/languages` (including compiled Sleigh `.sla`,
`.ldefs`, `.pspec`, `.cspec`) and `ghidra_scripts`. Build the extension with its own upstream
SDK build before consumption. ZIP acquisition/extraction, dependency resolution, building a
third-party extension and publishing extensions are outside this local management contract.

```sh
insight-cli ghidra extensions inspect --directory ./MyExtension --json
insight-cli ghidra extensions install --directory ./MyExtension --sha256 <content-sha256> --json
insight-cli ghidra extensions list --json
```

Inspect computes the content identity without executing extension code. Install requires the
`Destructive` permission, consumes all regular files into profile storage and verifies the
copy. It never edits the installed SDK or depends on the original directory after consumption.
The identity covers sorted relative paths, SHA256 and size for every file; it is not a ZIP hash.
Symlinks/special files, hidden/traversing paths and incompatible version metadata reject.
Limits: 32 modules/profile, 8192 files and 256 MiB/module, 16 path components.
A name stays pinned to one content identity; different builds use different module names or profiles.

```sh
insight-cli ghidra extensions disable --name MyExtension --json
insight-cli ghidra extensions enable --name MyExtension --json
```

Stop the Factory IPC owner after changing the enabled set, then run the next ordinary command.
A running owner refuses changed runtime configuration. Immutable module copies remain retained
when disabled, so saved contexts can resume with their original language/type dependencies after
re-enabling. Existing private work and unknown request/publication journals are preserved.
Disabling the language required by a saved program does not convert that program to another language.
Enablement/install are desired-state/content operations; repeating the same input is idempotent.
No automatic extension updates or network/package-manager installation occur.

Discover what the installed SDK actually provides:

```sh
insight-cli ghidra extensions capabilities --kind languages --filter MyProcessor --json
insight-cli ghidra extensions capabilities --kind analyzers --filter MyExtension --json
insight-cli ghidra extensions capabilities --kind plugins --filter MyExtension --json
```

These paged inventories return actual native IDs (and compiler IDs for languages); `managed`
on analyzer/plugin classes identifies consumed modules. Select a language/compiler using
`ghidra open --language <id> --compiler-spec <id>`. Use `analysis configure-analyzer --name <name>
--enabled true` and `analysis reanalyze` in an explicit context. Program writes remain complex
private changes and follow the existing saved-state verification/merge rules.
Extension scripts have explicit inventory IDs such as `extension:MyExtension/Example.java`;
run that ID through `scripts run`, never guess a process-global search path.

For a GUI plugin, use `ghidra plugins set --plugin <class-id> --enabled true|false` with
`--session` and `--target`. `plugins list` returns enabled managed plugins in that owned GUI tool.
Only classes from enabled managed modules can be toggled. Enablement is read back immediately;
its lifetime is the current GUI tool, rather than a promise to resurrect it after a crash.
Plugin constructors/disposal may change program state: the operation saves a private snapshot
and conservatively records a complex change. An uncertain effect is never replayed; close the
owned context when its live effect cannot be established. Configuration dialogs, arbitrary
plugin-specific option schemas, native libraries with platform installers and hot class unloading
are not promised by this module contract; the explicit script API remains available.

Extension code runs with the OS privileges of the owned JVM. Digest pinning establishes which
code runs, not a security sandbox or a guarantee of third-party compatibility. Workers, GUI,
inspection and publication helpers use the same verified enabled set. The storage-only local
Ghidra Server continues to use the pinned base SDK and does not run managed analysis plugins.

## Optional synchronization for one context

The default remains explicit `merge` and `refresh`. Reads keep the private view. Configure an
existing `(session, target, ghidra)` context explicitly:

```sh
insight-cli ghidra sync-policy get --session s_a --target t_exe --json
insight-cli ghidra sync-policy set --session s_a --target t_exe \
  --publish after-edit --refresh before-edit --json
```

| Setting | Behavior |
| --- | --- |
| `--publish manual` | Local edits and saves do not publish automatically. |
| `--publish after-edit` | After a supported program edit has a verified saved acknowledgment, merge all pending work in that context. Also publishes pending work on explicit `ghidra save`. |
| `--publish after-save` | Ordinary edits stay private; explicit scoped `ghidra save` merges all pending work after saving. |
| `--refresh manual` | No automatic incoming update. |
| `--refresh before-edit` | Refresh before a program-edit command; any returned conflict stops that edit before dispatch. Safe incoming changes from the refresh remain retained. |

Supported program-edit commands include ordinary names/comments, types, bytes/assembly,
analysis and scripts. Policy excludes control commands (`open`, `close`, `merge`, `refresh`,
policy/discard), cross-target transfer, GUI/debugger, archive/project/server operations, file
exports, library databases and Version Tracking. Session-wide `save-all` saves privately;
use scoped `save` for automatic publication. Read-only queries never trigger refresh/publication.
Automatic refresh/publication also requires the current Factory `Update` permission, including
when the edit itself is gated by `Destructive`. Revocation prevents starting those automatic
effects; retrieval of a completed workflow does not repeat them. No background timers, watchers
or automatic semantic conflict resolution are introduced.

A successful automatic edit includes its normal local result plus `automatic.refresh` and/or
`automatic.publication`, final `pendingChanges` and `sharedState`. After a publication conflict,
the command fails with `state: conflict`, `localApplied: true` and the retained `local` result.
Nothing from that merge is published. An incoming conflict reports `phase: refresh` and
`localApplied: false`; the requested edit was not started. Lost local replies may report
`localOutcome: unknown`; they do not falsely assert that the local effect failed.

Automatic merge uses exactly the manual contract: any conflict prevents the whole publication;
only verified scalar categories combine after divergence; complex divergence retains both
versions. Use explicit refresh, inspect/resolve scalar conflicts, or transfer complex changes
onto a current base. A failed automatic workflow does not silently retry after resolution;
use a new request or explicit merge for the new intention.

Policy survives owner replacement. Optional request IDs (up to 128 characters) bind the local edit, incoming refresh and publication workflow. Repeating the same ID/input
retrieves its result or reconciles the original publication; it never replays a check-in or
uncertain script. The original workflow keeps its original policy even if policy changes later.
Retrying an earlier manual edit does not retroactively publish it after enabling automatic mode.
Without a request ID, a call is a new intention, as elsewhere in the facade.

The caller ID reserves the complete automatic workflow in the common profile namespace, even
when incoming conflicts prevent the local command from starting. It cannot be reused by an
explicit merge, close, export or administration operation. Internal child effects have derived IDs.
