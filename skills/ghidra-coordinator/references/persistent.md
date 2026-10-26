# Persistent research calls

For a sequence of CLI research calls, keep one `insight-cli --json-rpc` frontend alive in the
agent's long-lived JavaScript runtime. The Factory owner and Ghidra processes have their own
lifetime; retaining only the owner still makes a new frontend validate its installed build.

The package exports a small stdio client, independent of the facade's eager imports:

```js
import {connectInsight, InsightCommandError, InsightTransportError}
  from '@eyeauras/insight-cli/persistent';

const cli = await connectInsight({
  executable: nodeExecutable,
  arguments: [installedBin],
  cwd: projectDirectory
});
// If reporting READY, first await a discovery RPC on this connection.
await cli.execute(['--profile', profile, 'tools', 'list']);
const result = await cli.execute([
  '--profile', profile,
  'ghidra', 'functions', 'inspect', '--session', session, '--target', target,
  '--function', 'main', '--fields', 'entry_point', '--include-call-context', 'false'
]);
// Keep cli for subsequent calls in this investigation.
```

When package-name resolution is unavailable in the agent host, dynamically import the
[`persistent-client.mjs`](persistent-client.mjs) beside this reference by its absolute file URL.
It is generated from the same canonical package module. In a persistent REPL retain `cli` as a
binding across tool invocations. A new Node process per query does not retain this connection.
Here `installedBin` is the absolute installed `dist/src/bin.js` path and `nodeExecutable` is
the Node executable used for this shared installation. Factory includes the Node version,
platform and architecture in its build identity. Use the same Node version and installed
artifact as the existing owner; an agent host's `process.execPath` or `PATH` can select a
different Node installation. `ipc-server status` reports the owner's build; a matching CLI
package version alone does not establish compatibility. A shared owner does not need to be
stopped merely to connect a client through the matching Node runtime. An idle owner may
exit and a later caller may start a new owner with a different Node installation: a previously
matching executable is not a permanent profile binding. Use one agreed Node runtime across
the shared clients, and inspect the current owner again after a compatibility failure.

The helper appends `--json-rpc` to its launch arguments. Factory requires that transport
flag to be the entire CLI invocation: `arguments` contains only the installed bin and any
Node runtime flags, with Node flags before the bin. Put `--profile <name>` in **every**
`execute(argv)` call as shown above. Adding profile flags to the frontend launch exits with
usage error before any request is dispatched. `env` optionally supplies the child environment.
There is no shell or separate profile/config.

A consumer that prints `READY` should first await an acknowledged RPC on that same connection,
as in the metadata call above. `connectInsight()` alone warrants a `SPAWNED` label. Discovery
confirms that the frontend reached Factory and returned a result; it does not start Ghidra or
prove native context readiness. Handle its failure before reporting readiness, preserve
`name`, `message`, `dispatched` and `termination` in the diagnostic receipt, and do not resend
research calls automatically. A later transport failure still requires ordinary outcome checks.

The helper code comes from the module actually imported by the consumer. Merging a newer
client into source does not update an older installed package or a long-lived imported module.
Check the installed version and loaded module when new diagnostic fields are absent; keep
original failure receipts rather than treating a new connection as recovery evidence.

`execute(argv)` returns the CLI result unchanged, without a JSON-RPC envelope. Calls are queued
in admission order. Native work can be long: await the original promise through the agent host's
existing wait facility. This V1 client deliberately has no per-request timeout or automatic
reconnect/retry. Factory permissions, command validation, IDs and native budgets remain authoritative.

* `InsightCommandError.rpc` preserves the JSON-RPC error code, message and data, including typed
  CLI error results. A command failure leaves a healthy connection usable for the next command.
* `connectInsight()` confirms that the frontend process spawned; it does not perform a
  readiness command or promise compatibility with the current Factory owner.
* `InsightTransportError.termination`, when the frontend has exited, reports its `exitCode`,
  `signal`, and a recognized `reason` category when available. The error message
  includes the fixed transport explanation and exit information, without raw stderr. These
  observations diagnose transport failure; they do not establish a command's outcome.
* `InsightTransportError.dispatched === true` means the request was handed to the stream and its
  acknowledgment is unavailable; it does not prove execution. Changing commands require their
  existing request-ID/status recovery. The client never resends them.
* `dispatched === false` means this client did not send that request, including queued requests
  after a transport failure. Reconnection is an explicit new connection, not an implicit replay.

The client bounds each response line to four MiB, validates IDs and envelopes, and fails the
connection on malformed, uncorrelated or oversized replies. It classifies recognized Factory
transport errors from a small rolling stderr window, clears that window on process exit, and
exposes only fixed explanations and exit metadata. Read command-level diagnostics from their
typed results and the existing profile diagnostic locations.

Finish owned Ghidra contexts with the normal scoped commands, following the project's shared
server policy. Then `await cli.close()` drains already admitted requests and ends this stdio
connection. It does not issue `ipc-server stop`, close another agent's context or stop a server.
Do not call close while expecting to admit more requests.
