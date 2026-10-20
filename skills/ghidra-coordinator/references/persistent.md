# Persistent research calls

For a sequence of CLI research calls, keep one `insight-cli --json-rpc` frontend alive in the
agent's long-lived JavaScript runtime. The Factory owner and Ghidra processes have their own
lifetime; retaining only the owner still makes a new frontend validate its installed build.

The package exports a small stdio client, independent of the facade's eager imports:

```js
import {connectInsight, InsightCommandError, InsightTransportError}
  from '@eyeauras/insight-cli/persistent';

const cli = await connectInsight({executable: 'insight-cli', cwd: projectDirectory});
const result = await cli.execute([
  'ghidra', 'functions', 'inspect', '--session', session, '--target', target,
  '--function', 'main', '--fields', 'entry_point', '--include-call-context', 'false'
]);
// Keep cli for subsequent calls in this investigation.
```

When package-name resolution is unavailable in the agent host, dynamically import the
[`persistent-client.mjs`](persistent-client.mjs) beside this reference by its absolute file URL.
It is generated from the same canonical package module. In a persistent REPL retain `cli` as a
binding across tool invocations. A new Node process per query does not retain this connection.
For an explicit installed bin, use `{executable: process.execPath, arguments: [installedBin], cwd}`.
`env` optionally supplies the child environment. There is no shell or separate profile/config.
Use existing `--profile` argv flags when selecting a profile explicitly.

`execute(argv)` returns the CLI result unchanged, without a JSON-RPC envelope. Calls are queued
in admission order. Native work can be long: await the original promise through the agent host's
existing wait facility. This V1 client deliberately has no per-request timeout or automatic
reconnect/retry. Factory permissions, command validation, IDs and native budgets remain authoritative.

* `InsightCommandError.rpc` preserves the JSON-RPC error code, message and data, including typed
  CLI error results. A command failure leaves a healthy connection usable for the next command.
* `InsightTransportError.dispatched === true` means the request was handed to the stream and its
  acknowledgment is unavailable; it does not prove execution. Changing commands require their
  existing request-ID/status recovery. The client never resends them.
* `dispatched === false` means this client did not send that request, including queued requests
  after a transport failure. Reconnection is an explicit new connection, not an implicit replay.

The client bounds each response line to four MiB, validates IDs and envelopes, and fails the
connection on malformed, uncorrelated or oversized replies. It drains stderr without retaining
arbitrary native diagnostics in memory. Read command-level diagnostics from their typed results
and the existing profile diagnostic locations.

Finish owned Ghidra contexts with the normal scoped commands, following the project's shared
server policy. Then `await cli.close()` drains already admitted requests and ends this stdio
connection. It does not issue `ipc-server stop`, close another agent's context or stop a server.
Do not call close while expecting to admit more requests.
