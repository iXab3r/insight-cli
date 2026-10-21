# insight-cli

A CLI/API for reverse-engineering agents. Spend more time understanding a program and
less time managing Ghidra processes or writing scripts around missing analysis metadata.

- Search raw strings and code references, and inspect functions in sparse Ghidra databases.
- Give each agent an isolated research context, with saved work and explicit merge/refresh.
- Use structured JSON results and a persistent client for sequences of research calls.

## Install

Requires **Node.js 24+**:

```sh
npm install --global @eyeauras/insight-cli
insight-cli profile create local
insight-cli profile set-default local
insight-cli permissions grant Update
insight-cli ghidra install
```

The last command downloads and verifies compatible Ghidra and JDK runtimes. No source
checkout or separate Java installation is needed. See [runtime setup](https://github.com/iXab3r/insight-cli/blob/main/skills/ghidra-coordinator/references/managed-runtime.md)
for existing installations and offline setup.

For an AI agent, [connect the packaged skills](https://github.com/iXab3r/insight-cli/blob/main/skills/ghidra-coordinator/references/agent-setup.md).
For repeated API calls, use the [persistent client](https://github.com/iXab3r/insight-cli/blob/main/skills/ghidra-coordinator/references/persistent.md).

## Quick example

Open a binary in a new private research context:

```sh
insight-cli ghidra open ./client.exe --session new --json
```

Reuse the returned session and target IDs in place of `SESSION` and `TARGET`:

```sh
insight-cli ghidra strings anchors --session SESSION --target TARGET \
  --text config --encodings ascii,utf16le --json
insight-cli sessions status SESSION --target TARGET --json
```

The search reads raw literal bytes, so it does not require defined Ghidra strings.
Results include scan coverage and a continuation cursor when incomplete. New imports
skip full automatic analysis by default; add `--analysis` to the first `open` to opt in.
Continue with the [research guide](https://github.com/iXab3r/insight-cli/blob/main/skills/ghidra-coordinator/references/research.md).

## Benchmarks

In a fresh-agent PoE 2 investigation, installed insight-cli 0.4.0 with its persistent
client finished in **16:35**, versus **19:43** through Ghidra MCP: **15.9% less wall time**,
with comparable core findings. This is one adaptive research pair, not a general speed guarantee.

[Benchmarks](https://github.com/iXab3r/insight-cli/blob/main/BENCHMARKS.md) includes phases, earlier runs and comparison limits.
[Development history and detailed reports](https://github.com/iXab3r/insight-cli/blob/main/docs/PROJECT-HISTORY.md) covers architecture,
acceptance, other experiments and releases. See [Contributing](https://github.com/iXab3r/insight-cli/blob/main/CONTRIBUTING.md) for development.
