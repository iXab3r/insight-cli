# insight-cli

CLI/API for reverse engineering with durable sessions, isolated Ghidra contexts,
explicit merge/refresh and ordinary saved files. Agents choose the investigation.

## Install

Use Node.js 24 or newer:

```sh
npm install --global @eyeauras/insight-cli
insight-cli --help
insight-cli skill insight-re
```

The executable is `insight-cli`. Its global npm executable directory must be on PATH.
No source checkout, TypeScript build or separate Factory installation is required.
The pinned Factory IPC runtime is a normal npm dependency fetched from an immutable
GitHub tarball URL; installation therefore needs npm registry and GitHub access.
Use `insight-cli ghidra install` to deliver the pinned Ghidra/JDK/native/server runtime.
External Ghidra launchers and Java paths are also supported.
`insight-cli ilspy install` delivers ILSpy and its private .NET runtime for managed-code
research. Tool downloads use pinned assets retained in our GitHub Releases.
Use `insight-cli tools processes` to inspect owned executions across tools.
Help, skill discovery and saving ordinary files do not need Ghidra or Java.

## Start

```sh
insight-cli profile create local
insight-cli --profile local permissions grant Update
insight-cli --profile local ghidra install
insight-cli --profile local ghidra status
insight-cli --profile local ghidra open ./client.exe --session new --json
```

Retain the returned `session` and `target` and supply both on research calls:

```sh
insight-cli --profile local ghidra strings search --session <session> --target <target> --contains config.json --json
insight-cli --profile local ghidra functions decompile --session <session> --target <target> --address <entry> --json
insight-cli --profile local ghidra merge --session <session> --target <target> --json
```

Another agent uses `--session new` for its own context on the same input. It receives
published changes with `ghidra refresh`; local work and conflicts remain explicit.
Managed local startup needs no separately configured Ghidra Server.

Save a completed project file or folder when a retained checkpoint is useful:

```sh
insight-cli --profile local artifacts save ./analysis --json
```

The response returns an ordinary saved path and digest. Follow existing project RE
rules, formats and evidence locations; the packaged RE skill fills unspecified gaps.
Installation does not register skills or change agent settings. Use `insight-cli skill`
and `insight-cli skill insight-re` to locate packaged instructions and references.

Full documentation and verification: [GitHub](https://github.com/iXab3r/insight-cli).
License: MIT. The bundled GhidraMCP bridge has its own Apache-2.0 license and notice.

Runtime management, local archives and external paths: [managed runtime](references/managed-runtime.md).
The host debugger and OS permissions are checked separately by `ghidra doctor`.

Static .NET commands and ordinary output files: [ILSpy](references/ilspy.md).
