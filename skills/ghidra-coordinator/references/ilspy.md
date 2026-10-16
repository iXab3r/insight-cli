# Static .NET research

Use the project's preferred tools and evidence conventions. When ILSpy is appropriate,
`insight-cli ilspy install` prepares its pinned CLI and private .NET runtime; a global SDK
or dotnet installation is unnecessary. Lifecycle and archive options appear in `--help`.
The ILSpy and runtime distributions come from our pinned GitHub Releases. For offline
installation supply `--archive` and `--dotnet-archive`, or use an already verified cache.
`--executable` selects a compatible external ilspycmd; uninstall preserves its files.

```sh
insight-cli ilspy types ./client.dll --json
insight-cli ilspy decompile --target <returned-target> --type Example.Policy --output policy.cs --json
insight-cli ilspy il --target <target> --type Example.Policy --json
insight-cli ilspy resources --target <target> --json
insight-cli ilspy resource --target <target> --name Example.settings.json --output extracted --json
insight-cli ilspy project --target <target> --output recovered-project --json
insight-cli ilspy metadata --target <target> --table MethodDef --json
```

Use either an input file or an existing target. Reusing the target associates Ghidra and
ILSpy results with the same immutable bytes. No Ghidra context or merge is needed for a
stateless ILSpy read. An optional `--session` associates an existing session; it does not
create one. These calls require Update to capture input and run a tool.

Text responses include `content`, input SHA, process ID, elapsed time and diagnostic paths.
`--member` selects a metadata token or XML member ID for decompilation. Output paths must
be new: text operations create one ordinary file, project/resource operations create a
folder. Keep useful output in the project's chosen evidence location; `artifacts save`
is an optional explicit checkpoint. Static decompilation does not execute an assembly.

Use `tools processes --tool ilspy --all` for execution history and `tools processes show
<process-id>` for retained diagnostics. A failed or interrupted export can leave partial
files/staging; inspect them and choose a new output path for another intentional run.
