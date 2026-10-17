# Connect the toolbox to an agent

npm installs the CLI and all declared skills. Native tool downloads are separate. A host needs
shell access to `insight-cli`, skill discovery and execution access to the assigned profile.
`insight-cli tools list --json` discovers shipped capabilities without profile configuration,
native runtimes, credentials or IPC. `skill <name>` returns the instructions' ordinary path;
it does not inject them into an agent automatically.

## Codex: one project-local bundle

The package prepares `skill-bundle`, containing an independent folder for every registered
skill. `insight-cli skill --json` returns its `bundlePath`. References stay inside each skill;
link the whole bundle once rather than connecting each tool separately. npm installation
never edits agent settings or project RE instructions.

With a global npm installation, run from the research project:

```sh
mkdir -p .agents/skills
ln -s "$(npm root -g)/@eyeauras/insight-cli/skill-bundle" .agents/skills/insight-toolbox
```

`ln` refuses an existing destination: inspect it instead of overwriting another skill or
connection. Local npm installations use the `bundlePath` from their actual CLI receipt.
These machine-local links are not portable files to commit to a shared project. Start a fresh
agent and verify all registered names/descriptions appear. The [official discovery contract](https://learn.chatgpt.com/docs/build-skills)
supports project skills and symlinked directories; our actual host gate must still establish
recursive discovery for this packaged bundle.

An npm upgrade at the same global prefix replaces the bundle at the same path, including newly
registered tool skills. Check its manifest/version and start a fresh host session after upgrade.
A changed npm prefix needs reconnection. To disconnect, inspect `readlink .agents/skills/insight-toolbox`
and remove only that owned symlink with `unlink .agents/skills/insight-toolbox`; preserve other
entries and the package. No copied skills, per-tool installer or second agent configuration
store is maintained. Other hosts may register this ordinary bundle through their own mechanism;
Codex is the first concrete supported-host gate.

## Execution access

A skill link does not grant filesystem or IPC permissions. Allow the assigned profile's AppData
and the CLI's `.runtime` directory, plus its exact local IPC endpoint. On macOS the application
root is `~/Library/Application Support/insight-cli`; its Unix socket is `.runtime/host.sock`.
Keep unrelated profiles outside the write scope and pass the assigned `--profile` explicitly.
Do not grant broad external network access merely to reach a local socket.

An inaccessible profile means readiness is unknown. Inspect access failures; stopping a shared
owner does not grant access to it. Existing restricted-host evaluation has not established a
complete facade workflow yet; a successful metadata call or filesystem grant alone is insufficient.

## Behavioral acceptance

Give a fresh agent an input and business question without commands/tool names. Verify startup
metadata, implicit skill selection, intended public-tool use, correct findings, saved ordinary
project files and cleanup. Ghidra edits additionally require merge and independent readback.
Repeat cold-runtime and prepared-runtime cases; retain failures and distinguish an external-tool
fallback from acceptance of the intended adapter. Package/skill existence is structural evidence,
not proof that a model completed research.
