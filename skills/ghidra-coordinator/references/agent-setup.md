# Make the tools visible to an agent

Installing a runtime makes it available to `insight-cli`; it does not add a tool to an
agent's native tool list. The agent needs shell access, `insight-cli` on PATH, permission
to access its profile storage, and the packaged skill in its host's skill discovery path.
Downloading Ghidra or ILSpy alone supplies none of that agent context.

For a one-off investigation, tell the agent to use `insight-cli` and read the file returned
by `insight-cli skill insight-re --json`. It can discover applications with `--help`,
inspect readiness with `ghidra status` or `ilspy status`, and read the linked references
only when needed. The command returns a file location, not the instructions themselves.

For recurring work, explicitly connect the packaged entry point to the agent host. Keep the
project's existing RE rules and formats. Do not overwrite its `AGENTS.md` or other skills.
The CLI never changes personal agent settings during npm or runtime installation.

## Codex, project-local setup

On macOS/POSIX with a global npm installation, run from the research project:

```sh
mkdir -p .agents/skills
ln -s "$(npm root -g)/@eyeauras/insight-cli" .agents/skills/insight-cli
```

These commands create links without replacing existing entries. The links belong to this
machine; they are not portable files to commit into a shared project. Start a new agent
session and check that `insight-cli` appears in its available skills. Its linked RE skill
and references remain inside the same package tree. Do not separately symlink the nested
`skills/insight-re` directory: that changes the base for its `../../` references. An agent
can also load the RE skill using the absolute path returned by `insight-cli skill insight-re`.
Codex supports skill directory symlinks and supplies their names/descriptions before
loading the selected instructions. See [official skill discovery documentation](https://learn.chatgpt.com/docs/build-skills).

The links follow the globally installed package through upgrades. If npm's global prefix
changes, reconnect them to the new package location. A local npm installation can be
connected using its actual package path instead. Other agent hosts need their own skill
registration mechanism; these Codex paths are not a universal agent integration.

## Runtime access is a separate prerequisite

Connecting a skill does not grant filesystem or IPC permissions. In a restricted agent
sandbox, allow access to the assigned profile's AppData and the CLI's `.runtime` directory,
and allow its local IPC endpoint. On macOS the application directory is
`~/Library/Application Support/insight-cli`; the Unix socket is `.runtime/host.sock`.
Keep other research profiles outside the write scope. Use the assigned `--profile` on
profile-scoped calls instead of changing another agent's default.

The practical evaluation found that filesystem grants alone were insufficient: the CLI
then reported an ownership error because the sandbox could not reach the existing owner.
A separate command smoke test passed with a specific Unix-socket allowance and no external
network access. The complete agent run under that restricted configuration has not passed;
do not treat this discovery recipe as a finished sandbox integration. Do not stop a shared
owner merely to work around a sandbox's denied connection.

## Check behavior, not just the path

Give a fresh agent an input and a research question without command examples. Verify that it:

1. Selects the relevant skill and discovers an appropriate application.
2. Checks/uses its intended profile and tool installation.
3. Produces evidence from actual decompilation or inspection, respecting project rules.
4. Saves useful ordinary files; when Ghidra annotations are requested, merges them and
   verifies the published state.

A visible skill is an entry point, not a guarantee that every model completes every task.
The repository's [practical discovery evaluation](https://github.com/iXab3r/insight-cli/blob/main/docs/AGENT-DISCOVERY.md)
distinguishes installation, startup discovery and observed task completion.
