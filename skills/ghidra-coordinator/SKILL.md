---
name: insight-cli
description: Choose and prepare reverse-engineering capabilities from the insight-cli toolbox for binary, managed-code and runtime investigations. Use to discover the appropriate tool or its packaged skill before installing native runtimes.
---

# insight-cli 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Read the project's RE instructions and existing findings first. They own tool choices,
evidence layout, formats and source of truth. These skills fill the remaining gaps.

1. Run `insight-cli tools list --json` to discover the capabilities shipped in this version.
   The catalog works before profile configuration, downloads or IPC startup. A downloaded
   runtime is not needed to discover what a tool does.
2. Use `insight-cli tools show <tool> --json` for tasks, supported inputs/platforms,
   dependencies and its skill path. Read that skill before preparing or using the tool.
3. Select a profile for execution. Run the selected application's `status` and generated
   `--help`. `install` prepares its private runtime; archives/offline and external paths
   are tool-specific and described in its skill. Update permission is required for tool
   preparation/execution and saved changes: `insight-cli permissions grant Update`.
4. Answer the question with focused queries and ordinary project files. Follow results to
   useful detail; a large raw dump is not an interpretation. External tools remain welcome.
5. Preserve completed files with `insight-cli artifacts save <path> --json` when a retained
   checkpoint helps. For several agents sharing Ghidra analysis, use separate sessions,
   then explicit merge/refresh as described by its skill.

`insight-cli skill` locates this entry point. `skill insight-re` gives investigation and
multi-agent guidance; `skill insight-ghidra`, `skill insight-ilspy` and
`skill insight-artifacts` locate the relevant instructions. Skills ship with the CLI;
installing npm binaries does not register them in an agent host. See
[agent connection](references/agent-setup.md) for current setup and access requirements.

Use generated help as the syntax authority. Catalog metadata describes shipped capabilities;
profile runtime readiness comes from the selected tool's `status`. Unavailable profile/IPC
access means execution readiness is unknown. Preserve work and diagnose access before trying
again; stopping a shared owner does not grant a denied agent access to it.
