---
name: insight-cli
description: Research several executable inputs through durable independent sessions and isolated Ghidra contexts using the matching insight-cli facade. Agents supply the investigation and interpret results.
---

# insight-cli 0.1.0

This skill and its executable helper are one npm package. Run `insight-cli skill` to locate
these installed resources. Use generated `--help` for syntax; read the references as needed.

1. Select the configured runtime profile. Ordinary work uses a managed local server; an external
   server is optional. See [setup](references/setup.md). Factory permissions authorize changes.
2. Open the input with `ghidra open <input> --session new`. Retain the returned session and target.
   Another agent chooses `new` independently; one session can open several inputs.
3. Pass both `--session` and `--target` on research calls. Follow strings to xrefs and their
   function addresses, then inspect/decompile. See [research](references/research.md).
4. Rename functions or set/clear comments through ordinary commands. An `applied` result means
   verified saved private work. Other sessions keep their own views; local edits remain unpublished.
5. Continue with `ghidra open --session <id> --target <id>`. For uncertain outcomes inspect
   `sessions status <id> --target <id>` and [recovery](references/recovery.md). Supplying a stable
   optional `--request-id` lets a repeated changing intent retrieve its outcome without rerunning.

The facade is under active implementation: this revision exposes opening, scoped research and
ordinary scalar edits. Merge/refresh, full catalog completion and installed/native final acceptance
remain in progress; do not describe this checkpoint as a complete delivery. Preserve private work
and journals while an outcome is unresolved. The CLI supplies the investigation tools; agents
choose research goals and interpret findings.
Installing this package does not register this skill in an agent's configuration.
