---
name: insight-artifacts
description: Retain a completed reverse-engineering evidence file or directory as an ordinary checkpoint using insight-cli artifacts save. Use after Ghidra or any external tool; preserve existing project formats and source of truth.
---

# Insight Artifacts 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Keep evidence as ordinary files in the project's existing layout. This supporting application
copies a completed file or stable directory; it has no native runtime to download or install.

Run `insight-cli artifacts save <path> --json` using a profile with Update permission.
Retain the returned ordinary `path` verbatim, file/byte counts and hash if the checkpoint matters.
Before reporting a saved checkpoint, read its returned path with ordinary file tools and
confirm that the expected files are present. Copy that exact path into the handoff; never
reconstruct profile UUIDs or storage directories from memory. If readback fails, report
the saved receipt and the unresolved access problem instead of claiming a verified handoff.
The original project records keep their canonical role. No Ghidra selectors, finding schema
or evidence IDs are required; saving does not merge tool databases or attest interpretations.

Wait until other agents stop editing the selected files. Links and special files are rejected;
select the actual regular files. A later source edit does not change the saved copy. After a
lost answer, inspect retained results before making a new intentional save: every call makes
a new checkpoint. See [save semantics](references/artifacts.md) for failure and folder behavior.
