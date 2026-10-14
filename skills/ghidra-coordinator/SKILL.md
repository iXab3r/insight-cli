---
name: insight-ghidra
description: Coordinate independent Ghidra readers and durable scoped-comment proposals with the matching insight-ghidra CLI. Use for parallel reverse-engineering findings and controlled publication to versioned shared programs.
---

# insight-ghidra 0.1.0

This skill and its executable helper are one npm package. Run `insight-ghidra skill` to locate
these installed resources. Use generated `--help` for syntax; read the references as needed.

1. Configure a Factory profile for a Ghidra Server and matching local runtime. Store the two
   accounts' passwords through `auth login --role reader|publisher --password-stdin`.
   See [setup](references/setup.md). Reader accounts need server-enforced read-only access.
2. Register the complete program identity, including exact input SHA, repository/path, language,
   compiler and image base. Do not select by basename or global current instance.
3. Start independent readers with `workers start`. Inspect explicit function selectors on a
   named worker. Journal proposed comments with the original baseline/version and evidence;
   `findings submit` persists before acknowledgment. See [findings](references/findings.md).
4. After authorized Update permission is enabled, `integrate <target>` applies proposals through
   one publisher checkout. Two callers of one program share the owner; different programs may
   publish concurrently. Read all result states and failures, including their attached batch.
5. On partial application or uncertain publication, use `status` and the specific `recover` batch.
   See [recovery](references/recovery.md) before attempting cleanup or another submission.

Only scoped listing comments are supported. MCP calls are staged separately; they are not an
atomic batch. Native database merge, types/signatures and cross-build transfer are outside this
version. Keep working copies and journals until independent readback verifies publication.
Installing this package does not register this skill in an agent's configuration.
