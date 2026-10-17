---
name: insight-binary
description: Query structured PE, ELF and thin Mach-O headers, sections, imports and exports, or make an explicitly guarded new PE subsystem copy through insight-cli binary. Use for scoped binary structure, linkage and copy-only header edits without target execution.
---

# Insight Binary 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Keep project RE/evidence conventions. LIEF is an internal packaged library. The native
helper is included with insight-cli; no separate download/install, SDK or compiler is
needed. The admitted host is macOS14+ ARM64; PE/ELF/Mach-O input formats do not imply
that the host can execute them. Arbitrary scripts or patches are outside this API.

1. `binary query app.exe --json` identifies format, architecture, entrypoint, image base,
   section/linkage counts and the PE subsystem/signature presence. Static metadata can
   be malformed; parser diagnostics mean partial evidence, not a successful absence claim.
2. `--view sections`, `libraries`, `imports` and `exports` provide focused JSON rows.
   `--filter TEXT` is a literal name substring, applied before `--limit`/`--offset` paging.
   Reuse the returned `--target` for immutable input identity. There is no active binary.
3. Addresses and sizes are strings to preserve precision. PE exports retain RVA and
   image-base-adjusted virtual address; forwarded exports retain the target name instead
   of pretending the forwarder is executable code. ELF/Mach-O views cover exported
   functions, not every exported data symbol. Non-PE import libraries may be unknown.
   Preserve Mach-O's native symbol spelling, including a leading underscore.
4. Universal Mach-O containers require explicit thin-slice extraction with a suitable
   external tool; the facade never silently chooses an architecture. Inputs are limited
   to 64 MiB and scans to 100000 metadata records; a reached bound remains partial.
5. A requested copy-only edit uses an explicit expectation:
   `binary edit-subsystem app.exe --expect-subsystem console --subsystem gui --output research/gui.exe --json`.
   Only this existing two-byte PE field is assigned. Independent LIEF readback and byte
   comparison verify the new copy; the original and existing outputs are preserved.
   This does not verify execution compatibility or repair PE checksum/Authenticode.
   Existing signatures may become invalid; keep both original and copied hashes.
6. `binary query --output research/page.json` saves the current bounded page to a new
   ordinary file. Preserve scope/partial flags in project notes and checkpoint selected
   evidence with `artifacts save` when useful. Readonly library queries need no Ghidra merge;
   annotations belong to an explicit Ghidra session/target when that tool is used.

Generated help owns exact options. LLVM remains useful for instruction/PDB windows;
Ghidra supplies shared analysis, isolated work contexts and merge/refresh.
