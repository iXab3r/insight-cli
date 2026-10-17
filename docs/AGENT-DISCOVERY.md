# Can an agent discover and use the installed tools?

The 2026-10-17 practical evaluation found a real onboarding gap. npm/runtime installation
alone does **not** advertise insight-cli to an agent. When given the CLI name or installed
skill, independent inexpensive agents could discover commands, perform useful analysis and
save results. A real Codex session selected a connected skill automatically, but its default
sandbox blocked the CLI. Installation, skill visibility and executable access are separate
acceptance criteria.

## What was actually tested

All agents used `gpt-6-luna`. Two independent workers had no parent conversation, product
source or prior research. They received copied binaries, a disposable profile and a business
question, without command examples, addresses or expected answers. Tools and Update
permissions were provisioned before the experiments: this evaluates using installed tools,
not autonomous download/setup. Product operations used the globally installed public CLI;
direct MCP access and target execution were prohibited.

Additional fresh `codex exec` sessions used the actual host's skill discovery, with user
configuration/rules ignored and session persistence disabled. Their research prompt named
neither insight-cli nor a decompiler. Project rules specified `analysis/report.md` and
`analysis/raw/`, prohibited a parallel `research` tree and assigned one profile. They were
allowed external static tools, consistent with the RE skill.

The tested installed artifact is the earlier accepted 0.2.0 candidate, not a new npm release.
[Receipt](verification/agent-discovery.json) pins its package/build/skill/input identities
and retained evidence. Later documentation changes are not rebound to that artifact.

| Experiment | Observed outcome | Assessment |
| --- | --- | --- |
| Fresh Codex after npm installation, no project registration | Neither packaged skill appeared in startup metadata | Installation alone does not provide discovery |
| Explicit project links to both skill directories | Both names appeared, but the nested RE link made a relative reference resolve to `.agents/SKILL.md`, which does not exist | Metadata visibility passed; this layout is unsuitable |
| Agent given only `insight-cli` and a managed-code question | Found `--help`, `skill`, the RE guide and ILSpy; decompiled C#/IL, extracted a resource, reported correct findings and saved a folder | Installed-tool usability passed |
| Agent given the absolute installed RE skill, managed DLL and 7zr.exe | Discovered ILSpy/Ghidra commands, followed strings and data references to code, annotated and merged R2, saved outputs and closed its context | Research and publication passed |
| Real Codex, both skill links, default workspace sandbox | Implicitly selected `insight-re`; CLI failed with runtime-storage access error; used external Mono tools and retained an ordinary ZIP | Automatic skill selection passed; CLI workflow failed |
| Real Codex, whole-package entry-point link, profile/IPC-directory filesystem grants | Implicitly selected `insight-cli`, read nested RE instructions with package structure preserved; CLI failed with an ownership diagnostic; continued externally | Routing/layout passed; CLI workflow still failed |
| One public CLI command in a sandbox with exact local socket allowance | `--help` passed with writes limited to the test profile/IPC directory and `--allow-unix-socket` for `host.sock`; no external network grant | Narrow IPC command smoke passed; not a complete agent run |

Do not count external-tool fallback as proof that the agent used our installed ILSpy. It
answered the question, but the intended facade and artifact-save workflow did not succeed.
Two proposed network-enabled retries were rejected by automatic approval review and did not
run. They provide no passing evidence; broad network access was not enabled.

## Useful work, independently checked

Both workers recovered the managed fixture's two cost branches, byte XOR, embedded settings
and P/Invoke declaration. The evaluator compared their files with actual decompilation and
the extracted JSON. Every file in the CLI-only worker's final seven-file saved copy matched
its settled source bytes. The second worker retained actual Ghidra and ILSpy JSON/C#/resource
outputs in its saved materials.

On real 7zr.exe the second worker found the function at `0x436fea` through CRC strings,
pointer-table references and incoming instruction references. It established that error
code 3 chooses `CRC Failed` when the second parameter is zero and the encrypted-file
`Wrong password?` warning otherwise. It correctly distinguished selecting a warning from
independently proving password failure. It set a plate comment, obtained a merge receipt for
R2 and read back the shared comment. The evaluator then opened a separate fresh context at
R2, read the exact shared comment and decompiled its function through the public CLI. The
new context was closed and the test profile's local server stopped afterward.

## Friction retained rather than hidden

* An agent initially made read-only status/list calls against the default profile before
  correcting to its assigned profile. Bootstrap instructions should carry that selector
  clearly; the experiment does not establish perfect profile discipline.
* Both workers initially hit AppData errors in the restricted shell, then used the
  experiment's explicitly allowed elevated CLI execution. That authorization was part of
  their environment, not something the skill or runtime installation supplied.
* Data-pointer addresses were initially passed to function/instruction operations, which
  rejected them. The Ghidra worker recovered by following references to actual code.
* The Ghidra worker issued an extra merge after uncertainty about a shell/redirection result.
  The retained first receipt shows R2 publication; the later merge returned `empty`. It
  inspected status/readback, but this is not a demonstrated lost-response recovery gate.
  No conflict, server crash or unknown publication outcome was injected here.
* The organizer created another profile while initial Ghidra work was active. Factory's
  exclusive configuration operation queued later calls. Those waits cannot demonstrate
  Ghidra/ILSpy serialization or be used as a performance comparison.
* The organizer's first fresh-context check supplied `--no-analysis`, changing the target's
  load settings, and was rejected. Continuation must retain the original settings.

## Priorities

| Priority | Gap | Concrete next acceptance |
| --- | --- | --- |
| P0 | A downloaded tool is absent from agent context | Explicit host onboarding connects one package entry point; a fresh agent sees it without being told the CLI name |
| P0 | Visible skill can still be unusable under sandbox policy | Complete the same blind task with only the assigned profile, required IPC access and no broad network grant; currently not passed in real Codex |
| P1 | IPC permission failure resembles ownership failure and suggests stopping the owner | Distinguish denied connection from an owner/lifecycle problem; preserve other agents' contexts |
| P1 | Separately linking the nested RE skill breaks relative references | Keep the package layout; verify all references through the host's actual displayed skill path |
| P1 | Explicit profile selection is easy to omit | Retain the assigned profile in agent bootstrap and check every state-changing invocation |
| P2 | Long operations and queued configuration calls look stalled | Keep operation/queue progress observable and record command outcomes without speculative retries |

The new packaged [agent setup reference](../skills/ghidra-coordinator/references/agent-setup.md)
documents the tested discovery layout and remaining access prerequisite. This change adds
documentation, not an automatic installer that edits personal agent settings. General skill
registration policy remains owned by Factory rather than a second product-specific framework.

## Reproduce without coaching the answer

Use a disposable research folder outside this source checkout. Make the global package
available on PATH, preinstall the selected tools in an assigned profile, grant Update, and
copy the pinned managed fixture or 7zr.exe. For the CLI-only case, give only the executable
name, assigned profile and research question. For the skill-guided case, give the absolute
path returned by `insight-cli skill insight-re`. Do not supply example commands or findings.

For host discovery, first start a fresh session without project links and ask whether the
startup skills list contains either name, explicitly prohibiting shell/file inspection.
Then connect the whole package using the setup reference and ask the business question
without naming the CLI. Capture JSONL host events and inspect actual skill reads, commands,
errors and resulting files. Give the host the required scoped storage/IPC access separately;
the docs link is not an access grant. Compare output with a hidden oracle and read published
annotations through a new context. Preserve failed runs alongside successful ones.

This is a small practical evaluation on one machine/model and two selected inputs. It does
not establish reliability across models/hosts, future adapters, autonomous installation,
multi-agent speedup, or universal sandbox compatibility. Those claims need their own gates.
