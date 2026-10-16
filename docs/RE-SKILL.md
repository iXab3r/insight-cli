# RE skill and ordinary saved materials

The npm package ships `skills/insight-re/SKILL.md`. Locate it with
`insight-cli skill insight-re`; `insight-cli skill` still locates the existing CLI skill.
Neither command registers skills or changes agent settings. The RE skill describes how
agents investigate, share intermediate findings, retain useful files, review conclusions
and publish Ghidra annotations. It does not run or schedule agents itself.

Read applicable project instructions, linked RE approaches and evidence templates first.
They determine tools, source of truth, canonical paths, naming, evidence sections, confidence,
recheck steps and promotion rules. The packaged skill supplies workflow defaults only for
unspecified details. Workers receive those rules and write directly to their assigned project
slices; there is no required parallel `research/`, `notes.md` or `finding.md` representation.

For example, a project may require `builds/<build>/<binary>/<intent>/`, structured evidence
notes with `Observations`, `Inferences` and `How To Recheck`, confidence labels and related
`.re.cpp` mirrors. Keep that contract, including any cross-build promotion gate and preferred
IDA/Ghidra/runtime tools. The skill does not replace it with a generic report or make Ghidra
authoritative merely because it supplies isolated contexts. Project policy can prescribe
additional metadata; insight-cli adds no mandatory evidence schema.

When no project convention exists, short notes and relevant output files with relative links
are a simple fallback. Independent agents own separate files or subfolders; one lead owns a
shared summary when useful. Use appropriate external tools directly. `artifacts save` can
checkpoint an existing project file or folder without conversion; its copy does not replace
the canonical project records. Saving is useful for requested checkpoints or handoff, rather
than a prerequisite for considering a project-formatted finding valid.

```sh
insight-cli skill insight-re
insight-cli artifacts save ./research/A-password --json
insight-cli artifacts save ./research/notes.md --json
```

Saving uses the selected profile's Update permission. It needs no Ghidra, Java, target or
session and returns an ordinary retained file/directory path, file/byte counts and SHA-256.
The returned copy preserves the original relative layout, including empty files/folders.
Edit the original and save again for another checkpoint. Each call creates a separate copy.
See the packaged [save contract](../skills/ghidra-coordinator/references/artifacts.md) for
concurrent edits, unsupported files, cancellation and lost-response semantics.

Materials are profile data. Profile deletion or configuration invalidation cannot discard
retained workspace/materials. Closing a Ghidra context does not remove saved materials.
Saving files and merging program databases remain separate actions.

## Installed-package acceptance on 7zr.exe

The [verification receipt](verification/re-skill.json) records the exact package, skill and
input identity, offline checks and real native workflow. Three fresh agents read the
installed skill: A investigated password input, B extraction diagnostics, and C binary
identity/imports through external `file`, `shasum` and LLVM utilities. A and B used separate
Ghidra processes on the same target, exclusively through the installed public CLI.
The Windows executable was examined statically and was never executed.

A followed the password prompt to `0x43f4f5`: clearing echo is best effort, and restoring
the previous mode requires the initial mode change to have succeeded. API failure does
not prevent input. B followed CRC string data references to `0x436fea`: result 1 selects
Unsupported Method, 2 Data Error, 3 CRC Failed; a nonzero second argument changes 2/3 to
encrypted-file messages suggesting a wrong password. Result 9 independently says Wrong
password. C established PE32/i386 console format and relevant imported console APIs,
explicitly distinguishing import presence from call-site behavior. Notes retain the
remaining type, data-flow and runtime limits.

The lead reviewed actual pseudocode/instructions and external output. Each worker saved
its settled folder. A published R2; B continued seeing R1 until explicit refresh, which
received A's annotation while preserving B's own edit. B then published R3. A fresh context
read both comments and native code; server history independently contained R1, R2 and R3.
The saved worker folders, combined research folder and separate notes file were compared
byte for byte with their sources. Owned contexts and server were closed afterward.

This run exposed a genuine single-function inspection bug: upstream `function=` returns
a bare function bundle, while `functions=` returns a map with counts. Our validator
previously required the latter in both cases. It now validates the selected response variant,
including field subsets and bulk-selector precedence. The pinned upstream
[service](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionBundleService.java#L134)
and [bundle builder](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionFacts.java#L163)
define these variants. The receipt distinguishes the original multi-agent artifact from
the final corrected artifact's focused native repetition. It does not rebind the original
run to a later build. The final artifact passes 139 offline tests, isolated-package proof
and real single/full, field-subset and bulk inspection. Its folder and single-file saves
again match the settled research bytes; repository history remains R1/R2/R3.

Some navigation addresses are interior instructions, not function entries. Function-entry
operations can reject them; inspect the containing function or existing instruction listing.
Arbitrary inline scripts are conservatively tracked as Update operations, even when their
author only prints existing data. A ran two such requests and an annotation; its R2 merge
published all three pending operations at an unchanged shared base. No script was replayed
to merge another agent's work. B had one scalar annotation, preserved across refresh.

## Reproduction and boundaries

The filenames below belong to this fixed acceptance scenario, not a required project RE format.

Run `npm test` and `node scripts/test-package.mjs --keep-installed` with Node 24. The package
check verifies relocated skill links and file/folder saves through CLI/RPC without native
configuration. `quick_validate.py` from the skill-creator skill also validates the RE skill.

On the configured macOS machine with Ghidra 12.1.2 and Java 21, create a fresh owned run:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/acceptance-re-skill.mjs prepare \
  /tmp/new-re-skill-run '<retained-installed-package-directory>' /path/to/7zr.exe
```

This driver accepts only the recorded input SHA-256 and macOS runtime paths. It creates
owned contexts and prints their selectors. Assign three real agents the questions above,
the installed skill, separate research folders and the returned Ghidra selectors. Workers
write `finding.md`, raw output and plate comments containing their relative finding paths;
they save folders with receipts `receipts/A.json`, `B.json`, `C.json`. The external worker
retains `sha256.txt` and `imports.txt`. Agents do not merge, refresh or close these contexts.
The lead reviews the evidence, updates `research/notes.md` and writes `review.json` with
`password`, `extraction`, `external` set to true and an actual review explanation. Then:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/acceptance-re-skill.mjs finish /tmp/new-re-skill-run
```

After the completed run, the `inspect` action takes that directory and a retained final
installed-package directory. It reopens the shared target through the final CLI, exercises
single/full, field-subset and bulk function inspection, saves the settled folder and notes
again, verifies unchanged history, and closes its own context/server.

On failure preserve the run and inspect public status/history before continuing. Do not
blindly rerun a finish step that may have published. The driver is an opt-in acceptance
helper, not an autonomous RE engine or a portable native test. Raw transcripts, copied
executable and personal runtime paths stay outside Git.

This is functional acceptance of the new skill/materials workflow. It is not a new speedup
measurement, the complete business suite, or a repeat of the historical GUI/debugger gate.
The existing [timing conclusions](7ZR-TIME-ANALYSIS.md) remain unchanged.

The project-convention clarification changes packaged instructions only. Historical native
and timing receipts retain their original artifact/skill hashes; they are not measurements
of this later wording.
