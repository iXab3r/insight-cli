# Fresh RE-skill timing assignment

Read the supplied installed `insight-re/SKILL.md` first; its linked installed references and generated help are allowed. You receive your trial, actor number, assigned part(s), Node and controller paths. Use that public-CLI recorder for Ghidra reads and saves so every request, including errors, has timestamps and raw output. It spawns the actual installed CLI with your exact independent session/target. No product internals or direct MCP calls.

Do not read repo source/docs, the controller source, correctness oracle, previous answers/trials or other actors' folders. Do not use external source/web or execute 7zr.exe. You may inspect your own trial.json solely for selectors and your assignment. Do not modify repository files. No subagents. The single actor may choose task order and batch independent reads; it must finish all three parts. Parallel actors finish only their assigned part.

After reading the installed skill, record readiness:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> mark <trial.json> <actor> ready
```

Read commands (require normal unsandboxed local IPC/keyring access):

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> call <trial.json> <actor> <part> strings search --contains '<clue>' --limit 30
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> call <trial.json> <actor> <part> xrefs to --address <address> --limit 30
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> call <trial.json> <actor> <part> functions decompile --address <entry>
```

Other allowed reads: `functions get/search/inspect/disassemble`, `xrefs from`, `memory read`, `analysis get-function-pcode`. Use entry addresses where required; xrefs may return a data pointer slot that needs another hop. The recorder prints the result and the retained ordinary raw file path. Use that path for relative links. Read only useful output; no needless repeated calls. Helpers and instructions may resolve ambiguous pseudocode. Do not run scripts or rename functions.

As soon as useful findings are established, write `<trial-dir>/research/<part>/finding.md`. Ordinary Markdown is enough: answer the question, at least three concrete conditions with relevant function addresses and links to raw responses, and explicit remaining limits. No mandatory JSON, no exhaustive architecture recovery, no padding. For timing, mark `writing:<part>` before writing and `written:<part>` afterward with the same `mark` action. You may make an early draft then refine it; keep a final settled note under 6000 characters. Avoid over-investigating optional questions once the specified answer is established; preserve uncertainty plainly.

When a part is complete, this action writes the actual private plate comment from your finding and saves the settled part folder through public `artifacts save`:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> checkpoint <trial.json> <actor> <part> <main-function-entry>
```

Do not edit that part's files afterward. The save receipt is outside the saved folder. Do not merge, refresh or close; the lead performs identical one-merge publication/verification in both modes. If all assigned parts are checkpointed, promptly record:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <controller> mark <trial.json> <actor> done
```

Return the main findings, paths and limits briefly; do not wait for colleagues. Report concrete blockers early. The lead watches checkpoints and will review actual source evidence, so an unsupported note or a missing required behavior fails acceptance. Your annotation is not proof of its own claim.
