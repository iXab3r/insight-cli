# Fresh-agent research contract

This is an actual static reverse-engineering task on the assigned production 7zr.exe.
Use only the assigned public CLI context. Do not execute the target. Do not read previous
answers, repository product source/docs, other actor/trial folders, external source/web,
or internal Ghidra/MCP state. The orchestrator supplies task parts from `protocol.json`,
the trial path, actor number, Node path and control script path. This file and that
protocol are the only repository files you need. Do not change repository files.

For an assigned actor, issue public reads as follows (replace the bracketed selectors):

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <control> call <trial.json> <actor> strings search --contains '<clue>' --limit 30
INSIGHT_NATIVE_DISPOSABLE=1 <node> <control> call <trial.json> <actor> xrefs to --address <string-address> --limit 30
INSIGHT_NATIVE_DISPOSABLE=1 <node> <control> call <trial.json> <actor> functions get --address <function-address>
INSIGHT_NATIVE_DISPOSABLE=1 <node> <control> call <trial.json> <actor> functions decompile --address <function-address>
```

These commands spawn installed public insight-cli processes with the assigned profile,
session and target. Network/keyring/process access requires the normal execution tool's
`require_escalated` option. Reads may be combined into one tool invocation; scope remains
fixed. Follow relevant callees/callers where necessary, using their actual addresses.
Make evidence-backed inferences and explicitly retain uncertainties. Do useful research;
do not add delays, padding, needless repeated commands, or synthetic workloads.

For every assigned part, write one JSON file inside the assigned
`<trial-directory>/actors/<actor>/` folder. Create that folder if necessary. Its schema is:

```json
{
  "part": "switches|password|extraction",
  "functionAddress": "0x...",
  "inferredName": "EvidenceSupportedName",
  "conclusion": "A useful explanation answering the assigned question (at least 80 characters).",
  "anchors": [{"text":"Exact clue text", "stringAddress":"0x...", "referenceFrom":"0x...", "functionAddress":"0x..."}],
  "facts": [{"claim":"Substantive observed condition or behavior", "functionAddress":"0x...", "codeQuote":"An exact literal code quotation from that function's decompilation, excluding comments"}],
  "limitations": ["Specific uncertainties retained by this static analysis"]
}
```

Provide at least one valid string/xref chain and at least three substantive code-backed
facts per part. Literal code quotations must contain code, not prose or comments, and
must preserve C escaping in JSON. Function names/prototypes are inferences unless proved.
The main function is the best navigation location for that finding; a fact may refer to
a relevant helper at a different function address. Keep the complete record below 16,000
characters. Do not rename functions, merge or close contexts yourself.

For an indirect clue, `referenceFrom` is the first incoming reference (for example a
data-pointer slot). Add `"via": ["0x..."]` with each successive incoming reference
address until the last reference lies in `functionAddress`. For example, a string
referenced by a pointer slot which is read by an instruction uses the slot as
`referenceFrom` and the instruction as the single `via` element. Confirm each hop with
`xrefs to`; do not describe a data slot as an instruction inside the final function.

Save each completed part privately through the real public CLI:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 <node> <control> submit <trial.json> <actor> <part-id> <your-json-path>
```

For a serial assignment, investigate and submit all three parts in order, in this one
context. For a parallel assignment, investigate and submit only your one assigned part.
Finish as soon as all your parts have returned `saved-private`. Your final reply names
the submitted part IDs and output paths, with a short account of findings and uncertainties.
Do not wait for colleagues or inspect their answers. The lead separately collects, merges
and independently verifies the published result; those costs are inside the task clock.
