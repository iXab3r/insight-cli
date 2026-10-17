---
name: insight-overview
description: Choose bounded tool overviews and focused drilldown through insight-cli without flooding agent context with whole-program code, traces or dumps. Use for tool discovery, scoped evidence paging and keeping native partial coverage separate from complete results.
---

# Insight Overview 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation, then use that route for later authorized
CLI calls too. An explicit **no command was sent** denial is known undispatched and can be
retried through that route. Keep HOME, profile and owner state; see
[host execution permissions](references/agent-execution.md). A lost mutation reply needs
request/status recovery, never blind retry.

Follow project tool and evidence conventions. This workflow uses existing APIs; it adds
no runtime, analysis database or installation step. `tools list`/`tools show CAPABILITY`
locate tasks and dedicated instructions before download. Discovery is not runtime readiness.

Start from the research question and exact input. Read metadata or an index, choose one
function/type/object/event/stream, then request its evidence. Keep ordinary full files
outside conversation when useful; `--output` does not mean paste the entire file into context.
Do not `cat` a large saved index or class after writing it. Filter it on disk with `jq`/`rg`
and print only the selected identity or excerpt. Size the next read from the overview counts.

For a managed-method question, use a short-name query before exporting a large index:

```sh
insight-cli ilspy query INPUT --view methods --name-filter KEYWORD --limit 10 --json
insight-cli ilspy decompile --target TARGET --member METHODDEF_TOKEN --limit-chars 2000 --json
```

Choose KEYWORD from the research question; it matches the short method name
case-insensitively, excluding namespaces/types/signatures. The response supplies the
exact target and MethodDef token for the second call. If no method matches, broaden the
term or inspect a bounded type/method page; that search alone does not prove global absence.
`--filter` instead matches the case-sensitive full signature, so a namespace term may
match every method. Do not replace a focused query with that broad match, a whole-class
read or the first/last rows of a shell-truncated result. Refine the query when output is
truncated before drawing conclusions. Metadata counts cover the queried scope, not
code you have actually inspected.

| Surface | Useful overview | Focused follow-up |
| --- | --- | --- |
| Ghidra | Scoped program info, function/string/reference pages | One function signature, instruction/address interval, decompilation character window |
| ILSpy / managed metadata | `ilspy query` assembly counts, types and method pages | Exact type/member, MethodDef IL, imports or filtered assembly comparison |
| DiE | Header information and paged signature findings | Selected signatures/deeper scan; heuristic absence remains unknown |
| LLVM / structured binaries | Headers, section and linkage pages | One section, symbol, PDB query or bounded instruction interval |
| 7-Zip | Paged ordinary entry inventory | Integrity check and selected bounded regular-file extraction |
| .NET dump / ClrMD | Runtime/heap availability and object-type query | Exact object fields, thread stack or focused SOS command |
| .NET stack / trace | Paged selected process stacks or thread-time ranking | Thread/method evidence and saved trace export; sampled time is not CPU proof |
| LLDB | Identify the native input statically first | Authorized selected breakpoint/hit, bounded registers/memory/backtrace; this launches a program |
| Frida | Authorized PID's module/export pages | Selected bounded hook observation; this attaches to a running process |
| WinDbg | Retained dump overview | Thread, frames, registers, memory or disassembly window with explicit symbols |
| ProcMon / strace | Scoped retained summary/event pages | Selected path/category/process events; capture/trace needs its declared native authorization |
| dnSpy | Managed metadata first | Authorized IL-token breakpoint parameters/stack or exact expected constant edit on a new copy |
| TShark / mitmproxy | Immutable packet/HTTP overview | Exact frame/stream/flow and bounded body; live proxy recording is a separate opt-in action |
| Process capture | Retained run overview | Output byte page, declared file changes or literal report comparison; running is explicit |
| Artifacts | Saved file/byte counts and digest | Open the chosen ordinary file; no artificial tool install or analysis merge |

ILSpy text commands and `ghidra functions decompile` return a 16000-character window by
default. `--limit-chars`/`--offset-chars` count Unicode characters, not bytes, lines,
addresses or IL instructions. Combine pages only when `textSha256` is unchanged. That
hash binds the **observed native text**; `sourceTruncated` still means a native prefix.
Native truncation is never cleared by reaching the final page. ILSpy `--output` retains
the full bounded native text; Ghidra pages retain session/target/function selectors.

Other APIs declare their own coordinates: rows/events, bytes, instructions, stack frames
or text lines. Read their generated help instead of assuming all offsets mean the same
thing. A source hash mismatch means the text changed: restart the selected read or retain
separate observations. Runtime captures at different times are never one snapshot merely
because their target binary is the same.

Preserve `complete`, `truncated`, scan bounds and unknown/missing values in findings.
A filtered page or incomplete parser output cannot establish global absence. Static reads
do not observe execution; choosing a debugger or collector is an explicit runtime decision.
