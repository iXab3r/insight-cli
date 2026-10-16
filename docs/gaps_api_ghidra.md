# Ghidra API gaps: native SDK → GhidraMCP → insight-cli

Runtime delivery is now a separate product layer: [complete Ghidra runtime management](MANAGED-GHIDRA-RUNTIME.md)
covers managed Ghidra/JDK/native/server installation and external executable selection. The pinned
SDK/MCP inventory below retains its own acceptance identities.

The subsequent [business Gherkin gate](BUSINESS-ACCEPTANCE.md) passes all 25 public-CLI
scenarios and six prepared-base speedup pairs on real Ghidra. It corrects one research
edge case: exported-data `Entry Point` xref metadata is retained as a non-navigable row
instead of rejecting the entire page. This adds no new catalogue operations; the older
P0–P3/full-facade receipts below keep their original source/artifact identity.

Source audit: **2026-10-15**. This compares the shipped facade against the pinned implementation,
not the newest upstream release. The unit of the detailed comparison is a user operation;
there is no literal bijection between SDK methods, MCP endpoints and CLI commands.
The appendix is a full operation inventory; G07 separately records parameter/variant gaps.
It does not claim every native overload or parameter combination is covered.

The later [production-EXE CLI walkthrough](AGENT-CLI-WALKTHROUGH.md) exercises discovery,
decompilation, isolated annotations and publication through the installed public facade. It
fixes an operational gap: synchronous import/analysis exceeded the generic HTTP budget.
Import now allows ten minutes; retained opening failures expose scope and continuation commands,
and unresolved open retries return nonzero without reimporting. Its focused evidence keeps a
separate source/artifact identity from the catalog-closure and combined reports below.
The subsequent [first-import recovery](INITIAL-IMPORT-RECOVERY.md) closes the retained-bootstrap
limit in that walkthrough: private completion receipts, independent staging readback and
conditional promotion recover the same profile without a repeated canonical check-in.

## P0/P1 closure

**G01–G07 P0/P1 are implemented in the facade.** The pinned upstream source/JAR is unchanged.
Its two analysis stubs are replaced with facade-owned native algorithms, and nested unavailable
responses are rejected. The facade also closes the audited memory/prototype input gaps.
The 210 operation mappings and eight bridge equivalents remain accounted for; the current tree has 271 public leaves, including selected native SDK extensions.
This remains a selected native API facade, not complete Ghidra SDK coverage.

[Current closure evidence](verification/api-gaps.json) binds the implementation source hashes,
real Ghidra cases, regressions and package checks. [Agent query semantics](../skills/ghidra-coordinator/references/query-semantics.md)
define supported ABIs, work budgets, completion flags and intentional limitations.
The original audit compared runtime `300884e` with pinned MCP `57e37a8`; findings below retain
that upstream distinction and identify what now differs in our implementation.

| Finding | P0/P1 outcome | Relevant implementation |
| --- | --- | --- |
| G01 | Closed: real bounded static CFG reachability and exact constant-table scans; placeholder responses fail closed | [native research](../skills/ghidra-coordinator/references/native/InsightResearchQueries.java), [response policy](../skills/ghidra-coordinator/src/query-policy.ts) |
| G02 | Closed: actual type inventory/resolution, parser-backed prototype diagnostics, isolated temporary types and stable program modification counter | [native research](../skills/ghidra-coordinator/references/native/InsightResearchQueries.java) |
| G03 | Closed: explicit x86 cdecl / Windows x64 / SysV x64 integer-slot ABIs, correct stack/return setup, bounded stepping, unsupported architecture/lowering errors | [native emulator](../skills/ghidra-coordinator/references/native/InsightEmulation.java) |
| G04 | Closed for the audited P1 contract: structured globals, bounded common scans/deeper response checks, explicit cost policy for remaining upstream operations | [query contracts](../skills/ghidra-coordinator/references/queries.json), [result checks](../skills/ghidra-coordinator/src/query-results.ts) |
| G05 | Closed: observations/estimates/suggestions/similarity carry algorithm and limitations; fixed confidence is labeled uncalibrated | [query policy](../skills/ghidra-coordinator/src/query-policy.ts), [cross reads](../skills/ghidra-coordinator/src/cross.ts) |
| G06 | Closed: external-entry metadata separated from name/image-base candidates | [native research](../skills/ghidra-coordinator/references/native/InsightResearchQueries.java) |
| G07 | Closed: bytes/fill/base64/overlay/uninitialized/volatile/comment block creation; explicit/default compiler convention; independent saved-state verification and lost-response recovery | [commands](../skills/ghidra-coordinator/src/cli.ts), [memory verification](../skills/ghidra-coordinator/src/memory-inputs.ts), [saved inspector](../skills/ghidra-coordinator/references/native/InsightSnapshotInspect.java) |

## Selected P2 closure

**N01–N09 and G07's direct placeholder convenience are implemented.** The selected native workflows
are described below and in the installed [agent reference](../skills/ghidra-coordinator/references/native-workflows.md).
[Separate P2 evidence](verification/api-gaps-p2.json) binds source hashes, actual native fixtures,
package acceptance and OS results. It supplements the older P0/P1 and M0–M5 reports.
The pinned MCP source/JAR remains unchanged. Native helpers call actual Ghidra facilities; custom
MCP function hashes are not presented as Version Tracking, FID or BSim.

Program edits remain independently verified complex private changes. A diverged base retains an
explicit conflict; P2 introduced no universal native DB merger or automatic publication strategy.
P3 subsequently adds opt-in synchronization using these same merge/refresh rules.
Live target writes have separate durable intents and never replay an uncertain effect. Schedules
are parsed/validated without execution. Whole-SDK parity and calibrated similarity probabilities
are outside these selected workflow contracts.

## P3 closure: extensions and synchronization

**Both P3 items are closed for the selected contracts.** [P3 evidence](verification/api-gaps-p3.json)
records 118 passing offline tests, nine installed real-Ghidra P3 cases, 13 native SDK regression
cases and two actual IPC-owner SIGKILL phases. All groups match the same executable source inputs
and npm artifact. Native acceptance is macOS headless/GUI.

The P3 consumer is an agent team that needs a processor/analyzer outside the base distribution
and wants to choose when verified private edits reach the shared program. The selected extension
contract consumes ready-built standard 12.1.2 modules, pins every file, discovers native capabilities
and configures managed GUI plugin enablement. The selected synchronization contract adds
per-context `after-edit` / `after-save` publication and `before-edit` refresh, with manual defaults.
See the installed [extension/synchronization reference](../skills/ghidra-coordinator/references/extensions-and-sync.md).

This is a concrete workflow contract rather than a denominator for every Java extension API.
Building/downloading third-party packages, arbitrary plugin option schemas, hot unloading,
automatic native markup application and universal semantic merging are outside it. Neither
content pinning nor an owned JVM promises a security sandbox for third-party extension code.

## Baseline, sources and scope

| Layer | Exact baseline | What is being counted |
| --- | --- | --- |
| A — native Ghidra | Ghidra **12.1.2**, Java 21; installed source archives, linked to the [matching release source](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.1.2_build/Ghidra) | Java SDK, service APIs and extension points. No invented “total SDK endpoints” denominator. |
| B — GhidraMCP | **7.0.0**, commit `57e37a8bf388b1279cff46378f85be1554548f61` | [210 REST catalog entries](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/tests/endpoints.json), plus eight Python bridge controls accounted separately. |
| C — insight-cli | Current combined M0–M5/P0–P3 build identified by [full acceptance source hashes](verification/full-facade-current.json); selected older [P2 OS evidence](verification/api-gaps-p2.json) retains its own identity | 271 public leaves across the facade command tree; not 271 distinct native Ghidra capabilities. |

Evidence: [coverage ledger](GHIDRA-COVERAGE.md), [210 operation joins](verification/coverage-evidence.json),
[current combined acceptance](verification/full-facade-current.json), [query contracts](../skills/ghidra-coordinator/references/queries.json),
[mutation contracts](../skills/ghidra-coordinator/references/mutations.json). The historical full M0–M5 report records
93 offline tests and 23 native groups at its own source revision. The current P0/P1 report records
the new native acceptance/regressions and package identity separately; it does not rebind that old
report to new code. Historical native acceptance targets macOS. The separate P2 report adds selected headless
Windows/Linux workflows; it does not claim an exhaustive parameter/OS matrix.

The REST catalog digest is `ebdaa9195ec2ea55fb706107bba1ee3732abd2eda783ed67a6ccc7359fdc5c66`.
The eight bridge tools include an import operation overlapping REST import. They must not be
added to 210 as eight independent program-analysis features. There is no useful SDK coverage percentage.

## What the three APIs actually are

**A. Ghidra** supplies in-process Java objects such as [Program][sdk-Program], its listing, memory,
function/type/symbol/reference managers, [DecompInterface][sdk-DecompInterface], debugger services and
project/server APIs. [FlatProgramAPI][sdk-FlatProgramAPI] and [GhidraScript][sdk-GhidraScript] are convenient
entry points over that SDK. Ghidra does not expose the MCP catalog as a built-in HTTP API.
SDK access also requires the correct program, transaction, task monitor and, for some services, GUI tool.

**B. GhidraMCP** is a plugin/headless server plus Python MCP bridge. Annotated Java service methods
and [manual descriptors](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ManualToolDescriptors.java)
expose selected operations. Some are thin SDK calls; others combine many calls, calculate custom
heuristics, format text, control processes or contact an external archive. The Python bridge discovers
and dispatches the server schema. It is not an exhaustive serialization of Java classes.

**C. insight-cli** supplies typed commands/flags through Factory's CLI and the same command tree through
`createInsightCli` / `cli.execute`. It owns session/target routing, private saved contexts, publication,
request identity, recovery and resources. It calls pinned REST handlers and uses native helpers where
required. A caller does not select arbitrary MCP instances or bypass publication via raw SDK objects.
See [entry point](../skills/ghidra-coordinator/src/index.ts), [command tree](../skills/ghidra-coordinator/src/cli.ts),
[context adapter](../skills/ghidra-coordinator/src/contexts.ts) and [native helpers](../skills/ghidra-coordinator/references/native).

### Native API families behind the exposed operations

These describe SDK breadth within each family; the appendix identifies the particular primitive
or service associated with each pinned operation. A listed SDK class does not mean every method
of that class is exposed.

| A — native family | B — exposed MCP subset | C — facade and remaining difference |
| --- | --- | --- |
| [Program][sdk-Program], [FunctionManager][sdk-FunctionManager], [Listing][sdk-Listing] | Functions, instructions, comments, tags, disassembly and selected edits | Scoped reads/edits and saved-state verification; not arbitrary iteration/editing of every SDK property. |
| [DecompInterface][sdk-DecompInterface], [HighFunction][sdk-HighFunction] | Decompilation, selected P-code/dataflow and variable operations | Typed command inputs and checked output variants; bounded typed SSA IR and selected native options/simplification; no entire object graph (N09). |
| [DataTypeManager][sdk-DataTypeManager], [Structure][sdk-Structure], [CParser][sdk-CParser] | Structures/unions/enums/derived types, C declaration import, validation | Saved complex edits; corrected top-level copy, parser-backed validation/inventory (G02), GDT source identity, packing, bitfields and settings (N07). |
| [SymbolTable][sdk-SymbolTable], [ReferenceManager][sdk-ReferenceManager], [ExternalManager][sdk-ExternalManager] | Labels, symbol rename, xrefs and external-location reads | Explicit scope and guarded mutations; dedicated namespace/class and external library/location CRUD (N08); not every reference-manager property. |
| [Memory][sdk-Memory], [MemoryBlock][sdk-MemoryBlock], [ProgramContext][sdk-ProgramContext] | Byte reads/search, block create/permissions, image base, metadata | Guarded patch/assembly, verified block split/join/move and bounded processor-context editing (N03). |
| [BasicBlockModel][sdk-BasicBlockModel], [AutoAnalysisManager][sdk-AutoAnalysisManager] | CFG, analyzer options/reanalysis and custom research summaries | Native mechanisms plus MCP algorithms; the two upstream stubs are replaced by bounded native facade analyses (G01). |
| [EmulatorHelper][sdk-EmulatorHelper], [PcodeEmulator][sdk-PcodeEmulator] | Two bounded function/hash helpers via EmulatorHelper | Supported x86/x64 integer-slot ABI policies, isolated results and explicit termination (G03); no persistent general emulation API. |
| [DomainFile][sdk-DomainFile], [DomainFolder][sdk-DomainFolder], [RepositoryAdapter][sdk-RepositoryAdapter] | Project/file lifecycle, repository/ACL/history/checkouts/check-in | Local managed startup or external profile; research lifecycle replaced by owned contexts and explicit merge/refresh. |
| [ProgramDiff][sdk-ProgramDiff], [ProgramMergeManager][sdk-ProgramMergeManager], [ProgramMultiUserMergeManager][sdk-ProgramMultiUserMergeManager] | Custom function/documentation comparison/transfer; no generic native program diff/merge endpoint | Scalar three-way merge and unchanged-base complex publication; no universal DB merge (N02). |
| [Trace][sdk-Trace], [Target][sdk-Target], [DebuggerStaticMappingService][sdk-DebuggerStaticMappingService] | 16 GUI debugger operations | Managed GUI/LLDB contexts and retained trace recovery; guarded live memory/register writes and selected bounded trace timeline/object/value/schedule queries (N06). |
| [GhidraScript][sdk-GhidraScript], [GhidraScriptUtil][sdk-GhidraScriptUtil] | Script execution, inline code; listing handler only gives GUI instructions | Actual logical script inventory; scripts are an extension route, not typed parity for every SDK feature. |
| [GoToService][sdk-GoToService], [ProgramManager][sdk-ProgramManager] | GUI cursor, tools, navigation; MCP prompt policy | Scoped GUI actions; GUI required. There is no promise to expose every plugin window/service. |
| [AutoImporter][sdk-AutoImporter], [Exporter][sdk-Exporter] | General file import and GZF program export/import, GAR project archive/restore | Managed inputs and verified snapshots/files; native loader/exporter inventory, explicit selection/options and restricted-range output (N04). |
| [VTSession][sdk-VTSession], [FunctionDatabase][sdk-FunctionDatabase], [FidService][sdk-FidService] | No dedicated Version Tracking / BSim / Function ID API in the 210 catalog | Dedicated native VT match sets/decisions and genuine FID/BSim database workflows supplement custom fuzzy matching (N01/N05). |

## Audited gaps and implemented P0/P1 behavior

### G01 — upstream stubs replaced; unavailable payloads rejected

Pinned [findDeadCode](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L1318)
and [detectCryptoConstants](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L807)
still return placeholders. Our context adapter runs its own native research implementation.
CFG reachability is bounded by visited inputs and time. Unresolved indirect flow, a missing decoded
entry or an incomplete traversal cannot produce unreachable findings. The result qualifies itself
as a static CFG observation, not a proof of runtime behavior or coverage of undecoded bytes.

Constant scans use the versioned `insight-constant-tables-v1` catalog: AES S-box, SHA-256/SHA-1/MD5
initial-state byte sequences in listed endian variants and the ChaCha sigma string. The complete
signature names/lengths are returned; exact matches are candidates, not proof of execution.
Byte budgets cover actual reads; continuation preserves unchecked boundary lookahead. Positive,
negative, budget-limited and unresolved-flow native fixtures establish the declared semantics.
Nested `Not yet implemented` / unsupported / unavailable statuses fail instead of becoming completed
analyses. The AES table also has an independent finite-field integrity test.

### G02 — actual inventory and parser-backed resolution

Pinned `get_valid_data_types` lists hard-coded names; the facade now lists actual program types and
successfully resolved builtins with path/category, size/alignment and source provenance. A filtered
or budget-limited inventory says so. `validate_data_type` reports resolution and diagnostics, not
an assurance that arbitrary memory can accept the type.

Prototype validation uses Ghidra's `FunctionSignatureParser` with the program's data organization
and required type definitions copied into an isolated temporary manager. Parser errors and
unsupported compiler conventions cannot pass as valid. Queries assert that the actual program's
modification counter is unchanged. This avoids treating save-container byte identity as a semantic
DB comparison. Validation does not apply a signature or persist newly resolved types.

`default` calling convention resolves to the active CompilerSpec's effective default. The adapter
uses that name for application because the pinned MCP setter rejects the literal `default`.
Inline conventions before the first parenthesis are normalized like the pinned setter; conventions
inside callback parameters are preserved, and an explicit flag takes precedence. Saved prototype
return/parameter types and effective convention are independently verified.

### G03 — explicit bounded emulation policies

The pinned helper's fixed ESP/four-byte stack setup is replaced by facade-owned emulation policies:
little-endian x86 cdecl, Windows x64 (including `clangwindows`) and SysV x64. Pointer-width return
addresses, stack alignment, Windows shadow space and integer/pointer argument register/stack slots
follow the selected policy. PC/SP are owned by that setup. Unsupported architectures, compiler
policies and typed floating/aggregate/variadic lowering are explicit errors.

Instruction and time budgets are enforced. `completed`, `hit_return`, `stop_reason` and batch
`outcomes` distinguish a returned function from a stop/error/limit. Incomplete candidates cannot
produce successful hash matches. Real x86 PE, x64 PE and SysV ELF cases exercise stack use and nested
calls; a real AArch64 input is rejected. Isolated emulator state does not implement OS services,
CPU/process restoration or general ABI lowering; raw unknown types still require agent interpretation.

### G04 — structured records, real scan budgets and explicit upstream cost

Globals now contain typed records (address/name/type/path/size/xrefs/naming/type flags/provenance),
not formatted display strings. Facade-owned global/string/type/instruction/byte scans bound visited
inputs, bytes and/or time. `scan`, `complete`, `truncated` and `total_known` expose incomplete work.
A real 5000-symbol fixture with a 50-input budget verifies that a five-row page does not hide an
unbounded backend scan. Returned pages retain bounded rows, and oversized string units stop a scan.
Type/category pages and filters retain their domain semantics within the declared scan scope.

Result checking covers the common record shapes, counts, parser diagnostics, entry provenance,
scan counters, byte limits and CFG/emulation completion consistency. Bounded regex search rejects
branching/nested repetition; supported syntax and limits are in the agent reference.

Unreplaced upstream algorithms can still scan globally before paging. Their results explicitly
state `scanPolicy.workBound: not-guaranteed`, the output ceiling and cancellation limitation.
This is reported cost, not a claim that every MCP algorithm became interruptible or bounded.
P2 adds a 32 MiB / 20000-symbol / 1000-type saved fixture and bounded new IR/trace interfaces. Further replacement of a specific upstream kernel remains conditional on a measured workload; the current cost qualification still applies.

### G05 — qualified heuristic results

Completeness scores, fuzzy similarity, array bounds, field names, malware/API patterns and IOC
matches now carry `semantics` with kind, algorithm and limits. Field-name confidence becomes
`null` / `uncalibrated` rather than presenting a fixed `medium` label as evidence. Cross-context
fuzzy commands carry the same qualification. These remain inputs to the agent's decision;
P2 adds native VT/FID/BSim algorithms with positive, negative and ambiguity fixtures (N01/N05). Their native scores remain uncalibrated; statistical calibration needs a separate labeled corpus and acceptance criterion.

### G06 — entry metadata separated from candidates

Pinned `get_entry_points` mixes external-entry symbols, conventional names and an image base
labeled `program_entry`. Our `entry_points` include explicit Ghidra external-entry provenance;
`candidates` separately contain conventional names and image base with `confirmed: false`.
The native PE fixture has different image-base and entry addresses and verifies this distinction.
Even confirmed external-entry designation is metadata, not proof of OS startup behavior.

### G07 — missing domain inputs added; logical lifecycle equivalents preserved

| B — pinned operation/input | C — current facade contract | Outcome |
| --- | --- | --- |
| `create_memory_block`: bytes, fill, initialization, overlay, comment, volatility and permissions | `memory create-block` accepts hex/base64 bytes, optional/inferred positive size, fill byte, `--initialized false`, overlay, volatile and comment inputs; ≤16 MiB | **P1 closed.** Saved metadata, overlay identity and entire initialized-content digest are verified independently. Lost-response acceptance confirms one actual creation and reconciliation from saved bytes. |
| `set_function_prototype`: separate convention | `--calling-convention` accepts explicit compiler-supported names and resolves `default` through CompilerSpec | **P1 closed.** Saved types and effective convention are checked; the default alias is covered natively. |
| `create_struct`: direct `replace_placeholder` convenience | `create-struct --replace-placeholder` directly uses verified native layout editing | **P2 closed:** only an explicitly selected empty structure can be replaced; native saved readback is required. |
| `rename_function`: name/address and `strict_mode` | Explicit address/name scalar rename; upstream naming strictness is off | Intentional exact-name/address contract, not MCP naming-policy parity. |
| Comments/documentation input names | Typed `--kind` / `--text` / `--clear`; `--document` | Equivalent renamed inputs. |
| Debugger executable/program and runtime paths | Target/context ownership; debugger Python/WinDbg profile settings | Rehomed inputs; native Windows debugger acceptance remains deferred. |
| Program import overwrite, arbitrary project paths, raw check-in/checkout/undo options | New managed destinations, owned projects and explicit open/merge/discard contracts | Intentional lifecycle/publication equivalents; do not restore raw bypass controls mechanically. |

Memory and prototype variants remain complex private edits. Publication requires the unchanged
shared base; divergence still preserves conflicts. Initial bytes on uninitialized blocks,
undersized content and inconsistent encodings are rejected before mutation dispatch.

## Facade differences that already close or intentionally change MCP behavior

| Operation / concern | Native and pinned MCP behavior | insight-cli behavior / boundary |
| --- | --- | --- |
| `clone_data_type` | SDK `clone(manager)` may return the original object. MCP then renames it. [StructureDB.clone][sdk-StructureDB] returns `this` for the same manager. | [Context adapter](../skills/ghidra-coordinator/src/contexts.ts) uses `copy(manager)`, checks identity and saved readback. This is an independent **top-level shallow copy**; referenced component types can remain shared per [DataType.copy][sdk-DataType]. Do not promise a recursively independent type graph. |
| `list_scripts` | Handler returns Script Manager instructions, not an inventory. | [scripts.ts](../skills/ghidra-coordinator/src/scripts.ts) provides bounded installed/context inventory and logical IDs; no private paths required from the agent. |
| `apply_function_documentation` | Pinned handler manually parses parts of JSON. | [Typed native helper](../skills/ghidra-coordinator/references/native/InsightApplyDocumentation.java), transactional application and independent saved-state verification. |
| `analyze_data_region`, `detect_array_bounds` | Upstream annotations say WRITE; bodies only read. | Facade ReadOnly commands, matching actual effects. The coverage ledger retains upstream labels for comparison. |
| Open/switch/list/close, checkout/check-in | Instance/global current-program and project working-copy operations. | Explicit session/target, managed context lifecycle; `merge`, `refresh`, saved `discard`; no caller-driven routing bypass. Equivalence is intentional, not parameter-for-parameter compatibility. |
| Program writes and remote check-in | SDK transactions/save/check-in are primitives; transport response alone is insufficient evidence. | Journals, retained snapshots, verified effects and exact-version publication readback. Unknown outcomes remain visible and block unsafe publication/replay. |
| Archive ingest | Custom HTTP exchange built around Ghidra function documentation; external archive is not a Ghidra SDK subsystem. | [archive.ts](../skills/ghidra-coordinator/src/archive.ts) owns Node-side exchange/profile credentials and durable outcome; contract tested, external service remains separate. |
| Debugger/GUI recovery | Live target/tool/trace services have process-local state. | Owned GUI/LLDB lifetime and saved traces; restored trace is disconnected. No CPU execution resurrection or automatic repeat of an uncertain live action. |

## Native SDK capabilities outside this MCP catalog

These are concrete **dedicated API gaps** in B and C, not claims that Java scripts cannot reach the
underlying SDK. A script can exercise more SDK functionality, but does not supply a stable typed
contract, bounded output, complete side-effect classification or acceptance evidence for that feature.
The following is a selected workflow inventory, not an exhaustive census of the Java SDK.

| ID / priority | A — native Ghidra capability | B — pinned MCP | C — insight-cli gap and useful acceptance |
| --- | --- | --- | --- |
| N01 / P2 | [VTSession][sdk-VTSession]: native match sets, associations, source/destination programs and markup | Custom fuzzy/hash comparison and documentation transfer; no native VT API | **Closed, selected workflow:** `ghidra version-tracking create/list/matches/markup/decide`. Persistent real VTSessionDB; exact-byte and duplicate-instruction correlators, native scores, explicit acceptance/reset/rejection and one-to-one constraints. Moved, duplicate/ambiguous and unmatched fixtures, owner replacement and snapshot provenance. Markup inventory precedes agent-directed ordinary edits; automatic native markup application is not exposed. |
| N02 / P2 | [ProgramDiff][sdk-ProgramDiff] categorized differences; native merge managers/resolvers | Function/documentation diffs; no generic structured native DB comparison | **Closed for read-only inspection:** `ghidra changes compare` compares selected saved contexts across eight native diff categories, bounded ranges and timeout. Equal/changed A/B fixtures. Native automatic DB merging remains outside this contract. |
| N03 / P2 | [Memory][sdk-Memory] setBytes/split/join/moveBlock, [Assembler][sdk-Assembler], [ProgramContext][sdk-ProgramContext] | Read/search/create/permissions/disassembly; no dedicated existing-byte patch/assembly/context editor | **Closed:** `memory patch-bytes/block-state/split-block/join-blocks/move-block`, `assembly preview/apply`, `processor-context read/set/clear`. Exact preconditions, complete bounded block digests, native rollback, immutable saved readback, lost-response reconciliation with one actual mutation, isolation and unchanged-base publication. Initialized block verification ≤16 MiB; byte edits ≤4096 bytes. |
| N04 / P2 | Native [Loader/AutoImporter][sdk-AutoImporter] selection/options and [Exporter][sdk-Exporter] extension points | General file import; GZF/GAR interchange | **Closed, selected native format contract:** `formats loaders/exporters/export`; `ghidra open --loader --loader-options`. Actual installed inventories, validated typed options, explicit loader/language/compiler and native restricted address sets. Non-default raw-loader offsets/length/base and observed exported bytes; all output/companion files have durable hashed receipts. No PE-rebuild claim. |
| N05 / P2 | [FidService][sdk-FidService], [FunctionDatabase][sdk-FunctionDatabase], [BSimClientFactory][sdk-BSimClientFactory] | No dedicated FID/BSim DB API | **Closed, local native workflows:** `libraries build-fid/fid-query/build-bsim/bsim-query`. Real native FID and embedded BSim/H2 signatures; database SHA, library/version, SDK/signature version, native scores, explicit no-match and immutable query inputs. Build/query/no-match/lost-completion fixtures. ≤1000 input functions, ≤256 MiB consumed DB; no external BSim-server provisioning or calibrated-probability claim. |
| N06 / P2 | [Target][sdk-Target] live writes, [Trace][sdk-Trace] time/object managers, [TraceSchedule][sdk-TraceSchedule] | Launch/control/read/breakpoints/mapping subset | **Closed, selected operations:** `debugger write-memory/write-register/timeline/objects/object-values/schedule`. Stopped/current live target, fresh native read-before/write/read-after, width/byte checks; uncertain writes never repeat. Real LLDB writes/restoration, retained changed trace bytes/IDs and loss of reply. Schedule parsing/validation reports `executed: false`; arbitrary schedule execution is not exposed. Owned adapter copy fixes the pinned LLDB SBProcess memory-write call. |
| N07 / P2 | [DataTypeManager][sdk-DataTypeManager] source archives/settings and [Structure][sdk-Structure] packing/bitfields | CRUD and C declaration import, no complete archive/layout API | **Closed, selected GDT/layout contract:** `types layout/define-layout/set-settings/archive-export/archive-import`. Real GDT round-trip with source archive ID, packing, bitfields and native default-setting definitions/clear. Conflicting layouts reject; divergent private archive work remains a complex conflict. ≤256 selected type paths/fields, consumed GDT ≤64 MiB. |
| N08 / P2 | [ExternalManager][sdk-ExternalManager] and [SymbolTable][sdk-SymbolTable] namespace/class/library/location CRUD | Reads/labels/symbol rename; selected class operations | **Closed:** `namespaces list/create/update/delete` and external library/location create/update/delete/list. Real saved native CRUD; only ordinary namespaces/classes, empty-container deletion and retained-dependency refusal. Existing `list_program_items` remains useful inventory. |
| N09 / P2 | [DecompInterface][sdk-DecompInterface] options/simplification and [HighFunction][sdk-HighFunction] typed SSA | Selected decompile/P-code/dataflow output | **Closed, bounded view:** `decompiler ir` returns actual SSA operations/typed varnodes, address-space/offset/size and block identity, selected native options/simplification, timeout/completion diagnostics and separate IR truncation. Positive and one-op partial fixtures; ≤10000 ops, ≤120-second native timeout. No entire Java object graph. |
| N10 / P3 | [GhidraScript][sdk-GhidraScript], [SleighLanguage][sdk-SleighLanguage], [GhidraApplicationLayout][sdk-GhidraApplicationLayout] / [ExtensionUtils][sdk-ExtensionUtils] and analyzer/plugin extension points | Script entry points; no generic plugin installation/configuration SDK wrapper | **Closed, selected module contract:** `extensions inspect/install/list/enable/disable/capabilities`, extension script inventory IDs and `plugins list/set`. Immutable consumed module trees, 12.1.2 metadata and runtime digests, owner restart boundary, actual SDK language/compiler/analyzer/plugin inventories, existing analyzer configuration/run and owned GUI plugin activation with saved private work. Native acceptance is recorded in the [P3 report](verification/api-gaps-p3.json); no arbitrary plugin option SDK or package acquisition/build promise. |

Ghidra already has multi-user merge machinery: `ProgramMultiUserMergeManager` takes original,
local, latest and result programs, and coordinates memory/type/listing/context and other resolvers.
Its GUI-oriented workflow is not the same contract as our unattended session merge and recovery.
The gap is exposing/adapting the needed native behavior, not the absence of native three-way merging.

The selected P2 workflows are now shipped together. New domain workflows should be driven by
measured agent tasks: first identify an actual format, analysis, trace or porting limitation,
then add a bounded/effect-aware contract and a native fixture. Further statistical calibration,
unrestricted plugin-specific SDK wrappers and universal merging do not follow merely from the SDK containing those APIs. P3
uses the concrete ready-built module workflow described above.

## What our API adds above Ghidra/MCP

| Agent need | insight-cli contract | Relationship to native state |
| --- | --- | --- |
| Several EXEs and independent agents | Immutable root targets, root sessions, `(session, target, ghidra)` contexts; explicit selectors | Same EXE can have independent saved program copies. No shared global active program as caller routing. |
| A publishes while B continues | Explicit `ghidra merge` / `ghidra refresh`; optional persisted `sync-policy`; status exposes pending/conflicted work | Verified scalar merge; refresh takes safe incoming changes while retaining local/shared conflicting values. Any merge conflict prevents the entire publication. |
| Complex edits on a diverged base | Retain both versions; agent transfers desired work onto the current base | Whole-program saved state may publish at unchanged shared base; universal complex DB merging is not implemented. This restriction is intentional. |
| Lost answer / owner failure | Optional `--request-id`, durable intents/results, saved work and reconciliation | No blind check-in/script/external-post replay. Debuggee execution is a separate live effect. |
| Dependable local startup | Managed server/repository/accounts, isolated headless workers, GUI on demand; external profile supported | Caller does not operate MCP ports/processes/checkout ownership. Administrative project/server operations remain separately scoped and do not become program merge proposals. |
| One public interface | `insight-cli ...` or Factory `cli.execute` against the same command tree | Stable logical API plus permissions/profiles/credentials; no separately complete REST/Java-object API promised. |

## Priorities after closure

| Priority | Status / work | Acceptance boundary |
| --- | --- | --- |
| **P0** | **Closed — G01:** unavailable payload rejection and real implementations for the two upstream stubs | No placeholder can count as completed analysis; bounded native positive/negative/partial cases. |
| **P1** | **Closed — G02/G05/G06:** parser/type truth, qualified heuristics and entry provenance | Actual resolution/diagnostics, no persisted validation changes, metadata distinguished from candidates. |
| **P1** | **Closed — G03:** supported ABI policies and honest termination | x86/Windows x64/SysV x64 native cases; unsupported architecture/lowering rejection. |
| **P1** | **Closed — G04/G07:** structured common results, bounded/reported work and missing domain variants | Large fixture budget, saved bytes/metadata/convention checks, retained lost-response effects and A/B publication. |
| **P2** | **Closed for the selected N01–N09 workflows and G07 convenience**, with larger saved-DB and native OS evidence recorded separately | Real native domain effects, lost-reply rules, conflicts, bounded new reads and installed-package checks. Conditional extra kernels/calibration require a concrete measured workload, rather than an implied whole-SDK promise. |
| **P3** | **Closed — N10 and automatic synchronization:** managed extensions and opt-in publication/refresh strategies | Content-pinned ready-built SDK modules; native language/analyzer/script/GUI workflows. `sync-policy` composes the existing verified merge/refresh with durable local acknowledgment; conflicts and unknown outcomes retain work. Manual default; no timer or automatic semantic conflict winner. |

No P0–P3 item remains open within the audited selected contracts. New SDK/workflow requests
require their own measured consumer and acceptance boundary.

The [final combined gate](verification/full-facade-current.json) repeats M0–M5 and selected P0–P3
on one unchanged current build: 118 offline tests, 33 native groups, two agents/two EXEs/four
contexts, conflict/refresh/merge, native response loss and nine actual owner SIGKILL phases.
The installed CLI/IPC and P3-resource tests use the same accepted tarball.
[Reproduction and limits](FINAL-ACCEPTANCE.md) record the scenarios and corrected merge-proof
adapter. The earlier P2 report retains its separate selected headless Windows/Linux identity;
this combined gate is native macOS and does not claim every GUI debugger on every OS.

## Appendix A — every pinned REST operation, 1:1:1

Every one of the **210** catalog paths occurs once below. The native column names the relevant
SDK primitive/service (including delegated helpers), not every transitive call or every overload.
Where the handler is a stub or a non-SDK operation, it says so explicitly. An available primitive
beside a stub is a possible implementation building block, not a claim that the stub calls it.
MCP links point to the pinned handler annotation/registration source; SDK links point to 12.1.2.
Some listed methods are inherited by that SDK interface/class. `open_project` also has a manual GUI
registration; its row links the annotated headless variant.

Commands omit the executable prefix `insight-cli`. Research commands additionally require
`--session` / `--target` and operation flags; administrative commands use explicit profile/project/
repository selectors. Use generated `--help` for syntax. Factory API uses these same command paths.

Status: **D** = mapped domain operation (bounded catalog contract, not full SDK parity);
**E** = intentional facade lifecycle/discovery equivalent; **F** = facade repairs/replaces upstream behavior;
**H** = heuristic/static/limited semantic result, see G02/G05; **S** = unimplemented upstream behavior (none remain unhandled in the facade);
**F** can therefore include a native replacement for an upstream stub. Multiple letters can apply. GUI/headless availability is in the
[coverage ledger](GHIDRA-COVERAGE.md); debugger and UI calls retain their GUI requirements.

### analysis — 20

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [BasicBlockModel][sdk-BasicBlockModel] `.getCodeBlocksContaining`; [Listing][sdk-Listing] `.getInstructions` | [`/analyze_control_flow`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L1153) | `ghidra analysis analyze-control-flow` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo`; [Memory][sdk-Memory] `.getBytes` | [`/analyze_data_region`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L318) | `ghidra analysis analyze-data-region` | **F** — ReadOnly despite upstream WRITE annotation. |
| [HighFunction][sdk-HighFunction]; [PcodeOpAST][sdk-PcodeOpAST] | [`/analyze_dataflow`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L4492) | `ghidra analysis analyze-dataflow` | **D** |
| [Function][sdk-Function]; [DecompInterface][sdk-DecompInterface] | [`/analyze_for_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L4156) | `ghidra analysis analyze-for-documentation` | **D/H** |
| [Function][sdk-Function]; [HighFunction][sdk-HighFunction] | [`/analyze_function_complete`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L2226) | `ghidra analysis analyze-function-complete` | **D** |
| [Function][sdk-Function]; [HighFunction][sdk-HighFunction] | [`/analyze_function_completeness`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L1363) | `ghidra analysis analyze-function-completeness` | **D/H** |
| [Function][sdk-Function]; [Listing][sdk-Listing] `.setComment` | [`/batch_apply_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationBatchService.java#L38) | `ghidra analysis batch-apply-documentation` | **D** |
| [Options][sdk-Options] `.setBoolean` | [`/configure_analyzer`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L230) | `ghidra analysis configure-analyzer` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo` + MCP estimator | [`/detect_array_bounds`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L503) | `ghidra analysis detect-array-bounds` | **F/H** — ReadOnly; estimated bounds. |
| [FunctionManager][sdk-FunctionManager] `.getFunctions`; [AddressSet][sdk-AddressSet] `.subtract` | [`/find_code_gaps`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L4367) | `ghidra analysis find-code-gaps` | **D** |
| [BasicBlockModel][sdk-BasicBlockModel] `.getCodeBlocksContaining` | [`/find_dead_code`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L1318) | `ghidra analysis find-dead-code` | **F** — Native bounded static CFG; incomplete/indirect flow has no unreachable conclusions. |
| [FunctionManager][sdk-FunctionManager] `.getFunctions` | [`/find_next_undefined_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L2139) | `ghidra analysis find-next-undefined-function` | **D** |
| [BasicBlockModel][sdk-BasicBlockModel]; [FunctionManager][sdk-FunctionManager] `.getFunctions` | [`/find_similar_functions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L1072) | `ghidra analysis find-similar-functions` | **D/H** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo`; [Listing][sdk-Listing] `.getInstructionAt` | [`/get_field_access_context`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L570) | `ghidra analysis get-field-access-context` | **D** |
| [HighFunction][sdk-HighFunction] `.getPcodeOps`; [PcodeOpAST][sdk-PcodeOpAST] | [`/get_function_pcode`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L4925) | `ghidra analysis get-function-pcode` | **D** — Selected IR, not whole decompiler object graph. |
| [Memory][sdk-Memory] `.getBytes` | [`/inspect_memory_content`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L677) | `ghidra analysis inspect-memory-content` | **D** |
| [Program][sdk-Program] `.getOptions`; [Options][sdk-Options] `.getOptionNames` | [`/list_analyzers`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L198) | `ghidra analysis list-analyzers` | **D** |
| [AutoAnalysisManager][sdk-AutoAnalysisManager] `.reAnalyzeAll` | [`/run_analysis`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L273) | `ghidra analysis run` | **D** |
| [Memory][sdk-Memory] `.getBytes` | [`/search_byte_patterns`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L834) | `ghidra analysis search-byte-patterns` | **F** — Bounded bytes and continuation; object result with matches. |
| [Listing][sdk-Listing] `.getInstructions` | [`/search_instructions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L935) | `ghidra analysis search-instructions` | **F** — Bounded scan and typed instruction records. |

### comment — 4

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Listing][sdk-Listing] `.setComment` | [`/batch_set_comments`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/CommentService.java#L244) | `ghidra comments set-batch` | **D** |
| [Function][sdk-Function] `.setComment`; [Listing][sdk-Listing] `.setComment` | [`/clear_function_comments`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/CommentService.java#L453) | `ghidra comments clear-function` | **D** |
| [Listing][sdk-Listing] `.getComment`; [Function][sdk-Function] `.getComment` | [`/get_comment`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/CommentService.java#L127) | `ghidra comments inspect` | **D** |
| [Listing][sdk-Listing] `.setComment`; [Function][sdk-Function] `.setComment` | [`/set_comment`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/CommentService.java#L218) | `ghidra comments set` | **D** |

### datatype — 32

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Structure][sdk-Structure] `.replaceAtOffset`; [Structure][sdk-Structure] `.add` | [`/add_struct_field`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1806) | `ghidra types add-struct-field` | **D** |
| [Listing][sdk-Listing]; [SymbolTable][sdk-SymbolTable] | [`/analyze_global_completeness`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L4279) | `ghidra types analyze-global-completeness` | **D/H** |
| [Structure][sdk-Structure]; [DecompInterface][sdk-DecompInterface] | [`/analyze_struct_field_usage`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2479) | `ghidra types analyze-struct-field-usage` | **D** |
| [Listing][sdk-Listing] `.createData`; [DataTypeManager][sdk-DataTypeManager] `.addDataType` | [`/apply_data_classification`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2858) | `ghidra types apply-data-classification` | **D** |
| [Listing][sdk-Listing] `.clearCodeUnits`; [Listing][sdk-Listing] `.createData` | [`/apply_data_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L980) | `ghidra types apply-data-type` | **D** |
| [Listing][sdk-Listing]; [ReferenceManager][sdk-ReferenceManager] | [`/audit_global`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L4069) | `ghidra types audit-global` | **D/H** |
| [Listing][sdk-Listing] `.getInstructions`; [ReferenceManager][sdk-ReferenceManager] `.getReferencesFrom` | [`/audit_globals_in_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L4309) | `ghidra types audit-globals-in-function` | **D/H** |
| [DataType][sdk-DataType] `.clone`; [DataType][sdk-DataType] `.copy` | [`/clone_data_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L737) | `ghidra types clone-data-type` | **F** — Uses copy; nested component types may remain shared. |
| [DataTypeManager][sdk-DataTypeManager] `.createCategory` | [`/create_data_type_category`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2419) | `ghidra types create-data-type-category` | **D** |
| [TypedefDataType][sdk-TypedefDataType]; [ArrayDataType][sdk-ArrayDataType]; [PointerDataType][sdk-PointerDataType] | [`/create_derived_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L794) | `ghidra types create-derived-type` | **D** |
| [EnumDataType][sdk-EnumDataType] `.add` | [`/create_enum`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L558) | `ghidra types create-enum` | **D** |
| [FunctionDefinitionDataType][sdk-FunctionDefinitionDataType] `.setArguments` | [`/create_function_signature`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L872) | `ghidra types create-function-signature` | **D** |
| [StructureDataType][sdk-StructureDataType] `.add` | [`/create_struct`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L393) | `ghidra types create-struct` | **D** — G07: no replace-placeholder flag. |
| [UnionDataType][sdk-UnionDataType] `.add` | [`/create_union`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L655) | `ghidra types create-union` | **D** |
| [DataTypeManager][sdk-DataTypeManager] `.remove` | [`/delete_data_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1169) | `ghidra types delete-data-type` | **D** |
| [DataTypeManager][sdk-DataTypeManager] `.getAllDataTypes` | [`/find_data_types`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L96) | `ghidra types find-data-types` | **F** — Bounded inventory/category scan and typed records. |
| [Enum][sdk-Enum] `.getNames` | [`/get_enum_values`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L287) | `ghidra types get-enum-values` | **D** |
| [Structure][sdk-Structure] `.getDefinedComponents` | [`/get_struct_layout`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L240) | `ghidra types get-struct-layout` | **D** |
| [DataType][sdk-DataType] `.getLength` | [`/get_type_size`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L208) | `ghidra types get-type-size` | **D** |
| MCP hard-coded name lists; actual inventory: [DataTypeManager][sdk-DataTypeManager] `.getAllDataTypes` | [`/get_valid_data_types`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L332) | `ghidra types get-valid-data-types` | **F** — Actual resolvable inventory and provenance; G02 closed. |
| [CParser][sdk-CParser] `.parse` | [`/import_data_types`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2359) | `ghidra types import-data-types` | **D** |
| [Structure][sdk-Structure] `.replaceAtOffset` | [`/modify_struct_field`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1246) | `ghidra types modify-struct-field` | **D** |
| [DataType][sdk-DataType] `.setCategoryPath` | [`/move_data_type_to_category`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2006) | `ghidra types move-data-type-to-category` | **D** |
| [StructureDataType][sdk-StructureDataType]; [DataTypeManager][sdk-DataTypeManager] | [`/recreate_struct`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1457) | `ghidra types recreate-struct` | **D** |
| [Structure][sdk-Structure] `.delete` | [`/remove_struct_field`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1934) | `ghidra types remove-struct-field` | **D** |
| [DataType][sdk-DataType] `.setName` | [`/rename_data_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2070) | `ghidra types rename-data-type` | **D** |
| [Structure][sdk-Structure] `.growStructure` | [`/resize_struct`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1370) | `ghidra types resize-struct` | **D** |
| [DataTypeManager][sdk-DataTypeManager]; [Structure][sdk-Structure] | [`/resolve_duplicate_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L1586) | `ghidra types resolve-duplicate-type` | **D** |
| [Listing][sdk-Listing] `.createData`; [SymbolTable][sdk-SymbolTable] | [`/set_global`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L4394) | `ghidra types set-global` | **D** |
| [Listing][sdk-Listing] `.getDataAt`; [Structure][sdk-Structure] `.getComponents` | [`/suggest_field_names`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2725) | `ghidra types suggest-field-names` | **D/H** |
| [DataTypeManager][sdk-DataTypeManager]; [DataType][sdk-DataType] | [`/validate_data_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2156) | `ghidra types validate-data-type` | **F** — Actual type resolution/layout diagnostics. |
| [Function][sdk-Function] | [`/validate_function_prototype`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DataTypeService.java#L2251) | `ghidra types validate-function-prototype` | **F** — Isolated SDK parser and compiler convention resolution. |

### debugger — 16

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [DebuggerStaticMappingService][sdk-DebuggerStaticMappingService] | [`/debugger/dynamic_to_static`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1235) | `ghidra debugger dynamic-to-static` | **D** |
| [Target][sdk-Target] `.collectActions` | [`/debugger/interrupt`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L793) | `ghidra debugger interrupt` | **D** |
| [TraceRmiLaunchOffer][sdk-TraceRmiLaunchOffer] `.launchProgram` | [`/debugger/launch`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L422) | `ghidra debugger launch` | **D** |
| [TraceRmiLauncherService][sdk-TraceRmiLauncherService] `.getOffers` | [`/debugger/launch_offers`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1289) | `ghidra debugger launch-offers` | **D** |
| [DebuggerLogicalBreakpointService][sdk-DebuggerLogicalBreakpointService] | [`/debugger/list_breakpoints`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L925) | `ghidra debugger list-breakpoints` | **D** |
| [TraceModuleManager][sdk-TraceModuleManager] `.getAllModules` | [`/debugger/modules`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1139) | `ghidra debugger modules` | **D** |
| [TraceMemoryManager][sdk-TraceMemoryManager] `.getBytes`; [Target][sdk-Target] `.readMemory` | [`/debugger/read_memory`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1023) | `ghidra debugger read-memory` | **D** |
| [TraceMemorySpace][sdk-TraceMemorySpace] `.getValue`; [Target][sdk-Target] `.readRegisters` | [`/debugger/registers`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L963) | `ghidra debugger registers` | **D** — Base registers ≤64 bits; not full vector register state. |
| [DebuggerLogicalBreakpointService][sdk-DebuggerLogicalBreakpointService] `.deleteAll` | [`/debugger/remove_breakpoint`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L882) | `ghidra debugger remove-breakpoint` | **D** |
| [Target][sdk-Target] `.collectActions` | [`/debugger/resume`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L770) | `ghidra debugger resume` | **D** |
| [Target][sdk-Target] `.placeBreakpoint` | [`/debugger/set_breakpoint`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L853) | `ghidra debugger set-breakpoint` | **D** |
| [TraceStackManager][sdk-TraceStackManager] | [`/debugger/stack_trace`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1084) | `ghidra debugger stack-trace` | **D** |
| [DebuggerStaticMappingService][sdk-DebuggerStaticMappingService] | [`/debugger/static_to_dynamic`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L1178) | `ghidra debugger static-to-dynamic` | **D** |
| [DebuggerTraceManagerService][sdk-DebuggerTraceManagerService]; [DebuggerTargetService][sdk-DebuggerTargetService] | [`/debugger/status`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L674) | `ghidra debugger status` | **D** |
| [Target][sdk-Target] `.collectActions` | [`/debugger/step`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L815) | `ghidra debugger step` | **D** |
| [DebuggerTraceManagerService][sdk-DebuggerTraceManagerService] `.getOpenTraces` | [`/debugger/traces`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DebuggerService.java#L737) | `ghidra debugger traces` | **D** |

### documentation — 12

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Function][sdk-Function]; [Listing][sdk-Listing]; [HighFunctionDBUtil][sdk-HighFunctionDBUtil] | [`/apply_function_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L475) | `ghidra documentation apply` | **F** — Typed transactional native helper. |
| [Function][sdk-Function]; [DecompInterface][sdk-DecompInterface] | [`/archive_ingest_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L1638) | `ghidra archive ingest-function` | **F** — External exchange, not native analysis. |
| [FunctionManager][sdk-FunctionManager]; [DecompInterface][sdk-DecompInterface] | [`/archive_ingest_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L1690) | `ghidra archive ingest-program` | **F** — External exchange, not native analysis. |
| [Listing][sdk-Listing] `.getDefinedData`; [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo` | [`/batch_string_anchor_report`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L879) | `ghidra documentation batch-string-anchor-report` | **D** |
| [FunctionManager][sdk-FunctionManager]; [Listing][sdk-Listing] | [`/bulk_fuzzy_match`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L1024) | `ghidra documentation bulk-fuzzy-match` | **D/H** |
| [FunctionManager][sdk-FunctionManager] `.getFunctions` | [`/compare_programs_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L745) | `ghidra documentation compare` | **D** |
| [Function][sdk-Function]; [Listing][sdk-Listing] | [`/diff_functions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L1064) | `ghidra functions diff` | **D** |
| [Function][sdk-Function]; [Listing][sdk-Listing] | [`/find_similar_functions_fuzzy`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L979) | `ghidra documentation find-similar-functions-fuzzy` | **D/H** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo`; [FunctionManager][sdk-FunctionManager] | [`/find_undocumented_by_string`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L800) | `ghidra documentation find-undocumented-by-string` | **D/H** |
| [Function][sdk-Function]; [HighFunction][sdk-HighFunction]; [Listing][sdk-Listing] | [`/get_function_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L313) | `ghidra documentation get` | **D** |
| [Function][sdk-Function]; [Listing][sdk-Listing] | [`/get_function_hash`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L65) | `ghidra documentation get-function-hash` | **D** |
| [DataTypeManager][sdk-DataTypeManager]; [FunctionManager][sdk-FunctionManager]; [Listing][sdk-Listing] | [`/merge_program_documentation`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/DocumentationHashService.java#L1126) | `ghidra documentation transfer` | **D** — Documentation transfer, not universal DB merge. |

### emulation — 2

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [EmulatorHelper][sdk-EmulatorHelper] `.run` | [`/emulate_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/EmulationService.java#L78) | `ghidra emulation emulate-function` | **F** — Supported integer-slot ABIs, isolated state and explicit completion. |
| [EmulatorHelper][sdk-EmulatorHelper] `.run` | [`/emulate_hash_batch`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/EmulationService.java#L329) | `ghidra emulation emulate-hash-batch` | **F** — Bounded candidates/instructions; incomplete runs cannot match. |

### function — 23

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Function][sdk-Function] `.addTag` | [`/add_function_tag`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4488) | `ghidra functions add-function-tag` | **D** |
| [Function][sdk-Function] `.setName`; [Variable][sdk-Variable] `.setName` | [`/batch_rename_function_components`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L2904) | `ghidra functions batch-rename-function-components` | **D** |
| [ClearFlowAndRepairCmd][sdk-ClearFlowAndRepairCmd] | [`/clear_flow_and_repair`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L3523) | `ghidra functions clear-flow-and-repair` | **D** |
| [Instruction][sdk-Instruction] `.setFlowOverride` | [`/clear_instruction_flow_override`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L2271) | `ghidra functions clear-instruction-flow-override` | **D** |
| [DisassembleCommand][sdk-DisassembleCommand]; [CreateFunctionCmd][sdk-CreateFunctionCmd] | [`/create_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L3130) | `ghidra functions create` | **D** |
| [FunctionManager][sdk-FunctionManager] `.removeFunction` | [`/delete_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L3042) | `ghidra functions delete` | **D** |
| [FunctionTag][sdk-FunctionTag] `.delete` | [`/delete_function_tag`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4657) | `ghidra functions delete-function-tag` | **D** |
| [DisassembleCommand][sdk-DisassembleCommand] | [`/disassemble_bytes`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L3263) | `ghidra functions disassemble-bytes` | **D** |
| [Listing][sdk-Listing] `.getInstructions` | [`/disassemble_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L476) | `ghidra functions disassemble` | **D** — Read instructions; creation is disassemble-bytes. |
| [DecompInterface][sdk-DecompInterface] `.decompileFunction` | [`/force_decompile`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L365) | `ghidra functions force-decompile` | **D** |
| [Function][sdk-Function]; [DecompInterface][sdk-DecompInterface] | [`/get_functions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionBundleService.java#L60) | `ghidra functions inspect` | **D** |
| [SymbolTable][sdk-SymbolTable]; [Function][sdk-Function] `.getParameters` | [`/list_class_members`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L1929) | `ghidra functions list-class-members` | **D** |
| [FunctionTagManager][sdk-FunctionTagManager] | [`/list_function_tags`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4622) | `ghidra functions list-function-tags` | **D** |
| [Function][sdk-Function] `.removeTag` | [`/remove_function_tag`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4565) | `ghidra functions remove-function-tag` | **D** |
| [Function][sdk-Function] `.setName` | [`/rename_function`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L913) | `ghidra functions rename` | **D** — Address selector; naming strict_mode forced off. |
| [Variable][sdk-Variable] `.setName`; [HighFunctionDBUtil][sdk-HighFunctionDBUtil] | [`/rename_variables`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L3811) | `ghidra functions rename-variables` | **D** |
| [Function][sdk-Function] `.setNoReturn` | [`/set_function_no_return`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L2175) | `ghidra functions set-function-no-return` | **D** |
| [FunctionSignatureParser][sdk-FunctionSignatureParser]; [ApplyFunctionSignatureCmd][sdk-ApplyFunctionSignatureCmd] | [`/set_function_prototype`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L1233) | `ghidra functions set-function-prototype` | **F** — Explicit/default convention and immutable saved signature checks. |
| [FunctionTag][sdk-FunctionTag] `.setComment` | [`/set_function_tag_comment`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4692) | `ghidra functions set-function-tag-comment` | **D** |
| [Function][sdk-Function]; [SymbolTable][sdk-SymbolTable] `.createClass` | [`/set_function_this_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L1747) | `ghidra functions set-function-this-type` | **D** |
| [Variable][sdk-Variable] `.setDataType`; [VariableStorage][sdk-VariableStorage] | [`/set_variable_storage`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L2367) | `ghidra functions set-variable-storage` | **D** |
| [HighFunctionDBUtil][sdk-HighFunctionDBUtil] | [`/set_variable_type`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L1887) | `ghidra functions set-variable-type` | **D** |
| [Function][sdk-Function]; [Variable][sdk-Variable]; [HighFunctionDBUtil][sdk-HighFunctionDBUtil] | [`/set_variables`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/FunctionService.java#L4057) | `ghidra functions set-variables` | **D** |

### getter — 1

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [ProgramLocation][sdk-ProgramLocation]; [ProgramSelection][sdk-ProgramSelection] | [`/get_ui_cursor`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1460) | `ghidra ui cursor` | **D** |

### headless — 3

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Project][sdk-Project] `.close` | [`/close_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/headless/HeadlessManagementService.java#L177) | `ghidra projects close` | **E** |
| [ProjectManager][sdk-ProjectManager] `.createProject` | [`/create_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/headless/HeadlessManagementService.java#L61) | `ghidra projects create` | **E** |
| [ProjectManager][sdk-ProjectManager] `.openProject` | [`/open_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/headless/HeadlessManagementService.java#L131) | `ghidra projects open` | **E** |

### listing — 12

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| Java numeric formatting; no Ghidra SDK dependency | [`/convert_number`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L1153) | `ghidra utility convert-number` | **D** |
| [FunctionManager][sdk-FunctionManager] `.getFunctions` | [`/find_functions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L334) | `ghidra functions search` | **D** |
| [SymbolTable][sdk-SymbolTable] `.getAllSymbols`; [Symbol][sdk-Symbol] `.isExternalEntryPoint` | [`/get_entry_points`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L854) | `ghidra listing get-entry-points` | **F** — Confirmed metadata separated from candidates. |
| [ExternalManager][sdk-ExternalManager] | [`/get_external_location`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L1069) | `ghidra listing get-external-location` | **D** |
| [FunctionManager][sdk-FunctionManager] `.getFunctionCount` | [`/get_function_count`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L546) | `ghidra listing get-function-count` | **D** |
| [CompilerSpec][sdk-CompilerSpec] `.getCallingConventions` | [`/list_calling_conventions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L481) | `ghidra listing list-calling-conventions` | **D** |
| [Listing][sdk-Listing]; [ReferenceManager][sdk-ReferenceManager] | [`/list_data_items_by_xrefs`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L228) | `ghidra listing list-data-items-by-xrefs` | **D** |
| [SymbolTable][sdk-SymbolTable]; [Listing][sdk-Listing]; [ReferenceManager][sdk-ReferenceManager] | [`/list_globals`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L619) | `ghidra listing list-globals` | **F** — Structured records and bounded input scan. |
| [SymbolTable][sdk-SymbolTable]; [Memory][sdk-Memory]; [Listing][sdk-Listing] | [`/list_program_items`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L38) | `ghidra listing list-program-items` | **D** |
| [SymbolTable][sdk-SymbolTable]; [Listing][sdk-Listing] | [`/list_shadowed_globals`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L753) | `ghidra listing list-shadowed-globals` | **D** |
| [Listing][sdk-Listing] `.getDefinedData` | [`/list_strings`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L502) | `ghidra strings list` | **F** — Bounded scan and typed records. |
| [Listing][sdk-Listing] `.getDefinedData` | [`/search_strings`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ListingService.java#L560) | `ghidra strings search-regex` | **F** — Bounded scan, supported regex subset and typed records. |

### malware — 5

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Listing][sdk-Listing] `.getInstructions`; [ReferenceManager][sdk-ReferenceManager] | [`/analyze_api_call_chains`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/MalwareSecurityService.java#L257) | `ghidra analysis analyze-api-call-chains` | **D/H** |
| [Memory][sdk-Memory] `.getBytes` | [`/detect_crypto_constants`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L807) | `ghidra analysis detect-crypto-constants` | **F** — Native versioned exact-table scan; candidate matches with byte/time limits. |
| [FunctionManager][sdk-FunctionManager]; [SymbolTable][sdk-SymbolTable]; [Listing][sdk-Listing] | [`/detect_malware_behaviors`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/MalwareSecurityService.java#L541) | `ghidra analysis detect-malware-behaviors` | **D/H** |
| [Listing][sdk-Listing] `.getDefinedData` | [`/extract_iocs_with_context`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/MalwareSecurityService.java#L444) | `ghidra analysis extract-iocs-with-context` | **D/H** |
| [SymbolTable][sdk-SymbolTable]; [Listing][sdk-Listing] `.getInstructions` | [`/find_anti_analysis_techniques`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/MalwareSecurityService.java#L67) | `ghidra analysis find-anti-analysis-techniques` | **D/H** |

### program — 33

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [AutoAnalysisManager][sdk-AutoAnalysisManager] | [`/analysis_status`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2150) | `ghidra analysis status` | **D** |
| [ProgramManager][sdk-ProgramManager] `.closeProgram` | [`/close_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1061) | `ghidra close` | **E** |
| [Memory][sdk-Memory] `.createInitializedBlock` | [`/create_memory_block`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3146) | `ghidra memory create-block` | **F** — Initial bytes/fill/overlay/uninitialized/comment/volatile; saved digest verification. |
| [PropertyMapManager][sdk-PropertyMapManager] | [`/create_property_map`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L494) | `ghidra program create-property-map` | **D** |
| [BookmarkManager][sdk-BookmarkManager] `.removeBookmark` | [`/delete_bookmark`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3486) | `ghidra program delete-bookmark` | **D** |
| [PropertyMapManager][sdk-PropertyMapManager] `.removePropertyMap` | [`/delete_property_map`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L544) | `ghidra program delete-property-map` | **D** |
| MCP process lifecycle; no single SDK analysis method | [`/exit_ghidra`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ServerLifecycleService.java#L26) | `ghidra close` | **E** — Close selected owned context, not arbitrary shared server exit. |
| [AddressFactory][sdk-AddressFactory] `.getAddressSpaces` | [`/get_address_spaces`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1167) | `ghidra memory spaces` | **D** |
| [Language][sdk-Language]; [CompilerSpec][sdk-CompilerSpec] | [`/get_language_metadata`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/AnalysisService.java#L5006) | `ghidra program get-language-metadata` | **D** |
| [Program][sdk-Program] | [`/get_metadata`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L174) | `ghidra program metadata` | **D** |
| [Program][sdk-Program] `.getOptions`; [Options][sdk-Options] | [`/get_program_options`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L240) | `ghidra program get-program-options` | **D** |
| [PropertyMapManager][sdk-PropertyMapManager] | [`/get_property`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L670) | `ghidra program get-property` | **D** |
| [AutoImporter][sdk-AutoImporter] | [`/import_file`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1985) | `ghidra open` | **E** |
| [BookmarkManager][sdk-BookmarkManager] `.getBookmarksIterator` | [`/list_bookmarks`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3413) | `ghidra program list-bookmarks` | **D** |
| [ProgramManager][sdk-ProgramManager] `.getAllOpenPrograms` | [`/list_open_programs`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1020) | `sessions status` | **E** — Logical contexts, not global native process roster. |
| [DomainFolder][sdk-DomainFolder] `.getFiles` | [`/list_project_files`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1563) | `ghidra projects files` | **D** |
| [PropertyMapManager][sdk-PropertyMapManager] | [`/list_properties`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L760) | `ghidra program list-properties` | **D** |
| [GhidraScriptUtil][sdk-GhidraScriptUtil] | [`/list_scripts`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2711) | `ghidra scripts list` | **F** — Actual inventory replaces GUI instructions. |
| [DomainFile][sdk-DomainFile] `.getDomainObject`; [ProgramManager][sdk-ProgramManager] | [`/open_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1856) | `ghidra open` | **E** |
| [Memory][sdk-Memory] `.getBytes` | [`/read_memory`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2756) | `ghidra memory read` | **D** |
| [AutoAnalysisManager][sdk-AutoAnalysisManager] `.reAnalyzeAll` | [`/reanalyze`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2129) | `ghidra analysis reanalyze` | **D** |
| [Options][sdk-Options] `.removeOption` | [`/remove_program_option`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L418) | `ghidra program remove-program-option` | **D** |
| [PropertyMap][sdk-PropertyMap] `.remove` | [`/remove_property`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L713) | `ghidra program remove-property` | **D** |
| [GhidraScript][sdk-GhidraScript]; [GhidraScriptUtil][sdk-GhidraScriptUtil] | [`/run_ghidra_script`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3554) | `ghidra scripts run` | **D** |
| [GhidraScript][sdk-GhidraScript]; [GhidraScriptProvider][sdk-GhidraScriptProvider] | [`/run_script_inline`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2529) | `ghidra scripts run-inline` | **D** |
| [Program][sdk-Program] `.save` | [`/save_all_programs`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L935) | `ghidra save-all` | **E** |
| [Program][sdk-Program] `.save` | [`/save_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L871) | `ghidra save` | **E** |
| [BookmarkManager][sdk-BookmarkManager] `.setBookmark` | [`/set_bookmark`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3333) | `ghidra program set-bookmark` | **D** |
| [Program][sdk-Program] `.setImageBase` | [`/set_image_base`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3701) | `ghidra program set-image-base` | **D** |
| [MemoryBlock][sdk-MemoryBlock] `.setRead`; [MemoryBlock][sdk-MemoryBlock] `.setWrite` | [`/set_memory_block`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L3053) | `ghidra memory set-block` | **D** |
| [Options][sdk-Options] | [`/set_program_option`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L327) | `ghidra program set-program-option` | **D** |
| [PropertyMapManager][sdk-PropertyMapManager] | [`/set_property`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L588) | `ghidra program set-property` | **D** |
| [ProgramManager][sdk-ProgramManager] `.setCurrentProgram` | [`/switch_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1512) | `ghidra open` | **E** |

### project — 11

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [Project][sdk-Project] | [`/archive_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProjectLifecycleService.java#L146) | `ghidra projects archive` | **D** |
| [DomainFolder][sdk-DomainFolder] `.createFolder` | [`/create_folder`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1615) | `ghidra projects create-folder` | **D** |
| [DomainFile][sdk-DomainFile] `.delete` | [`/delete_file`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1649) | `ghidra projects delete-file` | **D** |
| [ProjectManager][sdk-ProjectManager] `.deleteProject` | [`/delete_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/headless/HeadlessManagementService.java#L113) | `ghidra projects delete` | **D** |
| [DomainFile][sdk-DomainFile] `.packFile`; [DomainObjectAdapterDB][sdk-DomainObjectAdapterDB] `.saveToPackedFile` | [`/export_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProjectLifecycleService.java#L52) | `ghidra program export` | **D** — GZF DB snapshot, not reconstructed EXE. |
| [Project][sdk-Project]; [ProjectData][sdk-ProjectData] | [`/get_project_info`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L2083) | `ghidra projects info` | **D** |
| [DomainFolder][sdk-DomainFolder] `.createFile` | [`/import_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProjectLifecycleService.java#L107) | `ghidra program import` | **D** — GZF into managed project. |
| [ProjectManager][sdk-ProjectManager] | [`/list_projects`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/headless/HeadlessManagementService.java#L93) | `ghidra projects list` | **D** |
| [DomainFile][sdk-DomainFile] `.moveTo` | [`/move_file`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1693) | `ghidra projects move-file` | **D** |
| [DomainFolder][sdk-DomainFolder] `.moveTo` | [`/move_folder`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProgramScriptService.java#L1786) | `ghidra projects move-folder` | **D** |
| [Project][sdk-Project] | [`/restore_project`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ProjectLifecycleService.java#L198) | `ghidra projects restore` | **D** |

### server — 18

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [DomainFile][sdk-DomainFile] `.checkin` | [`/checkin_program`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L41) | `ghidra merge` | **E** — Explicit conflict-aware publication; no raw check-in bypass. |
| [RepositoryAdapter][sdk-RepositoryAdapter] `.setUserList` | [`/server/admin/set_permissions`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L369) | `ghidra server admin set-permissions` | **D** |
| [RepositoryAdapter][sdk-RepositoryAdapter] `.terminateCheckout` | [`/server/admin/terminate_all_checkouts`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L144) | `ghidra server admin terminate-all-checkouts` | **D** |
| [RepositoryAdapter][sdk-RepositoryAdapter] `.terminateCheckout` | [`/server/admin/terminate_checkout`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L123) | `ghidra server admin terminate-checkout` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] `.getAllUsers` | [`/server/admin/users`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L346) | `ghidra server admin users` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] | [`/server/authenticate`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L174) | `auth login` | **E** |
| [DomainFile][sdk-DomainFile] `.getCheckouts`; [RepositoryAdapter][sdk-RepositoryAdapter] | [`/server/checkouts`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L112) | `ghidra server checkouts` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] `.connect` | [`/server/connect`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L156) | `ghidra server connect` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] `.disconnect` | [`/server/disconnect`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L166) | `ghidra server disconnect` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] `.getRepositoryNames` | [`/server/repositories`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L241) | `ghidra server repositories list` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] `.createRepository` | [`/server/repository/create`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L324) | `ghidra server repositories create` | **D** |
| [RepositoryAdapter][sdk-RepositoryAdapter] `.getItem` | [`/server/repository/file`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L293) | `ghidra server repositories file` | **D** |
| [RepositoryAdapter][sdk-RepositoryAdapter] `.getItemList` | [`/server/repository/files`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L258) | `ghidra server repositories files` | **D** |
| [RepositoryServerAdapter][sdk-RepositoryServerAdapter] | [`/server/status`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L205) | `ghidra server status` | **D** |
| [DomainFile][sdk-DomainFile] `.addToVersionControl` | [`/server/version_control/add`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L89) | `ghidra open` | **E** |
| [DomainFile][sdk-DomainFile] `.checkout` | [`/server/version_control/checkout`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L63) | `ghidra open` | **E** |
| [DomainFile][sdk-DomainFile] `.undoCheckout` | [`/server/version_control/undo_checkout`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L76) | `ghidra changes discard` | **E** — Restore own saved base; retain discarded snapshot. |
| [DomainFile][sdk-DomainFile] `.getVersionHistory` | [`/server/version_history`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/VersionControlService.java#L104) | `ghidra server history` | **D** |

### symbol — 4

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [FunctionManager][sdk-FunctionManager]; [SymbolTable][sdk-SymbolTable] | [`/can_rename_at_address`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/SymbolLabelService.java#L1053) | `ghidra symbols can-rename-at-address` | **D** |
| [SymbolTable][sdk-SymbolTable] `.createLabel` | [`/create_label`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/SymbolLabelService.java#L259) | `ghidra symbols create-label` | **D** |
| [Symbol][sdk-Symbol] `.delete` | [`/delete_label`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/SymbolLabelService.java#L526) | `ghidra symbols delete-label` | **D** |
| [Symbol][sdk-Symbol] `.setName` | [`/rename_symbol`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/SymbolLabelService.java#L124) | `ghidra symbols rename-symbol` | **D** |

### system — 1

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| MCP prompt-policy state / GUI interception; no native analysis API | [`/prompt_policy`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/PromptPolicyService.java#L70) | `ghidra ui prompt-policy` | **D** — Scoped policy, GUI-dependent behavior. |

### utility — 5

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| MCP transport liveness; no native analysis API | [`/check_connection`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ManualToolDescriptors.java) | `ghidra status` | **E** |
| MCP runtime/transport metrics; no native analysis API | [`/mcp/health`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ManualToolDescriptors.java) | `ghidra status` | **E** |
| MCP reflection/descriptors; no native analysis API | [`/mcp/schema`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ManualToolDescriptors.java) | `--help` | **E** |
| [GoToService][sdk-GoToService] `.goTo` | [`/tool/goto_address`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/GuiToolService.java#L94) | `ghidra ui goto` | **D** |
| [ToolManager][sdk-ToolManager] `.getRunningTools` | [`/tool/running_tools`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/GuiToolService.java#L52) | `ghidra ui tools` | **D** |

### xref — 8

| A — native API / mechanism | B — pinned MCP | C — insight-cli | Status / difference |
| --- | --- | --- | --- |
| [ReferenceManager][sdk-ReferenceManager] `.addMemoryReference` | [`/add_memory_reference`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L213) | `ghidra xrefs add-memory-reference` | **D** |
| [FunctionManager][sdk-FunctionManager]; [ReferenceManager][sdk-ReferenceManager] | [`/analyze_call_graph`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L860) | `ghidra xrefs analyze-call-graph` | **D** |
| [Listing][sdk-Listing] `.getInstructionAt` | [`/get_assembly_context`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L1264) | `ghidra xrefs get-assembly-context` | **D** |
| [FunctionManager][sdk-FunctionManager]; [ReferenceManager][sdk-ReferenceManager] | [`/get_full_call_graph`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L698) | `ghidra xrefs get-full-call-graph` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesFrom`; [Function][sdk-Function] `.getCallingFunctions` | [`/get_function_call_graph`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L530) | `ghidra xrefs get-function-call-graph` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesFrom` | [`/get_xrefs_from`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L148) | `ghidra xrefs from` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.getReferencesTo` | [`/get_xrefs_to`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L78) | `ghidra xrefs inspect-to` | **D** |
| [ReferenceManager][sdk-ReferenceManager] `.delete` | [`/remove_reference`](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/XrefCallGraphService.java#L290) | `ghidra xrefs remove-reference` | **D** |

## Appendix B — the eight Python bridge controls

These live in [static_tools.py](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/python/bridge_mcp_ghidra/static_tools.py).
Instance/group controls are bridge mechanisms, not missing native Ghidra analysis methods.

| A — native mechanism | B — bridge control | C — equivalent |
| --- | --- | --- |
| No analysis method; process/project inventory | `list_instances` | Root session/target status reports logical owned contexts. |
| Project/program binding primitives | `connect_instance` | Scoped `ghidra open` / continuation selects the owned binding. |
| No native analysis method; schema grouping | `list_tool_groups` | Factory generated group help/discovery. |
| No native analysis method; lazy bridge registration | `load_tool_group` | Functionality discoverable in the installed command tree. |
| No native analysis method; lazy bridge registration | `unload_tool_group` | Internal resource/discovery detail; public commands remain available. |
| No native analysis method; bridge inventory | `check_tools` | Generated help and scoped status/prerequisite checks; nested unavailable payloads fail and the two known stubs have native facade replacements. |
| No native analysis method; bridge schema search | `search_tools` | Factory command help/discovery; no promise of an identically shaped bridge search endpoint. |
| Importer/project APIs | `import_file` | `ghidra open` consumes an immutable input and establishes an isolated context; overlaps REST import. |

## Maintaining this comparison

When changing the pinned runtime, compare the actual catalog, annotations/manual registrations,
handler bodies and Python bridge controls, then join against the actual Factory command tree.
Retain separate counts for mapped operations, implemented semantics and dedicated native features.
Do not infer semantics from endpoint names, access hints or an HTTP 200 response.

The current 210 rows were checked against `verification/coverage-evidence.json` and pinned source;
all native type links resolve to files in the 12.1.2 source distribution. The existing
`npm run test:coverage` checks the command mappings. Changes to this document alone do not rerun
or extend the combined native acceptance, and do not authorize npm publication.

### Native source references

[sdk-AddressFactory]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/AddressFactory.java
[sdk-AddressSet]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/AddressSet.java
[sdk-ApplyFunctionSignatureCmd]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/ApplyFunctionSignatureCmd.java
[sdk-ArrayDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/ArrayDataType.java
[sdk-Assembler]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/assembler/Assembler.java
[sdk-AutoAnalysisManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java
[sdk-AutoImporter]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/importer/AutoImporter.java
[sdk-BSimClientFactory]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/BSimClientFactory.java
[sdk-BasicBlockModel]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/block/BasicBlockModel.java
[sdk-BookmarkManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/BookmarkManager.java
[sdk-CParser]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/cparser/C/CParser.java
[sdk-ClearFlowAndRepairCmd]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/clear/ClearFlowAndRepairCmd.java
[sdk-CompilerSpec]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/CompilerSpec.java
[sdk-CreateFunctionCmd]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/CreateFunctionCmd.java
[sdk-DataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataType.java
[sdk-DataTypeManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataTypeManager.java
[sdk-DebuggerLogicalBreakpointService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/app/services/DebuggerLogicalBreakpointService.java
[sdk-DebuggerStaticMappingService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/app/services/DebuggerStaticMappingService.java
[sdk-DebuggerTargetService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/app/services/DebuggerTargetService.java
[sdk-DebuggerTraceManagerService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/app/services/DebuggerTraceManagerService.java
[sdk-DecompInterface]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompInterface.java
[sdk-DisassembleCommand]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/disassemble/DisassembleCommand.java
[sdk-DomainFile]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/DomainFile.java
[sdk-DomainFolder]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/DomainFolder.java
[sdk-DomainObjectAdapterDB]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/data/DomainObjectAdapterDB.java
[sdk-EmulatorHelper]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Emulation/src/main/java/ghidra/app/emulator/EmulatorHelper.java
[sdk-Enum]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/Enum.java
[sdk-EnumDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/EnumDataType.java
[sdk-Exporter]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/Exporter.java
[sdk-ExternalManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/ExternalManager.java
[sdk-FidService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/service/FidService.java
[sdk-FlatProgramAPI]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/program/flatapi/FlatProgramAPI.java
[sdk-Function]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Function.java
[sdk-FunctionDatabase]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/FunctionDatabase.java
[sdk-FunctionDefinitionDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/FunctionDefinitionDataType.java
[sdk-FunctionManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/FunctionManager.java
[sdk-FunctionSignatureParser]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/parser/FunctionSignatureParser.java
[sdk-FunctionTag]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/FunctionTag.java
[sdk-FunctionTagManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/FunctionTagManager.java
[sdk-GenericAssembler]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/assembler/GenericAssembler.java
[sdk-GhidraScript]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java
[sdk-GhidraScriptProvider]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScriptProvider.java
[sdk-GhidraScriptUtil]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScriptUtil.java
[sdk-GoToService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/services/GoToService.java
[sdk-HighFunction]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/HighFunction.java
[sdk-HighFunctionDBUtil]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/HighFunctionDBUtil.java
[sdk-Instruction]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Instruction.java
[sdk-Language]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/Language.java
[sdk-Listing]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Listing.java
[sdk-Memory]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/Memory.java
[sdk-MemoryBlock]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/MemoryBlock.java
[sdk-Options]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Gui/src/main/java/ghidra/framework/options/Options.java
[sdk-PcodeEmulator]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Emulation/src/main/java/ghidra/pcode/emu/PcodeEmulator.java
[sdk-PcodeOpAST]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/PcodeOpAST.java
[sdk-PointerDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/PointerDataType.java
[sdk-Program]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Program.java
[sdk-ProgramContext]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/ProgramContext.java
[sdk-ProgramDiff]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/program/util/ProgramDiff.java
[sdk-ProgramLocation]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/util/ProgramLocation.java
[sdk-ProgramManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/services/ProgramManager.java
[sdk-ProgramMergeManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/program/util/ProgramMergeManager.java
[sdk-ProgramMultiUserMergeManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/merge/ProgramMultiUserMergeManager.java
[sdk-ProgramSelection]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/Base/src/main/java/ghidra/program/util/ProgramSelection.java
[sdk-Project]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/Project.java
[sdk-ProjectData]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/ProjectData.java
[sdk-ProjectManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/ProjectManager.java
[sdk-PropertyMap]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/util/PropertyMap.java
[sdk-PropertyMapManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/util/PropertyMapManager.java
[sdk-ReferenceManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/ReferenceManager.java
[sdk-RepositoryAdapter]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/client/RepositoryAdapter.java
[sdk-RepositoryServerAdapter]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/client/RepositoryServerAdapter.java
[sdk-SleighLanguage]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighLanguage.java
[sdk-Structure]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/Structure.java
[sdk-StructureDB]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/StructureDB.java
[sdk-StructureDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/StructureDataType.java
[sdk-Symbol]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/Symbol.java
[sdk-SymbolTable]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/SymbolTable.java
[sdk-Target]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/debug/api/target/Target.java
[sdk-ToolManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Project/src/main/java/ghidra/framework/model/ToolManager.java
[sdk-Trace]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/Trace.java
[sdk-TraceMemoryManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/memory/TraceMemoryManager.java
[sdk-TraceMemorySpace]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/memory/TraceMemorySpace.java
[sdk-TraceModuleManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/modules/TraceModuleManager.java
[sdk-TraceRmiLaunchOffer]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/debug/api/tracermi/TraceRmiLaunchOffer.java
[sdk-TraceRmiLauncherService]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Debugger-api/src/main/java/ghidra/app/services/TraceRmiLauncherService.java
[sdk-TraceSchedule]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/time/schedule/TraceSchedule.java
[sdk-TraceStackManager]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/stack/TraceStackManager.java
[sdk-TypedefDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/TypedefDataType.java
[sdk-UnionDataType]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/UnionDataType.java
[sdk-VTSession]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/main/VTSession.java
[sdk-Variable]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Variable.java
[sdk-VariableStorage]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/VariableStorage.java

[sdk-GhidraApplicationLayout]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Utility/src/main/java/ghidra/GhidraApplicationLayout.java
[sdk-ExtensionUtils]: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.2_build/Ghidra/Framework/Generic/src/main/java/ghidra/util/extensions/ExtensionUtils.java
