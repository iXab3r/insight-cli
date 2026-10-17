# Agent toolbox: delivery plan

Status: full delivery authorized and implementation started on 2026-10-17. TB-01 audit is in progress; the shared Factory local-discovery/access fixes are merged and pinned; 7-Zip has native CLI and independently reviewed cold/prepared agent proof on a frozen package; LLVM native/Gherkin and reviewed medium-reasoning cold/prepared unit proofs passed; low-reasoning semantic failures remain recorded. Combined full-toolbox acceptance remains open. The owner selected the product direction:
insight-cli supplies a toolbox with a discoverable skill for each analytical tool. The
runtime-only delivery and two successful worker workflows do not establish toolbox readiness.
The current [inventory audit](TOOLBOX-AUDIT.md) records pinned candidates, delivery exceptions and unresolved feasibility checks.

Execution tracker: [epic #23](https://github.com/iXab3r/insight-cli/issues/23), with nine native stage sub-issues
and 22 tool/capability sub-issues under TB-07. All remain open; completion requires the evidence below.

## Outcome and scope

A newly connected agent receives the toolbox entry point and a business question. It can
identify the available analytical capabilities before their binaries are installed, load the
relevant tool skill, prepare its runtime, research the input and retain a checkable result.
The agent still supplies the intelligence and may use external tools directly. Existing
project RE instructions, evidence formats and source-of-truth choices retain precedence.

The owner explicitly selected the entire previously discussed tool set, its skills and agent
acceptance, rather than an initial two-tool toolbox layer. The earlier candidate list was
recovered from the 2026-10-16 discussion (research-tool selection turn), including its library
and cross-tool capability candidates; it had not been recorded in the runtime epic. The finite
inventory below now preserves that scope. Implementation proceeds one work item/tool at a
time, using the existing shared runtime. No tool is silently dropped because it was outside
the previous TR-01–TR-10 implementation.

Current verified inventory:

| Item | Current state | Role in toolbox |
| --- | --- | --- |
| Ghidra | Runtime/API implemented; selected installed-tool agent workflow passed | Analytical tool with its own skill and complete new toolbox gate still required |
| ILSpy | Runtime/API implemented; selected installed-tool agent workflow passed | Analytical tool with its own skill and complete new toolbox gate still required |
| artifacts | File/folder save implemented | Supporting application with concise workflow guidance; no artificial download/install lifecycle |
| Ghidra Server/headless/GUI/debugger roles | Managed within Ghidra | Explicit capabilities/lifecycle under Ghidra; list separately only when independently useful to the agent |
| JDK/.NET runtime | Managed dependencies | Delivered by the consuming tool; not advertised as independently accepted analytical tools |
| 7-Zip | Public CLI adapter, dedicated skill, native Gherkin and independent cold/prepared host trials passed for the recorded package | Container inventory, integrity and bounded ordinary-file recovery |
| LLVM utilities | Adapter/skill and pinned four-utility distribution implemented; native/Gherkin and reviewed cold/prepared medium-reasoning unit gates passed on the recorded package | Headers, linkage, symbols, instruction windows and PDB records |
| .NET dump / stack / trace | Three adapters and dedicated skills implemented; combined native CLI/Gherkin passed; dump cold/prepared agent proof reviewed; stack interrupted by model-account limit and trace agent gates pending | Managed snapshot objects, live waiting stacks and bounded EventPipe thread-time research |
| Detect It Easy | Console adapter/skill, private Qt/database and source/notices bundle; native CLI/Gherkin passed; independent agent gate pending | Header and compiler/runtime/packer triage with explicit partial scan results |
| LLDB | Owned-launch adapter/skill and pinned debugger/library/debugserver distribution; native snapshots and lifetime fault proof passed; independent model gate pending | Breakpoint arguments/returns, registers, memory and backtrace with kernel deadline after owner loss |
| Frida | Modules/exports and script-observation adapter/skill; official Node binding/runtime closure and full source/notices mirror; native CLI/collector and helper fault proof passed on the recorded candidate; independent model gate pending | Runtime argument/result corroboration while preserving the external target lifetime |
| Additional tool candidates | Recovered into the complete inventory below | All included in this planned delivery; none are claimed implemented |

The owner chose explicit tool-specific applicability, not a cross-platform expansion project.
Each catalog/skill row declares where that tool and capability work and returns a clear
unsupported result elsewhere. Do not make every tool run on every OS, add emulation, or create
a complete tool-by-all-OS test matrix. Native proof runs in an appropriate environment for that
tool; an unavailable environment leaves the row unverified, never implicitly passed. Codex is
the first actual agent-host gate, not the universal definition of an agent.

## Complete tool and capability inventory

This is the recovered earlier list, now included by the owner's full-scope answer. Each row
is a concrete child work item, not an interchangeable example. Versions, precise platform
support and redistribution paths are verified at TB-01 before recipes are pinned.

| Child | Tool/family | Planned native proof environment | Research outcome required for its own skill and agent acceptance |
| --- | --- | --- | --- |
| [TB-T01](https://github.com/iXab3r/insight-cli/issues/33) | Ghidra | macOS; exact prerequisites checked at TB-01 | Independent native research, useful edits, merge/refresh and conflicts; cover advertised static, server/context and debugger workflow families explicitly |
| [TB-T02](https://github.com/iXab3r/insight-cli/issues/34) | ILSpy / ilspycmd | macOS; exact prerequisites checked at TB-01 | C#/IL inspection, types/members, resources and project recovery; choose native analysis for NativeAOT rather than promise C# recovery |
| [TB-T03](https://github.com/iXab3r/insight-cli/issues/35) | Detect It Easy / diec | macOS; exact prerequisites checked at TB-01 | Classify input/architecture and compiler/packer evidence to choose a useful next analytical tool; retain uncertainty |
| [TB-T04](https://github.com/iXab3r/insight-cli/issues/36) | LLVM utilities | macOS; exact prerequisites checked at TB-01 | Headers/sections/imports/exports/symbols, focused disassembly and PDB queries; inventory readobj/objdump/nm/pdbutil separately inside this family |
| [TB-T05](https://github.com/iXab3r/insight-cli/issues/37) | 7-Zip | macOS; exact prerequisites checked at TB-01 | Inventory/extract supported containers, identify recovered DLL/configuration inputs and hand them to another tool |
| [TB-T06](https://github.com/iXab3r/insight-cli/issues/38) | dotnet-dump + SOS | macOS; exact prerequisites checked at TB-01 | Capture/analyze an owned managed fixture dump and answer a concrete stack/object question with matching runtime support |
| [TB-T07](https://github.com/iXab3r/insight-cli/issues/39) | dotnet-stack | macOS; exact prerequisites checked at TB-01 | Obtain actual threads/stacks from an owned managed process and identify the active/waiting work |
| [TB-T08](https://github.com/iXab3r/insight-cli/issues/40) | dotnet-trace | macOS; exact prerequisites checked at TB-01 | Collect/read a bounded trace and identify a concrete execution/event finding, preserving collection conditions |
| [TB-T09](https://github.com/iXab3r/insight-cli/issues/41) | Frida | macOS; exact prerequisites checked at TB-01 | Observe arguments/results at a selected native call on an owned fixture and distinguish observed execution from static inference |
| [TB-T10](https://github.com/iXab3r/insight-cli/issues/42) | LLDB | macOS; exact prerequisites checked at TB-01 | Break/inspect registers, memory and stack on an owned native fixture; account for existing Ghidra debugger capabilities and host requirements |
| [TB-T11](https://github.com/iXab3r/insight-cli/issues/43) | WinDbg | Windows | Useful Windows native/dump debugging through an actually automatable supported surface; prepare and test it on Windows |
| [TB-T12](https://github.com/iXab3r/insight-cli/issues/44) | Process Monitor | Windows | Determine which configuration/file/registry/process action an owned Windows fixture performs from a scoped real capture |
| [TB-T13](https://github.com/iXab3r/insight-cli/issues/45) | strace | Linux | Determine real file/process/syscall behavior of an owned Linux fixture; do not claim equivalence to ProcMon's Windows capabilities |
| [TB-T14](https://github.com/iXab3r/insight-cli/issues/46) | dnSpyEx | Windows | Managed debug/edit workflow without source on Windows; prove an actual controllable workflow, not just GUI installation/launch |
| [TB-T15](https://github.com/iXab3r/insight-cli/issues/47) | TShark | macOS; exact prerequisites checked at TB-01 | Answer a protocol question from an owned capture with inspectable packet/field evidence |
| [TB-T16](https://github.com/iXab3r/insight-cli/issues/48) | mitmproxy | macOS; exact prerequisites checked at TB-01 | Observe and compare bounded test HTTP exchanges on an owned local service; make capture/certificate prerequisites explicit |

The earlier three library candidates remain implementation dependencies behind our own APIs,
not standalone applications the agent must install or learn. Their user-facing capabilities
receive the same skill/routing/output and independent acceptance requirements:

| Child | Capability and likely existing-library substrate | Required result |
| --- | --- | --- |
| [TB-C01](https://github.com/iXab3r/insight-cli/issues/49) | Managed metadata/IL queries and assembly comparison; dnlib | Compare two fixture versions and identify actual changed methods, signatures/IL or P/Invoke metadata with bounded drilldown |
| [TB-C02](https://github.com/iXab3r/insight-cli/issues/50) | Programmable managed heap/dump queries; ClrMD | Find a known object/field/stack fact in a real compatible dump; report DAC/runtime/platform limitations |
| [TB-C03](https://github.com/iXab3r/insight-cli/issues/51) | Structured PE/ELF/Mach-O queries and selected copy-only edits; LIEF | Inspect binary structure and verify a declared edit on a new copy without changing the original |
| [TB-C04](https://github.com/iXab3r/insight-cli/issues/52) | Managed-to-native linkage | Trace a P/Invoke declaration to a concrete export/native function across metadata, binary tools and Ghidra; keep static correspondence distinct from observed invocation |
| [TB-C05](https://github.com/iXab3r/insight-cli/issues/53) | Repeatable process capture/comparison | Record inputs, output, exit state and declared file changes from bounded owned-fixture runs; compare results without an arbitrary new shell gateway |
| [TB-C06](https://github.com/iXab3r/insight-cli/issues/54) | Overview then drilldown | Every relevant application provides bounded overviews and focused follow-up without forcing complete decompilation/output into agent context |

C01–C03 cover the recovered library candidates; C01/C04–C06 also preserve the earlier REA-inspired
assembly comparison, interop, process-capture and bounded-output ideas. Concrete new namespace
names are chosen at TB-02. Use existing `insight-cli <application> ...` namespaces rather than
adding executables. Libraries do not need fake download commands or fake shared merges.

Source entry points for the early platform/automation audit include
[dnSpyEx's debugger/editor and scripting API](https://github.com/dnSpyEx/dnSpy),
[Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon),
[WinDbg installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/),
[ClrMD](https://github.com/microsoft/clrmd) and
[REA managed workflows](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md).
The proof environment column selects a useful native gate, not a promise of upstream
portability or an already passing test. If an exact release/capability is unavailable in that
environment, record and use its supported environment without broadening the whole project.
Windows GUI/kernel-dependent tooling requires a suitable actual environment; a generic hosted
runner is not assumed to provide it. TB-01 verifies this before that tool is implemented.

These sources inform investigation; they do not establish that our adapters or redistribution
rights are already verified. Check exact distribution terms, prerequisites and automation before
promising a mirror or admitting a platform. ProcMon uses the owner-selected exception: explicit Microsoft download, local cache and pinned
SHA256. WinDbg has the same verified redistribution restriction and uses a separate explicit
Microsoft delivery policy. If another source cannot be mirrored, record that obstacle
and decide a permitted delivery path explicitly; never silently fall back to arbitrary upstream.

## Agreed design direction

### Skills and admission contract

* `insight-cli`: short toolbox entry point, capability selection and routing.
* `insight-re`: research process, independent agents, ordinary materials, review and handoff.
* `insight-<tool>`: each analytical tool's applicability, preparation and useful workflows.
* Supporting applications such as artifacts receive guidance appropriate to their actual
  behavior; a runtime dependency does not automatically need an analytical skill.

Each tool skill explains when to choose the tool, supported inputs/tasks, installation and
readiness checks, download/local-archive/external-executable paths, representative workflows,
outputs and continuation, applicable cleanup and observed limitations. Generated help remains
the syntax authority. Details load progressively; agents do not receive every manual at startup.

All declared tool skills ship with the CLI before their runtimes are downloaded. A connected
agent can discover their task descriptions even when none of the tool binaries are installed. Tool admission
requires an adapter, current packaged skill, capability metadata and an agent evaluation case.
Build/release checks reject missing mappings or resources. Keep one canonical metadata source;
existing artifact/hash catalogs continue to describe distribution bytes, not research choices.

### Catalog and proposed CLI surface

The foundation candidate now implements these commands; whole-toolbox acceptance is still pending:

```text
insight-cli tools list --json
insight-cli tools show <tool> --json
insight-cli skill insight-<tool> --json
```

Keep existing `insight-cli skill`, `skill insight-re`, per-tool lifecycle and `tools processes`
compatible. The catalog describes purpose, relevant tasks/inputs, command namespace, skill
locator, declared platform support and dependencies. It distinguishes selectable analytical
capabilities, supporting applications and runtime components. Do not label planned adapters as
usable. Read-only catalog/skill discovery must work without a native installation, configured
profile, credentials, downloads or a running IPC owner. Profile readiness remains explicit via
the selected tool's status; an inaccessible profile means unknown, not not-installed.

### Packaging and host connection

Each registered skill must retain working references when installed or relocated independently.
Remove dependence on fragile `../../` paths crossing another skill directory. Shared authoring
sources may feed deterministic package resources; do not maintain diverging manual copies.
Preserve existing locators while moving Ghidra instructions out of the generic entry point.

The release versioner currently enumerates only the two original skills in
`scripts/release-version.mjs`. TB-04 must derive the full packaged skill set from the admitted
inventory, and TB-09 must verify that manual release previews and idempotent reruns keep the
CLI and every shipped skill on the same selected version. Adding files without changing this
release path would leave later tool skills stale.

Provide one explicit connection of the toolbox bundle to the supported host, with update and
removal semantics scoped to owned entries. New admitted tool skills must become discoverable
without a bespoke user procedure for each tool. npm installation does not silently edit agent
settings. The selected mechanism is one explicit project-local link to the deterministic `skill-bundle`,
whose path comes from `skill --json`. A stable global npm prefix carries upgrades; disconnect
removes only that owned link. This avoids a second host configuration store or per-tool installers. Verify actual startup metadata and implicit routing.

Factory owns generic help/discovery/bootstrap and IPC behavior. Its open
[skill policy issue #29](https://github.com/iXab3r/EyeAuras.CliFactory/issues/29) already owns the
shared registration/distribution direction. Product-specific tool metadata and workflows stay
here. A needed shared mechanism or IPC diagnostic fix goes into Factory with regression tests;
insight-cli consumes a prepared version. Do not add a product-specific replacement host.

Host connection and execution access are separate acceptance steps. Make the assigned profile,
required storage and local IPC access explicit. An IPC denial must not masquerade as a reason
to stop another agent's owner. Grant no broad network access just to reach a local socket.

## Ordered work hierarchy

TB-01 is in progress. Required discovery/skill foundation work for TB-02–TB-05 is in draft PR #55;
no phase exit is claimed. TB-06–TB-09 remain pending their gates. The owner selected full inventory
scope and tool-specific applicability. Preliminary metadata and vendor probes do not complete
the audit or the tool delivery.

| ID | Deliverable | Depends on | Acceptance / exit condition |
| --- | --- | --- | --- |
| [TB-01](https://github.com/iXab3r/insight-cli/issues/24) | Audit the recovered full inventory TB-T01–T16 / TB-C01–C06; freeze versions, automation surfaces, platforms, licensing and delivery | — | All listed tools/capabilities have concrete tasks and feasible distribution/host plans; dependencies are not counted as tools; no implicit scope reduction |
| [TB-02](https://github.com/iXab3r/insight-cli/issues/25) | Record toolbox/skill admission, catalog and explicit host-connection contracts; resolve Factory ownership/dependencies | [TB-01](https://github.com/iXab3r/insight-cli/issues/24) | One versioned design, stable existing locators, one selected connection mechanism, specified update/remove behavior and concrete access prerequisites |
| [TB-03](https://github.com/iXab3r/insight-cli/issues/26) | Add capability registry and side-effect-free catalog/skill discovery | [TB-02](https://github.com/iXab3r/insight-cli/issues/25) | Fresh CLI lists capabilities and resolves skills without profile/auth/runtime/IPC; missing adapter/skill/resource links fail admission checks |
| [TB-04](https://github.com/iXab3r/insight-cli/issues/27) | Package self-contained entry-point, RE, Ghidra, ILSpy and supporting artifact guidance | [TB-03](https://github.com/iXab3r/insight-cli/issues/26) | Existing tools have task selection, preparation, workflows and output rules; isolated local/global/relocated installs preserve all references |
| [TB-05](https://github.com/iXab3r/insight-cli/issues/28) | Deliver and verify host connection plus scoped runtime/IPC execution; improve misleading diagnostics at their owner | TB-02, TB-04 | A new real Codex session sees the intended skills and completes a small public-CLI operation with intended access; no manual skill path/CLI name hints, shared-owner shutdown or broad network workaround |
| [TB-06](https://github.com/iXab3r/insight-cli/issues/29) | Add repeatable Gherkin/Automation toolbox and per-tool business acceptance, plus isolated-agent runner/scorer | TB-02; runs against TB-03 onward | Public installed CLI only, raw observed commands/outcomes, hidden oracle, finite deadline and owned cleanup; no injected solution; failures/fallbacks remain explicit |
| [TB-07](https://github.com/iXab3r/insight-cli/issues/30) | Deliver every TB-T01–T16 tool/family and TB-C01–C06 capability as complete adapter+distribution+skill+evaluation units | TB-01, TB-03, TB-05, TB-06 | Each child passes its own cold/prepared workflow gate before it is counted; unsupported or blocked rows stay visibly incomplete, not silently deferred |
| [TB-08](https://github.com/iXab3r/insight-cli/issues/31) | Run combined exact-artifact delivery gate across the entire admitted inventory and cross-tool workflows | TB-04–TB-07 | Every inventory row passes on the delivered package; cold and prepared runs separate; real multi-agent Ghidra merge is independently read back |
| [TB-09](https://github.com/iXab3r/insight-cli/issues/32) | Update author guide, coverage/evidence and release readiness | [TB-08](https://github.com/iXab3r/insight-cli/issues/31) | New-tool recipe requires skill/evaluation; no private artifacts in Git; source/package/skills/input identities recorded; selected release path verified |

TB-06's runner/protocol is designed early so TB-04/TB-07 do not invent a different proof for
each tool. Implement the items sequentially; begin the next only after affected checks pass.
Do not wait until the end to discover that a tool's skill cannot perform its advertised task.

For each additional tool, TB-07 expands into these concrete child tasks:

1. Verify applicable platform, license/redistribution, pinned executable/runtime inputs and
   exact supported task. Decide admission on evidence rather than presumed vendor support.
2. Prepare immutable mirrored assets and required notices/sources with the existing release
   workflow; verify download hashes and offline/local/external paths as applicable.
3. Add the minimal shared-runtime adapter, target association, ordinary outputs and owned process
   behavior needed by the task. Do not force stateless tools into Ghidra contexts/merge.
4. Add the tool skill and registry entry in the same change; verify packed resources and links.
5. Run deterministic CLI checks and independent blind agent cold/prepared tasks with actual
   inputs. Retain exact receipts and gaps; complete the child only after its acceptance passes.

## Acceptance matrix

### Per analytical tool

| Case | Agent receives | Required observation |
| --- | --- | --- |
| Cold runtime | Connected toolbox, business question, raw input, assigned profile and preauthorized normal actions | Chooses a suitable skill, notices missing runtime, installs declared dependencies, answers from actual tool output and saves useful evidence |
| Prepared runtime | Same question/input contract, tool already installed | Discovers and uses the existing installation without redundant download/setup; produces correct findings |
| Explicit alternate path | Local archive or external executable according to the tool's supported contract | Chooses documented setup, verifies readiness, completes a real task and preserves external files |
| Interrupted/unavailable operation | Specific controlled failure relevant to this tool | Reports actual state, retains useful work, resumes where supported and does not invent output or blindly replay effects |
| Host skill/package upgrade | New installed package plus previously connected toolbox | Current skills/resources are discovered consistently; stale versions and dangling references are detected; unrelated host entries are preserved |

For each advertised workflow family in a skill, record the actual task, commands/results and
acceptance coverage. A single successful decompile does not validate all Ghidra operations,
all LLVM utilities or all runtime-diagnostics workflows. Reuse existing deterministic suites
as regression support on the new artifact; older receipts do not validate a new skill package.

During blind agent trials the evaluator does not provide the tool name, skill path, commands,
addresses or expected findings. The task requires the selected capability, but an appropriate
authorised alternative is not called a research failure. It does not prove the intended adapter
was used, so record it separately from that adapter's passing gate. Remediation may adjust skill
routing or adapter behavior; repeat with a fresh agent and preferably a held-out task/input.

Deterministic Gherkin tests may call named CLI commands: they prove product behavior, not the
agent's ability to choose tools. Label these layers separately. Offline CI verifies contracts,
packaging and synthetic error boundaries; native/agent evaluations are opt-in, bounded and retain
actual transcripts. Never replace real native proof with a mocked passing agent answer.

### Combined workflows

* Managed and native inputs: choose appropriate tools for decompilation, native behavior and
  supporting format/resource work; associate outputs with exact immutable inputs.
* Several tools on the same target: reuse its identity without creating unnecessary Ghidra state.
* Two agents on one EXE: independent Ghidra contexts, useful annotations, explicit merge/refresh,
  conflict retention and independent fresh-context verification.
* External-tool output plus artifacts: preserve project evidence conventions and ordinary files;
  no adapter requirement or imposed evidence schema for an external utility.
* Resume after process/tool failure: preserve private work and journals, inspect actual state and
  do not blindly repeat publication or scripts. Never stop a shared owner to mask IPC denial.
* Host/access failure: skill selection can pass while execution fails; the combined workflow
  remains failed until the intended facade and saved result work in the real host.

Minimum per-tool evidence is one complete cold-runtime trial and one complete prepared-runtime
trial on a representative real input. This is a smoke acceptance floor, not a statistical model
reliability claim. Freeze model, permissions, prompts, inputs and scoring before each measured
series; retain initial failures and all retries. Use held-out inputs for at least the combined
verification to avoid accepting a skill tailored to one visible fixture.

Useful-work correctness, intended public-tool execution, saved evidence and required cleanup
must all pass. Report trial counts, first-attempt completion, wrong commands/tool choices,
external fallback, human interventions and time by setup/research/save/merge/verification.
Cold setup time is separate from prepared work. This delivery does not claim a new multi-agent
speedup from the existence of a toolbox; any new acceleration claim needs a separate fixed-task
paired experiment with useful results and merge verification.

## Definition of done and resolved owner choices

The toolbox is complete only when **every admitted analytical tool** has its adapter,
mirrored/otherwise explicitly supported delivery, discoverable versioned skill and passing
cold/prepared agent evidence, and the combined real-host workflow passes on the exact delivered
package. No `SKILL.md exists`, `--help passed`, two-tool sample or externally completed fallback
can substitute for the whole inventory's acceptance.

The owner selected all TB-T01–T16 tools/families and recovered library/workflow capabilities,
including skills and agent acceptance. Applicability is tool-specific; universal OS support is
not a goal. Do not defer a required native proof and still claim that tool accepted. Environment
availability and redistribution/automation feasibility are concrete TB-01 engineering checks;
report an actual blocker rather than inventing support or silently removing a tool.
Host mechanics, reference packaging, admission checks, test bindings and scoped IPC diagnostics
are engineering tasks within the selected direction. Publishing a new npm version remains a
separate release action, not implied by planning.

Native delivery checkpoint: LLDB and Frida have managed runtimes, public facades,
packaged guidance and real macOS fault/CLI proof. WinDbg now has a Windows x64
read-only dump facade and native Gherkin proof; strace has a source-built mirrored
Linux x64 runtime and native Gherkin proof. Exact artifacts and limitations are in
`verification/toolbox-{lldb,frida,windbg,strace,procmon}.json`. Windows common Job Object
lifetime also passed real completion, timeout, kill, owner-loss and overflow cases.
These checkpoints do not close independent agent or combined full-inventory gates.
ProcMon now has a vendor-direct lifecycle, scoped observe/retained inspect facade,
private HKCU, packaged skill and public Windows Gherkin proof, including stop/kill,
external drift and preserved original process/settings. dnSpyEx debug/edit, TShark,
mitmproxy and the six capability units remain in the ordered implementation list. Account inference quota only
defers the independent model gates.
