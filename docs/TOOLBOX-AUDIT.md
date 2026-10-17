# Toolbox inventory and delivery audit

Audit date: 2026-10-17. TB-01 is in progress. These are frozen upstream candidates,
not full toolbox delivery or agent acceptance. 7-Zip now has a working adapter/skill and
passed its isolated globally installed public CLI developer proof and independently reviewed
cold/prepared business trials on the frozen package recorded in
[host evidence](verification/toolbox-agent-host.json). This does not pass the remaining tools
or the combined full-toolbox gate. Existing Ghidra/ILSpy runtime acceptance
remains separately identified in [tool runtime acceptance](TOOL-RUNTIME-ACCEPTANCE.md).
The [toolbox plan](TOOLBOX-PLAN.md) owns the complete inventory and required native/agent gates.

## Inventory

The native proof host is deliberately tool-specific. A Windows-only capability is described as
such; failure to run it on macOS is not a reason to invent an equivalent capability or drop it.
Versions below were inspected at their primary release/package sources. A version is admitted
only after its archive, dependency closure, license companions and real workflow pass.

| Child | Frozen candidate / primary source | Agent surface and dependency closure | Delivery and remaining admission check |
| --- | --- | --- | --- |
| T01 | [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build), GhidraMCP 7.0.0, Temurin 21.0.11+10 | Existing facade: isolated static contexts, server, GUI and debugger; bundled JDK/native/bridge | Existing immutable release recipes and licenses; new dedicated skill and whole-toolbox agent gates required |
| T02 | [ILSpy 11.1.0.9782](https://www.nuget.org/packages/ilspycmd/11.1.0.9782), .NET 10.0.13 | Existing facade: types/C#/IL/resources/project; private runtime | Existing immutable release recipes and MIT/dependency companions; new dedicated skill and toolbox agent gates required |
| T03 | [DiE 3.21](https://github.com/horsicq/DIE-engine/releases/tag/3.21) | `diec` console, signature database, Qt frameworks; macOS ARM64 package can be extracted without installer execution | MIT engine plus Qt and dependency terms; derive console bundle preserving dependency closure and matching source/notices. Real PE probe found mixed JSON/diagnostics; see below |
| T04 | [LLVM 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | readobj/objdump/nm/pdbutil, no non-system dylibs; macOS 14+ ARM64 | Derived 23 MB subset retains exact executables, full matching license and source companions. Real CLI/Gherkin and reviewed medium-reasoning cold/prepared business trials passed on a frozen package; low-reasoning reports remain incomplete; no compiler required by users |
| T05 | [7-Zip 26.04](https://github.com/ip7z/7zip/releases/tag/26.04) | `7zz` list/test/extract into new output directory; macOS native bundle | LGPL/BSD/unRAR terms and matching source; immutable binary/source release companions |
| T06 | [dotnet-dump 10.0.750501](https://www.nuget.org/packages/dotnet-dump/10.0.750501) | collect/analyze + SOS, private .NET, matching native RID and DAC support | MIT plus dependencies; package declares net8 with major roll-forward. Prove .NET 10 compatibility and actual owned dump/object workflow |
| T07 | [dotnet-stack 10.0.750501](https://www.nuget.org/packages/dotnet-stack/10.0.750501) | report owned managed-process threads/stacks; private .NET/diagnostics transport | MIT plus dependencies; exact runtime/process association and real stack task required |
| T08 | [dotnet-trace 10.0.750501](https://www.nuget.org/packages/dotnet-trace/10.0.750501) | bounded collect/report/convert; private .NET | MIT plus dependencies; retain conditions and actual trace interpretation |
| T09 | [Frida 17.24.0](https://github.com/frida/frida/releases/tag/17.24.0), [frida-tools 14.11.0](https://pypi.org/project/frida-tools/14.11.0/) | Spawn/attach/hooks on owned fixtures; official Node NAPI-v8 binding is feasible on the existing Node 24 host, avoiding a private Python dependency | wxWindows Library Licence 3.1; complete dependency/source audit pending. Real Node hooks/detach passed on a CoreFoundation-loaded fixture; bare-C attach failed explicitly; no adapter admitted |
| T10 | [LLDB 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | Pinned lldb/liblldb/debugserver subset passed breakpoint, registers, memory and backtrace on an owned macOS fixture; reuse existing Ghidra debugger ownership principles | Apache-2.0 with LLVM exceptions; normal inferior cleanup independently verified. Public adapter, complete distribution and crash/timeout/recovery ownership proof remain pending |
| T11 | [WinDbg 1.2610.1001.0](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) | Exact MSIX bundle contains amd64/arm64/x86 `cdb.exe`, DbgEng and related libraries; use supported console automation, Windows | Embedded EULA prohibits redistribution. Explicit Microsoft delivery policy with pinned bytes/local cache; no mirror. Do not consume mutable auto-update appinstaller as the managed version |
| T12 | [Process Monitor 4.12](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | Scoped native file/registry/process capture, owned Windows fixture; driver/admin requirements | **Owner-selected exception:** explicit Microsoft download + local cache + pinned SHA256. [Sysinternals terms](https://learn.microsoft.com/en-us/sysinternals/license-terms) prohibit our mirror. Actual driver/capture feasibility must be proven |
| T13 | [strace 7.2](https://github.com/strace/strace/releases/tag/v7.2) | Scoped syscall/file/process capture, owned Linux fixture | LGPL-2.1-or-later for tool; test/UAPI notices retained. Build a pinned Linux artifact from exact source; ptrace host prerequisite |
| T14 | [dnSpyEx 6.6.0](https://github.com/dnSpyEx/dnSpy/releases/tag/v6.6.0) | Windows WPF debugger/editor, extension/scripting APIs; managed debug/edit automation must be established | GPL-3.0. Mirror exact binary + matching source/notices. GUI launch is not acceptance; real controlled debugging/editing remains a feasibility gate |
| T15 | [TShark / Wireshark 4.6.9](https://www.wireshark.org/download.html) | Offline packet fields/filtering first, then supported owned capture; CLI dependency closure from official macOS bundle | GPL-2.0 and bundled components; matching source + notices. No global BPF permission changes; Windows Npcap is separate, not implicitly redistributed |
| T16 | [mitmproxy 12.2.3](https://github.com/mitmproxy/mitmproxy/releases/tag/v12.2.3) | Standalone mitmdump CLI, pinned embedded Python/dependencies; controlled localhost HTTP workflow | MIT plus bundled notices. Official standalone archive has framework symlinks; use verified relocatable closure. Profile-local CA only, no global trust changes |
| C01 | [dnlib 4.5.0](https://www.nuget.org/packages/dnlib/4.5.0) | Prebuilt managed metadata/IL/comparison helper behind our application API | MIT; no user SDK requirement, no pretend library installation commands |
| C02 | [ClrMD 4.2.751201](https://www.nuget.org/packages/Microsoft.Diagnostics.Runtime/4.2.751201) | Prebuilt heap/dump helper behind API, matching DAC/runtime/OS | MIT; real compatible dump task required; report unsupported DAC/platform explicitly |
| C03 | [LIEF 1.0.0](https://github.com/lief-project/LIEF/releases/tag/1.0.0) | Binary query/copy-only edit API; native SDK or private Python ABI3 wheel | Apache-2.0; reuse private runtime where feasible; original input never overwritten |
| C04 | Existing C01 + binary utility + Ghidra APIs | P/Invoke declaration → matching native export → imported function, with exact identities | No additional runtime; distinguish static correspondence from observed invocation |
| C05 | Existing owned tool supervisor + explicit fixture-run API | Bounded input/output/exit/files capture and comparison | No arbitrary shell execution gateway or broad process ownership claim |
| C06 | Application-specific overview/drilldown queries | Bounded first results plus focused follow-up | Admission checks verify each advertised workflow family, not just one command |

## Pinned inspected bytes

These upstream SHA256 values establish the inspected input, **not a published mirror catalog**.
The installation catalog will pin the final retained asset bytes after any deterministic
repack and required license/source companions. An upstream changing a mutable URL fails closed;
it is not accepted by updating the hash at runtime.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `die_mac_qt6_3.21_arm64.pkg` | 41179549 | `9b6411f4976593988fbcdc8d1ed2fd8123996e4b9f4a43df6a841460c229794b` |
| `LLVM-23.1.3-macOS-ARM64.tar.zst` (independently downloaded) | 871033366 | `a3f181b1176406893c097443e21b2a54b85afeac2d10eca3b6d251e6dca32eb3` |
| `llvm-utilities-23.1.3-macos-arm64.tgz` (reviewed derived subset) | 23318992 | `2599cb40282085a61a3d8b50003d75d556010d764c05a9bf30e45a7c7b5b7861` |
| `7z2604-mac.tar.xz` (release metadata) | 1861928 | `bee04358cbcbc7106273cee0e8d72916db2696c48067a3538c34d8cd6fd16578` |
| `dotnet-dump.10.0.750501.nupkg` | 10482522 | `ae70c9f37548e1e006467893e21ae41a005fefaf2270e29642b415df053324a7` |
| `windbg.msixbundle`, exact `1-2610-1001-0` vendor path | 1203512387 | `4662ae17bc0dc77db987b89cccea32c30058baa06268f861d09e0ab4e4f45c20` |
| `ProcessMonitor.zip`, inspected version 4.12 | 3202206 | `477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10` |
| `mitmproxy-12.2.3-macos-arm64.tar.gz` | 54227612 | `0a09ee3b82569e8985aff8186e4792618b8e5d0c766098db093d09a87d4b013a` |
| `Wireshark 4.6.9.dmg` (official signature manifest; not independently downloaded) | 147277050 | `10bd54ccdc3f40457f6a1f0c517bc93703fcb327c4cd4b93002e7a623dacbf38` |

DiE's release repository is `horsicq/DIE-engine`; `horsicq/Detect-It-Easy` contains signature
materials and has no release artifacts. Wireshark and mitmproxy binary downloads are on their
official download hosts rather than GitHub release assets. Recipes must use the verified source,
then mirror permitted retained bytes instead of assuming every GitHub release contains binaries.

WinDbg's installer XML advertises periodic automatic updates. Its exact versioned bundle was
inspected directly: console debugger binaries are present and its embedded EULA forbids sharing,
publishing or distributing the software. Keep Microsoft delivery intentional and visible in
catalog/help; no fallback from a broken mirror to an arbitrary vendor URL. Source exceptions do
not grant administrative rights, accept arbitrary terms silently, or prove execution readiness.

## Feasibility findings and required corrections

* **DiE stdout is not always a standalone JSON value.** A direct 3.21 macOS ARM64 `diec -j`
  probe against the real 7zr PE returned structured classifications followed by a JavaScript
  signature TypeError in stdout, with `Unimplemented code.` on stderr and exit code 0. Preserve
  diagnostics and expose partial/incomplete status. Investigate the pinned engine/database pair;
  do not silently discard trailing text or equate zero exit with a complete scan. This vendor
  probe does not count as public insight-cli acceptance.
* **Safe extraction must handle actual distribution formats.** DiE ships an installer package,
  LLVM/7-Zip use xz/zstd, Wireshark a DMG, WinDbg nested MSIX, and standalone Python/mitmproxy
  contain framework symlinks. Perform controlled recipe-time extraction/repack, without executing
  installers or relaxing the runtime extractor's path/link rules. Verify relocated binaries.
* **Managed diagnostics need more than a DLL.** Inventory RID-specific native libraries, SOS/DAC
  and runtime resolution; prove real collect/analyze, stack and trace tasks with the pinned private
  runtime. NuGet declaring major roll-forward is only a compatibility hypothesis.
* **Windows proof environment is not presumed.** The repository has hosted Windows CI and no
  self-hosted runner. Confirm ProcMon's driver/admin capture and dnSpyEx's actual automation in
  that environment before counting them feasible. A successful download or visible GUI is
  insufficient. [Windows run 39029921856](https://github.com/iXab3r/insight-cli/actions/runs/39029921856)
  passed WinDbg console commands, ProcMon observation of a successful owned configuration
  ReadFile, and dnSpyEx GUI/extension-contract availability. ProcMon needed a normalized
  Windows path in the probe oracle. This proves host feasibility only; scoped capture and
  dnSpyEx debug/edit automation still need their own adapter/agent evidence. Later ProcMon
  runs repeatedly recorded zero owned events. Run 39038803051 still missed the owned read
  with `/WaitForIdle` exit 0: readiness alone did not fix it. The next probe retains a bounded
  post-exit capture window and adds owned-PID counters. Run 39039221126 still recorded
  zero owned-PID/config events after that window. Explicitly clearing capture/export filters
  with the pinned binary's `/NoFilter` then passed twice on commit 353cb6a (run 39039589569,
  attempts 1/2): each observed one successful owned ReadFile and 654 fixture-PID events.
  This supports inherited filter state as the missing-event cause; a product-side prefilter
  and public adapter/agent gates are still required. The
  [Windows receipt](verification/toolbox-windows-feasibility.json) preserves both outcomes.
* **Skills must be usable before install.** Existing Factory IPC routing is root-based and Core
  handlers resolve profiles. Shared [Factory #52](https://github.com/iXab3r/EyeAuras.CliFactory/issues/52)
  was delivered in [Factory PR #53](https://github.com/iXab3r/EyeAuras.CliFactory/pull/53).
  Core now owns local handlers/classification and IPC uses that same parser for nested routing.
  [Factory PR #55](https://github.com/iXab3r/EyeAuras.CliFactory/pull/55) also distinguishes
  denied access from a missing owner and cancels only an unready startup child. Both passed
  independent review and their full platform CI. The consumer pins these prepared artifacts;
  its `tools list/show` and skill locators are profile/transport independent.

TB-01 remains open until the remaining distribution/dependency and native automation feasibility
checks have concrete results. The audit does not waive TB-07 cold/prepared per-tool agent proof,
TB-08 exact-artifact combined acceptance or the full delivery definition of done.

## Current agent-host finding

The actual Codex app-server discovers all packaged skills through one project bundle link;
upgrade/disconnect metadata checks passed without touching unrelated skills. Two standalone
cold model trials selected the correct ILSpy/artifacts skills but failed their runtime gate:
commands were denied IPC access, and the agents used Mono instead. Their correct business
answers are **not** toolbox passes. A no-model preflight succeeds with an explicit exact-socket
CLI grant, but the named permission-profile socket rule did not reach this host execution path.
Do not enable general network or stop a shared owner as a workaround. Use normal reviewed
permission for the precise CLI execution and verify actual execution before counting a pass.

The 7-Zip 26.04 adapter and its skill passed a globally installed isolated CLI developer
workflow: local pinned installation/doctor, bounded inventory, archive test, exact DLL/config
recovery, checkpoint, overwrite refusal, terminal process check and uninstall preserving
materials. Binary stdout is exported without UTF-8 conversion. A maintainer-only xz→gzip
repack preserves the original tar bytes and verifies both original and derived digests; matching
source and full notices accompany the distribution. This is not yet its independent agent gate.

The actual standalone Codex host subsequently passed the same container business question
in cold and prepared contexts with no skill/tool list or command sequence in the task prompt.
The project bundle supplied startup metadata. Exact CLI execution used ordinary automatic
permission review; no broad filesystem/network grant or proxy exception was added. An earlier
test helper prestarted an incompatible owner; the corrected trial lets the requested public
CLI start its own owner. Factory compatibility includes Node as well as deployed code and
dependencies, so callers sharing one owner must align their runtime. Do not stop unrelated
research just to switch an operator terminal runtime. Reviewed receipts are recorded separately
from model exit status. `scripts/toolbox/run-agent.mjs` retains a real opt-in trial as
`needs_review`; useful findings, checkpoint bytes and tool-specific cleanup require independent
review before acceptance.

### Repeated Windows feasibility

The initial Windows feasibility receipt remains historical, not adapter acceptance. Subsequent
runs 39031889515 and 39032790185 failed the ProcMon owned-file observation: the fixture
read its file successfully but no corresponding captured rows were found. WinDbg console
and dnSpy launch checks continued to pass. ProcMon capture readiness remains unresolved;
do not treat one earlier successful capture as a stable product workflow. The owner confirmed
explicit Microsoft download, pinned hash and local cache for its non-redistributable payload.

The shared installer now implements this Microsoft-only exception: explicit vendor opt-in
before network access, exact size/hash checks, verified offline cache reuse, and no implicit
mirror fallback. The mirror publisher rejects vendor-only assets. This source policy is
implemented independently of the still-unaccepted Windows adapters.

### LLVM native and agent evidence

The four utilities are published as a 23 MB immutable subset with exact corresponding source
and the full matching license. Real globally installed CLI/Gherkin proof covers PE/PDB, ELF,
Mach-O, section bytes, instruction ranges, PDB type indices and external sibling drift/removal.
[LLVM evidence](verification/toolbox-llvm.json) separates this native proof from model quality.
Initial low-reasoning trials were incomplete: first the concrete pricing constants were absent;
a section-data query fixed that usability gap, but later reports still contained address or
symbol-table mistakes. Saved bytes and process exit do not override those semantic failures.
Two fresh `gpt-6-luna` medium-reasoning cold/prepared trials passed the required business
questions on the same improved package. Pricing constants, boundary sums, layout, address
correspondence, retained bytes and cleanup were independently verified. Minor reporting
limitations are preserved in the receipt. This does not rehabilitate the four incomplete
low-reasoning trials or imply full-toolbox acceptance.

### .NET diagnostics native admission

The pinned 10.0.750501 NuGet family passed real globally installed CLI checks with private
.NET 10.0.13 on macOS ARM64: waiting stacks, a real Heap dump, SOS object/field/root queries,
a two-second EventPipe trace, method ranking and readable Speedscope export. Full matching
MIT text is shipped in the npm resources and copied into each owned installation; NuGet
third-party notices are preserved. Exact source/license release companions are published in the immutable tool release.
[Diagnostics evidence](verification/toolbox-diagnostics.json) records the native candidate;
dump cold/prepared agent trials passed independent field/stack and byte checks. Stack cold was
interrupted by the model-account usage limit after collection; its incomplete report also
miscounted raw lines. Stack prepared and trace trials remain pending, with no acceptance
credit from the native tests. The native `cpu-sampling` profile is
Linux collect-linux only in this pinned version; our default is `dotnet-sampled-thread-time`,
which measures thread wall-clock samples and can rank a sleep at 100% without proving CPU use.
Collectors do not take ownership of the explicitly selected external target process.

### Detect It Easy native admission

The 3.21 console subset retains its exact upstream executable/database and the five required
dynamic Qt 6.11.0 frameworks. Its deterministic maintainer recipe uses `pkgutil --expand-full`
on macOS, runs no installer, embeds full license/attribution files from the complete matching
DiE source and three Qt source archives, and retains those archives as release companions.
No system Qt installation is required. Copied external bundles can replace compatible Qt
libraries and be reselected; managed integrity verification does not silently accept changes.

`die classify` combines file information with compiler/runtime/packer signatures. Native PE
probes exposed the pinned database's JavaScript TypeError after JSON despite exit zero; the
facade retains useful data plus diagnostics with `state: partial` and `complete: false`.
Unknown signatures never prove absence. The skill distinguishes AnyCPU PE header architecture
from eventual process architecture and routes managed/native follow-up to the appropriate tool.

[DiE evidence](verification/toolbox-die.json) records the installed package, unchanged inputs,
external database drift refusal, preserved files/materials and all five native Gherkin scenarios.
The first DiE doctor failed because generic installation fingerprints mixed canonical link
targets with an aliased `/tmp` root. Canonical relative targets fix relocation without accepting
escaping links; dedicated regression tests cover both. Independent cold/prepared model trials
remain pending after the evaluator account usage limit; native proof is not agent acceptance.

### Frida backend feasibility

The official Frida 17.24.0 Node NAPI-v8 addon worked on Node 24.19.0 without Python: the
owned fixture yielded 15 argument/result observations, including count 10 → 130 and count
11 → 109, then the collector unloaded its script and detached while the target remained alive.
The matching bare C fixture failed attach because CoreFoundation was not found. Retain this
capability gap; do not inject a framework into an unrelated target as an implicit workaround.

The standalone frida-inject executable also failed with piped stdin (`tcgetattr`) after the
CoreFoundation-loaded attach. That is unsuitable for the existing pipe-based process runner;
the Node binding provides an actual noninteractive route. [Feasibility evidence](verification/toolbox-frida-feasibility.json)
records both failures and the useful observations. `scripts/toolbox/audit-frida.mjs` reproduces
the native backend probe using `instrumented.c` compiled with/without
`INSIGHT_WITH_CORE_FOUNDATION` and `-framework CoreFoundation`. Distribution/source/notices,
public adapter, skill and independent agent gates remain open. This probe is not CLI acceptance.

### LLDB backend feasibility

The official LLVM 23.1.3 archive supplies lldb, liblldb and debugserver with system-library
dependencies. Selecting that private debugserver via `LLDB_DEBUGSERVER_PATH`, disabling init
files and using direct `process launch` passed a real named breakpoint, parameter/register
inspection, a memory window and a backtrace on the owned C fixture. `process kill` ended the
inferior and an independent PID probe confirmed absence. No separate Python setup was used.

The first `run` alias required lldb-argdumper, missing from the trial subset. The explicit
argv launch path avoids shell expansion. [LLDB feasibility](verification/toolbox-lldb-feasibility.json)
and `scripts/toolbox/audit-lldb.mjs` retain the exact binary/fixture identities and limits.
A normal batch exit is not proof of crash-safe ownership: timeout, debugger/helper failure,
owner replacement and uncertain inferior lifetime remain required before public admission.
Existing Ghidra debugger ownership rules remain authoritative; no arbitrary PID adoption or
second shared debugger owner is introduced by this probe.
