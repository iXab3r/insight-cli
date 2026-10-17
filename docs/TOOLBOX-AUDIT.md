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
| T09 | [Frida 17.24.0](https://github.com/frida/frida/releases/tag/17.24.0), [frida-tools 14.11.0](https://pypi.org/project/frida-tools/14.11.0/) | Bounded attach/hooks on owned fixtures; official Node NAPI-v8 binding is feasible on the existing Node 24 host, avoiding a private Python dependency | Frida-declared LGPL-2.0 WITH WxWindows-exception-3.1 and separate dependency terms; full notices and 69 exact source/component archives retained. Node facade/native proof delivered; independent model gate pending |
| T10 | [LLDB 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | Owned-launch facade with explicit symbol companion, bounded breakpoint snapshot, registers, memory and backtrace; native macOS ARM64 CLI proof | Apache-2.0 with LLVM exceptions; immutable binary/source/license release, native snapshots and controller/owner-loss cleanup proof passed; independent model gate pending |
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

### Frida native admission

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
`INSIGHT_WITH_CORE_FOUNDATION` and `-framework CoreFoundation`. The early backend probe is not CLI acceptance. The later adapter provides `frida modules`,
`exports` and bounded `observe --script FILE` through the existing Node runtime, without Python.
Module/export records and event pages remain bounded; full snapshots are ordinary new files.
Scripts are captured by hash and passed unchanged after a separate runtime-version preflight,
so strict directives and source line numbers retain their meaning. Script errors remain partial
even when unload/detach succeeds.

The immutable Node runtime/source release retains the official NAPI-v8 addon, six exact npm
components, full notices indexed to their original source files and all 69 matching Frida/SDK/
nested-submodule/component archives. Assembly executes no vendor install script.

The first fault probe found that default SIGTERM could leave the collector busy. Explicit
unload/detach handling fixes graceful stop. A deeper tree audit then found that native
`frida-helper` calls setsid and can outlive a killed collector. A first-party ARM64/ARM64e
constructor now arms each owned helper with the same absolute kernel deadline and writes its
PID/birth/deadline receipt before helper main. It is loaded only by the collector’s SDK helper
execs; the external target gets no such loader environment. No guardian service or arbitrary
PID adoption is added. Initial ARM64-only and UUID-less library probes failed explicitly;
the verified Apple ABI universal build includes source, hashes and reproducibility metadata.

Status exposes native children and remains unverified/native_children_pending until they exit;
installation guards block removal meanwhile. Observed exits are durably acknowledged so old
helper PIDs cannot later make a reused PID appear active. Receipts only describe lifetime and
never authorize signals. [Frida acceptance](verification/toolbox-frida.json) records public
CLI/native faults, including restored ordinary fixture output after hook loss, preserved
target lifetime and independent helper absence. Model/complete-toolbox gates remain open.

### LLDB native admission

The official LLVM 23.1.3 archive supplies lldb, liblldb and debugserver with system-library
dependencies. Selecting that private debugserver via `LLDB_DEBUGSERVER_PATH`, disabling init
files and using direct `process launch` passed a real named breakpoint, parameter/register
inspection, a memory window and a backtrace on the owned C fixture. `process kill` ended the
inferior and an independent PID probe confirmed absence. No separate Python setup was used.

The first `run` alias required lldb-argdumper, missing from the trial subset. The explicit
argv launch path avoids shell expansion. [LLDB feasibility](verification/toolbox-lldb-feasibility.json)
and `scripts/toolbox/audit-lldb.mjs` retain the exact binary/fixture identities and limits.
The initial controller-loss probes left the inferior alive under both SIGTERM and SIGKILL.
The native cause was `target.detach-on-error` defaulting to true. The facade explicitly sets
it false before launch; repeated faults independently verified disappearance of debugger,
debugserver and inferior. A small first-party POSIX exec helper arms a kernel alarm before
exec, so the deadline survives loss of the owner. It keeps the tracked PID/process group;
there is no new service or arbitrary PID adoption. The deterministic helper includes source,
reviewed hash and build provenance; only libSystem is linked. Other adapters do not opt into
this contract without proving their own signal/child behavior.

`lldb inspect` uses literal argv, disables init files and inferior stdio, supports a selected
hit, register/memory/backtrace capture and optional step-out, then kills its owned launch.
It accepts native thin ARM64 Mach-O files on macOS 14+, rather than trying to execute an
imported Windows PE. An adjacent dSYM is lost when the executable alone is copied: the initial
installed CLI probe exposed that gap. `--symbols FILE` now captures a matching DWARF companion
and LLDB checks its correspondence before launch. `--variables` requires usable debug info;
registers/backtraces remain available without it. Ordinary output retains all native warnings.

[LLDB acceptance](verification/toolbox-lldb.json) records installed public CLI results,
source/release readback and fault tests. After owner loss, a live recovered macOS process
remains unverified; observed exit records an unknown result. It does not replay execution or
claim a completed snapshot. Cold/prepared independent model acceptance and the combined
full-toolbox gate remain open; model quota does not block native implementation of other tools.

### WinDbg adapter native gate in progress

The Windows x64 adapter now exposes typed, read-only user-minidump queries, captures
the dump and optional local PDB, and disables inherited initialization, shell commands
and network symbol lookup. Microsoft's pinned bundle is acquired only through explicit
vendor delivery or a supplied matching archive; nested x64 MSIX bytes are checked before
extraction. External `amd64/cdb.exe` selections fingerprint their console runtime family.

Windows CI prepares a native calculation stopped inside `quote_total`, creates its dump
and PDB, installs the npm artifact globally in isolation, and checks stack, registers,
the actual value 109 in dump memory, bounded output, unreadable-memory uncertainty,
external dependency drift and checkpoint preservation. Native acceptance is pending this
run; no agent or whole-toolbox acceptance is claimed. The first new Windows build exposed
CRLF-sensitive skill metadata admission before native execution; parsing now accepts both
line endings without rewriting source files.

### Verified Linux strace source build

The [Linux build receipt](verification/toolbox-strace-build.json) records two identical
stripped strace 7.2 builds with GCC 11.4.0 on glibc 2.35, actual owned configuration
reads, `--kill-on-exit`, timeout, launcher-kill and owner-loss cleanup. Optional
SELinux/termcap/unwinding/mpers dependencies are disabled; system libc and loader
remain the only linked requirements. The exact runtime, full source, first-party
launcher/build sources and MIT license are published as immutable
`tool-strace-7.2-r1`; all six assets were downloaded and verified after upload.
The public owned-launch facade and relocatable skill now join discovery; Linux
Gherkin acceptance is pending its native run. Model quota does not block that work.

### Verified Windows executor lifetime

The [Windows native receipt](verification/toolbox-windows-job.json) proves completion,
timeout, launcher kill, owner kill and output overflow leave no live owned child or
grandchild on Windows x64/Node 24. PowerShell module autoload hung before child creation
in the isolated environment; JSON and receipt I/O moved into the small .NET executor.
PowerShell now loads the DLL and invokes it without profile, module, compiler or JSON
cmdlet dependencies. The replacement DLL reproduced byte-for-byte in two builds.
WinDbg public CLI acceptance remains a separate gate.

The [strace public receipt](verification/toolbox-strace.json) now confirms a real Linux
Gherkin pass from an isolated global installation: fresh mirror download, offline
installation, actual config `openat`/`read` plus application value, bounded pages,
public stop/kill and timeout cleanup, drift refusal and retained checkpoints. A
separate source-build audit rerun hit `/proc` ESRCH after a process disappeared;
its observer now treats that as absence. The passing CLI job and failing overall
workflow are recorded separately. Platform tags keep unsupported profiles explicitly
skipped rather than pretending that one host proved the entire toolbox.

WinDbg's [public native receipt](verification/toolbox-windbg.json) confirms a Windows
Gherkin pass using a globally installed artifact, with `quote_total`, registers and
actual value 109 in dump memory, bounded pagination, unreadable-memory uncertainty,
external runtime drift refusal and preserved PDB/dump/checkpoint bytes. The CDB version
probe accepts its real console product banner; startup command echoes are not accepted
as snapshot result markers. Independent model and full-inventory gates remain open.

ProcMon's next native probe uses a first-party PMC serializer based on the pinned
[original format research](https://github.com/eronnen/procmon-parser/blob/96080961e51745ddc6e83490c24e540553c44c71/docs/PMC%20Format.md).
It loads PID/path include rules and destructive filtering before two owned workers
read the same configuration, then exports the retained PML with display filtering
disabled. This checks actual capture scope rather than hiding unrelated rows during
export. Public ProcMon admission remains pending; no broad raw capture is uploaded.

ProcMon [pre-capture scope passed](verification/toolbox-procmon-scope.json): two owned
processes read the same file, while unfiltered export of the destructively filtered
PML retained five events, all from the chosen PID/path, including one successful
ReadFile. The next native observation checks whether capture and export alter
ProcMon's user preferences before choosing their preservation mechanism.

The preference observation found 26 ProcMon user settings written into the real
HKCU key; export did not change them further. A new native-only prototype loads a
first-party shim into the freshly created suspended ProcMon child using pinned MIT
Microsoft Detours import preparation. The shim redirects HKCU to an application
hive file under the owned run directory before the tool entry point. No existing
process is injected or assigned to the job. The verifier requires an actual filtered
read, saved private FilterRules, unchanged global settings, automatic runtime exit
and Unicode directory support. Source, license and deterministic build provenance
are retained; public admission stays blocked until those native checks pass.


### ProcMon private preferences and public native gate passed

The [private HKCU receipt](verification/toolbox-procmon-isolation.json) supersedes the
pending prototype check above: 25 successful scoped reads, private captured FilterRules,
two constructor receipts/hives, unchanged global preferences and Unicode paths passed.
The [globally installed CLI receipt](verification/toolbox-procmon.json) then passed
Windows Gherkin: explicit Microsoft download, offline archive installation, 59 actual
successful reads of the selected PID/path, bounded pagination, cached inspection without
recollection, stop/kill uncertainty, preserved borrowed process/settings, external runtime
drift refusal and retained checkpoints. Timed native capture returned 1 while its complete
PML/readback was valid; exit code alone is not the research gate. Raw PML/CSV/hives remain
private. The packaged helper imports only KERNEL32/ADVAPI32; two independent native builds
matched. No compiler or existing-process injection is needed at runtime.

The current inventory contains 13 analytical families plus supporting artifacts, with 16
packaged skills including entry and RE guidance. Remaining tool families are dnSpyEx,
TShark and mitmproxy, plus the six planned capabilities. dnSpyEx has a typed extension
compiled against its pinned actual contracts; its debugger/editor native gate is running.
Independent cold/prepared model and combined full-inventory gates remain open; inference
quota does not block implementation or native checks.


### dnSpyEx debugger/editor API proof and distribution audit

The [native API receipt](verification/toolbox-dnspy-debug-edit.json) confirms that the
first-party MEF extension actually read argument 11 at a managed IL breakpoint, retained
stack frames, edited an expected IL constant through dnSpy's loaded document and verified
the changed copy's behavior (37) while preserving the original. Opening a GUI alone is
not this gate. The Framework proof passed; Core apphost and globally installed public CLI
scenarios are being checked separately on the new adapter/skill artifact.

[Component audit](verification/toolbox-dnspy-components.json) found 39 NuGet dependencies
and the self-contained .NET/WindowsDesktop 10.0.9 runtime. Six VS 2017 SDK packages use
[separate Microsoft terms](https://visualstudio.microsoft.com/license-terms/mlt552233/)
that prohibit sharing/publishing. The main application's GPL declaration is not a grant
to mirror those separately licensed DLLs. The exact unmodified dnSpyEx bundle therefore
uses explicit upstream GitHub acquisition (`--vendor-direct`), SHA256, local cache and
local-archive/external setup through the existing delivery path. It never enters our mirror
publisher. The first-party MIT bridge's sources, contracts hashes, prebuilt managed DLL
and two-build provenance are packaged; no third-party reference DLLs or consumer compiler
are included. Managed Core target setup additionally delivers the existing private .NET
10.0.13 component; other target runtime versions require a compatible explicit host.

The subsequent Core gate found an upstream ANSI `LoadLibraryEx` import: dbgshim was
present and x64, but its Unicode installation path could not be loaded. An attempted
executable device alias timed out and was removed. Preparation now corrects the exact
pinned GPL engine import in owned staging, retaining metadata tokens and its original
strong-name identity with the upstream deliberately public source build key. It never
patches external files: an external selection gets a separately fingerprinted owned copy
of the 867 exact vendor files. This preparation and the Core/public CLI flow still require
native confirmation; the earlier Framework receipt remains scoped historical evidence.
See [local loader correction](../skills/ghidra-coordinator/runtime/native/dnspy-extension/UNICODE-LOADER.md).

The corrected loader subsequently passed the actual Framework **and Core** breakpoint,
argument, stack, copied IL edit and changed-behavior gate on source `ef28f51`
([receipt](verification/toolbox-dnspy-debug-edit.json)). The Windows source build also
matched the packaged extension SHA256. Public CLI installation separately exposed private
plan path validation; its gate remains open while normalized comparisons and field-specific
errors are tested. No model acceptance is inferred from this native API proof.

### TShark console delivery and offline protocol evidence

The source-complete [immutable runtime release](https://github.com/iXab3r/insight-cli/releases/tag/tool-tshark-4.6.9-r1)
contains an unchanged 4.6.9 console subset: 28 linked code files, 342 native protocol data
files, full sources for Wireshark and all 22 bundled libraries, matching upstream build
recipes and 76 full notices. Qt, GUI, dumpcap, extcap and system installers are excluded;
macOS system libraries remain explicit host prerequisites. The recipe and relative file
hash layout retain the exact original DMG identity and reproducible subset procedure.
No system helper, root capture or trust/configuration change is performed.

The new `tshark inspect` facade provides overview, filtered packet rows, one-frame detail,
stream identities and typed TCP/UDP raw follow chunks. It captures immutable PCAP/PCAPNG
inputs, disables external name/GeoIP lookup, uses private settings and bounds native
output/lifetime. Inventory/filter/follow have a 10000-frame read boundary; row pagination
is applied after filtering. A prefix cannot claim whole-file absence. The packaged
`insight-tshark` skill explains those limits and links ordinary packet/stream evidence to
capture identity. External selection prepares only the pinned known console files in an
owned, separately fingerprinted copy. Native public CLI and Gherkin receipts are separate
from the still-open quota-limited independent model gate.

The next public CLI attempt completed managed preparation and doctor, then correctly
refused to invent a breakpoint frame: the debugger reported the long Windows module
path while the captured plan used its 8.3 alias. Matching now authenticates both existing
files through `GetFinalPathNameByHandleW`, rather than comparing path spellings. The
captured module token and input SHA remain required. Its native public CLI gate is rerun;
the existing successful API receipt is not relabeled as public adapter acceptance.
