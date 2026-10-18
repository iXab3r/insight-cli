# Toolbox inventory and delivery audit

Audit date: 2026-10-18. All sixteen analytical families and six capabilities have
implemented facades, packaged guidance and real native proofs. The
[toolbox plan](TOOLBOX-PLAN.md) provides the current acceptance matrix; sections below
retain the investigation history, including failed candidates. Native and independent
agent acceptance are separate. Reviewed cold/prepared units now cover container, LLVM,
dump/stack/trace, DiE, LLDB, Frida, packets/HTTP, C01–C06, ILSpy projects/resources
and selected Ghidra GUI research units on their recorded artifacts.
The final whole-toolbox agent gate and some broader family/host workflows remain open.
Current final native implementation: source `f3ea16f`, exact frozen package
`87c0807bdbf3043eb0ce4b381ff024c66ca8beb9218b537d49f07e3fd1909ab0`.
All 20 macOS scenarios passed in 21m35s, with four declared Windows/Linux skips. The separate
recursive public-CLI preflight passed on the same package; current Windows seven-job native,
Linux and offline CI are green. [Exact results](verification/toolbox-combined-native.json)
and [caller/runtime correction](verification/toolbox-ghidra-caller-native.json) preserve the
older failed candidates and the scope of independent model units.

Existing Ghidra/ILSpy runtime acceptance is separately identified in
[tool runtime acceptance](TOOL-RUNTIME-ACCEPTANCE.md).

## Inventory

The native proof host is deliberately tool-specific. A Windows-only capability is described as
such; failure to run it on macOS is not a reason to invent an equivalent capability or drop it.
Versions below were inspected at their primary release/package sources. A version is admitted
only after its archive, dependency closure, license companions and real workflow pass.

| Child | Frozen candidate / primary source | Agent surface and dependency closure | Delivery and remaining admission check |
| --- | --- | --- | --- |
| T01 | [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build), GhidraMCP 7.0.0, Temurin 21.0.11+10 | Isolated static contexts, server, GUI and debugger; bundled JDK/native/bridge plus private LLDB/Python on macOS 15+ ARM64 | Immutable distributions/licenses and dedicated skill shipped. Selected cold/prepared GUI business units passed; complete family and whole-toolbox agent gates remain separate |
| T02 | [ILSpy 11.1.0.9782](https://www.nuget.org/packages/ilspycmd/11.1.0.9782), .NET 10.0.13 | Existing facade: types/C#/IL/resources/project; private runtime | Immutable runtime and MIT/dependency companions shipped. Native CLI and reviewed cold/prepared project/resource and metadata units passed on recorded packages; combined agent gate remains separate |
| T03 | [DiE 3.21](https://github.com/horsicq/DIE-engine/releases/tag/3.21) | `diec` console, signature database, Qt frameworks; macOS ARM64 package can be extracted without installer execution | Console bundle with private Qt/database and matching sources/notices shipped. Native CLI and reviewed cold/prepared triage units passed; scan uncertainty remains explicit |
| T04 | [LLVM 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | readobj/objdump/nm/pdbutil, no non-system dylibs; macOS 14+ ARM64 | Derived 23 MB subset retains exact executables, full matching license and source companions. Real CLI/Gherkin and reviewed medium-reasoning cold/prepared business trials passed on a frozen package; low-reasoning reports remain incomplete; no compiler required by users |
| T05 | [7-Zip 26.04](https://github.com/ip7z/7zip/releases/tag/26.04) | `7zz` list/test/extract into new output directory; macOS native bundle | Immutable binary/source release under LGPL/BSD/unRAR terms; native CLI and reviewed cold/prepared container units passed |
| T06 | [dotnet-dump 10.0.750501](https://www.nuget.org/packages/dotnet-dump/10.0.750501) | collect/analyze + SOS, private .NET, matching native RID and DAC support | MIT/dependency companions and private runtime shipped. Actual .NET 10 dump/object workflows and reviewed cold/prepared dump units passed |
| T07 | [dotnet-stack 10.0.750501](https://www.nuget.org/packages/dotnet-stack/10.0.750501) | report owned managed-process threads/stacks; private .NET/diagnostics transport | Private runtime/transport and exact process association shipped; native CLI and reviewed cold/prepared waiting-stack units passed |
| T08 | [dotnet-trace 10.0.750501](https://www.nuget.org/packages/dotnet-trace/10.0.750501) | bounded collect/report/convert; private .NET | Bounded collection/reporting shipped with MIT/dependency companions; native CLI and reviewed cold/prepared trace units passed with explicit capture conditions |
| T09 | [Frida 17.24.0](https://github.com/frida/frida/releases/tag/17.24.0), [frida-tools 14.11.0](https://pypi.org/project/frida-tools/14.11.0/) | Bounded attach/hooks on owned fixtures; official Node NAPI-v8 binding is feasible on the existing Node 24 host, avoiding a private Python dependency | Frida-declared LGPL-2.0 WITH WxWindows-exception-3.1 and separate dependency terms; full notices and 69 exact source/component archives retained. Node facade/native and collector/helper fault proof delivered; reviewed cold/prepared passive-hook units passed; combined agent gate remains open |
| T10 | [LLDB 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | Owned-launch facade with explicit symbol companion, bounded breakpoint snapshot, registers, memory and backtrace; native macOS ARM64 CLI proof | Apache-2.0 with LLVM exceptions; immutable binary/source/license release, native snapshots, controller/owner-loss cleanup and reviewed cold/prepared breakpoint units passed; combined agent gate remains open |
| T11 | [WinDbg 1.2610.1001.0](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) | Exact MSIX bundle contains amd64/arm64/x86 `cdb.exe`, DbgEng and related libraries; use supported console automation, Windows | Pinned vendor-only Microsoft download/local cache; no mirror or mutable appinstaller version. Native dump CLI passed; independent Windows model gate remains open |
| T12 | [Process Monitor 4.12](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | Scoped native file/registry/process capture, owned Windows fixture; driver/admin requirements | **Owner-selected exception:** explicit Microsoft download + local cache + pinned SHA256. Native capture, fault, registry and scope checks passed; independent Windows model gate remains open |
| T13 | [strace 7.2](https://github.com/strace/strace/releases/tag/v7.2) | Scoped syscall/file/process capture, owned Linux fixture | Source-built Linux x64 immutable runtime/source/notices shipped under retained LGPL/UAPI terms. Native CLI passed; independent Linux model gate remains open; ptrace is a host prerequisite |
| T14 | [dnSpyEx 6.6.0](https://github.com/dnSpyEx/dnSpy/releases/tag/v6.6.0) | Windows debugger/editor facade with actual managed breakpoint observations and copy-only edits | Catalog uses explicit vendor-only download, pinned bytes and local cache for the distributed bundle. Native debug/edit, registry and lifetime checks passed; independent Windows model gate remains open |
| T15 | [TShark / Wireshark 4.6.9](https://www.wireshark.org/download.html) | Offline packet fields/filtering first, then supported owned capture; CLI dependency closure from official macOS bundle | Source-complete GPL/component mirror and relocatable console closure shipped; native CLI and reviewed cold/prepared offline packet units passed. Capture prerequisites remain explicit |
| T16 | [mitmproxy 12.2.3](https://github.com/mitmproxy/mitmproxy/releases/tag/v12.2.3) | Standalone mitmdump CLI, pinned embedded Python/dependencies; controlled localhost HTTP workflow | Relocatable source-complete MIT/component closure shipped; native HTTP/HTTPS, lifetime faults and reviewed cold/prepared units passed. Only profile-local trust is configured |
| C01 | [dnlib 4.5.0](https://www.nuget.org/packages/dnlib/4.5.0) | Prebuilt managed metadata/IL/comparison helper behind our application API | MIT; no user SDK requirement, no pretend library installation commands |
| C02 | [ClrMD 4.2.751201](https://www.nuget.org/packages/Microsoft.Diagnostics.Runtime/4.2.751201) | Prebuilt heap/dump helper behind API, matching DAC/runtime/OS | Prebuilt helper/notices shipped; native compatible-dump queries and reviewed cold/prepared units passed. Unsupported DAC/platform stays explicit |
| C03 | [LIEF 1.0.0](https://github.com/lief-project/LIEF/releases/tag/1.0.0) | Binary query/copy-only edit API; native SDK or private Python ABI3 wheel | Apache-2.0; reuse private runtime where feasible; original input never overwritten |
| C04 | Existing C01 + binary utility + Ghidra APIs | P/Invoke declaration → matching native export → imported function, with exact identities | No additional runtime; distinguish static correspondence from observed invocation |
| C05 | Existing owned tool supervisor + explicit fixture-run API | Bounded input/output/exit/files capture and comparison | No arbitrary shell execution gateway or broad process ownership claim |
| C06 | Application-specific overview/drilldown queries | Bounded first results plus focused follow-up | Admission checks verify each advertised workflow family, not just one command |

## Pinned inspected bytes

These upstream SHA256 values establish the inspected input, **not a published mirror catalog**.
The retained installation catalog pins the final assets separately after deterministic
repacking and required license/source companions. An upstream changing a mutable URL fails closed;
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
packaged skills including entry and RE guidance. TShark now adds a fifteenth analytical family and an eighteenth packaged skill.
Its native receipt is linked below. The final dnSpyEx native public gate subsequently passed (receipt below). Remaining tool
families are mitmproxy and the six planned capabilities. dnSpyEx has a typed extension
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

[Native TShark Gherkin proof](verification/toolbox-tshark.json) passed on a frozen global
artifact from source `3840238` and a fixture reconstructed from our matching source mirror.
It found PUT /1 at frame 4 and PUT /3 at frame 10, retained the TCP stream's reassembled
application bytes and tested post-filter pagination, one-frame detail, missing frame/stream,
invalid filters, conservative prefix coverage, original-input preservation, owned external
copy/drift/preservation, checkpoints and terminal jobs. The scenario passed in 39 seconds.
The full Node 24 offline suite passed 199/201 with two opt-in skips; all 29 release/admission
tests passed. Independent model and combined full-inventory acceptance remain separate.

The [final dnSpyEx public CLI Gherkin receipt](verification/toolbox-dnspy.json) passed
on Windows x64, Node 24, frozen source `fa2b03a`: explicit upstream acquisition, offline
managed installation, Unicode loader preparation, Framework/Core argument 11, managed
stack/pagination, real document edit and changed-copy execution, expected-value rejection,
stop/kill without relaunch, immutable originals, owned external execution copy, drift
refusal, checkpoints and terminal owned jobs. The separately rebuilt API proof also passed
with the exact packaged extension SHA. The two concrete path defects and failed alias
attempt remain documented above. Independent cold/prepared model and final combined gates
remain open; this native success does not consume or replace those gates.

### mitmproxy source closure and native HTTP API checkpoint

The pinned 12.2.3 macOS ARM64 standalone runtime embeds Python 3.14.4 built for macOS 15,
OpenSSL 3.6.2 in Python and 3.5.5 in cryptography, liblzma 5.8.3, libmpdec 4.0.1 and zstd
1.5.7. All 77 native code files were inspected: imports are bundle-relative or macOS
system libraries, without absolute Homebrew runtime dependencies. Original full sources
and lockfiles, 525 checksum-verified Rust crates, pinned Git/Swift sources and verbatim
published notices/declarations are retained. The Rust source set deliberately includes
build/test/other-platform packages; it is not a claim they are all compiled into macOS.
Where a crate omits a separate license file, its original declaration/attribution and
available exact-VCS notices are preserved, with clearly identified standard SPDX references.
No copyright statement is invented. The R1 application archive is unchanged; R2 only reorders identical entries as described below.

[Native addon feasibility](verification/toolbox-mitmproxy-api.json) actually observed GET
and POST, recovered the response value, wrote/reopened a native flow archive and retained
two valid observations before a damaged tail as explicit partial data. Only the owned
loopback proxy exited; the original service stayed alive. Its live process tree contained
one mitmdump process, without a detached PyInstaller child. The public facade/skill now
cover bounded record, readiness status, immutable archive/HAR inspection and selected-field
comparison. HTTPS is explicit per-client trust with a private CA and optional public
upstream root; no system trust/proxy/Network Extension setup is requested. The global public CLI Gherkin gate now passed native GET/POST response values, explicit client/upstream TLS trust, refused trust as partial empty evidence, archive/pagination/comparison without replay, stop/kill recovery, retained checkpoints, external drift and preserved originals ([receipt](verification/toolbox-mitmproxy.json)). Independent model acceptance remains pending.

The first global install correctly rejected the upstream chained symlink targets under
Node tar's traversal protections. R1 remains an immutable historical source/runtime
artifact; the default R2 repack writes aliases before their link dependencies. It preserves
all 327 original entry names/types/modes, regular file bytes and symlink strings exactly;
two independent repacks matched, and extraction through the unchanged safe helper passed.
[Packaging proof](verification/toolbox-mitmproxy-packaging.json) records the logical tree
and archive hashes. Both original and reordered app bundles fail strict deep bundle signature
verification identically; publisher notarization is not asserted. Exact pinned bytes,
logical-tree identity and actual runtime behavior are verified instead. The passing public CLI gate uses R2 and unchanged extraction protection. External bundles are fingerprinted and cloned into a separately verified owned execution tree; the original bundle is never launched or modified.

### Managed metadata capability checkpoint

`ilspy query` and `ilspy compare` use a first-party prebuilt .NET 10 helper and
[dnlib 4.5.0](https://github.com/0xd4d/dnlib/tree/v4.5.0), with locked dependency,
full MIT notice and two independently identical builds. This is a library-backed
capability, without another installation namespace. The existing ILSpy private runtime
is reused; consumers need no SDK. PDB and ambient dependency loading are disabled.

The [global public CLI Gherkin proof](verification/toolbox-managed-metadata.json)
compared two real assembly revisions: changed IL constant, changed P/Invoke, one added
method and unchanged methods whose metadata RIDs shifted. Overview, exact-token IL,
pagination, invalid selections, immutable input hashes and checkpoint retention passed.
An execution witness remained absent throughout: queries never ran the target code.
Structural comparison does not establish behavioral equivalence. Independent model
and combined full-inventory gates remain open.

### Structured managed dump queries

`dotnet-dump query` packages a reproducibly built first-party helper over
[ClrMD 4.2.751201](https://www.nuget.org/packages/Microsoft.Diagnostics.Runtime/4.2.751201).
All 20 locked packages have exact hashes, source repository commits where published,
full original license/third-party notices and binary/source manifest checks. Existing
diagnostics delivery supplies the private .NET runtime; no SDK or new tool install is
required. A custom no-files locator disables automatic external image/symbol lookup.
The explicitly selected native DAC is loaded with version mismatch checks enabled.

The [global public CLI Gherkin proof](verification/toolbox-managed-heap.json) captured a
real owned Heap dump, found `BusinessState.Pending = 37` and `Job = owned-report`, then
identified `WaitForRelease`/`Thread.Sleep` in an actual dump thread. Exact object/type
and thread drilldown, field pagination, scan-bound partial coverage, wrong DAC/runtime/
object/type rejection, input immutability, subject lifetime and evidence retention
passed. Native support is matching macOS ARM64 CoreCLR dumps; the managed default DAC
is 10.0.13, and a different trusted matching DAC must be selected explicitly. There is
no live attachment, expression evaluation or automatic symbol acquisition in this API.
Independent model and full combined gates remain open.

### Structured binary capability

`binary query` and `binary edit-subsystem` package a first-party native C++ helper
statically linked to unmodified LIEF 1.0.0. Two independent canonical builds matched.
Only system libc++/libSystem are dynamic; consumers need no SDK/compiler or another
installation namespace. Full original SDK/source, vendored dependency source/build/test
superset, available full notices and first-party helper source/binary are hash-verified
in an [immutable release](https://github.com/iXab3r/insight-cli/releases/tag/tool-lief-1.0.0-r1).
The old span short revision no longer resolves upstream; its complete bundled header,
original attribution and explicitly referenced official Boost license are retained.

The [global public CLI Gherkin proof](verification/toolbox-binary.json) read actual PE
imports/exports with scoped RVA/VA, ELF linkage and thin Mach-O structure. It created a
new PE GUI-subsystem copy, independently compared all other bytes and read back the
changed header. Wrong expectation/format, overwrite and bounds were refused; originals
and ordinary evidence remained intact. Native parser diagnostics are partial. Universal
Mach-O requires an explicit slice; ELF/Mach-O exports cover functions, not every data
symbol. Copy editing does not execute a target or recompute checksums/signatures.
Native host profile is macOS14+ ARM64. Independent model/combined gates remain open.

### Managed/native correspondence workflow

C04 composes existing `ilspy query`, `binary query` and scoped Ghidra APIs; it does not
add a speculative universal loader/resolver or another runtime. The dedicated interop
skill requires exact declaration/spelling/ABI metadata, an explicitly supplied native
candidate, immutable identities, a real export and native function readback. Forwarders,
ordinals, decoration/charset ambiguity and runtime file selection stay explicit.

[Real Ghidra Gherkin](verification/toolbox-interop.json) followed a concrete exact-spelling
Cdecl P/Invoke to `PolicyNative.dll!quote_total`, verified the implementation's
`count * 9 + 10`, and retained qualified static correspondence. Two isolated contexts
proved unchanged views until refresh, preservation of the second local annotation,
both explicit merges and independent published readback. The local server is stopped
explicitly: stopping only the CLI owner intentionally preserves that server's lifecycle.
No observed Windows execution/invocation or inference-model run is claimed.

### Repeatable owned process observations

C05 adds `capture run/show/compare`, a dedicated skill and no installation step. Runs
copy the selected thin native program and ordinary inputs into a separate working
directory, use literal argv/byte stdin and snapshot only declared relative files. The
common process runner optionally retains exact bounded stdout/stderr bytes; existing
adapters keep their original defaults. Portable reports retain base64 and byte hashes,
while normal responses are small previews. Known nonzero subject exits are captured
outcomes; timeouts, signals, overflow and unknown observations are partial.

[Native fault proof](verification/toolbox-capture.json) verified controlled inputs with
109/142 outputs and resulting files, non-UTF8 bytes, binary stdin, exit 17, literal
arguments, copied-input mutation, paging, comparison without rerun, duplicate/different
request identity, timeout/overflow and stop/kill prefix retention. Killing the isolated
Factory owner left the intent unknown, preserved working files and did not replay the
program. Existing SQLite request identity is reused rather than adding another host or
request service. This is not an OS sandbox or global file/network trace; the native alarm
survives ordinary owner loss but a subject can deliberately replace its inherited alarm.

### Bounded overview and drilldown

C06 is a discoverable navigation skill across the existing tool APIs. Every admitted
analytical workflow has an index/overview and focused bounded follow-up; tools retain
their own row/byte/frame/instruction/line coordinates. ILSpy text and Ghidra function
decompilation now default to 16000 Unicode-character windows, with explicit offsets,
observed-text SHA256 and native source truncation. Pages from changed text cannot be
silently combined. Full bounded ILSpy text can still be written to an ordinary file.
Managed assembly reference/resource previews also expose their individual truncation.

[Native global CLI proof](verification/toolbox-overview.json) selected managed methods,
paged actual ILSpy and Ghidra text, independently checked full-file hashes and retained
scope/identity through the final page. Offline regressions cover supplementary Unicode
characters and a native truncated prefix that remains partial even at page EOF. Other
applications' packet/event/object/stack/symbol bounds retain their dedicated native
receipts. Inventory is 16 analytical families, six capabilities and 25 skills. All
independent cold/prepared and combined inference-agent gates remain separately tracked;
account quota does not stop native implementation or acceptance.

### Combined candidate and renewed agent evaluation

All sixteen analytical families and six capabilities now have public adapters/workflows and
packaged skills (25 skills including the toolbox, RE and artifact guides). This describes
implemented surfaces, not overall acceptance. On source `4027416`, the complete offline
suite passed 204 tests with two explicit opt-in skips; release/admission checks passed 29/29.
The exact globally installed package SHA-256 is
`d1969fd4382ea5d56957d377619dec97e5f95c9cdcd8e2c050362e409f689b61`;
a clean source pack reproduced those bytes. Windows run
[39070879670](https://github.com/iXab3r/insight-cli/actions/runs/39070879670), Linux run
[39070879669](https://github.com/iXab3r/insight-cli/actions/runs/39070879669) and offline CI
[39070879735](https://github.com/iXab3r/insight-cli/actions/runs/39070879735) passed.

The first combined macOS run `e63c150ff2f9411ab4cbe8d76481e1bf` failed: 11 passed,
six failed and four OS-specific scenarios skipped. Five failures were empty-output native
version-probe timeouts on newly extracted LLVM, private .NET or TShark; another was a Frida
attach cancellation before its runtime acknowledgment. Individual earlier proofs remain
valid for their exact artifacts; they do not erase this combined failure. One hundred
subsequent launches of the retained LLVM executable and twelve fresh executable copies
passed. A sampled delayed first execution was in dyld, not the JavaScript gate; this alone
does not establish the cause of the 30-second timeouts. A repeat of the identical package
is being evaluated without increasing deadlines or automatically replaying tool operations.

Real model inference also became available again. Fresh C01 cold/prepared trials found
correct useful static differences, but neither passed the full gate: cold used a Mono
fallback after sandbox AppData/IPC denial, and prepared produced correct metadata evidence
and a byte-verified 15-file checkpoint but reconstructed the wrong profile UUID in its final
checkpoint link. [The reviewed receipt](verification/toolbox-agent-managed-metadata.json)
retains these failures. Common skill guidance now explains the host's normal scoped
permission escalation while preserving the selected profile; artifact/RE handoffs require
saved-file readback and copying the returned path verbatim. Fresh trials, rather than a
relabeling of these failed histories, must verify the change. Historical quota failures do
not excuse these concrete issues or prevent native implementation and verification.

The first guidance retest exposed an evaluator isolation defect: a login shell replaced PATH
and selected the unrelated user global CLI. That cold trial is invalid, even though it found
correct differences. It temporarily granted/revoked Update on the user default profile and
left an additive checkpoint; it did not install a native runtime or change original inputs.
The evaluator now disables login-shell semantics and provides an explicit candidate launcher
that supplies the private preload as an argument, independently of inherited NODE_OPTIONS.
A per-trial invocation journal makes actual candidate use reviewable; a synthetic regression
proves execution with both PATH and NODE_OPTIONS removed. These are test harness controls,
not changes to user host configuration or relaxed sandbox/approval policy. The guidance
prepared trial corrected its final path/readback, but both modes are repeated with the fixed
binding before C01 is accepted. The official [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
describes the non-login-shell setting used by this harness.

With the fixed binding, new C01 cold/prepared trials passed independent review: the cold agent
installed the managed runtime itself, both used actual public metadata/IL comparisons, found
the formula, added-method and P/Invoke differences and kept shifted tokens distinct from
behavior changes. All 17 cold and 11 prepared checkpoint files matched their project bytes;
both final paths were the exact saved receipts and both owners stopped. Timings were
106.3s/110.1s, not a speedup claim. The receipt binds the exact package/skill hashes and retains
all prior failures. This closes the C01 unit model gate only.


### Combined native rerun and further business-unit proof

The unchanged-package repeat completed successfully: macOS run
`ca1bf9b1f40744c7845c1ecd207f829f` passed all 17 applicable scenarios in 15m45s, with four
Windows/Linux cases skipped locally and separately green in their native CI. The
[combined receipt](verification/toolbox-combined-native.json) retains the original six
failures alongside this result. No deadline was enlarged and no unknown operation was
replayed. The subsequent Frida-summary run passed; its exact result is recorded below.

[LLDB cold/prepared unit review](verification/toolbox-agent-lldb.json) now proves the actual
10→130 / 11→109 boundary, register/stack observations and owned-inferior absence without
available author source. Earlier source-assisted histories are explicitly excluded. The new
maintainer fixture producer maps DWARF paths to an unavailable virtual source root while
preserving parameter metadata; both model runs recovered the branch from machine code.
The cold agent conservatively left its own checkpoint readback unverified under the test
project's outside-read rule; maintainer review independently matched all 13 saved files.
Future trial rules explicitly permit the selected profile's returned checkpoint/diagnostic paths.

[C03 unit review](verification/toolbox-agent-binary.json) passed both modes: correct PE
import/export and ELF dependency controls, thin Mach-O identification and independently
verified console→GUI PE copies whose other bytes were identical. [C05 unit review](verification/toolbox-agent-capture.json)
passed both modes: exactly two executions, 109/142 stdout, known exits and declared file
hash changes; comparing retained reports added no execution. Both agents correctly limited
their claims to file metadata rather than inventing result-file contents. All saved files,
final paths, original input hashes and terminal owned jobs were independently checked.

A Frida prepared agent manually counted 28 calls while its retained output held 29; the
boundary findings and hook cleanup were correct. The facade now provides a bounded protocol
summary (total events, script send/error/log counts) in both returned and saved envelopes.
A send message is not universally a function call; skills require selecting the actual hook
payload. Native and offline checks distinguish these counts from inventory records and
service receipts. Common permission guidance also distinguishes a definite "no command was
sent" refusal, which can use the approved execution route, from an unknown mutation outcome.
Those subsequent cold/prepared Frida, heap, packet and triage trials passed and are recorded below.

### Managed profile aliases and expanded independent research

The Frida-summary candidate completed native run `b7c18ad481444e52982894ccea273389`:
17 passed, zero failed, four OS skips, 14m51s. A clean source pack reproduced its exact bytes.
Independently reviewed cold/prepared business receipts now also cover
[Frida](verification/toolbox-agent-frida.json), [ClrMD heap](verification/toolbox-agent-managed-heap.json),
[TShark](verification/toolbox-agent-tshark.json), [DiE](verification/toolbox-agent-die.json) and
[owned HTTP comparison](verification/toolbox-agent-mitmproxy.json). The cold heap/packet tests
were repeated after correcting test policy that had accidentally prohibited their own runtime
downloads; those honest incomplete histories remain recorded. DiE heuristic errors remain
partial, and no packer absence is claimed. HTTP evidence keeps literal URL pairing separate
from the documented version pairing and makes no TLS/cache-hit claim.

A subsequent independent cold interop task exposed a real managed Ghidra defect missed by
external-path acceptance: an install receipt retained `/tmp`, while Workspace resolved the
same profile to `/private/tmp`. The ownership check incorrectly rejected that alias. Runtime
selection now verifies that the recorded and caller profile roots resolve to the same directory,
and rejects an inner installation symlink redirected outside it. Managed storage/probe paths
are canonical once the profile exists; passive empty status still creates no directories.
The exact original profile and first session were continued through the upgraded public CLI,
reached R1 and decompiled the native function. Both old sessions and journals were preserved,
the old selection bytes were unchanged, and their contexts/server stopped. Two consecutive
managed doctor probes also passed. [The recovery receipt](verification/toolbox-managed-profile-alias.json)
records those checks. The alias-corrected combined native run `efb2eb66f0ca47a8bb6368d3bcb12451` passed all 17 macOS cases with four OS skips (16m03s); fresh interop agents separately check autonomous cleanup.

The 1001-method fixture also distinguished API bounds from agent behavior: the first cold
agent kept completed command stdout at 6002 bytes, but prepared requested a 149713-byte
unfiltered saved-index read. That is terminal stdout, not a measurement of model input tokens.
Overview guidance now calls for on-disk short-member filtering, explains full-signature
namespace collisions and points to exact-member decompilation. Fresh bounded-context trials
must verify this refinement rather than relabel the earlier broad read.

Windows source `ea54e0f` passed all seven native facade/lifetime jobs, but its older feasibility
probe failed: `/WaitForIdle` returned success while its own receipt showed the ProcMon driver
not running before the short fixture. The original required owned-file-read assertion is retained;
readiness now requires both the endpoint and kernel driver before starting that fixture.
Native CI verifies this adjustment; no raw system capture is published.


The subsequent driver/CIM wait also failed in legacy native-feasibility run
[39075613185](https://github.com/iXab3r/insight-cli/actions/runs/39075613185), while its scoped
ProcMon registry/first-event/file workflows and dnSpy jobs passed. That legacy user-default,
unfiltered startup path is superseded by the seven real native facade/lifetime jobs. The
existing `native-feasibility` check is now an aggregate requiring success of all seven,
with a receipt explicitly labeled aggregate-only; no actual observation assertion in those
jobs is removed. The historical audit script and failed receipts remain available. Fork
restrictions for private Automation access are preserved.

Fresh alias-corrected interop cold research published and independently read its annotation,
but reviewer status found an owned local server still running after the agent closed its
contexts and IPC owner. That trial is not accepted for autonomous cleanup. The reviewer
stopped only that profile's server via the public CLI and retained all work. Ghidra's short
skill now gives the explicit context → exclusively-owned server → optional IPC-owner order;
a shared worker leaves server shutdown to the coordinator. A fresh cold/prepared retest
verifies the guide rather than erasing this failure.

### Live diagnostics and current native CI

Independently reviewed cold/prepared [stack](verification/toolbox-agent-stack.json) and
[trace](verification/toolbox-agent-trace.json) agents found the actual release-wait path.
The borrowed worker survived each investigation; the controller subsequently stopped only
its own subject. Trace agents collected once and reused the retained trace for ranking and
Speedscope export. Reports explicitly distinguish sampled thread time from CPU consumption
and retain the weak macOS process-birth identity limitation. Every checkpoint file matched
its ordinary project source bytes and the final handoff used the returned path.

Windows run [39076493625](https://github.com/iXab3r/insight-cli/actions/runs/39076493625)
at `5f1f471` passed all seven actual native jobs and the required aggregate. Linux
[39076493599](https://github.com/iXab3r/insight-cli/actions/runs/39076493599) and offline
[39076493608](https://github.com/iXab3r/insight-cli/actions/runs/39076493608) passed too.
The aggregate itself performs no native observation; the seven prerequisite jobs do.
This establishes native CI, not independent Windows/Linux model acceptance.

A second bounded-discovery guide trial still returned a false absence after a large
full-signature index read. That failure remains excluded. The API now adds optional
`ilspy query/compare --name-filter` for case-insensitive short method names, excluding
namespace/type/signature matches; the existing case-sensitive `--filter` contract remains.
The locked managed helper was rebuilt twice with identical bytes. Native and fresh model
checks must establish the actual behavior before accepting this refinement.

The final [C04 cold/prepared interop proof](verification/toolbox-agent-interop.json)
verified the exact declared import/export, native calculation, R2 publication and identical
annotation from a separate context. Reviewer status confirmed both profiles' local server
stopped with no Ghidra processes. The prepared agent's manually transcribed secondary
status JSON was malformed and is explicitly excluded: complete actual merge events and
fresh-context responses establish the result. All saved bytes still matched the project;
that byte check alone does not certify the contents of every manually copied evidence file.

### Bounded method discovery: current result and retained handoff gap

[C06 independent review](verification/toolbox-agent-overview.json) confirms both direct-query
agents used case-insensitive method-name discovery and the exact MethodDef member. Both
answered 20→217 and 27→253 correctly without whole-class decompilation. Maximum completed
command stdout was 11437 bytes cold and 10515 prepared; these figures are not billed token
or actual model-input measurements. Every saved file matched its ordinary source bytes.
The cold agent omitted the exact checkpoint locator in final prose, although it had saved
and read back that checkpoint. Prepared included its locator. The receipt therefore records
`research_passed_handoff_gap`, not an unqualified whole-workflow pass. Earlier false-absence
and broad-read trials remain rejected.

The short-name API native refinement passed Gherkin run
`555c98b4f99444e8bd925a6bb99a77af`. The first C06 extension passed its native assertions but
the Gherkin summary reader rejected a numeric value in its Boolean checks map; that
maintainer receipt-shape error was corrected. The final candidate's complete native rerun
also checks the fixed summary shape. The clean source at `bac359c` reproduces the frozen
candidate byte-for-byte (`f3fab8ab6fd5582f902bb878c58d66366ba60c3c9eb25fb927eff206151bfa99`).
Offline regression passed 206/208 tests with two explicit opt-in skips, release checks
29/29, all 25 skill validators and the offline relocated-package proof. An initially empty
isolated npm cache was populated from the lockfile before the offline relocation retry;
no user npm configuration or global install was modified.

[Initial ILSpy project/resource family review](verification/toolbox-agent-ilspy-project.json)
confirmed both agents recovered the actual source project/configuration, cost 9→108 and
10→107, XOR decoding 0x13→0x49 and the declared Windows import without target execution.
Cold prose incorrectly assigned the resource-list digest to the extracted file and did not
read back or locate its saved project checkpoint. Prepared independently extracted the
resource, compared both copies and handed off a verified complete findings checkpoint.
The cold evidence/handoff gap remains explicit. ILSpy guidance now requires hashing actual
extracted bytes and reading/returning the exact saved path; overview guidance has the same
checkpoint handoff rule. Fresh trials run on that guide-only refinement. Its 382 executable,
runtime and reference files are byte-identical to the frozen combined-native candidate.
The refined package passed all 29 release checks, all 25 source skill validators and the
offline relocated-package proof. Broader model gates are not closed by that native identity.

### Final source-blind project/resource and handoff refinement

Fresh [ILSpy project/resource agents](verification/toolbox-agent-ilspy-project.json)
passed cold/prepared after the guide correction: both recovered an inspectable source
project and a separate resource, independently matched its 64 bytes/hash against the
project copy, retained correct findings and handed off a byte-verified saved findings folder.
No supplied target was executed or compiled. Prior cold errors remain in the same receipt.

The later [bounded discovery tasks](verification/toolbox-agent-overview.json) also returned
both exact saved locators and correct method results with no whole-class decompilation.
Maximum completed command stdout was 10015/12079 bytes. The cold saved report still has its
pending-checkpoint footer: only that footer was updated in the ordinary report after save.
All raw evidence and the analytical report body matched; the record deliberately does not
claim every final project byte equals the checkpoint. Prepared passed the full byte check.
The earlier locator gap is resolved in these trials, while this snapshot-metadata difference
remains explicit. No additional analytical evidence was missing from the cold saved copy.

[The package delta receipt](verification/toolbox-skill-handoff-refinement.json) binds the
new guide-only artifact to the combined-native implementation: only the two skills, their
bundle copies and build manifest differ. All 382 executable/runtime/reference files match.
This does not silently relabel a different whole package as the exact native-tested artifact.

### Earlier combined native implementation baseline

Run `05ba05150f7641e28b55753420524383` passed **17 macOS native scenarios, zero failures,
four OS-specific skips**, in 16m07s on the frozen `bac359c` implementation package. It
includes actual LLDB lifetime/owner-loss and Frida collector/hook faults, the extended
1001-method C06 proof and C04 publication/readback. The [combined receipt](verification/toolbox-combined-native.json)
retains every prior failed/pass candidate separately. The later `75cca82` handoff-guide
package has the same 382 executable/runtime/reference files, a clean byte-identical pack,
its own package/release checks and fresh ILSpy/C06 model receipts.

Windows [39077664218](https://github.com/iXab3r/insight-cli/actions/runs/39077664218) passed
all seven actual native jobs plus their aggregate on `75cca82`. Linux
[39077664171](https://github.com/iXab3r/insight-cli/actions/runs/39077664171) and offline
[39077664196](https://github.com/iXab3r/insight-cli/actions/runs/39077664196) also passed.
The separate prepared Ghidra GUI/debugger model investigation is still under review;
neither static interop nor this native suite silently completes that agent-family gate.


### Ghidra GUI/debugger caller and retained-trace correction

The [GUI model history](verification/toolbox-agent-ghidra-debugger.json) retains sixteen
source-unavailable trials. Earlier trials exposed profile alias rejection, host-yield confusion,
incomplete cleanup, missing live breakpoints and stale CPU coordinates. The latest cold and
prepared business units on the recorded `d807f7f` package both completed actual 10→130 and
11→109 research, both disconnected trace readbacks, R2 publication, independent annotation
readback, byte-identical saved reports, exact final locators and autonomous cleanup. Cold took
868.007 seconds / 92 CLI invocations; prepared took 746.963 seconds / 76 invocations, within
the unchanged 900-second budget. These reviewed unit passes do not erase earlier timeouts or
prove the entire debugger family or the later managed-backend package. No uncertain old CPU
intent or publication was replayed.

Earlier [alias continuation](verification/toolbox-ghidra-debugger-alias.json),
[default-launch](verification/toolbox-ghidra-gui-native.json) and
[entry-stop](verification/toolbox-ghidra-entry-native.json) native receipts retain their
original package identities. The caller candidate `24fb63a` passed two focused cases once,
then failed both CPU cases in an unchanged combined repeat (17 passed, two failed, four OS
skips). That failure prevents claiming stable acceptance from the first pass.

A read-only native diagnostic then established the concrete inconsistency: frame code
address `0x100000464`, PC register `0x100000508`, return register `0x6d` (109), matched
caller SP and fresh stop ID 15. Repeating execution was unnecessary. The corrected owned
adapter verifies live PC/SP registers and exports the top stack PC/function from that
native PC. Caller frames retain unwound code addresses: a recursive native check showed
that caller register aliases can describe the live frame instead of its return address. It dispatches one thread/stack-qualified one-shot caller breakpoint, then the
facade awaits correlated native stop confirmation through the existing owned LLDB
interpreter after the MCP action returns. This avoids waiting under the native RPC's locks.
Automatic PC/SP memory capture and register traversal avoid target-executing evaluation;
explicit agent expressions retain their usual semantics. Transient control breakpoints do
not become static program bookmarks. No user Ghidra installation is modified.

The [caller receipt](verification/toolbox-ghidra-caller-native.json) records exact package,
failed experiments, ordinary/recursive public-CLI cases and the combined repeat. Current
offline checks pass 216 tests with two native opt-in skips and 31 release checks; relocated
npm installation and both actual LLDB supervisor startup/early-stop lifetime tests pass.
These tests do not substitute for independent model or whole-toolbox acceptance.


### Completed cold overview checkpoint correction

The fresh C06 cold trial used the installed artifact
`b702eacbe01b776ea0a1fd18306f97e7fe20d9da403e8dad5d5eddaf412f22f5`
and the unchanged business-only large-assembly question. The independent medium-reasoning
agent selected ILSpy, installed the missing private runtime, narrowed 1,001 methods to the
exact invoice method and retained its complete focused body. Review verified the actual
217/253 calculations, two saved files (4,591 bytes), byte-identical final report/evidence
and the exact checkpoint locator in the final handoff. The trial took 68.810 seconds and
14 public CLI invocations. This closes the prior pending-footer defect for this reviewed
cold unit; the older failure and prepared artifact remain explicit in
[the overview receipt](verification/toolbox-agent-overview.json). It does not replace the
combined exact-artifact toolbox gate.

### Isolated Python-capable LLDB backend

The same `d807f7f` artifact passed the 19-case macOS combined native run in 29m20s, but its
separate recursive focused repeat failed: Apple LLDB 17 exposed caller PC `0x100000464`
while the actual native LR was `0x100000494`, and the target exited. The passing combined
run cannot cancel this failure. A controlled substitution of Python-capable LLDB 22 passed
a recursive workflow and then both ordinary/recursive workflows in 8m33s. A private relocated
LLDB 23.1.3/Python 3.15 closure subsequently passed those two workflows in 8m21s.
These substitutions were diagnostic builds; no hardcoded Homebrew path entered product source.

Ghidra now has its own managed LLDB/Python dependency, using the shared archive installer,
code fingerprint, process ownership and removal rules. macOS 15+ ARM64 install/download
includes it; external Ghidra selection and an explicit offline `--debugger-archive` are supported.
The GUI pins its receipt and the owned debugger supervisor verifies its code before launch.
The separate public LLDB application retains its independently selected runtime. Ghidra's
existing core fingerprint and saved research identities are preserved.

The [immutable runtime mirror](https://github.com/iXab3r/insight-cli/releases/tag/tool-lldb-python-23.1.3-r2)
contains the binary, exact matching sources for nine components, full notices and reconstruction
scripts/layout. Repacking is byte reproducible. A relocated cleared-environment probe loaded
private Python/SSL/SQLite/decimal/lzma without Homebrew or Apple Python. Revision 1 failed
strict Node extraction because of chained symbolic links before any target execution; revision 2
normalizes direct internal aliases and passes that same strict extractor. Its failure remains
recorded instead of weakening extraction safeguards or replacing an immutable asset.

The final managed-backend package is undergoing focused and whole-toolbox public CLI
acceptance, including a new Gherkin case for offline install/doctor, dependency drift, active
context removal refusal, and evidence/external-tool preservation after uninstall. Native and
independent-model receipts remain separately scoped.

A subsequent public-inventory check found that a running managed LLDB was marked
`unverified` under the native `/tmp` profile alias. The ownership verifier now normalizes
only the profile parent, retains Factory's raw process binding and rejects substituted child
links. Debugger records also retain their research session. The native assertion still requires
an authenticated `running` child, and the new regression covers both accepted aliases and
rejected identity/path substitution. Source `457f481` passes 216 offline tests, two explicit
native opt-in skips, 30 release checks, relocated package installation and both real LLDB
supervisor startup/early-stop checks. The final source pack is byte identical to the frozen
`ec498d69480f262700fdcd657ca0235de165477e5d30207410c889b27c73f1c7` candidate.

### Reentrant trace batch and checkpoint correction

The unchanged `457f481` package subsequently passed its two focused CPU cases, but the
combined repeat passed 19 and failed the recursive case at trace checkpoint (four host skips).
The correlated native receipt verified caller PC/SP; no second CPU action was issued. The
checkpoint and attempted close could not obtain the trace lock. The retained cleanup receipt
verified inferior exit, and the GUI/supervisor/LLDB/inferior PIDs were later independently absent.
The profile, request journal and trace material were retained. This is a real failed repeat,
not stable acceptance inferred from the earlier focused pass.

Inspection found a separately reproducible deadlock pattern in the pinned SDK Python client:
`Client.end_batch` waits for remote results while holding the mutex needed by reentrant reply
callbacks. The owned adapter releases that mutex before waiting. Model transactions abort on
failure, batch cleanup runs in `finally`, and tracked transaction state is reset on failure.
The caller observer yields while trace batches remain active before/after stopped-trace
synthesis; it does not hold a new global lock or repeat execution. A bounded regression fails
on the pinned implementation, passes on the adapter, and verifies model transaction/batch
cleanup. The actual pinned wheels were patched and syntax-checked successfully.

Source `f3ea16f` has 216 passing offline tests, two explicit native opt-in skips and 31 passing
release checks. Its relocated package check passes, and its source pack matches frozen artifact
`87c0807bdbf3043eb0ce4b381ff024c66ca8beb9218b537d49f07e3fd1909ab0` byte for byte.
A fresh public-CLI recursive preflight completed all 33 calls: actual arguments 5/4/3, return 6,
one-frame stack reduction, request replay without execution, disconnected trace readback,
byte-identical saved evidence and native cleanup. The complete 24-case repeat is recorded in
the caller/combined receipts; independent model and whole-toolbox agent gates remain separate.

### Final managed-backend combined native acceptance

Run `07cdc39c00724feab3b0bc563fbbf9f0` passed **20 macOS native scenarios, zero failures,
four declared host skips**, in 21m35s on the unchanged frozen `f3ea16f` package above. The
recursive checkpoint that failed in the previous combined candidate now passed alongside
ordinary caller/stack/register verification, two disconnected traces, private LLDB/Python
installation/doctor/drift/removal, the real standalone LLDB/Frida lifetime faults and the
remaining toolbox workflows. A separate recursive preflight passed on that same package.

Windows [39100877533](https://github.com/iXab3r/insight-cli/actions/runs/39100877533) passed all
seven scoped native jobs and their aggregate. Linux
[39100877444](https://github.com/iXab3r/insight-cli/actions/runs/39100877444) and offline
[39100877450](https://github.com/iXab3r/insight-cli/actions/runs/39100877450) also passed on
`f3ea16f`. The [combined receipt](verification/toolbox-combined-native.json) identifies this
revision as the latest native-tested implementation. The separately reviewed model units
retain their original package identities; complete GUI/family/host model and whole-toolbox agent
gates remain open. Draft PR #55 remains a review artifact, with no npm publication implied.
