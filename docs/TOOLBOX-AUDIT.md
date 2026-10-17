# Toolbox inventory and delivery audit

Audit date: 2026-10-17. TB-01 is in progress. These are frozen upstream candidates,
not full toolbox delivery or agent acceptance. 7-Zip now has a working adapter/skill and
passed its isolated globally installed public CLI developer proof; its cold/prepared agent
gates remain open. Existing Ghidra/ILSpy runtime acceptance
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
| T04 | [LLVM 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | readobj/objdump/nm/pdbutil, selected dylibs; macOS ARM64 official bundle | Apache-2.0 with LLVM exceptions. Retain notices and selected dependency closure; avoid making a full compiler toolchain a prerequisite |
| T05 | [7-Zip 26.04](https://github.com/ip7z/7zip/releases/tag/26.04) | `7zz` list/test/extract into new output directory; macOS native bundle | LGPL/BSD/unRAR terms and matching source; immutable binary/source release companions |
| T06 | [dotnet-dump 10.0.750501](https://www.nuget.org/packages/dotnet-dump/10.0.750501) | collect/analyze + SOS, private .NET, matching native RID and DAC support | MIT plus dependencies; package declares net8 with major roll-forward. Prove .NET 10 compatibility and actual owned dump/object workflow |
| T07 | [dotnet-stack 10.0.750501](https://www.nuget.org/packages/dotnet-stack/10.0.750501) | report owned managed-process threads/stacks; private .NET/diagnostics transport | MIT plus dependencies; exact runtime/process association and real stack task required |
| T08 | [dotnet-trace 10.0.750501](https://www.nuget.org/packages/dotnet-trace/10.0.750501) | bounded collect/report/convert; private .NET | MIT plus dependencies; retain conditions and actual trace interpretation |
| T09 | [Frida 17.24.0](https://github.com/frida/frida/releases/tag/17.24.0), [frida-tools 14.11.0](https://pypi.org/project/frida-tools/14.11.0/) | Spawn/attach/hooks on owned fixtures; private Python, pinned tools/core wheels and transitive dependencies | wxWindows Library Licence 3.1; preserve dependency licenses. Native attach/signing prerequisites require actual macOS proof |
| T10 | [LLDB 23.1.3](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3) | Selected LLVM debugger bundle; inspect existing Ghidra LLDB ownership hooks before adding a frontend | Apache-2.0 with LLVM exceptions; native owned-inferior proof and cleanup; no duplicate owner or arbitrary PID kill gateway |
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
| `LLVM-23.1.3-macOS-ARM64.tar.xz` (release metadata; not yet independently downloaded) | 1569721928 | `3dcfd88aec10be204a24037bcb0dc0ad777882e9dbe8ac60e2639060d8a794b1` |
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
  dnSpyEx debug/edit automation still need their own adapter/agent evidence.
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
