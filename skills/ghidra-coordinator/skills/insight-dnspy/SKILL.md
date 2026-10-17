---
name: insight-dnspy
description: Debug a managed Windows EXE at an IL breakpoint and read primitive arguments, or change one expected IL Int32 constant in a new assembly copy through insight-cli dnspy. Use when C# decompilation needs observed execution or a controlled binary edit.
---

# Insight dnSpyEx 0.2.0

Keep the project's RE and evidence format. Debugging executes the supplied application
in a new owned process; its ordinary file/network side effects still apply. Use only
inputs whose execution is authorized. The original process is not attached or reused.
Windows x64 and an interactive desktop are required. No source code or PDB is required
for a MethodDef token breakpoint and indexed primitive parameter read.

1. Check `insight-cli dnspy status --json`. `dnspy install --vendor-direct` acquires the
   pinned upstream dnSpyEx 6.6.0 bundle and our mirrored private .NET 10.0.13 target runtime.
   dnSpy's own debugger runtime is self-contained .NET 10.0.9. The upstream bundle contains
   separately licensed VS 2017 DLLs that prohibit our redistribution, so its bytes are
   fetched explicitly from dnSpyEx GitHub, checked by SHA256 and cached locally.
   `download --vendor-direct` prepares acquisition first. For offline setup use
   `install --archive dnSpy-net-win64.zip --dotnet-archive dotnet-runtime.zip --offline`.
   `install --executable C:\tools\dnSpy\dnSpy.exe` selects the complete pinned external
   runtime; only its pinned vendor files are copied into owned execution storage. The
   first setup starts a private GUI to prepare a Unicode-compatible Core loader there;
   external originals remain unchanged. Both copies are fingerprinted, and uninstall
   preserves the external distribution. `doctor` checks
   version and exact extension contracts without opening the GUI.
2. Use ILSpy metadata/IL to identify the managed module's MethodDef token (`0x060000NN`)
   and exact decimal IL instruction offset. `dnspy inspect app.exe --method 0x06000002
   --il-offset 0 --parameters 0 --json` launches a private Framework debugger, stops at that
   location, reads selected zero-based primitive parameter indices and records a bounded
   managed stack. After flushing the snapshot, its one-shot GUI exits and the owned Windows Job Object terminates the debuggee; it does not resume the program or rely on UI teardown.
   A token belongs to one exact module; it is not a native address or stable cross-build ID.
3. For a Core application, select its apphost EXE and paired DLL:
   `dnspy inspect app.exe --runtime core --module app.dll --companion app.runtimeconfig.json
   app.deps.json --method 0x06000002 --parameters 0 --json`.
   Explicitly add any required local DLLs with `--companion`; names and captured hashes are
   retained. Managed setup supplies .NET 10.0.13; a different target runtime version may require a compatible explicit host. With an external debugger selection,
   provide `--dotnet-host C:\dotnet\dotnet.exe` for a compatible Core runtime. Self-contained
   applications may need additional declared companions; the facade does not copy a source
   directory or guess startup dependencies. Use literal `--arg` values for program arguments.
4. `dnspy edit-constant app.dll --method 0x06000003 --il-offset 0 --expect-int32 7
   --set-int32 37 --output research/app-patched.dll --json` changes only the selected existing
   Int32 load instruction through dnSpy's loaded document and writes a new assembly.
   A mismatched expected value fails; originals and existing output files are preserved.
   Verify the output independently. Editing can invalidate signatures/strong names and does
   not prove that the changed path executes. No Ghidra merge or original-file replacement occurs.
5. `--target ID` reuses a captured input; debug companions remain explicit. Debug `--limit` and
   `--offset` bound returned stack frames; `--output research/managed-stop.json` saves the full
   bounded result in a new ordinary file. Follow project evidence conventions and use
   `artifacts save` for a checkpoint when helpful. Missing breakpoints, optimized/unavailable
   parameters and runtime/dependency failures are unknowns, not invented values.
6. Every operation uses private settings and an isolated GUI under the Windows Job Object.
   `tools processes --tool dnspy --all` retains jobs and diagnostics. Stop/kill target only an
   owned process ID through `tools processes stop/kill`. Owner loss/deadline kills the owned
   process tree; saved inputs and partial diagnostics remain. Lost responses do not trigger
   automatic relaunch, expression evaluation, attach or edit replay.

Generated `dnspy inspect --help` and `dnspy edit-constant --help` own exact syntax.
