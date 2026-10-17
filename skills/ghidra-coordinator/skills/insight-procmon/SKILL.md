---
name: insight-procmon
description: Observe actual file and registry access by an authorized running Windows process through insight-cli procmon. Use when static paths or configuration guesses need runtime evidence; inspect retained captures without collecting again.
---

# Insight ProcMon 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Follow the project's RE and evidence conventions. This Windows x64 facade observes an
explicit existing PID. It preserves that process's lifetime and scopes collection to
that PID before capturing; subprocesses are excluded. Administrator privileges are
required by the native driver. Use an authorized elevated terminal; an already running
unelevated insight-cli owner must be stopped before invoking from that terminal.

1. Check `insight-cli procmon status --json`. `procmon install --vendor-direct` explicitly
   downloads Microsoft's pinned Process Monitor 4.12 and verifies its hash. The distribution
   is not mirrored because Microsoft prohibits redistribution. `download --vendor-direct`
   prepares the local cache; `install --archive FILE --offline` accepts matching local bytes.
   `install --executable C:\tools\Procmon64.exe` selects an existing x64 executable.
   `doctor` checks version and owner privileges. Uninstall preserves research and external files.
2. `insight-cli procmon observe --pid PID --duration-seconds 5 --json` records a bounded
   interval. Add `--path "C:\research\settings.json"` for an exact file/native registry path
   once known. Trigger the authorized application action during that interval; a completed
   action before collection began cannot appear retroactively. No matching events means only
   that nothing matching was retained in this interval. A successful `ReadFile` proves a read;
   a failed open alone does not prove configuration was consumed.
3. Use `--limit`/`--offset` to page events or `--output research/access.json` for a new ordinary
   JSON file. The response includes the capture `process` ID and operation counts.
   `procmon inspect PROCESS_ID --json` reuses retained PML and a hash-verified export without
   collecting another interval. After a timeout or interruption, inspect that retained ID;
   incomplete data and unknown outcomes remain partial. No automatic recollection occurs.
4. Private PML/CSV and settings live under profile diagnostics. Our owned ProcMon uses private
   process-local HKCU; user ProcMon settings are preserved. An existing ProcMon instance blocks
   collection/export instead of being reused or terminated. Only our owned collector's process
   tree is killed on owner loss/deadline. Windows driver activity is system-wide internally;
   retained events are destructively prefiltered before capture. Other processes' events are
   rejected by the reader if native scope cannot be verified.
5. Native exports are bounded to 16 MiB/100000 events and retained PML queries to 64 MiB.
   A `partial` response, filtered event, dropped/unobserved activity or unsuccessful export is
   not proof of absence. Keep these limits with findings. Save useful ordinary evidence through
   `artifacts save` when appropriate; no Ghidra context or merge is required.

Generated `procmon observe --help` and `procmon inspect --help` own exact syntax.
