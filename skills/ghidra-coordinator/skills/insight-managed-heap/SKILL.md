---
name: insight-managed-heap
description: Query structured .NET heap objects, primitive fields and managed stacks from a retained CoreCLR dump through insight-cli dotnet-dump query. Use for bounded offline dump investigation with an explicit matching DAC, preserving uncertainty and immutable input identity.
---

# Insight Managed Heap 0.2.0

Follow project RE/evidence rules. ClrMD is an internal packaged library, not an application
that needs another install. This API reads one immutable dump; it never attaches to a live
process, evaluates target expressions or downloads symbols/dependencies.

1. Use `dotnet-dump status` and `dotnet-dump install` for the existing private .NET runtime.
   No compiler/SDK is needed. Native acceptance is macOS ARM64 CoreCLR only.
2. `dotnet-dump query worker.dmp --json` identifies the dump architecture, CLR runtime and
   heap availability. The managed default DAC is 10.0.13. A different runtime needs an
   explicitly trusted matching `--dac-file /runtime/libmscordaccore.dylib`; matching OS,
   architecture and runtime are required. An external diagnostics selection also needs
   `--dotnet-host /runtime/dotnet`. Mismatch fails; it is never silently ignored.
3. `dotnet-dump query --target TARGET --view objects --type Exact.Type --json` lists object
   addresses and sizes. Heap/Full dumps are normally needed. `--max-objects` bounds scanning;
   a reached bound means partial prefix coverage, never proof that a type is absent.
4. Drill down with `--view object --address 0xADDRESS --type Exact.Type`. Addresses belong
   only to that exact dump. Primitive fields and up to 256 string characters are returned;
   reference fields supply an address for another explicit query. Structs, unreadable
   memory and unsupported field values remain unavailable, without expression evaluation.
   64-bit numeric values and pointers are strings to preserve precision.
5. `--view stacks` returns managed frames; `--thread OS_THREAD_ID` focuses one dump thread.
   Each selected stack is bounded to 128 frames. A dump is a snapshot, not proof that a
   frame is still executing or consuming CPU. Missing code/symbols can leave methods unknown.
6. `--limit`/`--offset` page objects, fields or threads. `--output research/query.json` saves
   this bounded result to a new ordinary JSON file; preserve partial flags in project notes.
   Checkpoint selected evidence with `artifacts save` when useful. Removing the diagnostics
   runtime preserves immutable dump inputs and saved research.

Generated `dotnet-dump query --help` owns options. Existing `analyze --command` remains useful
for focused native SOS text, but SOS output errors are not successful object findings.
