# P2 native workflows

The owner requested autonomous implementation, real-Ghidra acceptance, documentation, commit
and push for the remaining P2 findings on 2026-10-15. All selected workflows, combined native regressions and Windows/Linux headless checks pass.
[Final evidence](verification/api-gaps-p2.json) records tested source, receipts and artifact identity.

- [x] N02: categorized native program differences between explicitly selected saved contexts.
- [x] N03: guarded bytes/assembly, memory split/join/move and processor-context editing.
- [x] N08: namespace/class and external library/location CRUD with saved effect verification.
- [x] N09: bounded typed decompiler IR, simplification/options and timeout diagnostics.
- [x] N01: native Version Tracking correlation, durable provenance and explicit association decisions and markup inspection.
- [x] N04: native loader/exporter inventory, selection/options and selected-range export.
- [x] N07: GDT archive round-trip, source identity, packing/bitfields and settings.
- [x] N05: genuine FID/BSim workflows with database identity, scores and no-match semantics.
- [x] N06: guarded live debugger writes and bounded trace objects/timeline/schedule access.
- [x] G07 convenience: direct create-struct placeholder replacement.
- [x] Larger fixtures and affected native/installed regressions; assess native OS availability.
- [x] Reconcile the gap ledger with actual evidence, privacy scan, commit and push.

Factory remains the CLI/API/IPC owner. New program edits are complex private changes with
immutable saved-state verification and unchanged-base publication. External/live effects retain
durable intent and uncertain-outcome rules; they are never replayed blindly.

Additional SDK response-loss acceptance verifies exactly one real patch and independent saved-state
reconciliation. The final artifact matches installed native acceptance; 104 offline tests pass.
