# Recovery

States: queued -> applying -> staged -> checking_in -> publication_unknown -> published_verified.
Conflicting proposals are quarantined as conflict_pending. Other pre-publication failures stay
failed with their batch and stage, and block new integration. The SQLite WAL uses synchronous
FULL transactions; acceptance commits before replying. Batch IDs appear in the native version
history as `insight batch <id>`. Events preserve each transition.

At applying/staged/failed, no persisted check-in intent means the coordinator has not started a
publication request. Preserve the local copy and stop any owned publisher before an explicit
`recover <batch> --abandon-staged`. The runtime saves a backup and requires server checkout
release before clearing the lane. If a checkout remains, perform identified operator cleanup;
there is no automatic terminate-every-checkout operation. Submit fresh reviewed proposals afterward.

At checking_in/publication_unknown, the request may have committed. Recovery only reads history
and uses a new independent reader to verify exact program identity, every proposed value, version
and checkout release. A single matching batch marker plus readback establishes publication.
Missing/duplicate history or a readback mismatch leaves the lane blocked. Recovery cannot discard
an unknown batch and cannot retry check-in. A server operator may need to supply further evidence
and restore availability; this version does not infer non-publication merely from a missing marker.

A live prior owner is never replaced after a TTL. PID reuse may conservatively block recovery;
unknown process identity is not permission to signal or take over. Reader cleanup signals only
receipt-verified PID/endpoint bindings. Publisher stages survive owner disposal when unresolved.
After verified publication their owned processes can be stopped without releasing someone else's
checkout. A hard kill preserves the journal but may leave a Ghidra process requiring explicit cleanup.

These are recoverable staged calls, not a tested atomic remote batch or exactly-once execution.
Do not point real write acceptance at existing databases. Server durability, resource capacity and
Ghidra-version support require evidence for the exact disposable environment being exercised.
