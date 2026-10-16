# Coordinator maintainer

Own target/binding validation, durable journals, lane serialization and Ghidra publication.
Read DESIGN and the skill recovery reference. Persist before acknowledgment or remote writes.
Keep every uncertain stage observable and recoverable. Check result content, counts and readback,
not just HTTP success. A batch is staged, not an atomic group of MCP calls. Verify each remote
binding by PID, endpoint, repository/path, SHA and language/compiler/image base. Keep two EXEs
with equal names isolated. Use offline fault-injection tests; real acceptance must own its fixtures.
