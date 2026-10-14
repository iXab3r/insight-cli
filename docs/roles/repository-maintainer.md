# Repository maintainer

Own reproducible npm install/build/test/pack and offline CI. Pin runtime dependencies and retain
lockfiles. Prepare external IPC support in Factory, not a second host here. State package source,
license and artifact hashes. Inspect packages in isolated installs without author paths or source
checkouts. Separate dependency acquisition from offline execution. Registry publication requires
its own user request; do not infer it from source publication.
