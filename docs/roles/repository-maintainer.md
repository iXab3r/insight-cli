# Repository maintainer

Own reproducible npm install/build/test/pack and offline CI. Pin runtime dependencies and retain
lockfiles. [Release CI](../RELEASE-CI.md) owns the verification and npm release procedure. Factory owns the existing external IPC lifecycle; extend it there when required,
not through a second host here. State package source,
license and artifact hashes. Inspect packages in isolated installs without author paths or source
checkouts. Separate dependency acquisition from offline execution. Registry publication requires
its own user request; do not infer it from source publication.
