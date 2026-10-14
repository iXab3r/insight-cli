# Prepared Factory IPC dependency

`provenance.json` pins the exact upstream commit and SHA256 of the official prepared IPC package.
It is an npm package artifact, not copied Factory source or a product-specific IPC implementation.
The source implements package preparation/election/readiness/compatibility in Factory PR #51.
Core 0.4.1 is consumed from the registry. No registry publication occurred for IPC or insight-cli.

Until a separately authorized IPC registry release, source installs use this locked file dependency;
packed insight CLI and IPC artifacts are installed together. The artifact includes its MIT notice.
To reproduce it, checkout the pinned Factory commit, run npm ci and the IPC build, then
`npm pack --ignore-scripts --workspace @eyeauras/cli-factory-ipc`. Compare SHA256/provenance before
updating. Do not silently replace an artifact under the same filename. Updating changes both the
source pin and file name, then npm lockfile and isolated package proof.
