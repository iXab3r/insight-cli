# npm distribution

The owner authorized npm publication, global installation and verification on 2026-10-16.
The package is `@eyeauras/insight-cli`; its executable and application ID stay `insight-cli`.
The earlier unpublished `@ixab3r` artifacts retain their historical verification identities.

## Install and configure

Use Node.js 24 or newer:

```sh
npm install --global @eyeauras/insight-cli
insight-cli --version
insight-cli --help
insight-cli skill insight-re
```

npm's global executable directory must be on PATH. Installation needs no source checkout,
TypeScript, .NET, Automation or Factory checkout. It does not register skills or edit agent
settings. [Packaged instructions](../skills/ghidra-coordinator/README.md) cover profile creation,
permissions, opening inputs and research. Ghidra 12.1.2 and Java 21 are external runtime
requirements for Ghidra operations; help, skill discovery and ordinary file saves need neither.

The package pins published Factory Core 0.4.1 and MCP SDK 1.32.1. Factory IPC 0.1.0 is the
verified official prepared artifact, fetched by npm from an immutable GitHub tarball URL.
[Provenance](../vendor/provenance.json) binds the URL, source commit, license and SHA-256.
Both npm registry and GitHub access are needed at install time. No separate archive must be
installed manually, and no separate IPC registry release is made by this consumer.
Partial IPC bundling was rejected during preflight because incomplete dependency trees left
missing transitive modules in a fresh global install. The release uses ordinary dependency
resolution, including platform-specific keyring packages selected by npm.

## Prepare and publish

Run from a clean checkout using the locked dependencies:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
npm run pack:cli
npm publish ./artifacts/eyeauras-insight-cli-0.1.0.tgz --access public --ignore-scripts
```

Publish the inspected archive, not an unbuilt workspace. The prepack build prepares Factory's
package manifest after TypeScript compilation. The archive includes the CLI/API, both skills,
references/native helpers, GhidraMCP bridge/license/notice and README. Source tests, private
research files and dependency credentials are excluded. Future versions must update package
and CLI/skill versions together and repeat the install proof. Never overwrite an existing
registry version with different bytes.

Authentication is npm's normal browser login/2FA, outside package code. It grants no insight-cli
runtime permissions. Verify the served version's SHA-1/integrity against the exact local tarball
before claiming publication, then install that exact version from the registry using `-g`.

## Public executable proof

The opt-in [global proof](../scripts/proof-global-package.mjs) runs the real executable from
outside the source tree, in an owned disposable profile. On this macOS Ghidra/Java environment:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/proof-global-package.mjs \
  /absolute/path/to/bin/insight-cli /path/to/7zr.exe /tmp/global-proof.json
```

It checks executable help/version and installed RE skill, ordinary file/folder saves including
source-edit independence, and actual 7zr.exe strings → xrefs → native decompilation. A private
annotation is published once as R2 and read back with native code from a fresh session. The input
hash remains unchanged. Only its own native contexts/server are closed; profile data, snapshots
and journals remain retained. On failure inspect transcripts before retrying a mutation.

The fixed static input is 7zr.exe SHA-256
`256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282`.
This focused distribution proof does not repeat or rebind historical full-facade, GUI or timing
acceptance. Personal installation paths and raw transcripts remain outside Git.
