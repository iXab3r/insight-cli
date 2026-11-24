# npm distribution

For the Vivarium verification and staged release, see [Release CI](RELEASE-CI.md). The receipts below
remain historical evidence of releases made through an earlier, removed pipeline.

The recorded 0.2.0 release includes [managed runtime delivery](MANAGED-GHIDRA-RUNTIME.md).
The historical 0.1.0 receipt and executable proof remain below. Run the historical
`proof-global-package.mjs` only with its matching 0.1.0 executable/artifact; current releases use
the Vivarium build, staged publication and global-install gate.

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
permissions, opening inputs and research. `insight-cli ghidra install` delivers Ghidra 12.1.2,
Java 21 and local server support; external installations remain supported. Help, skill discovery
and ordinary file saves need neither.

Build dependencies pin prepared Factory Core 0.5.2 and IPC 0.1.0 to immutable GitHub archives.
[Core provenance](../vendor/factory-core-fcb793f.json) and [IPC provenance](../vendor/provenance.json)
bind their source commit, license and SHA-256. The distribution bundles the complete locked
CLI runtime dependency tree, including these exact Factory packages. Its Factory dependencies use exact versions,
so global `npm list --all` does not depend on URL metadata that npm drops in global installs.
No Factory registry publication is required. MCP SDK remains pinned to 1.32.1.

Bundling uses a standalone staging directory because npm workspace packing omits hoisted
dependencies. The acquisition step caches every keyring platform binary; each is checked
against the lockfile's SHA-512 and included in the archive. A package built on Windows therefore
also carries the Linux and macOS binaries. Bundled dependencies retain their package metadata
and licenses. The larger archive installs offline without GitHub, the npm registry or a
populated npm cache. Partial bundles are unsupported: the package gate installs into a fresh
global prefix with an empty npm cache, checks the tree, and compares both installed Factory
payloads against the prepared archives.

## Prepare and publish

Run from a clean checkout using the locked dependencies:

```sh
npm ci --ignore-scripts
npm run cache:factory
npm test
npm run test:package
npm run pack:cli
```

Release the inspected archive from `npm run pack:cli`, not a raw workspace pack. This command
builds TypeScript, prepares the complete Factory bundle offline, and calls Factory's canonical
build-manifest helper for the staged package. The archive includes the CLI/API, both skills,
references/native helpers, GhidraMCP bridge/license/notice and README. Source tests, private
research files and dependency credentials are excluded. Future versions must update package
and CLI/skill versions together and repeat the install proof. Never overwrite an existing
registry version with different bytes.

Authentication is npm's normal browser login/2FA, outside package code. It grants no insight-cli
runtime permissions. Verify the served version's SHA-1/integrity against the exact local tarball
before claiming publication, then install that exact version from the registry using `-g`.

## Published 0.2.0

[`@eyeauras/insight-cli@0.2.0`](https://www.npmjs.com/package/@eyeauras/insight-cli/v/0.2.0)
is published with `latest=0.2.0`. [Verification](verification/npm-release-0.2.0.json) binds
source commit `a8479eec06eead393d434486311fddb7eb403303` to the exact native-tested archive:
1,005,214 bytes, 174 files, SHA-256
`ac24a6fa06bacf0f48d6472ebe26b2f6efe68966b47990466494bc5f52c70dab`.
Registry SHA-1/SHA-512 match, and the npm provenance statement identifies that commit and
release run 38960073085.

The build, publication and fresh Linux registry global-install jobs all pass.
The ordinary macOS global installation also uses the registry, with a fresh cache and user npm
config disabled; all 174 installed files match the inspected archive. Version/help, installed
RE skill and managed-runtime command discovery pass. Native Ghidra acceptance is inherited
only through exact artifact equality; its separate scope and platform boundaries remain intact.

## Local global native build 0.5.9

On 2026-10-27 the owner requested a global-install update and a new disposable native proof.
The local 0.5.9 build replaces the observed global 0.5.8 installation. Package and all shipped
skill versions are synchronized; this is a local installation, not an npm registry publication
or a claim about the registry's latest version. The canonical standalone bundle installs offline.

The [global native delivery report](verification/native-global-cli-delivery.json) binds the exact
archive, all installed payloads, global shim/entrypoint and native execution evidence. Its proof
uses the actual global `dist/src/bin.js` with disposable `APPDATA`/`LOCALAPPDATA`, profile and
server, without a backend or runtime-arguments wrapper. Existing product profiles/processes and
`ec2-native` data are excluded. The [native architecture](NATIVE-CLI-INTEGRATION.md) records the
working-copy, native Update/check-in, verification and disposal boundary; GC and migration remain
separate work.

Preflight found and corrected a clean-build executable-mode difference and a relative archive
argument that npm interpreted as GitHub shorthand. The first full run failed before publication;
the corrected run accepted 0.2.0 once. Five offline publication cases now cover local archive
syntax, immutable-version comparison, downgrade rejection and lost-response readback.

## Historical 0.1.0 public executable proof

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

## Published 0.1.0 receipt

[`@eyeauras/insight-cli@0.1.0`](https://www.npmjs.com/package/@eyeauras/insight-cli)
was published with `latest=0.1.0` at that release. [Verification](verification/npm-release-0.1.0.json)
binds source commit `e800acfa3e8d1e860c847072fa3da9b2f51e1659` to the exact tested tarball:
990075 bytes, SHA-256
`f8448298834d21577aa711086359d82e828f544101fa87da6329724c8170be05`, registry SHA-1
`af8244f84d5c70836c2bb94ef29660ffa422793d` and matching SHA-512 integrity.

The committed rebuild is byte-identical to the candidate tested before publication.
After npm's first-publication processing, ordinary `npm install --global` by package name
succeeded in the machine's default prefix, with an initially empty cache and user npm config
disabled. The real PATH command reports 0.1.0. All 164 packaged files and 80 IPC files match
the inspected sources byte for byte. The registry installation passes the same native 7zr.exe
research, private annotation, single R2 merge, fresh readback, file/folder save and owned native
cleanup proof as the candidate. Node 26.4.0 is used for actual global execution; 139 offline
tests and the locked isolated-package checks pass on Node 24. Release-source CI is green.

The receipt retains preflight corrections and the initial registry 404 propagation delay.
There was one accepted publication; no repeated upload or replacement version was used.
The copied EXE, profile names, personal paths and raw CLI output remain outside Git.
