# Manual npm release

Open [Release npm](https://github.com/iXab3r/insight-cli/actions/workflows/release-npm.yml),
choose **Run workflow**, leave the branch at **main** and keep **publish** checked.
The default **bump=patch** publishes the next patch after the greater of the source version
and npm's current `latest`. Choose **minor** or **major** for those increments, or **none** to
use the exact committed package version. For example, with source/latest 0.2.0, patch selects
0.2.1, minor selects 0.3.0 and major selects 1.0.0.

The source package version is a baseline. CI applies the selected version to the package,
workspace lock entry and both skill headings in its disposable checkout. The public CLI and
skill-discovery API read their version from the installed package manifest. The release receipt
records the source commit and version transformation; no automated commit or main-branch write
is needed. Historical documentation and dependency versions are never globally replaced.

Uncheck **publish** for a preview build and global installation of its archive. Other branches may run previews; publishing
requires main. There is no publication trigger on push, PR or tag creation.

## What runs

1. Resolve the version once and retain `npm-version-<run>` before a build can publish. Re-runs
   restore that record, validate its run/source/increment and do not query npm to choose again.
2. Check out the dispatched commit on Node 24 and apply the reserved version. Install locked
   dependencies without lifecycle scripts; run offline tests, isolated package installation and
   the normal pack. Verify that tracked changes are exactly the four expected version inputs;
   unrelated or additional edits fail the build.
3. Upload `npm-package-<run>-<attempt>` with `package.tgz` and `release.json`. The receipt binds
   the selected version, source commit/ref, version transformation, byte count, SHA-256 and
   SHA-512 integrity. Download this artifact for manual inspection or local installation.
4. When publish is checked, a separate job in `npm-release` receives OIDC permission and publishes the exact archive
   using npm 11.17.0, public access, `latest`, provenance and disabled lifecycle scripts.
   It does not check out or execute application source, and uses no stored npm token.
5. Read registry metadata back and compare integrity. A job without OIDC permission installs
   that exact registry version globally with a fresh cache, or the archive for a preview. It verifies the real
   executable's version/help, installed RE skill, ordinary file saving and passive Ghidra
   status. It does not repeat the separate native Ghidra acceptance matrix.

Official actions are pinned to commit SHAs. Runs serialize without cancelling a running
publication. Version records and build artifacts are retained for 90 days, and registry readback is retained as
a separate artifact. Workflow/job summaries provide the source and integrity receipt.

## First-time publication authorization

GitHub's `npm-release` environment and npm's trusted publisher must exist before publishing.
Until setup is complete, leave the repository variable `NPM_RELEASE_READY` absent/false.
Publication then fails before any deployment environment is used; previews remain available.
For one-button releases, the environment permits branch `main` with no extra review gate.
This is a persistent deployment access setting; do not remove existing protection to obtain it.

The package-side trust is scoped to this repository, exact workflow filename and environment:

```sh
npm trust github @eyeauras/insight-cli \
  --repo iXab3r/insight-cli --file release-npm.yml \
  --env npm-release --allow-publish --yes
```

After both sides are configured, enable the repository variable:

```sh
gh variable set NPM_RELEASE_READY --repo iXab3r/insight-cli --body true
```

npm requires interactive account 2FA for initial trust configuration. GitHub access and an
ordinary npm login do not replace it. No npm credential is copied into GitHub secrets; never
disable account 2FA to bootstrap CI. After setup, the workflow uses short-lived OIDC credentials.
See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) and
[npm trust](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

## Re-runs and failures

**Run workflow** is a new release intent and resolves a new version. **Re-run jobs** keeps the
original version, even if npm latest has advanced. Missing/corrupt/expired version records fail
instead of silently allocating another version. If initial version allocation failed before its
artifact was uploaded, start a new workflow. Package downloads use the exact build artifact ID,
so retrying only a failed publication/verification job can reuse a previous attempt's build.

If this version already exists with identical SHA-512 integrity and `latest` points to it,
a re-run verifies and installs it without uploading again. Existing different bytes fail
before publication: commit a new version. The workflow does not move an existing version's
tag automatically. A version below the observed current latest is rejected before upload.

An unsuccessful publish response causes bounded read-only registry checks. If the matching
version is visible, the run continues; otherwise the job fails. It never automatically repeats
the upload. After a missing registry response, inspect the run before a manual re-run.

Build success is not proof of package-side authorization or publication. The release is
complete only when **publish** and **verify-global** succeed. A build-only run can verify
the pipeline before one-time authorization is available. Version and installed CLI/skills are
also checked in preview mode.

## Verified initial release

The [0.2.0 release run](https://github.com/iXab3r/insight-cli/actions/runs/38960073085) passes
all three jobs. One-time authorization is configured, with no stored npm token. Its archive
matches the native-tested macOS archive byte for byte, and npm provenance identifies the exact
main commit. The registry installation also passes on macOS.
[Release receipt](verification/npm-release-0.2.0.json) records the source, hashes, jobs and boundaries.

Clean builds explicitly set the CLI entrypoint's POSIX executable mode before preparing identity,
so a pre-existing output file cannot change archive integrity. npm receives `./release/package.tgz`;
the `./` is required to avoid GitHub-shorthand parsing. Both preflight corrections are covered
by packaging/publication checks.
