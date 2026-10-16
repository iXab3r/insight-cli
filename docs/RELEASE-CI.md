# Manual npm release

Open [Release npm](https://github.com/iXab3r/insight-cli/actions/workflows/release-npm.yml),
choose **Run workflow**, leave the branch at **main** and keep **publish** checked.
The workflow releases the stable version committed in
`skills/ghidra-coordinator/package.json`; it does not invent a version or edit the source.
Commit the matching CLI/skill version changes before releasing a new version.

Uncheck **publish** for a build-only run. Other branches may run build-only; publishing
requires main. There is no publication trigger on push, PR or tag creation.

## What runs

1. Check out the exact dispatched commit on Node 24. Install locked dependencies without
   lifecycle scripts; run offline tests, isolated package installation and the normal pack.
   Require a clean tracked tree after building.
2. Upload `npm-package-<run>-<attempt>` with `package.tgz` and `release.json`. The receipt binds
   the package version, actual source commit/ref, byte count, SHA-256 and SHA-512 integrity.
   Build-only runs end here. Download the artifact for manual inspection or local installation.
3. A separate job in `npm-release` receives OIDC permission and publishes the exact archive
   using npm 11.17.0, public access, `latest`, provenance and disabled lifecycle scripts.
   It does not check out or execute application source, and uses no stored npm token.
4. Read registry metadata back and compare integrity. A third job without OIDC permission
   installs that exact registry version globally with a fresh cache. It verifies the real
   executable's version/help, installed RE skill, ordinary file saving and passive Ghidra
   status. It does not repeat the separate native Ghidra acceptance matrix.

Official actions are pinned to commit SHAs. Runs serialize without cancelling a running
publication. Build artifacts are retained for 30 days, and registry readback is retained as
a separate artifact. Workflow/job summaries provide the source and integrity receipt.

## First-time publication authorization

GitHub's `npm-release` environment and npm's trusted publisher must exist before publishing.
Until setup is complete, leave the repository variable `NPM_RELEASE_READY` absent/false.
Publication then fails before any deployment environment is used; build-only remains available.
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

If this version already exists with identical SHA-512 integrity and `latest` points to it,
a re-run verifies and installs it without uploading again. Existing different bytes fail
before publication: commit a new version. The workflow does not move an existing version's
tag automatically. A version below the observed current latest is rejected before upload.

An unsuccessful publish response causes bounded read-only registry checks. If the matching
version is visible, the run continues; otherwise the job fails. It never automatically repeats
the upload. After a missing registry response, inspect the run before a manual re-run.

Build success is not proof of package-side authorization or publication. The release is
complete only when **publish** and **verify-global** succeed. A build-only run can verify
the pipeline before one-time authorization is available.
