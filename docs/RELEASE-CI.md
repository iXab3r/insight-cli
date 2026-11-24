# Vivarium verification and npm release

Project `EyeAuras_InsightCli` on [Vivarium](https://viv.eyeauras.net/project/EyeAuras_InsightCli)
runs one entrypoint, `build/teamcity.sh`, in a digest-pinned
`node:24-bookworm` image on a Linux agent. Keep the same digest from staging until registry
verification: a different Node can change archive bytes.

| Job | Trigger | Effect |
| --- | --- | --- |
| Verify | every change of `main` | Locked install, offline tests, isolated package installation, unchanged tree |
| NpmStage | manual | One release mode; the default never contacts npm with a credential |

The entrypoint drops inherited CI variables, uses the exact npm in `packageManager` and an empty
npm configuration. Only `--stage` receives `NPM_TOKEN`, and only npm's stage commands inherit it. NpmStage must run one build at a time.

Pull requests have no automatic trigger; run Verify manually on their branch. There is no Windows
or macOS job: platform secrets, storage migration, managed runtimes and process tests specific to
those systems are checked locally.

## Version

The committed package version is the released version. Change it in a reviewed pull request:

```sh
node scripts/release-version.mjs 0.6.1
```

This updates the package, its lock entry and the skill headings. Historical documentation and
dependency versions are not replaced.

## Release

Set `env.RELEASE_REVISION` to the full commit and `env.RELEASE_MODE` to one of:

1. `--dry-run` (default): require the clean exact revision and a version newer than `latest`; run the
   offline gate, pack, install the archive globally in a fresh prefix and exercise the executable,
   then run npm's publish dry run.
2. `--stage`: additionally require that the revision is the current remote `main`. Refuse if the
   version already has a stage. Upload once with `npm stage publish`, save the stage ID before any
   further check, download the stage and compare SHA-512. Nothing is public yet.
3. The owner reviews and approves the stage on npm with 2FA. No job can approve it.
4. `--verify-registry`: rebuild the same revision, require equal registry SHA-512 and `latest`, then
   install that exact registry version. A release is complete only after this passes.

Each release build publishes `npm-release.zip` with the archive, its manifest and `release.json` with the
last reached state. `stage-upload-unknown` means an upload started and its outcome was not read.
After a lost or failed stage response, inspect the retained stage ID and npm's stage list before
another run; there is no automatic retry, tag move or overwrite. `NPM_TOKEN` is a protected job
parameter holding a granular token limited to this package; the owner keeps account 2FA enabled.

Native acceptance is separate and never runs in this job; see [verification](verification/README.md).
