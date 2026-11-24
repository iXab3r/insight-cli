#!/usr/bin/env bash
# Vivarium entrypoint, run inside node:24-bookworm from the repository root.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mode="${RELEASE_MODE:---verify}"
case "$mode" in
    --verify|--dry-run|--stage|--verify-registry) ;;
    *) printf '%s\n' 'Use --verify, --dry-run, --stage or --verify-registry.' >&2; exit 2 ;;
esac
# Only staging receives the npm credential; every other child runs without CI variables.
stage_token="${NPM_TOKEN-}"
for key in $(compgen -e); do
    case "$key" in
        PATH|HOME|TEMP|TMP|TMPDIR|RELEASE_REVISION|LANG|LC_ALL) ;;
        *) unset "$key" ;;
    esac
done
export CI=true GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$(pwd)"
tools="$(mktemp -d)"
trap 'rm -rf -- "$tools"' EXIT
export NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ NPM_CONFIG_USERCONFIG="$tools/npmrc" NPM_CONFIG_GLOBALCONFIG="$tools/global-npmrc"
: > "$NPM_CONFIG_USERCONFIG"
: > "$NPM_CONFIG_GLOBALCONFIG"
npm install --global --prefix "$tools/npm" --no-audit --no-fund --ignore-scripts "$(node -p "require('./package.json').packageManager")"
export PATH="$tools/npm/bin:$PATH"
if [[ "$mode" == --stage ]]; then
    NPM_TOKEN="$stage_token" node scripts/release.mjs stage
else
    node scripts/release.mjs "${mode#--}"
fi
