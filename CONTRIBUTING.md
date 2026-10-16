# Contributing

Use Node 24+. `npm ci` acquires locked dependencies; `npm test` builds and runs only offline
synthetic scenarios. Read AGENTS and DESIGN. Public command changes include skill updates.
`npm run pack:cli` prepares immutable artifacts; `npm run test:package` checks isolated installation.
No existing Ghidra database/configuration is part of a normal test. Use disposable fixtures only
for opted-in local acceptance, and publish sanitized counts/assertions rather than raw logs.

Do not commit AppData, personal runtime paths or credentials. Prepared dependency artifacts need
license and exact upstream source/hash provenance. Do not publish npm packages as part of a source PR.
