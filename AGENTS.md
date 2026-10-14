# insight-cli agent router

This repository ships independent, game-agnostic CLIs and their matching skills. Read
[design](docs/DESIGN.md) before changing a public contract.

| Surface | Read next |
| --- | --- |
| `skills/ghidra-coordinator/**` | [coordinator maintainer](docs/roles/coordinator-maintainer.md) |
| `SKILL.md`, references, packaging | [skill maintainer](docs/roles/skill-maintainer.md) |
| CI, dependency updates, releases | [repository maintainer](docs/roles/repository-maintainer.md) |

Factory owns commands, output, profiles, secrets, permissions and IPC lifecycle. Do not copy
its core or build helper. Helpers live canonically under the skill npm workspace. Add another
CLI only for a real consumer. All mutable data derives from profile AppData; no checkout-local
runtime state. Updates are disabled by default. Investigators may read and propose; only the
coordinator publishes. A local lock cannot enforce server authorization.

Unknown check-in outcomes freeze the lane until history and independent readback establish the
result. Preserve journals and local copies; never retry a check-in blindly or expire a live owner.
Default tests are offline; real writes use only explicitly created disposable fixtures.
Before every commit inspect the tracked tree and staged diff for credentials, personal paths,
private logs and accidental runtime artifacts. Never close the delivery issue on unverified work.
