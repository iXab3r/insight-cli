# insight-cli agent router

This repository develops the game-agnostic `insight-cli` facade and matching skills. Targets
and sessions are shared above tool namespaces such as `ghidra`. Read
[design](docs/DESIGN.md) before changing a public contract; distinguish its agreed target model
from the existing publication prototype. [CLI scenarios](docs/CLI-SCENARIOS.md) describe the
agent-facing contract; [milestones](docs/PLAN.md) define the agreed full delivery plan.
The owner chose one full M0–M5 delivery; [coverage](docs/GHIDRA-COVERAGE.md) accounts for the pinned
functionality. This documentation update does not start facade implementation. Do not mark a
milestone complete using prototype evidence alone or reopen confirmed owner choices.
[Work items](docs/WORK-ITEMS.md) order implementation; final acceptance requires the combined full facade.

| Surface | Read next |
| --- | --- |
| `skills/ghidra-coordinator/**` | [coordinator maintainer](docs/roles/coordinator-maintainer.md) |
| `SKILL.md`, references, packaging | [skill maintainer](docs/roles/skill-maintainer.md) |
| CI, dependency updates, releases | [repository maintainer](docs/roles/repository-maintainer.md) |

Factory owns commands, output, profiles, secrets, permissions and IPC lifecycle. Do not copy
its core or build helper. Helpers live canonically under the skill npm workspace. Add another
CLI only for a real consumer. All mutable data derives from profile AppData; no checkout-local
runtime state. Updates are disabled by default. Agents edit isolated working contexts;
the service coordinates shared publication. A local lock cannot enforce server authorization.

Unknown check-in outcomes freeze the lane until history and independent readback establish the
result. Preserve journals and local copies; never retry a check-in blindly or expire a live owner.
Default tests are offline; real writes use only explicitly created disposable fixtures.
Before every commit inspect the tracked tree and staged diff for credentials, personal paths,
private logs and accidental runtime artifacts. Never close the delivery issue on unverified work.
