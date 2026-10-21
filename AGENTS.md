# insight-cli agent router

This repository develops the game-agnostic `insight-cli` facade and matching skills. Targets
and sessions are shared above tool namespaces such as `ghidra`. Read the relevant
[design](docs/DESIGN.md) and [CLI scenarios](docs/CLI-SCENARIOS.md) before changing a public contract.
The original M0–M5 delivery is complete on its recorded acceptance revision; the publication
prototype remains a scoped regression fixture. [Project history](docs/PROJECT-HISTORY.md),
[milestones](docs/PLAN.md), [work items](docs/WORK-ITEMS.md) and [coverage](docs/GHIDRA-COVERAGE.md)
retain accepted decisions and exact evidence boundaries. Follow the current task and its existing
authorization; historical plans are not a request to restart delivery or implement unrelated work.
Do not reopen confirmed owner choices or treat historical acceptance as proof of a changed build.

AGENTS.md and docs/roles/ are shared across current harnesses. Load these canonical files
explicitly when automatic instruction loading is unavailable; do not create duplicate role policy.

| Surface | Read next |
| --- | --- |
| Ghidra target/context binding, journals, merge/refresh and publication | [coordinator maintainer](docs/roles/coordinator-maintainer.md) |
| Shared tool runtime or another tool adapter | [tool runtime](docs/TOOL-RUNTIME.md), [adding tools](docs/ADDING-TOOLS.md), plus the affected tool contract |
| `SKILL.md`, references, packaging | [skill maintainer](docs/roles/skill-maintainer.md) |
| CI, dependency updates, releases | [repository maintainer](docs/roles/repository-maintainer.md) |
| `tests/acceptance/**`, Automation runner | [Gherkin acceptance](docs/ACCEPTANCE-AUTOMATION.md), [business gate](docs/BUSINESS-ACCEPTANCE.md) |

Factory owns commands, output, profiles, secrets, permissions and IPC lifecycle. Do not copy
its core or build helper. Helpers live canonically under the skill npm workspace. Add another
CLI only for a real consumer. Factory owns profile configuration and AppData control state. Analysis data uses configured
profile storage (the installation default for new profiles; AppData before configuration) and migration-owned compatibility paths; no checkout-local
runtime state. Updates are disabled by default. Agents edit isolated working contexts;
the service coordinates shared publication. A local lock cannot enforce server authorization.

Unknown check-in outcomes freeze the lane until history and independent readback establish the
result. Preserve journals and local copies; never retry a check-in blindly or expire a live owner.
Default tests are offline; real writes use only explicitly created disposable fixtures.
Before every commit inspect the tracked tree and staged diff for credentials, personal paths,
private logs and accidental runtime artifacts. Close a task only after its scoped acceptance and delivery are verified.

## Independent architecture and review

Adopt the roles needed for the changed behavior; role adoption alone does not spawn an agent.
When delegation is authorized by the user or applicable instructions, start every architect and
reviewer with no parent conversation or previous-task history. With spawn_agent use
fork_turns="none"; use an equivalent fresh session elsewhere. Give one narrow neutral question
and let the recipient inspect sources and gather its own perspective.

Supply the absolute repository root, relevant guides, goal, accepted constraints, scope/exclusions,
and evidence locations; for review include exact base/head/target and acceptance criteria.
Separate accepted requirements from proposals and unverified claims. Do not forward the author's
reasoning, conversation summary, preferred verdict or another reviewer's conclusions. A proposal
or test result is an artifact to evaluate, not a prescribed answer.

Use a new independent reviewer for a completed candidate, distinct from its author and earlier
design/audit participants. It reports concrete findings, checks and evidence gaps without editing
files or external state. Reuse that reviewer to verify fixes in the same review; identify the final
revision. The integration lead records results and owns authorized Git/tracker/publication writes.
Workers receive disjoint file ownership and must preserve other writers' edits. Read-only prose
does not create a sandbox; actual permissions come from the invoking host.

Verify the changed risk. Docs/setup edits need routing/link and metadata checks, plus applicable
repository checks; do not invent runtime tests or reuse old runtime evidence as a new pass.
