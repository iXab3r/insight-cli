# Persistent client and fast inspection observations

The owner approved this narrow V1 on 2026-10-20. Research loops can keep a packaged client of the
existing Factory stream alive across calls. Compact function inspection reads native state
through a precompiled ReadOnly endpoint, retaining the before/after consistency guard.

The [verification report](verification/persistent-inspect.json) identifies the immutable installed
artifacts, source hashes, native controls and matched workload. This is a development candidate;
Factory dependencies, command routing, permissions and lifecycle policy are unchanged.

## Packaged client

```js
import {connectInsight} from '@eyeauras/insight-cli/persistent';
const cli = await connectInsight({executable: 'insight-cli', cwd: projectDirectory});
const result = await cli.execute([
  'ghidra', 'functions', 'inspect', '--session', session, '--target', target,
  '--function', 'main', '--fields', 'entry_point', '--include-call-context', 'false'
]);
// Reuse cli for subsequent queries.
await cli.close();
```

The module starts one child with `--json-rpc`, sends the existing `cli.execute` envelopes, queues
requests in order and correlates IDs. It returns original results, retains typed command-error
data, bounds framing and fails the stream on malformed/uncorrelated replies. Transport failure
does not reconnect or resend. Queued work that never reached the stream remains undispatched;
an unacknowledged sent request retains uncertainty. `close` drains admitted requests and ends
the connection. It does not issue owner/server shutdown commands.

The canonical module lives in the skill npm workspace. The package exports `persistent`, and
the three entry skills link a self-contained generated copy for agent hosts whose module
resolution does not include the installed npm prefix. The [agent reference](../skills/ghidra-coordinator/references/persistent.md)
describes lifetime, errors and request/status recovery. Root package and explicit legacy deep
paths remain resolvable with ESM and `require`.

## Native observation

```http
GET /insight/research-view/v1?program=/program
Authorization: Bearer <owned-worker-token>
```

```json
{"protocol":"insight-research-view-v1","modification":"42","language":"x86:LE:64:default","compiler":"windows"}
```

The service selects an exact, already-open domain-file path through the provider's open-program
inventory, uses the native threading strategy and reads three facts. It does not open programs,
start analysis, transact, save or execute a script. Normal scanner/schema registration places it
behind the existing bridge authentication and HTTP guard in headless and GUI modes.

Only `functions inspect` selects the fast observation path. The facade verifies process/source
binding for context open, the first observation, the actual function read and the second
observation. Facts and incarnation come from the same verified record for each observation,
removing the old duplicate selection within that one observation. Both observations still run.
Protocol versioning is validated and stripped before constructing the existing logical view
identity. A changed counter/incarnation/view, malformed response, missing endpoint, binding
failure or lost observation fails the read; no fallback silently weakens the guard.

Public inspect arguments, returned fields, text bounds, saved-file behavior and `--expect-view`
semantics remain the contract. Other observation consumers retain their previous path.

## Validation

The installed public client matches one-shot results, preserves the benchmark's
`getFunctionBefore` compile rejection and permits the next read in that same context. Closing
the client leaves the owner available. Native traces show two fast view reads and no
`/run_script_inline` per compact inspection.

Disposable native controls cover a real program edit between observations, actual close/restart
with an obsolete continuation view, malformed/lost read replies, authentication and rejection
of an unopened program. PID and source-SHA mismatch controls inject foreign native response
facts over the real bridge; they are not claims of an actual foreign process/program swap.
Failed reads leave the saved snapshot/generation available and do not replay the native query.
Both headless and owned GUI controls passed, with owned cleanup acknowledged.

Offline checks include framing split inside multibyte UTF-8, literal argv, command-error data,
one child/ordered admission, graceful drain, lost mutation acknowledgment with no replay,
undispatched queued work, malformed/oversized responses and module resolution compatibility.
The complete suite passed 272 tests with four existing skips; 33 release checks and the isolated
spaces/Unicode package/resource relocation proof passed.

## Matched measurement

The before/after runner uses the same deterministic sparse PE and the original three operations:
32-byte memory read, compact `main` entry-point inspection and context status. Each operation has
24 samples per transport per build: 288 measured requests total. Both builds use the identical
packaged client bytes. Separate profiles/contexts permit immutable old and new builds to stay
warm together; queries never overlap. Build order alternates before/after and after/before by
round; the original alternating transport/operation order remains inside each round.

Setup, first import/JVM work, handshake, warmups, gate waits, transcript writes and agent tool
latency are excluded. Each build checks its exact full result hashes and unchanged saved state,
owner and native process records. Cross-build comparison validates the requested scope, then
normalizes scope IDs, view identity and the native provider's revision epoch/save-time/token.
It preserves native modification counts and flags, recursively sorts object keys and preserves array order.
Nested native/backend/context spans overlap. Outside-handler time is a combined residual,
not an isolated IPC measurement. The shared host has variable load and warm filesystem caches.

```sh
node scripts/benchmark-cli-before-after.mjs --ack-disposable \
  --before <old-frozen-installed-package> --after <new-frozen-installed-package> \
  --root <new-absolute-fixture-directory> --java <jdk>/bin/java \
  --ghidra-home <ghidra> --rounds 24
```

The verification JSON retains all measured latencies and phase aggregates. Exploratory runs,
including the initially rejected return type and an initial comparator that incorrectly treated
object-key order as content, remain private. The final verifier binds every recorded response
hash to its retained raw sample before comparing content with fixture-specific identities normalized;
this correction does not alter recorded command timings.

Final counterbalanced results on the shared host:

| Operation | Before one-shot p50 / p95 | After one-shot p50 / p95 | Before persistent p50 / p95 | After persistent p50 / p95 |
| --- | ---: | ---: | ---: | ---: |
| Memory, 32 bytes | 1398 / 3618 ms | 1399 / 2903 ms | 36.4 / 56.1 ms | 37.0 / 49.9 ms |
| Compact inspect | 1903 / 4553 ms | 1477 / 3038 ms | 719 / 1294 ms | 65.3 / 92.7 ms |
| Context status | 1377 / 2984 ms | 1334 / 2363 ms | 6.51 / 15.8 ms | 4.82 / 9.80 ms |

Persistent compact inspection improved about 11 times at p50. The same 72 persistent requests
took **17.61 s before / 3.43 s after (5.13×)**, excluding connection setup. Connection startup
was 690 / 653 ms (one sample per build). This host was slower than in the earlier short-call
report; comparisons use this counterbalanced pair rather than attributing host-load differences
between reports to code.

The two inline-script observation requests consumed p50 **603 ms together** before. The two
precompiled observations consume **3.60 ms together** after. Compact inspect's complete facade
handler p50 is 707 / 61.6 ms. Native HTTP request count fell from 27 to 19: process/source
verification occurs at the four retained boundaries rather than the old duplicate selections.
Factory still accounts for a large combined outside-handler residual on one-shot calls;
memory-read outside-handler p50 is about 1370 / 1366 ms. No isolated IPC improvement is claimed.

## Reproducible bridge patch

The pinned bridge changes only the `AnnotationScanner` constructor registration and adds
`com.eyeauras.insight.InsightResearchView`. All other original class/resource bytes match the
upstream prepared artifact; ZIP ordering/timestamps are normalized. The helper is compiled
ahead of requests. Original license/notice remain, with an explicit modification notice and
source/build/ASM/JDK hashes in `runtime/research-view.provenance.json`.

```sh
git show 6e4bfc9:skills/ghidra-coordinator/runtime/GhidraMCP-7.0.0.jar > <original-jar>
node scripts/build-research-view-bridge.mjs --input <original-jar> \
  --java <jdk>/bin/java --ghidra-home <ghidra> \
  --output <prepared-jar> --receipt <provenance-json>
```

The builder refuses any other input digest and requires exactly one constructor insertion.
Two builds reproduced the same prepared jar. Package admission checks the jar and helper source
against provenance. The new CLI and bridge are shipped as one verified pair; live workers are
not patched in place. This work does not claim global installation, profile migration, registry
publication, a full native facade reacceptance or a fresh game-RE agent benchmark.
