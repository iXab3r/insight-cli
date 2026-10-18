# Native performance evidence, 2026-10-18

The initial component experiments below ran on an occupied macOS ARM64 host. They
establish component behavior, not isolated end-to-end native performance acceptance.
All rows, including warmups, are retained; summaries exclude declared warmups only.

| Component, n=30 per variant | Before p50/p95, ms | After p50/p95, ms | Equivalence |
| --- | ---: | ---: | --- |
| Deployed-byte artifact verification | 567.11 / 856.05 | 148.29 / 204.99 | All 62 observed build digests identical |
| Read-only Java view guard | 154.05 / 444.81 | 115.45 / 160.84 | All 66 observed values and modification counters identical |
| Trace sink, 100 no-op requests / 200 spans | 0.089 / 0.174 off | 2.908 / 14.572 on | Exact work count; 6,600 emitted records, no dangling parents |

Artifact hashing alternates old/new algorithms on the same installed public 0.2.4
package, with one warmup and 30 measurements each. View guard and trace cost alternate
three warmups plus 30 measurements each. The trace experiment excludes process startup
and measures sink/API overhead, not complete native overhead. Raw JSON is under
`components/`; no private inputs, endpoint credentials, local program paths or raw
research logs are included.

The main serial matrix freezes source `97e272413fc8974b4ad7be313fc0b248c872eff7`,
package artifact `01d03023112c2b36e7a540c3436a88929bb86f0f0aad6bad60701ec9f63979fc`
and resolved deployed-runtime graph
`716ced78afe22b8b1f983d89aa1be74fa5889f759ac9ab8e097ec911ea912e32`.
The earlier `c308a3c77622451ef330dd86b48495a46c9bb7b8aac0995b7ba49743cc75f49c`
was an unmeasured candidate plan, replaced before its first native request. The
original baseline rows and initial identity remain retained. Package-file identity
and resolved dependency-graph identity are distinct hashes; both are verified.
The installed dependency inventory retains actual versions/integrities, including
baseline/candidate `qs` 6.16.1/6.16.0, Node type-package differences and candidate
test-only tooling. Controlled component comparisons use the same installation;
whole serial version phases are descriptive comparisons under host load.
Full native results and attribution are pending; reduced smoke results are not
substituted for the 30-warm / 5-cold protocol.
