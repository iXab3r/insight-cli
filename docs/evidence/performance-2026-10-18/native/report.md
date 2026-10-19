# Native performance measurement

**Stopped at the user’s request; the full matrix is incomplete.** Completed measurements remain valid diagnostic evidence. Missing persistence/concurrency, stock-version-factor and native trace/proof phases are not replaced by smoke runs. Strict completeness and performance acceptance are not passed. See [run status and omissions](run-status.json).

Run started: 2026-10-18T15:34:08.578Z. Host: Apple M5, 10 logical CPUs, arm64, Node v26.4.0, Ghidra 12.1.2. Recorded one-minute load: min 4.39, p50 9.83, p95 29.03, max 58.56.

**Occupied-host diagnostic evidence.** This run permits external host work and retains load observations. Version phases are serial, OS caches are not flushed, and results do not establish isolated idle-host acceptance or a causal general speed ratio. Every original sample is retained. No retries replace failures.

Public baseline: npm @eyeauras/insight-cli@0.2.4, artifact `b72f26afe4c42a03e655b5b3d77836ce57aa13daa1da1178cd870d2e77810d38`. Candidate: unreleased source `97e272413fc8974b4ad7be313fc0b248c872eff7`, artifact `01d03023112c2b36e7a540c3436a88929bb86f0f0aad6bad60701ec9f63979fc`. See [identities](identity.json), [per-phase collector hashes](collector-identities.json), [candidate protocol addendum](candidate-update.json), [storage addendum](storage-addendum.json), [dispatcher recovery addendum](resume-addendum.json).

Completeness: FAIL (732 groups, 30 warm / 5 cold repetitions). Useful-output equivalence: PASS. Regression budget: FAIL. Trace coverage: FAIL. Program-only script effects: PASS. These checks remain distinct from the occupied-host limitation.

Every table cell is **p50 / p95 ms (n)**. Failure and censored counts appear when nonzero; full SD/MAD/min/max and all raw rows are retained in the linked JSON files. Declared warmups are excluded. Stock Java 7/Python 6 uses the exact prepared GZF; Java 6/Python 6 is the separate version factor. Stock has no matching read-only bounded pseudo-decode.

Dispatcher recovery: all baseline contention samples and owned cleanup completed before an archival PID-identity check failed. The original nonzero phase exit is retained in phases.json. Archival resumed after read-only verification that reused PIDs belonged to unrelated processes; no measured row was replaced and installed baseline/candidate graph hashes were verified unchanged. See the dispatcher recovery addendum.

## Failed budget checks

Budgets and repetition requirements are unchanged. Missing or short groups fail independently of measured latency regressions.

| Family | Case | Reason | Baseline ms | Candidate ms | Allowed increase ms |
| --- | --- | --- | ---: | ---: | ---: |
| read. | /tiny/analysis/rpc/read.strings | tail regression | 229.18 | 389.22 | 68.75 |
| read. | /tiny/analysis/rpc/read.undefined | tail regression | 238.06 | 330.16 | 71.42 |
| read. | /tiny/no-analysis/cli/read.missing | tail regression | 1857.74 | 2488.37 | 557.32 |
| persistence. | /large/analysis/cli/persistence.new-context | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.peer-context | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.edit | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.durable-replay | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.read-script | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.merge | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.refresh | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.refresh-readback | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.peer-close | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.close | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.reopen | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.reopen-readback | missing case | — | — | — |
| persistence. | /large/analysis/cli/persistence.final-close | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.new-context | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.peer-context | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.edit | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.durable-replay | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.read-script | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.merge | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.refresh | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.refresh-readback | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.peer-close | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.close | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.reopen | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.reopen-readback | missing case | — | — | — |
| persistence. | /large/no-analysis/cli/persistence.final-close | missing case | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.new-context | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.peer-context | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.edit | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.durable-replay | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.read-script | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.merge | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.refresh | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.refresh-readback | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.peer-close | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.close | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.reopen | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.reopen-readback | insufficient or failed evidence | — | — | — |
| persistence. | /tiny/analysis/cli/persistence.final-close | insufficient or failed evidence | — | — | — |
| concurrency. | — | empty evidence | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.long-operation | missing case | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.diagnostic | missing case | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.queued-configuration | missing case | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.independent-read | missing case | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.first-read | missing case | — | — | — |
| concurrency. | /tiny/no-analysis/cli/concurrency.second-read | missing case | — | — | — |

Native functional proofs with tracing off/on: **FAIL**. The [sanitized proof checks](native-proofs.json) cover unchanged decode/snapshot, RPC diagnostics, actual bulk files/manifest, changed views, independently verified saved function mutation and durable-ID replay, input integrity, unsupported language and owned cleanup. Private call transcripts are excluded.

## Prepared warm reads

| Case | Baseline CLI | Baseline RPC | Candidate CLI | Candidate RPC | Stock Java 7 | Stock Java 6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| tiny/no-analysis/read.metadata | 797.75 / 1886.05 (30) | 28.75 / 78.06 (30) | 404.36 / 505.59 (30) | 15.73 / 26.95 (30) | 1.78 / 6.69 (30) | N/A |
| tiny/no-analysis/read.decompile | 1047.48 / 2328.02 (30) | 282.62 / 483.23 (30) | 618.10 / 857.34 (30) | 253.09 / 268.31 (30) | 234.57 / 291.62 (30) | N/A |
| tiny/no-analysis/read.hash-decompile | 1043.34 / 2240.05 (30) | 278.15 / 579.19 (30) | 665.56 / 782.58 (30) | 256.60 / 296.34 (30) | 235.28 / 265.85 (30) | N/A |
| tiny/no-analysis/read.bulk | 1616.12 / 3459.12 (30) | 865.62 / 1482.81 (30) | 1206.60 / 2503.43 (30) | 779.44 / 1159.25 (30) | 467.94 / 531.16 (30) | N/A |
| tiny/no-analysis/read.memory | 799.36 / 2316.55 (30) | 31.72 / 61.03 (30) | 414.63 / 1038.10 (30) | 17.07 / 40.24 (30) | 2.10 / 5.42 (30) | N/A |
| tiny/no-analysis/read.large-output | 697.95 / 1636.46 (30) | 30.56 / 45.64 (30) | 376.41 / 714.04 (30) | 16.87 / 47.94 (30) | 1.92 / 7.66 (30) | N/A |
| tiny/no-analysis/read.paging | 791.63 / 1801.57 (30) | 28.68 / 51.04 (30) | 395.45 / 691.40 (30) | 15.35 / 38.73 (30) | 1.97 / 7.93 (30) | N/A |
| tiny/no-analysis/read.strings | 1067.66 / 2208.49 (30) | 209.03 / 461.45 (30) | 572.74 / 923.31 (30) | 188.35 / 369.95 (30) | 1.95 / 8.55 (30) | N/A |
| tiny/no-analysis/read.xrefs | 820.70 / 1744.89 (30) | 32.19 / 72.08 (30) | 405.54 / 558.03 (30) | 16.34 / 25.01 (30) | 1.77 / 7.13 (30) | N/A |
| tiny/no-analysis/read.missing | 729.25 / 1857.74 (30) | 29.80 / 45.44 (30) | 376.65 / 2488.37 (30) | 16.34 / 35.79 (30) | 1.96 / 7.24 (30) | N/A |
| tiny/no-analysis/read.undefined | 882.76 / 2685.71 (30) | 187.07 / 528.03 (30) | 572.48 / 1232.80 (30) | 185.76 / 288.56 (30) | N/A | N/A |
| tiny/analysis/read.metadata | 487.38 / 808.14 (30) | 22.85 / 37.26 (30) | 312.09 / 479.77 (30) | 14.01 / 21.71 (30) | 2.57 / 4.84 (30) | N/A |
| tiny/analysis/read.decompile | 707.37 / 1111.78 (30) | 260.94 / 286.90 (30) | 530.93 / 924.98 (30) | 252.25 / 283.26 (30) | 242.48 / 349.90 (30) | N/A |
| tiny/analysis/read.hash-decompile | 699.83 / 1193.91 (30) | 262.90 / 283.49 (30) | 529.36 / 1095.48 (30) | 253.62 / 272.43 (30) | 244.67 / 362.59 (30) | N/A |
| tiny/analysis/read.bulk | 1216.15 / 1827.48 (30) | 742.78 / 939.57 (30) | 983.43 / 1809.52 (30) | 696.40 / 1134.05 (30) | 492.21 / 597.33 (30) | N/A |
| tiny/analysis/read.memory | 514.32 / 943.27 (30) | 23.76 / 39.97 (30) | 314.25 / 606.33 (30) | 15.22 / 24.12 (30) | 2.90 / 6.91 (30) | N/A |
| tiny/analysis/read.large-output | 470.50 / 849.98 (30) | 22.99 / 36.41 (30) | 294.79 / 638.15 (30) | 15.96 / 24.57 (30) | 2.99 / 10.47 (30) | N/A |
| tiny/analysis/read.paging | 464.78 / 1179.58 (30) | 23.89 / 49.04 (30) | 293.01 / 634.41 (30) | 13.80 / 25.94 (30) | 2.69 / 7.59 (30) | N/A |
| tiny/analysis/read.strings | 671.62 / 1926.30 (30) | 151.55 / 229.18 (30) | 437.90 / 1072.45 (30) | 148.87 / 389.22 (30) | 3.10 / 7.45 (30) | N/A |
| tiny/analysis/read.xrefs | 522.85 / 888.67 (30) | 34.06 / 47.88 (30) | 320.30 / 586.84 (30) | 20.11 / 36.75 (30) | 2.35 / 7.93 (30) | N/A |
| tiny/analysis/read.missing | 481.60 / 1333.82 (30) | 23.36 / 44.59 (30) | 290.02 / 731.70 (30) | 14.96 / 27.93 (30) | 2.86 / 5.67 (30) | N/A |
| tiny/analysis/read.undefined | 607.87 / 956.65 (30) | 149.15 / 238.06 (30) | 437.04 / 814.27 (30) | 143.11 / 330.16 (30) | N/A | N/A |
| large/no-analysis/read.metadata | 500.62 / 1656.12 (30) | 28.66 / 48.16 (30) | 384.48 / 729.89 (30) | 16.95 / 30.80 (30) | 2.40 / 4.46 (30) | N/A |
| large/no-analysis/read.decompile | 708.05 / 2056.55 (30) | 261.35 / 413.07 (30) | 625.61 / 1063.77 (30) | 259.75 / 272.45 (30) | 240.26 / 275.93 (30) | N/A |
| large/no-analysis/read.hash-decompile | 719.24 / 1971.05 (30) | 263.70 / 411.14 (30) | 618.17 / 1030.21 (30) | 261.14 / 314.12 (30) | 243.49 / 254.89 (30) | N/A |
| large/no-analysis/read.bulk | 1195.47 / 3197.72 (30) | 749.88 / 1361.39 (30) | 1156.11 / 1670.12 (30) | 777.40 / 1141.90 (30) | 474.75 / 583.59 (30) | N/A |
| large/no-analysis/read.memory | 493.26 / 1506.08 (30) | 25.94 / 102.89 (30) | 396.24 / 1032.09 (30) | 17.18 / 36.27 (30) | 2.50 / 3.89 (30) | N/A |
| large/no-analysis/read.large-output | 501.11 / 1797.68 (30) | 56.12 / 108.76 (30) | 432.62 / 826.80 (30) | 64.97 / 89.09 (30) | 31.71 / 62.03 (30) | N/A |
| large/no-analysis/read.paging | 477.87 / 1338.97 (30) | 23.83 / 58.39 (30) | 377.92 / 619.59 (30) | 17.89 / 29.40 (30) | 2.88 / 5.49 (30) | N/A |
| large/no-analysis/read.strings | 659.04 / 2170.72 (30) | 154.03 / 349.29 (30) | 549.95 / 878.19 (30) | 191.56 / 266.60 (30) | 2.84 / 7.56 (30) | N/A |
| large/no-analysis/read.xrefs | 484.66 / 1278.48 (30) | 24.29 / 47.19 (30) | 400.87 / 683.09 (30) | 18.33 / 28.29 (30) | 2.56 / 4.82 (30) | N/A |
| large/no-analysis/read.missing | 452.17 / 1711.47 (30) | 24.06 / 42.03 (30) | 374.86 / 769.72 (30) | 17.78 / 31.24 (30) | 2.46 / 3.19 (30) | N/A |
| large/no-analysis/read.undefined | 600.49 / 2995.38 (30) | 156.72 / 458.46 (30) | 561.31 / 1168.58 (30) | 173.60 / 381.97 (30) | N/A | N/A |
| large/analysis/read.metadata | 478.78 / 736.49 (30) | 21.74 / 36.13 (30) | 299.26 / 354.14 (30) | 14.19 / 18.16 (30) | 2.53 / 4.73 (30) | N/A |
| large/analysis/read.decompile | 696.33 / 1089.42 (30) | 259.00 / 282.16 (30) | 505.52 / 556.72 (30) | 246.59 / 261.91 (30) | 241.19 / 270.71 (30) | N/A |
| large/analysis/read.hash-decompile | 695.89 / 884.56 (30) | 261.36 / 269.37 (30) | 509.78 / 654.67 (30) | 253.53 / 265.67 (30) | 244.56 / 254.88 (30) | N/A |
| large/analysis/read.bulk | 1207.53 / 1894.26 (30) | 734.59 / 793.55 (30) | 958.65 / 1154.86 (30) | 677.89 / 710.18 (30) | 477.32 / 552.73 (30) | N/A |
| large/analysis/read.memory | 488.65 / 919.89 (30) | 23.34 / 35.43 (30) | 299.54 / 346.25 (30) | 14.21 / 17.76 (30) | 2.56 / 3.10 (30) | N/A |
| large/analysis/read.large-output | 500.30 / 707.18 (30) | 52.95 / 74.01 (30) | 307.13 / 412.55 (30) | 56.13 / 66.99 (30) | 31.54 / 44.09 (30) | N/A |
| large/analysis/read.paging | 476.81 / 1090.63 (30) | 23.96 / 37.33 (30) | 274.01 / 345.66 (30) | 14.34 / 20.16 (30) | 3.00 / 7.25 (30) | N/A |
| large/analysis/read.strings | 590.04 / 825.51 (30) | 147.41 / 206.62 (30) | 415.31 / 592.72 (30) | 137.96 / 171.64 (30) | 2.99 / 4.89 (30) | N/A |
| large/analysis/read.xrefs | 494.36 / 643.36 (30) | 33.69 / 42.49 (30) | 307.46 / 396.70 (30) | 19.93 / 38.36 (30) | 2.77 / 4.34 (30) | N/A |
| large/analysis/read.missing | 460.06 / 844.58 (30) | 22.48 / 28.53 (30) | 275.53 / 334.16 (30) | 14.29 / 20.85 (30) | 2.77 / 4.29 (30) | N/A |
| large/analysis/read.undefined | 599.05 / 879.08 (30) | 144.30 / 185.61 (30) | 412.84 / 469.53 (30) | 134.08 / 165.64 (30) | N/A | N/A |

## Paired one-shot CLI minus persistent RPC

Adjacent CLI/RPC requests alternate order each round and use matching prepared private states. Negative deltas are retained. Package versions and stock phases are serial and are not time-paired. These descriptive differences do not isolate a single causal layer. Full pairs and dispersion: [paired overhead](paired-overhead.json).

| Case | Baseline delta p50 / p95 ms (n) | Candidate delta p50 / p95 ms (n) |
| --- | ---: | ---: |
| tiny/no-analysis/read.metadata | 766.69 / 1844.33 (30) | 386.41 / 489.10 (30) |
| tiny/no-analysis/read.decompile | 711.73 / 1982.07 (30) | 356.38 / 606.11 (30) |
| tiny/no-analysis/read.hash-decompile | 717.75 / 1920.60 (30) | 402.00 / 515.06 (30) |
| tiny/no-analysis/read.bulk | 718.80 / 1976.31 (30) | 403.91 / 1585.55 (30) |
| tiny/no-analysis/read.memory | 763.53 / 2280.05 (30) | 395.70 / 997.86 (30) |
| tiny/no-analysis/read.large-output | 672.04 / 1590.81 (30) | 356.41 / 666.10 (30) |
| tiny/no-analysis/read.paging | 761.18 / 1762.55 (30) | 379.75 / 668.93 (30) |
| tiny/no-analysis/read.strings | 807.28 / 1747.04 (30) | 366.73 / 642.22 (30) |
| tiny/no-analysis/read.xrefs | 795.89 / 1707.45 (30) | 391.51 / 533.02 (30) |
| tiny/no-analysis/read.missing | 699.45 / 1816.75 (30) | 360.31 / 2404.16 (30) |
| tiny/no-analysis/read.undefined | 691.05 / 2192.07 (30) | 369.26 / 850.12 (30) |
| tiny/analysis/read.metadata | 464.76 / 778.73 (30) | 296.33 / 448.27 (30) |
| tiny/analysis/read.decompile | 443.13 / 824.88 (30) | 277.56 / 607.02 (30) |
| tiny/analysis/read.hash-decompile | 443.30 / 926.12 (30) | 274.29 / 823.05 (30) |
| tiny/analysis/read.bulk | 478.78 / 934.80 (30) | 296.07 / 679.65 (30) |
| tiny/analysis/read.memory | 490.69 / 915.84 (30) | 300.89 / 558.67 (30) |
| tiny/analysis/read.large-output | 447.50 / 823.31 (30) | 279.48 / 613.58 (30) |
| tiny/analysis/read.paging | 443.86 / 1130.54 (30) | 274.47 / 611.89 (30) |
| tiny/analysis/read.strings | 516.07 / 1610.80 (30) | 298.52 / 719.06 (30) |
| tiny/analysis/read.xrefs | 476.63 / 856.17 (30) | 299.75 / 485.66 (30) |
| tiny/analysis/read.missing | 456.15 / 1289.23 (30) | 276.90 / 686.88 (30) |
| tiny/analysis/read.undefined | 471.03 / 720.54 (30) | 297.97 / 484.11 (30) |
| large/no-analysis/read.metadata | 477.59 / 1607.96 (30) | 367.52 / 707.07 (30) |
| large/no-analysis/read.decompile | 446.51 / 1766.10 (30) | 366.78 / 735.42 (30) |
| large/no-analysis/read.hash-decompile | 458.19 / 1525.30 (30) | 359.14 / 735.47 (30) |
| large/no-analysis/read.bulk | 457.40 / 1996.43 (30) | 371.88 / 748.55 (30) |
| large/no-analysis/read.memory | 467.54 / 1398.56 (30) | 379.06 / 1011.19 (30) |
| large/no-analysis/read.large-output | 450.52 / 1723.01 (30) | 367.86 / 753.20 (30) |
| large/no-analysis/read.paging | 455.19 / 1300.44 (30) | 363.55 / 557.47 (30) |
| large/no-analysis/read.strings | 484.95 / 1839.18 (30) | 368.38 / 611.59 (30) |
| large/no-analysis/read.xrefs | 460.40 / 1246.37 (30) | 376.14 / 664.13 (30) |
| large/no-analysis/read.missing | 430.18 / 1675.99 (30) | 358.10 / 745.09 (30) |
| large/no-analysis/read.undefined | 455.20 / 2594.13 (30) | 378.50 / 759.86 (30) |
| large/analysis/read.metadata | 457.17 / 714.24 (30) | 283.52 / 342.09 (30) |
| large/analysis/read.decompile | 445.08 / 809.10 (30) | 258.60 / 317.83 (30) |
| large/analysis/read.hash-decompile | 436.13 / 623.13 (30) | 261.45 / 344.28 (30) |
| large/analysis/read.bulk | 472.92 / 943.35 (30) | 285.09 / 459.76 (30) |
| large/analysis/read.memory | 466.25 / 884.46 (30) | 286.41 / 330.47 (30) |
| large/analysis/read.large-output | 445.80 / 644.67 (30) | 258.53 / 348.22 (30) |
| large/analysis/read.paging | 452.95 / 1068.11 (30) | 259.11 / 324.64 (30) |
| large/analysis/read.strings | 448.49 / 572.96 (30) | 277.77 / 442.15 (30) |
| large/analysis/read.xrefs | 460.92 / 609.67 (30) | 286.66 / 355.23 (30) |
| large/analysis/read.missing | 437.41 / 812.82 (30) | 260.79 / 320.91 (30) |
| large/analysis/read.undefined | 460.71 / 698.48 (30) | 276.74 / 312.56 (30) |

## Prepared first query in each fresh native trial

| Case | Baseline CLI | Baseline RPC | Candidate CLI | Candidate RPC | Stock Java 7 | Stock Java 6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| tiny/no-analysis/first.metadata | 4237.98 / 5038.33 (5) | 480.06 / 874.90 (5) | 3613.60 / 14141.18 (5) | 273.13 / 980.30 (5) | 3.15 / 8.42 (5) | N/A |
| tiny/no-analysis/first.decompile | 817.36 / 1447.33 (5) | 307.34 / 337.37 (5) | 608.58 / 2275.95 (5) | 298.57 / 426.96 (5) | 305.17 / 448.92 (5) | N/A |
| tiny/no-analysis/first.hash-decompile | 714.21 / 888.80 (5) | 278.28 / 287.58 (5) | 635.00 / 1411.68 (5) | 261.78 / 321.17 (5) | 273.10 / 300.04 (5) | N/A |
| tiny/no-analysis/first.bulk | 2356.82 / 2530.13 (5) | 1614.16 / 2045.51 (5) | 1549.87 / 3862.58 (5) | 1172.17 / 2090.96 (5) | 485.07 / 553.13 (5) | N/A |
| tiny/no-analysis/first.memory | 633.99 / 743.16 (5) | 31.51 / 38.99 (5) | 469.18 / 1530.42 (5) | 32.36 / 71.03 (5) | 3.87 / 5.53 (5) | N/A |
| tiny/no-analysis/first.large-output | 552.72 / 671.10 (5) | 29.20 / 32.82 (5) | 353.09 / 1231.58 (5) | 18.61 / 27.28 (5) | 3.56 / 4.93 (5) | N/A |
| tiny/no-analysis/first.paging | 645.78 / 1430.21 (5) | 34.18 / 48.46 (5) | 312.27 / 1270.67 (5) | 19.76 / 40.69 (5) | 6.53 / 26.00 (5) | N/A |
| tiny/no-analysis/first.strings | 852.28 / 1107.79 (5) | 323.19 / 863.12 (5) | 693.86 / 2056.80 (5) | 362.90 / 1127.07 (5) | 5.64 / 7.14 (5) | N/A |
| tiny/no-analysis/first.xrefs | 625.60 / 2048.14 (5) | 27.61 / 56.44 (5) | 331.55 / 1235.20 (5) | 16.29 / 56.72 (5) | 4.78 / 7.04 (5) | N/A |
| tiny/no-analysis/first.missing | 547.71 / 627.65 (5) | 30.29 / 31.48 (5) | 350.81 / 731.60 (5) | 16.54 / 58.66 (5) | 3.99 / 4.21 (5) | N/A |
| tiny/no-analysis/first.undefined | 770.84 / 826.12 (5) | 279.15 / 393.77 (5) | 563.04 / 2607.77 (5) | 292.80 / 1072.43 (5) | N/A | N/A |
| tiny/analysis/first.metadata | 5878.81 / 13030.61 (5) | 690.16 / 2330.40 (5) | 4322.50 / 5949.43 (5) | 320.84 / 407.67 (5) | 3.17 / 4.64 (5) | N/A |
| tiny/analysis/first.decompile | 1534.25 / 3694.66 (5) | 327.76 / 371.67 (5) | 664.71 / 1256.75 (5) | 319.37 / 334.93 (5) | 270.10 / 397.86 (5) | N/A |
| tiny/analysis/first.hash-decompile | 1132.58 / 1253.82 (5) | 298.99 / 400.61 (5) | 578.66 / 699.76 (5) | 266.97 / 275.64 (5) | 251.67 / 296.34 (5) | N/A |
| tiny/analysis/first.bulk | 2190.64 / 5056.43 (5) | 1654.64 / 1858.86 (5) | 1560.06 / 2247.24 (5) | 1379.99 / 1527.58 (5) | 500.62 / 2329.46 (5) | N/A |
| tiny/analysis/first.memory | 615.21 / 1755.98 (5) | 35.03 / 145.45 (5) | 342.80 / 474.44 (5) | 22.72 / 31.94 (5) | 5.30 / 24.99 (5) | N/A |
| tiny/analysis/first.large-output | 500.53 / 794.05 (5) | 27.65 / 41.54 (5) | 309.21 / 574.87 (5) | 19.37 / 24.10 (5) | 6.18 / 25.85 (5) | N/A |
| tiny/analysis/first.paging | 662.40 / 1756.50 (5) | 29.98 / 88.27 (5) | 342.15 / 442.75 (5) | 17.05 / 24.68 (5) | 13.95 / 16.64 (5) | N/A |
| tiny/analysis/first.strings | 986.08 / 1446.69 (5) | 242.65 / 347.48 (5) | 635.27 / 867.28 (5) | 363.52 / 450.98 (5) | 17.71 / 49.12 (5) | N/A |
| tiny/analysis/first.xrefs | 620.77 / 871.45 (5) | 38.09 / 48.46 (5) | 336.40 / 450.04 (5) | 29.85 / 35.26 (5) | 5.03 / 17.68 (5) | N/A |
| tiny/analysis/first.missing | 505.09 / 737.65 (5) | 27.12 / 33.54 (5) | 296.75 / 406.17 (5) | 17.58 / 21.16 (5) | 4.09 / 20.80 (5) | N/A |
| tiny/analysis/first.undefined | 841.64 / 1050.17 (5) | 282.21 / 428.31 (5) | 557.91 / 699.81 (5) | 272.67 / 350.19 (5) | N/A | N/A |
| large/no-analysis/first.metadata | 3994.30 / 6620.98 (5) | 461.30 / 764.81 (5) | 4625.59 / 8368.00 (5) | 357.57 / 887.05 (5) | 3.86 / 4.99 (5) | N/A |
| large/no-analysis/first.decompile | 1058.71 / 2265.89 (5) | 311.47 / 345.76 (5) | 712.48 / 4678.55 (5) | 310.55 / 940.48 (5) | 294.09 / 348.61 (5) | N/A |
| large/no-analysis/first.hash-decompile | 735.56 / 1182.11 (5) | 281.38 / 299.42 (5) | 587.07 / 1444.38 (5) | 270.46 / 320.25 (5) | 256.16 / 301.63 (5) | N/A |
| large/no-analysis/first.bulk | 2081.33 / 3117.20 (5) | 1494.29 / 1866.05 (5) | 1572.56 / 2685.69 (5) | 1270.75 / 1742.13 (5) | 485.43 / 513.96 (5) | N/A |
| large/no-analysis/first.memory | 585.65 / 622.08 (5) | 28.92 / 45.79 (5) | 370.83 / 764.42 (5) | 25.76 / 31.28 (5) | 4.11 / 9.35 (5) | N/A |
| large/no-analysis/first.large-output | 663.35 / 1205.85 (5) | 116.56 / 128.08 (5) | 421.62 / 719.18 (5) | 111.34 / 159.64 (5) | 125.04 / 275.54 (5) | N/A |
| large/no-analysis/first.paging | 532.98 / 979.54 (5) | 30.36 / 57.71 (5) | 333.69 / 606.73 (5) | 20.09 / 31.22 (5) | 9.03 / 11.29 (5) | N/A |
| large/no-analysis/first.strings | 703.43 / 1670.95 (5) | 243.78 / 342.51 (5) | 715.19 / 1499.63 (5) | 376.32 / 860.37 (5) | 6.37 / 7.74 (5) | N/A |
| large/no-analysis/first.xrefs | 518.42 / 915.82 (5) | 27.74 / 45.98 (5) | 361.58 / 855.18 (5) | 21.96 / 82.26 (5) | 4.51 / 6.36 (5) | N/A |
| large/no-analysis/first.missing | 529.96 / 1164.00 (5) | 26.32 / 41.59 (5) | 333.18 / 796.13 (5) | 17.40 / 30.29 (5) | 4.24 / 6.63 (5) | N/A |
| large/no-analysis/first.undefined | 690.50 / 1616.88 (5) | 241.53 / 805.35 (5) | 587.37 / 1368.89 (5) | 268.09 / 724.45 (5) | N/A | N/A |
| large/analysis/first.metadata | 4947.88 / 5276.72 (5) | 465.93 / 617.63 (5) | 4208.74 / 7036.86 (5) | 272.83 / 496.75 (5) | 3.23 / 5.22 (5) | N/A |
| large/analysis/first.decompile | 945.01 / 3196.53 (5) | 306.66 / 328.88 (5) | 617.92 / 654.66 (5) | 291.75 / 305.82 (5) | 291.49 / 348.51 (5) | N/A |
| large/analysis/first.hash-decompile | 862.31 / 893.45 (5) | 279.83 / 290.32 (5) | 529.17 / 589.76 (5) | 262.26 / 267.09 (5) | 249.08 / 264.65 (5) | N/A |
| large/analysis/first.bulk | 1986.01 / 2298.81 (5) | 1533.12 / 1676.61 (5) | 1391.14 / 1495.63 (5) | 1088.39 / 1242.23 (5) | 482.18 / 494.14 (5) | N/A |
| large/analysis/first.memory | 578.17 / 837.37 (5) | 28.60 / 37.11 (5) | 327.60 / 409.52 (5) | 17.28 / 20.20 (5) | 4.39 / 6.01 (5) | N/A |
| large/analysis/first.large-output | 551.30 / 798.51 (5) | 104.39 / 126.24 (5) | 361.07 / 533.77 (5) | 93.33 / 110.65 (5) | 89.90 / 219.11 (5) | N/A |
| large/analysis/first.paging | 483.49 / 722.37 (5) | 29.49 / 41.52 (5) | 293.32 / 435.36 (5) | 18.57 / 19.36 (5) | 4.86 / 5.49 (5) | N/A |
| large/analysis/first.strings | 761.87 / 982.25 (5) | 268.57 / 319.15 (5) | 615.08 / 763.63 (5) | 315.26 / 405.16 (5) | 7.22 / 11.96 (5) | N/A |
| large/analysis/first.xrefs | 625.34 / 752.93 (5) | 51.15 / 57.71 (5) | 364.20 / 466.30 (5) | 32.03 / 39.89 (5) | 4.53 / 5.21 (5) | N/A |
| large/analysis/first.missing | 552.64 / 613.63 (5) | 28.29 / 33.26 (5) | 287.11 / 346.02 (5) | 16.38 / 18.25 (5) | 3.01 / 4.33 (5) | N/A |
| large/analysis/first.undefined | 679.05 / 926.26 (5) | 241.00 / 298.34 (5) | 502.20 / 1229.90 (5) | 262.36 / 689.46 (5) | N/A | N/A |

## Cold startup and warm server / new input

Insight cold open includes server/model publication and private-context work. Stock server and import stages are separate; a stock import is not an equivalent shared publication. Cold RPC includes fresh transport startup plus an actual public open. See phase-specific first-query results above.

| Input / analysis | Operation | Baseline | Candidate | Stock Java 7 | Stock Java 6 |
| --- | --- | ---: | ---: | ---: | ---: |
| tiny/no-analysis | cold.open | 39055.09 / 49806.36 (5) | 45797.37 / 76935.71 (5) | N/A | N/A |
| tiny/no-analysis | warm.new-input | 33943.70 / 38750.05 (5) | 33448.00 / 38218.63 (5) | N/A | N/A |
| tiny/no-analysis | cold.rpc-process-and-open | 37335.64 / 43911.58 (5) | 33565.65 / 34443.78 (5) | N/A | N/A |
| tiny/no-analysis | cold.server | N/A | N/A | 5711.95 / 9260.95 (5) | N/A |
| tiny/no-analysis | cold.import | N/A | N/A | 15465.10 / 20069.08 (5) | N/A |
| tiny/analysis | cold.open | 48222.82 / 70866.89 (5) | 41157.65 / 73225.49 (5) | N/A | N/A |
| tiny/analysis | warm.new-input | 51404.53 / 56397.65 (5) | 45818.70 / 95494.86 (5) | N/A | N/A |
| tiny/analysis | cold.rpc-process-and-open | 40606.85 / 42451.86 (5) | 36199.37 / 38335.68 (5) | N/A | N/A |
| tiny/analysis | cold.server | N/A | N/A | 3487.49 / 6261.99 (5) | N/A |
| tiny/analysis | cold.import | N/A | N/A | 19681.05 / 26737.16 (5) | N/A |
| large/no-analysis | cold.open | 39380.70 / 45884.82 (5) | 43549.47 / 106276.77 (5) | N/A | N/A |
| large/no-analysis | warm.new-input | 29628.00 / 37580.52 (5) | 33183.48 / 67617.54 (5) | N/A | N/A |
| large/no-analysis | cold.rpc-process-and-open | 40804.86 / 42596.61 (5) | 36145.96 / 38232.88 (5) | N/A | N/A |
| large/no-analysis | cold.server | N/A | N/A | 3629.46 / 6664.49 (5) | N/A |
| large/no-analysis | cold.import | N/A | N/A | 13563.31 / 16540.40 (5) | N/A |
| large/analysis | cold.open | 49393.40 / 88847.31 (5) | 61464.03 / 106514.12 (5) | N/A | N/A |
| large/analysis | warm.new-input | 34028.20 / 54031.70 (5) | 32705.93 / 40816.99 (5) | N/A | N/A |
| large/analysis | cold.rpc-process-and-open | 49375.35 / 62185.46 (5) | 41966.13 / 44269.81 (5) | N/A | N/A |
| large/analysis | cold.server | N/A | N/A | 5786.48 / 8775.99 (5) | N/A |
| large/analysis | cold.import | N/A | N/A | 58393.36 / 63888.64 (5) | N/A |

## Warm insight persistence and independent readback

| Case | Baseline CLI | Candidate CLI |
| --- | ---: | ---: |
| tiny/no-analysis/persistence.new-context | 11818.09 / 36174.73 (30) | 11209.48 / 28624.55 (30) |
| tiny/no-analysis/persistence.peer-context | 11937.19 / 37107.32 (30) | 11773.25 / 30466.33 (30) |
| tiny/no-analysis/persistence.edit | 2875.80 / 7428.53 (30) | 2589.29 / 6174.48 (30) |
| tiny/no-analysis/persistence.durable-replay | 495.81 / 1511.58 (30) | 320.30 / 1316.18 (30) |
| tiny/no-analysis/persistence.read-script | 4355.89 / 10954.29 (30) | 4111.66 / 12625.86 (30) |
| tiny/no-analysis/persistence.merge | 19190.49 / 44064.43 (30) | 17737.24 / 44325.25 (30) |
| tiny/no-analysis/persistence.refresh | 15560.47 / 43275.14 (30) | 13821.77 / 29059.55 (30) |
| tiny/no-analysis/persistence.refresh-readback | 5427.79 / 13238.82 (30) | 4223.16 / 10204.28 (30) |
| tiny/no-analysis/persistence.peer-close | 1582.87 / 3120.20 (30) | 893.96 / 1721.01 (30) |
| tiny/no-analysis/persistence.close | 5048.97 / 14211.92 (30) | 4276.70 / 10008.32 (30) |
| tiny/no-analysis/persistence.reopen | 3701.00 / 13314.77 (30) | 3450.79 / 7132.12 (30) |
| tiny/no-analysis/persistence.reopen-readback | 577.31 / 2727.84 (30) | 347.41 / 851.99 (30) |
| tiny/no-analysis/persistence.final-close | 1039.92 / 3049.09 (30) | 808.06 / 1140.82 (30) |
| tiny/analysis/persistence.new-context | 11249.39 / 17249.63 (30) | 11631.38 / 39312.90 (4) |
| tiny/analysis/persistence.peer-context | 11510.29 / 20296.03 (30) | 13169.73 / 28754.97 (3) |
| tiny/analysis/persistence.edit | 2852.38 / 3937.06 (30) | 3552.90 / 4533.21 (3) |
| tiny/analysis/persistence.durable-replay | 521.53 / 1009.94 (30) | 852.73 / 902.91 (3) |
| tiny/analysis/persistence.read-script | 4281.09 / 5994.09 (30) | 5464.09 / 7003.47 (3) |
| tiny/analysis/persistence.merge | 17793.81 / 41270.41 (30) | 21146.34 / 27723.05 (3) |
| tiny/analysis/persistence.refresh | 14220.88 / 29687.27 (30) | 19145.97 / 47261.54 (3) |
| tiny/analysis/persistence.refresh-readback | 4733.51 / 12516.40 (30) | 6242.42 / 11204.60 (3) |
| tiny/analysis/persistence.peer-close | 1535.23 / 3593.04 (30) | 1573.76 / 2280.42 (3) |
| tiny/analysis/persistence.close | 4452.22 / 11807.67 (30) | 9659.52 / 17538.95 (3) |
| tiny/analysis/persistence.reopen | 3379.54 / 8824.92 (30) | 7984.64 / 10035.27 (3) |
| tiny/analysis/persistence.reopen-readback | 538.53 / 2783.43 (30) | 886.37 / 1013.52 (3) |
| tiny/analysis/persistence.final-close | 1020.25 / 2560.34 (30) | 879.19 / 1528.11 (3) |
| large/no-analysis/persistence.new-context | 11871.96 / 18465.52 (30) | N/A |
| large/no-analysis/persistence.peer-context | 11988.27 / 14889.87 (30) | N/A |
| large/no-analysis/persistence.edit | 3083.12 / 3902.31 (30) | N/A |
| large/no-analysis/persistence.durable-replay | 583.50 / 1061.66 (30) | N/A |
| large/no-analysis/persistence.read-script | 4525.78 / 5858.70 (30) | N/A |
| large/no-analysis/persistence.merge | 19661.94 / 43946.55 (30) | N/A |
| large/no-analysis/persistence.refresh | 14958.47 / 29264.40 (30) | N/A |
| large/no-analysis/persistence.refresh-readback | 4791.89 / 7821.40 (30) | N/A |
| large/no-analysis/persistence.peer-close | 1642.77 / 2658.01 (30) | N/A |
| large/no-analysis/persistence.close | 4799.96 / 6753.18 (30) | N/A |
| large/no-analysis/persistence.reopen | 3466.21 / 5733.49 (30) | N/A |
| large/no-analysis/persistence.reopen-readback | 541.38 / 1780.39 (30) | N/A |
| large/no-analysis/persistence.final-close | 1177.75 / 1442.58 (30) | N/A |
| large/analysis/persistence.new-context | 11867.05 / 16909.51 (30) | N/A |
| large/analysis/persistence.peer-context | 11879.48 / 16629.61 (30) | N/A |
| large/analysis/persistence.edit | 2994.57 / 4883.97 (30) | N/A |
| large/analysis/persistence.durable-replay | 483.93 / 1290.41 (30) | N/A |
| large/analysis/persistence.read-script | 4533.23 / 5675.60 (30) | N/A |
| large/analysis/persistence.merge | 19364.04 / 22321.70 (30) | N/A |
| large/analysis/persistence.refresh | 14767.25 / 19578.99 (30) | N/A |
| large/analysis/persistence.refresh-readback | 4682.68 / 6855.53 (30) | N/A |
| large/analysis/persistence.peer-close | 1266.08 / 2818.21 (30) | N/A |
| large/analysis/persistence.close | 4686.34 / 6173.16 (30) | N/A |
| large/analysis/persistence.reopen | 3449.82 / 4737.01 (30) | N/A |
| large/analysis/persistence.reopen-readback | 529.56 / 1109.12 (30) | N/A |
| large/analysis/persistence.final-close | 1179.01 / 1481.83 (30) | N/A |

A bare stock save performs less work than a merge with journal, shared revision history, immutable snapshots and independent publication readback. The next table reports stock operations separately, without treating those guarantees as equal.

## Warm stock save / close / reopen

| Case | Stock Java 7 | Stock Java 6 |
| --- | ---: | ---: |
| tiny/no-analysis/persistence.read-script | 260.79 / 492.29 (30) | N/A |
| tiny/no-analysis/persistence.edit | 4.67 / 11.11 (30) | N/A |
| tiny/no-analysis/persistence.save | 15.42 / 40.35 (30) | N/A |
| tiny/no-analysis/persistence.close | 5.34 / 17.67 (30) | N/A |
| tiny/no-analysis/persistence.reopen | 9.85 / 26.87 (30) | N/A |
| tiny/no-analysis/persistence.readback | 3.60 / 13.19 (30) | N/A |
| tiny/analysis/persistence.read-script | 382.45 / 596.53 (30) | N/A |
| tiny/analysis/persistence.edit | 3.22 / 7.47 (30) | N/A |
| tiny/analysis/persistence.save | 11.79 / 29.66 (30) | N/A |
| tiny/analysis/persistence.close | 3.00 / 5.14 (30) | N/A |
| tiny/analysis/persistence.reopen | 6.61 / 12.95 (30) | N/A |
| tiny/analysis/persistence.readback | 2.28 / 5.54 (30) | N/A |
| large/no-analysis/persistence.read-script | 164.30 / 490.24 (30) | N/A |
| large/no-analysis/persistence.edit | 2.63 / 4.69 (30) | N/A |
| large/no-analysis/persistence.save | 143.35 / 259.59 (30) | N/A |
| large/no-analysis/persistence.close | 2.81 / 9.23 (30) | N/A |
| large/no-analysis/persistence.reopen | 5.89 / 22.67 (30) | N/A |
| large/no-analysis/persistence.readback | 2.36 / 10.20 (30) | N/A |
| large/analysis/persistence.read-script | 299.00 / 534.06 (30) | N/A |
| large/analysis/persistence.edit | 3.15 / 9.15 (30) | N/A |
| large/analysis/persistence.save | 19.16 / 215.29 (30) | N/A |
| large/analysis/persistence.close | 3.41 / 5.46 (30) | N/A |
| large/analysis/persistence.reopen | 6.36 / 10.54 (30) | N/A |
| large/analysis/persistence.readback | 2.88 / 9.77 (30) | N/A |

## Independent-context contention

| Case | Baseline CLI | Candidate CLI |
| --- | ---: | ---: |
| tiny/no-analysis/concurrency.long-operation | 10406.77 / 11328.24 (30) | N/A |
| tiny/no-analysis/concurrency.queued-configuration | 9405.24 / 10329.56 (30) | N/A |
| tiny/no-analysis/concurrency.independent-read | 8930.91 / 9866.93 (30) | N/A |
| tiny/no-analysis/concurrency.diagnostic | 8903.77 / 9828.39 (30) | N/A |
| tiny/no-analysis/concurrency.first-read | 768.52 / 1510.46 (30) | N/A |
| tiny/no-analysis/concurrency.second-read | 768.19 / 1514.34 (30) | N/A |

The queued profile mutation intentionally reproduces the existing FIFO diagnostic blockage tracked by issue #68. These optimizations preserve scheduling semantics; an improvement in prepared reads does not claim to resolve #68.

## Native timing boundaries

These diagnostic spans are inclusive, can overlap and include Ghidra process initialization. Exclusive summaries subtract the union of immediate children within the same process/request tree. Do not add rows or processes into a critical path. See [all trace stages](trace-summary.json), [sanitized raw events](trace-events.jsonl) and [isolated request windows and call counts](trace-request-windows.json). Maxima remain visible because infrequent long queue waits can fall beyond a global p95.

| Boundary | Count | Inclusive p50 / p95 / max ms | Exclusive p50 / p95 ms |
| --- | ---: | ---: | ---: |

[Program-only script transitions](script-effects.json) retain pending-change counts and unchanged shared/base revisions for every trial. The ordinary opaque-program save/export and durable request path remains active even for the println script. Instrumentation exposes result-file writes and synchronous output enqueue separately; the native trace phase is required to measure those boundaries. output.write does not measure asynchronous OS drain.

## Interpretation and next work

1. Shipped: synchronous full deployed-byte validation, preserving identical hashes and link rejection; cached authenticated static descriptors with fresh request cancellation/token binding and actual input/PID/receipt checks; removal of an unused metadata request; small read-only view guard. See the separate alternating component experiments in the parent evidence directory.
2. Native stage attribution was not recorded before this run stopped. Helper startup, saved-effect inspection and publication readback remain hypotheses to measure, without a native ranking from this dataset. Investigate a reusable independently isolated inspection worker through the existing backend API, while preserving immutable artifact hashing, read-only ProgramDB access, authority checks, unknown-outcome recovery and exact saved-effect verification. Do not skip verification to improve timings.
3. Address the existing queued-configuration/status scheduling problem separately in #68; analysis/progress discoverability remains #69.

The large owned fixture is over 75 MiB and mostly compressible data with small code. It exercises byte volume, copying, hashing and output transfer; it does not model dense proprietary code or high-entropy large-program analysis. No private program inputs were used. All failed/censored samples and the explicit gate decision remain in [raw requests](requests.jsonl), [coverage](coverage.json), [equivalence](equivalence.json) and [budget results](gate.json).
