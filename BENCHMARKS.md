# Benchmarks

## Why insight-cli exists

An RE agent should spend its time understanding a program. Finding evidence, recovering a
session and working around missing analysis metadata should be reusable tool operations.

insight-cli provides isolated, durable research contexts, a persistent client, structured
function inspection and bounded searches over raw strings, code references and PE runtime
ranges. These work with sparse Ghidra databases where defined strings, xrefs and recorded
function bodies can be missing. The agent still has to interpret and verify the evidence.

## PoE 2: gems and player skills

On **October 21, 2026**, two fresh agents investigated gems, supports and player skills in
the same Windows client. One used Ghidra MCP; the other used **installed insight-cli 0.4.0
with its persistent client**. Both had the same prepared snapshot, task and hints, worked
independently, and received the same conceptual follow-ups. The coordinator only
orchestrated and reviewed results.

**Wall time from research start to the finished report:**

| Tool | First run (R1) | Previous run (R7) | Final run (R8) |
|---|---:|---:|---:|
| insight-cli | 28:57 | 17:08 | **16:35** |
| Ghidra MCP | 37:19 | 18:42 | **19:43** |

insight-cli used **15.9% less wall time** in the final pair. Across the series, its total
fell **42.7%**; MCP's fell **47.2%**. These are end-to-end outcomes, not isolated API speeds.

| Final-run metric | insight-cli | Ghidra MCP |
|---|---:|---:|
| First concrete evidence chain | 1:41 | 2:34 |
| Discovery | 2:47 | 2:34 |
| Structure reconstruction | 4:58 | 4:51 |
| Hypothesis validation | 5:25 | 7:41 |
| Report writing | 3:25 | 4:37 |
| Research tool calls | 57 | 50 |
| Persistent client / SDK roundtrips, summed | 63.8 s | 61.3 s |

Both recovered a comparable evidence-backed core: definitions versus per-player state,
support eligibility, component ownership, stat providers and activation paths. CLI went
deeper into stat updates; MCP traced overlay precedence and notifications. Neither proved
the complete damage formula or all modifier ordering.

CLI used packaged sparse-navigation operations; MCP recovered missing metadata through
native scripts. **Fewer calls is not the goal:** MCP batched more functions per call. The
useful outcome is reaching a defensible explanation with less total agent time.

## What these numbers do not prove

- One pair per reported run; adaptive paths, manually marked phases, no statistical
  confidence claim. Preparation/imports are excluded. Heap limits differed: CLI 768 MiB,
  MCP 8 GiB. Roundtrip times are already inside wall time.
- R7/R8 used identical native bridge and persistent-client bytes. CLI's total improved only
  **3.2%**; research before reporting took **1.8% longer**. No further large gain appeared.
- R1 had the same executable but a different prepared snapshot and startup/recovery
  conditions. Its improvement cannot be attributed entirely to insight-cli changes.
- Static client RE proves neither server-authoritative behavior nor zero runtime overhead.
  Raw receipts/logs are retained privately; only sanitized results are published here.

See the [README](README.md) for installation and the public workflow.
