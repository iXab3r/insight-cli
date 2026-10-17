---
name: insight-capture
description: Capture one explicitly authorized native program run, exact stdout/stderr and declared file snapshots through insight-cli capture, then inspect or compare retained reports without replay. Use for controlled input/output research, preserving original files and interrupted or unknown outcomes.
---

# Insight Capture 0.2.0

Follow project RE and evidence conventions. Use this only for an authorized runtime
observation. The current native host/input profile is macOS14+ ARM64 thin Mach-O
executables. There is no extra install, compiler, shell string or implicit active target.

1. `capture run ./program --arg normal --input-file ./settings.txt --watch settings.txt result.txt --output research/run.json --json`
   copies the selected program and input files into a fresh owned working directory.
   Input files retain unique basenames; arguments are literal, without shell expansion.
   To pass an option-shaped subject argument use `--arg=--subject-option`.
   `--stdin-file FILE` supplies exact bytes, bounded to 1 MiB.
2. The result gives the immutable program target/hash, copied input hashes, request ID,
   known subject exit/signal, bounded output previews and declared file changes. Known
   nonzero subject exits (0–126) are observable outcomes; reserved launcher failure,
   signal, timeout, overflow or unavailable files leave a partial capture and nonzero CLI.
   Exact output bytes are stored as base64 with SHA256; UTF-8 previews may replace invalid
   characters. Binary output should be read as base64, not reconstructed from a preview.
3. `capture show REQUEST --view stdout --limit 256 --offset 0 --json` pages retained bytes;
   `--view stderr` and `--view files` focus other evidence. `--output FILE` exports a new
   portable report. The default overview remains small; never paste an entire report
   into context just to find one value. `artifacts save` can checkpoint selected files.
4. Only `--watch` relative regular files are snapshotted before/after. A missing file is
   explicit; links, unstable/oversized or unreadable files are unknown. This is not a
   trace of all effects or an OS sandbox: the program still has normal host access.
   The default deadline is 10 seconds (up to 600). Its inherited native alarm survives
   ordinary owner loss; a subject can deliberately replace that alarm. Use stronger
   host isolation separately when required by the actual target or project rules.
5. `capture compare research/before.json research/after.json --json` compares exact retained
   stdout/stderr, exit state and declared resulting files. It never executes the program.
   `sameDeclaredIntent` distinguishes changed input/argv from repeated observations;
   equal fields do not establish causal/semantic equivalence or a speedup claim.
   Partial reports cannot prove global equality. Imported reports are asserted data,
   not independent proof that an execution occurred.
6. An optional `--request-id ID` binds the exact effective intent. Retrying it returns
   the durable prior outcome, or an explicit unknown/partial state; it never repeats
   the run. A different intent with the same ID is refused. Without an ID each call is
   a new intentional observation. After owner loss, `capture show REQUEST` exposes retained
   intent, process state and working directory; preserve existing files and investigate
   the unknown result instead of blindly launching it again.

Limits: 64 MiB program and total selected files, 16 MiB per selected/watched file,
32 files/watch paths, 64 literal arguments and 4 MiB aggregate native output. No native
merge exists here; publish any Ghidra annotations through their explicit session/target.
Generated help owns options. Local project formats take precedence over this example.
