# Controlled native budget fixtures

These are opted-in Windows headless Ghidra 12.1.2/JDK 21 fixtures. Use only a disposable,
non-private native PE. Neither fixture modifies the pinned bridge or a global installation.
Raw transcripts, program identities and absolute paths stay outside the repository.

`LongBudgetAnalyzer.java` is an ordinary SDK analyzer which waits 610 seconds and sets
`LongBudgetFixture.completed=true`. Build it with the installed Ghidra module jars into
an unpacked `LongBudget/lib/LongBudget.jar`; add empty `Module.manifest` and
`extension.properties` with `name=LongBudget`, `version=12.1.2`. The acceptance runner
pins that module through public extension inspect/install. A stock 0.2.2 import is killed
at its old 600-second boundary; the candidate must complete and independently publish R1.

`SlowSaveFixture.java` records a program option and execution count, then installs a
one-shot DomainFile proxy in its disposable JVM. The proxy delays 36 seconds inside the
real `/save_program` call, restores the original DomainFile, and delegates to the real
Ghidra save. This deterministically exercises the transport deadline, actual database save,
packed export, reopen, merge and independent readback. It is controlled fault injection,
not a disk-throughput benchmark or reproduction on a private research input.

Run against an isolated installed package:

```sh
INSIGHT_NATIVE_DISPOSABLE=1 node scripts/acceptance-ghidra-budgets.mjs \
  <package-root> <private-diagnostics> <disposable-pe> <ghidra-home> <java> \
  import <compiled-LongBudget-module>
```

Replace `import <module>` with `save` for the >30-second save/readback case, or `abandon`
for a one-second configured save deadline. Abandon must fail while the original worker
is live, retain its unknown outcome after verified termination, preserve the prior saved
view, and never replay the original script. Use `recover-import` for a one-second import timeout followed by `ghidra budgets set`
and successful continuation of the original request/session/target. Each case uses its own
profile/AppData/IPC owner.
The script uses the repository's existing public-fixture helper only for storage isolation;
research and mutations use the installed public CLI.
