# Native float/double return conflict regression

The observed loss came from the prototype's incomplete headless integration. Ghidra
12.1.2 detected the native return-type conflict correctly. No change to datatype
identity, type comparison or winner selection is required for this case.

The [accepted ownership boundary](DESIGN.md#native-merge-ownership) remains unchanged:
Ghidra owns merge semantics; insight-cli adapts execution, conflicts and publication.

## Minimal reproduction

The Java fixture `NativeReturnTypeRepro.java` under
`skills/ghidra-coordinator/tests/fixtures/native-merge/` creates one x86-64 function
returning `int` and clones its native DB into original/latest/private/result programs.
The baseline contains neither `float` nor `double`. Latest changes only the return
to `float`; private changes only the return to `double`. Their new local type IDs
collide. The fixture passes native change sets to the stock resolver sequence.
It uses no server, product workspace, publication logic or custom type comparison.

Using the same explicitly supplied Ghidra 12.1.2/JDK/bridge paths and disposable
output base as the broad prototype, run:

```text
node scripts/proof-native-merge.mjs --case return-types --ack-disposable --ghidra-home GHIDRA_HOME --java JAVA --mcp-jar MCP_JAR --output-base DISPOSABLE_BASE
```

This asserts a native conflict, correct native remapping to `double`, unchanged
latest/private return-type observations, and zero GUI windows. Source/runtime hashes are retained.

For the historical unsafe control, append `--function-conflict-ui stock`. That option
is restricted to this offline diagnostic; it is forbidden for server publications.
Only the function-conflict display seam changes between the two builds. The control
asserts the swallowed null-panel exception, completed merge and retained `float`.
Its successful test receipt means **the unsafe behavior was reproduced**, not that
the merge was correct. Both runs retain all fixture data.

## Cause and correction

`AbstractFunctionMerger.determineReturnConflict` resolves the types through the
native datatype mapping. The private `double` gets a distinct result type even
though its local numeric ID equals the latest `float` ID. The ID-collision hypothesis
is ruled out for this reproducer.

The native merger then reaches `AbstractFunctionMerger.setupConflictPanel`.
The prototype returns null from `getListingMergePanel`. Stock code dereferences
that panel inside `SwingUtilities.invokeAndWait`, catches `InvocationTargetException`,
logs a display error and returns before calling `showListingMergePanel`. The
prototype's rejection hook is never reached, so its synchronous loop finishes and
the result retains latest. In the old server experiment this allowed check-in to
release private work without recording its `double` result.

The pinned headless integration patch redirects an already-detected function conflict
to the adapter's rejection hook **before** GUI setup. An unexpected hook return also
throws. The conflict exits the native transaction instead of being swallowed by the
GUI display catch. Native detection, remapping and merge decisions are unchanged.
This seam was added for existing-type conflicts in the earlier extended candidate;
the float/double loss is the same missing seam, rather than a separate unresolved
native type-merging defect. The older report's unresolved classification is superseded.

The old `native-merge-proof-A8uqWN` application log independently contains this exact
null-panel stack, followed by check-in completion; its retained authoritative readback
shows `float`. The new regression retains both before/after controls and fresh server
tests with `float`/`double` in both publication orders, independent readback, preserved
private checkout/content and refusal to drop unresolved work.
The reverse-order server case uses a separate `uint`-return function; `float` already
exists in the shared datatype manager by then. It does not claim a second proof in
which both builtin types are absent from that server baseline.

Exact hashes and outcomes are in the [regression report](verification/native-return-type-regression.json).
This resolves the observed float/double loss in the prototype; production CLI adoption,
native refresh, conflict resolution, crash recovery and broader native semantics still
need their scoped acceptance. The memory-comment compatibility fix and the previously
unclassified preseed experiment are separate issues. No `ec2-native` data is used.
