---
name: insight-frida
description: Observe native call arguments/results or inspect runtime modules and exports in an explicitly selected authorized process with bounded Frida scripts. Use insight-cli frida to corroborate static findings with actual execution on macOS ARM64.
---

# Insight Frida 0.2.0

Follow existing project RE and evidence conventions. Frida instruments a running process;
choose an explicitly authorized PID. This facade owns the collector, while the target stays
with its original owner. Stopping the collector never signals that target.

1. `insight-cli frida status --json` checks readiness. `frida install` obtains our pinned
   Frida Node 17.24.0 bundle from GitHub Releases, including its NAPI-v8 binding, JavaScript
   dependencies and full notices. It uses the CLI's Node runtime; Python is unnecessary.
   Managed delivery requires macOS 14+ ARM64. `download`, `install --archive FILE --offline`,
   `doctor` and `uninstall` use the shared lifecycle. An external compatible Node bundle can
   be selected with `install --executable /path/to/frida/build/src/frida.js`; adjacent binding
   and resolved runtime dependency families are fingerprinted and never deleted.
2. `frida modules --pid PID --json` establishes runtime module names and load addresses.
   `frida exports --pid PID --module NAME --json` narrows to one module. `--limit`/`--offset`
   page records. Runtime pointers differ from static addresses under ASLR; establish module
   and image correspondence before combining findings from Ghidra/LLVM with live evidence.
3. Write a focused ordinary JavaScript file using the [Frida JavaScript API](https://frida.re/docs/javascript-api/).
   For a known integer-valued exported function, an observation hook can be:

   ```javascript
   const at = Process.mainModule.getExportByName('quote_total');
   Interceptor.attach(at, {
     onEnter(args) { this.count = args[0].toInt32(); },
     onLeave(value) { send({count: this.count, result: value.toInt32()}); }
   });
   ```

   Match argument types, calling convention and module to the actual program. This example
   is not a generic signature for every function. `frida observe --pid PID --script FILE
   --duration-seconds 2 --output research/calls.json --json` captures the source bytes, loads
   it, collects messages, requests unload and detaches. The output records the source hash,
   runtime version, original PID/birth, native diagnostics and cleanup acknowledgment.
4. Inspect `complete`, `state`, script errors and cleanup fields. Script errors or early
   target detach produce partial evidence. No observed call does not prove absence. Ordinary
   `send`/console/error messages and optional binary payloads are retained. `--limit`/`--offset`
   page event messages; `--output` saves the full bounded envelope to a new ordinary file and
   creates parents. Use `artifacts save` for a checkpoint when useful.
5. The observation window is 1–120 seconds; collector execution has a separate finite deadline
   that survives owner loss. Native SDK helpers have their own inherited deadlines; status
   remains `native_children_pending` and uninstall is blocked until they exit. Native output is bounded to 4 MiB and 10000 messages. Arbitrary
   script patches or application side effects are not automatically rolled back by unload.
   Avoid unnecessarily broad hooks and large payloads. `tools processes --tool frida --all`
   shows owned collector history. A recovered live macOS PID may be unverified: wait for the
   deadline and inspect retained evidence instead of replaying an injection blindly.

The pinned backend has a known attach failure on a bare C process without CoreFoundation;
our native probe reproduces it explicitly. A process already loading CoreFoundation worked.
Report the failure and choose a suitable debugger/fixture; do not silently load frameworks
into an unrelated process. macOS authorization/hardened targets can also prevent attach.
An imported PE is not a runnable local macOS process. Generated help owns exact syntax.
