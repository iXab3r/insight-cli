@toolbox @native
Feature: The installed toolbox supports a real investigation
  These checks establish host discovery, container recovery, native binary investigation and live managed diagnostics.
  Independent model findings are reviewed separately; native execution is not an agent pass.

  @macos
  Scenario: Discover tools before installing their runtimes
    Given an isolated globally installed toolbox candidate is selected
    When Codex connects and disconnects the packaged skill bundle
    Then all shipped skills are visible and unrelated project skills survive

  @macos
  Scenario: Recover useful input from a supplied container
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI recovers the owned container and retains its materials
    Then exact recovered bytes and configuration survive tool removal

  @macos
  Scenario: Investigate native linkage and debug records
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI inspects native images and their debug records
    Then native linkage and focused debug evidence survive tool removal

  @macos
  Scenario: Explain waiting managed work from stacks, heap and sampled time
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI investigates the owned managed worker
    Then the waiting stack and heap state have retained diagnostic evidence

  @macos
  Scenario: Classify unknown binaries without hiding signature failures
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI classifies owned native and managed inputs
    Then header and signature evidence retains scan uncertainty

  @macos
  Scenario: Corroborate a native boundary with concrete arguments and returns
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI observes owned native breakpoint snapshots
    Then runtime evidence and checkpoints survive debugger removal

  @macos
  Scenario: Retain bounded debugger lifetime after interruption or owner loss
    Given an isolated globally installed toolbox candidate is selected
    When the installed debugger runner suffers controlled lifetime faults
    Then owned debugger processes exit and uncertain results are not replayed

  @macos
  Scenario: Corroborate native calls while preserving the original process
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI observes calls in the owned instrumented worker
    Then hook evidence and checkpoints retain source identity and cleanup

  @macos
  Scenario: Remove temporary hooks after collector interruption or owner loss
    Given an isolated globally installed toolbox candidate is selected
    When the public instrumentation collector suffers controlled lifetime faults
    Then the original target remains alive with its ordinary behavior restored

  @strace @linux
  Scenario: Explain real Linux file reads and bound owned process lifetime
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI traces the owned Linux worker
    Then syscall evidence and checkpoints survive tracer removal

  @windbg @windows
  Scenario: Explain a stopped native Windows calculation from its captured state
    Given an owned Windows native dump fixture is prepared
    When the public CLI investigates the native Windows dump
    Then dump findings and checkpoints survive debugger removal

  @procmon @windows
  Scenario: Explain actual file access without taking ownership of the running application
    Given an owned Windows file-observation fixture is prepared
    When the public CLI observes and reopens the Windows file capture
    Then actual file evidence survives collector interruption and removal

  @dnspy @windows
  Scenario: Observe managed arguments and verify a separately patched assembly
    Given an owned Windows managed-research fixture is prepared
    When the public CLI debugs and edits the managed Windows inputs
    Then managed runtime findings and copied edits preserve original inputs

  @tshark @macos
  Scenario: Explain observed protocol behavior from retained packet and stream evidence
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI investigates the offline HTTP capture
    Then packet and stream evidence preserves input identity and bounded coverage

  @mitmproxy @macos
  Scenario: Compare observed HTTP behavior without system interception or replay
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI records and compares the owned HTTP exchanges
    Then HTTP evidence and explicit TLS failures survive interruption and removal

  @managed-metadata @macos
  Scenario: Compare managed behavior structure without executing either revision
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI compares managed metadata without executing targets
    Then managed metadata and normalized IL retain immutable input identity

  @managed-heap @macos
  Scenario: Explain queued work and a waiting thread from one retained managed dump
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI queries the captured managed heap and stacks
    Then object field and waiting stack evidence preserve dump identity and runtime limits

  @binary @macos
  Scenario: Inspect native linkage and verify one guarded field on a new PE copy
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI queries binary structure and guards a copied PE edit
    Then binary linkage and exact copy-only edits retain original bytes

  @interop @macos
  Scenario: Trace a declared managed boundary to a concrete native function and shared evidence
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI traces managed metadata through a native export into shared analysis
    Then qualified static correspondence survives merge and independent readback

  @capture @macos
  Scenario: Compare actual owned executions and preserve interrupted or unknown observations
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI captures controlled native runs and interrupted outcomes
    Then exact observations and unknown intents survive without automatic execution replay

  @overview @macos
  Scenario: Narrow a research question to bounded metadata and stable decompiled text windows
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI narrows managed and native code to stable text windows
    Then bounded evidence retains source hashes and explicit native truncation

  @ghidra-debugger @macos
  Scenario: Corroborate a native calculation and retain its disconnected context trace
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI debugs the owned program and reopens its retained trace
    Then paused CPU evidence and disconnected trace readback preserve ownership and input identity
