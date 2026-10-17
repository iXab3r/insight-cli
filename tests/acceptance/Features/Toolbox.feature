@toolbox @native
Feature: The installed toolbox supports a real investigation
  These checks establish host discovery, container recovery, native binary investigation and live managed diagnostics.
  Independent model findings are reviewed separately; native execution is not an agent pass.

  Scenario: Discover tools before installing their runtimes
    Given an isolated globally installed toolbox candidate is selected
    When Codex connects and disconnects the packaged skill bundle
    Then all shipped skills are visible and unrelated project skills survive

  Scenario: Recover useful input from a supplied container
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI recovers the owned container and retains its materials
    Then exact recovered bytes and configuration survive tool removal

  Scenario: Investigate native linkage and debug records
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI inspects native images and their debug records
    Then native linkage and focused debug evidence survive tool removal

  Scenario: Explain waiting managed work from stacks, heap and sampled time
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI investigates the owned managed worker
    Then the waiting stack and heap state have retained diagnostic evidence

  Scenario: Classify unknown binaries without hiding signature failures
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI classifies owned native and managed inputs
    Then header and signature evidence retains scan uncertainty

  Scenario: Corroborate a native boundary with concrete arguments and returns
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI observes owned native breakpoint snapshots
    Then runtime evidence and checkpoints survive debugger removal

  Scenario: Retain bounded debugger lifetime after interruption or owner loss
    Given an isolated globally installed toolbox candidate is selected
    When the installed debugger runner suffers controlled lifetime faults
    Then owned debugger processes exit and uncertain results are not replayed

  Scenario: Corroborate native calls while preserving the original process
    Given an isolated globally installed toolbox candidate is selected
    When the public CLI observes calls in the owned instrumented worker
    Then hook evidence and checkpoints retain source identity and cleanup

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
