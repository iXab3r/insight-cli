@toolbox @native
Feature: The installed toolbox supports a real investigation
  These checks establish host discovery, container recovery and native binary investigation.
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
