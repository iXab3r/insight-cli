@native @technical @runtime
Feature: Deliver the complete local Ghidra tool without manual dependency setup
  Agents install through the global public CLI and keep research when replacing the tool.

  Scenario: Managed delivery and an external launcher both support real EXE research
    Given the current insight-cli distribution has been built
    And disposable native acceptance is explicitly enabled
    When global CLI runtime delivery acceptance runs
    Then managed and external runtime acceptance succeeds
