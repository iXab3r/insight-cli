@native @technical
Feature: Preserve existing real Ghidra acceptance during migration
  These bridge scenarios keep existing assertions and fixture ownership intact.
  The business scenario hierarchy will be agreed separately.

  @facade
  Scenario: Independent CLI processes retain isolated work and publish shared results
    Given the current insight-cli distribution has been built
    And disposable native acceptance is explicitly enabled
    When the installed multi-agent native acceptance runs
    Then the native acceptance reports success

  @full
  Scenario: The established complete native gate remains executable
    Given the current insight-cli distribution has been built
    And disposable native acceptance is explicitly enabled
    When the complete native acceptance runs
    Then the complete native gate succeeds
