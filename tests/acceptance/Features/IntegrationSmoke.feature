@offline @technical
Feature: Existing offline integration checks under Automation
  These checks connect the runner to existing evidence.
  They do not establish native Ghidra behavior or research throughput.

  Scenario: The installed package exposes the agent interface without its checkout
    Given the current insight-cli distribution has been built
    When the isolated package integration check runs
    Then the package interface check succeeds

  Scenario: Session commands satisfy the existing offline integration checks
    Given the current insight-cli distribution has been built
    When the offline CLI integration checks run
    Then all selected CLI integration checks pass
