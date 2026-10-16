@business @native
Feature: 02 One agent investigates several EXEs

  Background:
    Given the installed public CLI and versioned EXE oracle are ready

  @BS-06
  Scenario: BS-06 Alternate between two exes
    When I alternate between two EXEs
    Then each target retains its own private findings

  @BS-07
  Scenario: BS-07 Distinguish identically named exes
    When I distinguish identically named EXEs
    Then publication affects only the selected executable

  @BS-08
  Scenario: BS-08 Compare two program versions
    When I compare two program versions
    Then the known differences are tied to the correct builds

  @BS-09
  Scenario: BS-09 Return to an earlier exe
    When I return to an earlier EXE
    Then the original context retains its private work
