@business @native
Feature: 03 Several CLIs investigate the same EXE

  Background:
    Given the installed public CLI and versioned EXE oracle are ready

  @BS-10
  Scenario: BS-10 Divide an investigation between two cli actors
    When I divide an investigation between two CLI actors
    Then concurrent actors retain independent private findings

  @BS-11
  Scenario: BS-11 Combine independent findings
    When I combine independent findings
    Then the shared result includes both contributions

  @BS-12
  Scenario: BS-12 Continue after a colleague publishes
    When I continue after a colleague publishes
    Then refresh receives shared findings and preserves local work

  @BS-13
  Scenario: BS-13 Agree independently with a colleague
    When I agree independently with a colleague
    Then identical proposals publish without an artificial conflict

  @BS-14
  Scenario: BS-14 Resolve contradictory findings
    When I resolve contradictory findings
    Then the chosen resolution is independently readable

  @BS-15
  Scenario: BS-15 Keep a conflicting finding set intact
    When I keep a conflicting finding set intact
    Then a failed merge publishes none of the selected local work

  @BS-16
  Scenario: BS-16 Transfer a complex finding to the current base
    When I transfer a complex finding to the current base
    Then the transferred structure and shared findings coexist
