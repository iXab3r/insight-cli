@business @native
Feature: 01 One agent investigates one EXE

  Background:
    Given the installed public CLI and versioned EXE oracle are ready

  @BS-01
  Scenario: BS-01 Start an investigation
    When I start an investigation
    Then a usable context identifies the intended EXE

  @BS-02
  Scenario: BS-02 Find a point of interest
    When I find a point of interest
    Then the clue identifies the expected program location

  @BS-03
  Scenario: BS-03 Trace the behavior behind a clue
    When I trace the behavior behind a clue
    Then references and decompilation explain the expected behavior

  @BS-04
  Scenario: BS-04 Record a finding privately
    When I record a finding privately
    Then the agent sees its edits while another session does not

  @BS-05
  Scenario: BS-05 Deliver a completed result
    When I deliver a completed result
    Then an independent session reads the published findings
