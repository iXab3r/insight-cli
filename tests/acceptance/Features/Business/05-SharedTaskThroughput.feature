@business @native
Feature: 05 Complete a shared task and measure acceleration

  Background:
    Given the installed public CLI and versioned EXE oracle are ready

  @BS-21 @performance
  Scenario: BS-21 Complete the shared task with one worker
    When I complete the shared task with one worker
    Then all expected findings are published by the serial baseline

  @BS-22 @performance
  Scenario: BS-22 Complete the shared task with three workers
    When I complete the shared task with three workers
    Then three native workers produce the equivalent shared result

  @BS-23 @performance
  Scenario: BS-23 Compare prepared-base serial and parallel execution
    When I compare prepared-base serial and parallel execution
    Then the declared paired comparison proves repeatable acceleration

  @BS-24 @performance
  Scenario: BS-24 Measure the same task from a cold start
    When I measure the same task from a cold start
    Then correct serial and parallel cold timings are reported separately

  @BS-25 @performance
  Scenario: BS-25 Complete a task with uneven work distribution
    When I complete a task with uneven work distribution
    Then all findings and actual scaling limits are reported
