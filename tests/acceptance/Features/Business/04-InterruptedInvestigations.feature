@business @native
Feature: 04 Continue an interrupted investigation

  Background:
    Given the installed public CLI and versioned EXE oracle are ready

  @BS-17
  Scenario: BS-17 Continue an interrupted first import
    When I continue an interrupted first import
    Then the original scope delivers one initial base and a later finding

  @BS-18
  Scenario: BS-18 Recover an active investigation
    When I recover an active investigation
    Then acknowledged private work survives and can be delivered

  @BS-19
  Scenario: BS-19 Establish an edit outcome after losing its reply
    When I establish an edit outcome after losing its reply
    Then the original intent continues without a duplicate effect

  @BS-20
  Scenario: BS-20 Establish a merge outcome after losing its reply
    When I establish a merge outcome after losing its reply
    Then the finding is accepted through one publication
