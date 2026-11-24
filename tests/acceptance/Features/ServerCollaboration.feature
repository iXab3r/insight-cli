@server-business @native
Feature: Agents collaborate through the shared Ghidra repository
  Findings belong to independent agents until deliberately delivered.
  Receiving and delivering findings must preserve names, types and unrelated work.
  Disagreements must remain inspectable and must never choose a winner silently.

  Background:
    Given an isolated installed CLI and a disposable Ghidra repository are ready

  Scenario Outline: <id> <goal>
    When agents perform collaboration workflow "<id>"
    Then the collaboration outcome is "<outcome>"

    Examples:
      | id    | goal                                                   | outcome                                                        |
      | GS-01 | Investigate privately at the same time                  | Each agent sees only its own unpublished name                   |
      | GS-02 | Deliver complementary function findings                 | A fresh agent reads both function names                         |
      | GS-03 | Deliver independently discovered data types              | A fresh agent reads both complete structure definitions         |
      | GS-04 | Revise and retire existing data types                   | A fresh agent reads both revised types and neither retired type |
      | GS-05 | Preserve a float result while combining findings        | Float survives receiving, delivery and fresh readback           |
      | GS-06 | Preserve a double result while combining findings       | Double survives receiving, delivery and fresh readback          |
      | GS-07 | Receive findings during an unfinished investigation     | Incoming and private findings survive further work and delivery |
      | GS-08 | Receive findings without private changes                | Incoming findings appear without publishing another revision    |
      | GS-09 | Resume saved private work after restarting the service  | The same checkout retains findings and can deliver more work    |
      | GS-10 | Decide when to receive a colleague's work               | Private reads remain stable until an explicit receive           |
      | GS-11 | Agree independently on the same function name           | The agreed name is delivered without a false conflict           |
      | GS-12 | Encounter contradictory findings in a larger change set | All private work survives and no partial result is delivered     |
      | GS-13 | Inspect a function disagreement                         | The conflict identifies the function and all three alternatives  |
      | GS-14 | Settle a function disagreement by deliberate transfer    | The chosen name and unrelated findings are delivered and usable  |
      | GS-15 | Settle a type disagreement by deliberate transfer        | The chosen type and unrelated findings are delivered and usable  |
      | GS-16 | Establish delivery after losing its reply               | Original-request retry leaves exactly one accepted revision      |
      | GS-17 | Finish one contribution and start the next              | Verified delivery releases the copy and continued work is fresh  |
      | GS-18 | Inspect a type disagreement                             | The conflict identifies the type and all three alternatives      |
      | GS-19 | Continue after the owned repository service restarts    | Saved private and shared findings remain usable and deliverable  |
      | GS-20 | Investigate without publication credentials              | The private worker is offline and delivery goes through service  |
