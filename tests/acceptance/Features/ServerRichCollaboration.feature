@server-business @native
Feature: Rich investigation results survive collaboration through Ghidra Server
  Combining analysis must preserve the meaning and relationships of findings.
  Agents must also retain control of conflicting evidence and temporary copies.

  Background:
    Given an isolated installed CLI and a disposable Ghidra repository are ready

  Scenario Outline: <id> <goal>
    When agents perform collaboration workflow "<id>"
    Then the collaboration outcome is "<outcome>"

    Examples:
      | id    | goal                                                    | outcome                                                           |
      | GS-21 | Share a reconstructed model used by the executable       | Both data models retain their definitions and executable bindings  |
      | GS-22 | Share navigable evidence and investigation annotations   | Both agents' evidence remains navigable and retains its meaning    |
      | GS-23 | Share corrected code and execution assumptions           | Both corrections retain code, regions and execution assumptions    |
      | GS-24 | Disagree about a byte correction                         | Neither byte correction nor supporting private work is lost         |
      | GS-25 | Delete a region description while a colleague revises it | Deletion versus revision requires a decision and preserves work     |
      | GS-26 | Revise a region description while a colleague deletes it | Revision versus deletion requires a decision and preserves work     |
      | GS-27 | Reconstruct different aspects of the same function       | One shared function retains all three agents' complementary findings |
      | GS-28 | Deliver two contributions at the same time               | Both simultaneous contributions become independently readable       |
      | GS-29 | Save and reopen repeatedly without accumulating copies  | One private copy survives iterations and is removed after delivery  |
      | GS-30 | Inspect shared history and active investigations        | Contributions and copies are attributable under separate authority  |
      | GS-31 | Disagree with an incoming float result                   | Incoming float and private double survive without a silent winner   |
      | GS-32 | Disagree with an incoming double result                  | Incoming double and private float survive without a silent winner   |
