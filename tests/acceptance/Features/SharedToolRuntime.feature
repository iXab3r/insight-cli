@native @technical @tool-runtime
Feature: Agents use a complete managed native and .NET tool slice
  Delivery and lifecycle are shared while each tool preserves its research semantics.

  Scenario: Independent clients research real native and managed inputs with safe recovery
    Given the current insight-cli distribution has been built
    And disposable native acceptance is explicitly enabled
    When global CLI shared tool runtime acceptance runs
    Then both tools satisfy delivery research recovery and removal acceptance
