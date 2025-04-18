TESTING_STANDARDS.md
## 1. Hypothesis Tests for Behavior Validation

```
When implementing a new feature or function, create hypothesis tests that validate expected behaviors:

1. For each function, identify the core hypothesis of what it should accomplish
2. Write tests that:
   - Define clear expectations ("Given X, the function should return Y")
   - Test both positive and negative cases
   - Include boundary conditions
   - Verify error handling behaviors
3. Express these tests in the appropriate testing framework (e.g., pytest, Jest)
4. Include descriptive test names that document the behavior being validated

Example structure:
```python
def test_user_authentication_valid_credentials():
    """HYPOTHESIS: Given valid credentials, authentication should succeed."""
    # Arrange
    valid_username = "test_user"
    valid_password = "correct_password"
    
    # Act
    result = authenticate_user(valid_username, valid_password)
    
    # Assert
    assert result.success is True
    assert result.error_message is None
```

## 2. Regression Tests for Known Fail States

```
When fixing bugs or addressing edge cases, always create regression tests:

1. For each bug fix, create a test that:
   - Documents the original issue clearly in the test description
   - Recreates the exact conditions that caused the failure
   - Verifies the fix works as expected
   - Includes issue/ticket references for context
2. Maintain a dedicated regression test suite that runs with every build
3. Label regression tests appropriately for traceability
4. Include timestamps and version information where relevant

Example structure:
```python
def test_calculation_with_zero_division_protection():
    """REGRESSION: Bug #1234 - Division by zero crash in calculation module.
    
    This test ensures that when a divisor of zero is provided, the function
    returns a default value rather than raising an exception.
    """
    # Arrange
    input_value = 10
    divisor = 0
    expected_result = None  # Our fix returns None instead of raising ZeroDivisionError
    
    # Act
    result = safe_divide(input_value, divisor)
    
    # Assert
    assert result == expected_result
```


## 3. Benchmark Tests with SLA Enforcement

```
Implement benchmark tests that enforce Service Level Agreements (SLAs):

1. Define clear performance metrics for your system:
   - Response time / latency (milliseconds)
   - Throughput (requests per second)
   - Resource usage (memory, CPU)
   - Error rates
2. Create benchmark tests that:
   - Establish baseline performance expectations
   - Run consistently in controlled environments
   - Measure against defined thresholds
   - Alert on SLA violations
3. Include both average and percentile measurements (p95, p99)
4. Document the testing environment and conditions

Example structure:
```python
def test_api_response_time_sla():
    """BENCHMARK: API must respond within 200ms for 95% of requests.
    
    SLA Requirements:
    - p95 response time: < 200ms
    - p99 response time: < 500ms
    - Error rate: < 0.1%
    """
    # Arrange
    num_requests = 1000
    endpoint = "/api/users"
    
    # Act
    response_times = []
    errors = 0
    for _ in range(num_requests):
        start_time = time.time()
        try:
            response = client.get(endpoint)
            if response.status_code >= 400:
                errors += 1
        except Exception:
            errors += 1
        finally:
            response_times.append((time.time() - start_time) * 1000)  # Convert to ms
    
    # Assert
    error_rate = errors / num_requests
    p95 = numpy.percentile(response_times, 95)
    p99 = numpy.percentile(response_times, 99)
    
    assert p95 < 200, f"95th percentile response time {p95}ms exceeds SLA of 200ms"
    assert p99 < 500, f"99th percentile response time {p99}ms exceeds SLA of 500ms"
    assert error_rate < 0.001, f"Error rate {error_rate} exceeds SLA of 0.1%"
```


## 4. Grammatical Evolution (GE) for Fuzzing + Edge Discovery

```
Implement Grammatical Evolution (GE) for advanced fuzzing and edge case discovery:

1. Define a grammar that represents valid inputs for your system:
   - Create BNF (Backus-Naur Form) or similar grammar definition
   - Include all possible input variations, formats, and structures
   - Define mutation operations that preserve grammatical correctness
2. Implement an evolutionary algorithm that:
   - Generates test cases based on the grammar
   - Evolves test cases using fitness functions
   - Prioritizes edge cases and unexpected inputs
   - Tracks code coverage to focus on unexplored paths
3. Log and analyze failures to identify patterns
4. Automatically add discovered edge cases to regression tests

Example structure:
```python
def test_with_grammatical_evolution():
    """FUZZING: Use GE to discover edge cases in the input parser.
    
    This test uses grammatical evolution to generate various inputs
    that conform to our API grammar but might trigger unexpected behaviors.
    """
    # Define grammar for API requests
    grammar = {
        'start': ['<request>'],
        'request': ['{"command": "<command>", "params": <params>}'],
        'command': ['get', 'set', 'update', 'delete', '<random_string>'],
        'params': ['<simple_param>', '<complex_param>', '<nested_param>', '<malformed_param>'],
        # ... additional grammar rules
    }
    
    # Configure GE parameters
    max_generations = 50
    population_size = 100
    mutation_rate = 0.1
    
    # Run GE-based fuzzing
    fuzzer = GrammaticalEvolutionFuzzer(grammar=grammar, 
                                      coverage_tracker=CoverageTracker(),
                                      target_function=api_request_handler)
    
    results = fuzzer.run(max_generations, population_size, mutation_rate)
    
    # Analyze results
    edge_cases = results.filter(lambda r: r.status == 'failure')
    
    # Assert
    assert not edge_cases.has_critical_failures(), f"Critical failures found: {edge_cases.critical_failures}"
    
    # Add discovered edge cases to regression suite
    for case in edge_cases:
        add_to_regression_suite(case)
```

## 5. Structured Logs for Agent Feedback

```
Implement structured logging for comprehensive agent feedback:

1. Design a structured logging system that captures:
   - Input/output pairs for each agent operation
   - Decision points with considered alternatives
   - Confidence scores for predictions or responses
   - Time and resource utilization metrics
   - Any deviation from expected behavior
2. Use a consistent JSON or similar structured format
3. Include correlation IDs to track actions across system components
4. Implement log levels that enable filtering for different analysis needs
5. Create analyzers that process logs to identify patterns and issues

Example structure:
```python
def test_agent_logging_completeness():
    """AGENT FEEDBACK: Verify agent produces comprehensive structured logs.
    
    This test ensures our agent properly logs all required information
    for debugging, monitoring, and improvement purposes.
    """
    # Arrange
    test_input = "Process this complex request with multiple steps"
    expected_log_fields = [
        "request_id", "timestamp", "input", "parsed_intent", 
        "selected_action", "considered_alternatives", "confidence_score", 
        "execution_time_ms", "output", "status"
    ]
    
    # Setup log capture
    log_capture = LogCapture()
    
    # Act
    agent.process(test_input, log_handler=log_capture)
    
    # Assert
    logs = log_capture.get_logs_as_json()
    assert len(logs) > 0, "No logs were produced"
    
    # Check if all required fields are present in the logs
    for log in logs:
        for field in expected_log_fields:
            assert field in log, f"Required log field '{field}' is missing"
    
    # Verify log sequence completeness
    assert "agent_started" in [log["event"] for log in logs]
    assert "agent_completed" in [log["event"] for log in logs]
    
    # Verify decision points are logged with alternatives
    decision_logs = [log for log in logs if log["event"] == "decision_point"]
    assert len(decision_logs) > 0, "No decision points were logged"
    for decision in decision_logs:
        assert "considered_alternatives" in decision
        assert len(decision["considered_alternatives"]) > 0
```


## Combined Meta-Prompt for Test Suite Generation

```
Generate a comprehensive test suite for this code that follows the Minimal Testing Manifesto:

1. Create hypothesis tests that validate core behaviors:
   - What are the key functions and their expected behaviors?
   - What are the contracts these functions must fulfill?
   - What invariants must be maintained?

2. Implement regression tests for known issues:
   - What edge cases have been identified?
   - What bugs were previously fixed that must not reappear?
   - What are the failure modes we've observed?

3. Add benchmark tests with SLA enforcement:
   - What performance guarantees must the code provide?
   - What are the time, memory, or throughput constraints?
   - What are the expected error rates and reliability metrics?

4. Use grammatical evolution for fuzzing and edge discovery:
   - What is the grammar of valid inputs?
   - What mutations would generate interesting test cases?
   - How can we systematically explore the input space?

5. Include structured logging for agent feedback:
   - What information must be captured at each step?
   - How should decision points be documented?
   - What metrics are needed for monitoring and improvement?

For each test, include:
- Clear documentation of the purpose and hypothesis
- Detailed setup of test conditions
- Explicit assertions with descriptive failure messages
- Appropriate test categorization (unit, integration, etc.)

The test suite should be maintainable, reliable, and provide rapid feedback on code quality and correctness.
