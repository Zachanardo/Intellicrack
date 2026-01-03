# How to Run FlexLM Binary Protocol Production Tests

## Quick Start

### Run All FlexLM Binary Protocol Tests
```bash
cd D:\Intellicrack
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -v
```

## Test Categories

### 1. Binary Protocol Parsing Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestFlexLMBinaryProtocolParsing -v
```

### 2. RLM Protocol Support Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestRLMProtocolSupport -v
```

### 3. Encrypted Payload Handling Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestEncryptedPayloadHandling -v
```

### 4. Checkout/Checkin Sequence Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestLicenseCheckoutCheckinSequences -v
```

### 5. License File Response Generation Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestValidLicenseFileResponseGeneration -v
```

### 6. FlexLM 11.x Edge Cases
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestFlexLM11xEdgeCases -v
```

### 7. lmgrd Clustering Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestLmgrdClustering -v
```

### 8. Error Handling Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestEdgeCasesAndErrorHandling -v
```

### 9. Performance Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestPerformanceAndScalability -v
```

### 10. Integration Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestIntegrationScenarios -v
```

## Run Specific Tests

### Run Single Test
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestFlexLMBinaryProtocolParsing::test_parse_binary_flexlm_checkout_with_all_magic_numbers -v
```

### Run Tests Matching Pattern
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -k "binary" -v
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -k "signature" -v
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -k "cluster" -v
```

## Coverage Reports

### Generate HTML Coverage Report
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py \
  --cov=intellicrack.core.network.protocols.flexlm_parser \
  --cov-report=html:htmlcov
```

Then open `htmlcov/index.html` in your browser.

### Generate Terminal Coverage Report
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py \
  --cov=intellicrack.core.network.protocols.flexlm_parser \
  --cov-report=term-missing
```

### Coverage for Specific Lines (239-250)
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py \
  --cov=intellicrack.core.network.protocols.flexlm_parser \
  --cov-report=term-missing | grep -A20 "flexlm_parser.py"
```

## Debugging Failed Tests

### Run with Detailed Output
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -vv -s
```

### Run with PDB Debugger
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py --pdb
```

### Show Full Traceback
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py --tb=long
```

### Run Failed Tests Only
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py --lf
```

## Performance Profiling

### Show Slowest Tests
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py --durations=10
```

### Benchmark Mode (requires pytest-benchmark)
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py::TestPerformanceAndScalability --benchmark-only
```

## Parallel Execution

### Run Tests in Parallel (requires pytest-xdist)
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -n auto
```

### Run Tests in Parallel with 4 Workers
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -n 4
```

## Test Markers

### Run Real Data Tests Only
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -m real_data
```

### Run Integration Tests Only
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -m integration
```

### Run Performance Tests Only
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py -m performance
```

## Expected Results

### All Tests Pass
```
============ 41 passed in X.XXs ============
```

### Expected Coverage
```
intellicrack/core/network/protocols/flexlm_parser.py    95%+
```

## Troubleshooting

### Import Errors
If you see import errors, ensure you're in the correct directory:
```bash
cd D:\Intellicrack
pixi shell
```

### Missing Dependencies
```bash
pixi install
```

### Environment Issues
```bash
pixi clean
pixi install
```

### Windows Path Issues
Use forward slashes or escaped backslashes:
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py
# OR
pixi run pytest tests\\core\\network\\test_flexlm_binary_protocol_production.py
```

## Continuous Integration

### Run Tests with JUnit XML Output
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py \
  --junitxml=test-results/flexlm-binary-protocol.xml
```

### Run with Coverage and XML Report
```bash
pixi run pytest tests/core/network/test_flexlm_binary_protocol_production.py \
  --cov=intellicrack.core.network.protocols.flexlm_parser \
  --cov-report=xml:coverage.xml
```

## Test Validation Checklist

Before committing code, verify:

- [ ] All 41 tests pass
- [ ] Coverage is >95% for flexlm_parser.py
- [ ] No new warnings or errors
- [ ] Performance tests complete within time limits
- [ ] Integration tests validate end-to-end workflows
- [ ] Error handling tests verify robust failure handling

## Related Test Files

Run all FlexLM-related tests:
```bash
pixi run pytest tests/core/network/protocols/test_flexlm_parser*.py -v
```

Run all network protocol tests:
```bash
pixi run pytest tests/core/network/ -k "flexlm or hasp or protocol" -v
```

---

**Test File:** `D:\Intellicrack\tests\core\network\test_flexlm_binary_protocol_production.py`
**Summary:** `D:\Intellicrack\tests\core\network\TEST_FLEXLM_BINARY_PROTOCOL_SUMMARY.md`
**Created:** 2026-01-01
