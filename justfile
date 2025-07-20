# Intellicrack Testing Commands
# ALL TESTS MUST USE REAL DATA - NO MOCKS ALLOWED

# Quick unit tests - validates REAL functionality
test:
    pytest tests/unit -v --tb=short

# Full test suite - comprehensive REAL data validation
test-all:
    pytest tests/ -v

# Coverage report - ensures 95%+ REAL code coverage
test-coverage:
    pytest --cov=intellicrack --cov-report=html --cov-report=term --cov-fail-under=95 tests/

# Test specific module with REAL data
test-module module:
    pytest tests/unit/{{module}} -v

# Performance benchmarks on REAL operations
test-bench:
    pytest tests/performance --benchmark-only

# Security tests with REAL attack vectors
test-security:
    pytest tests/security -v

# Integration tests with REAL workflows
test-integration:
    pytest tests/integration -v -m integration

# Functional tests with REAL binaries
test-functional:
    pytest tests/functional -v -m functional

# Quick smoke test
test-smoke:
    pytest tests/unit -k "not slow" --tb=short -v

# Test with coverage for specific module
test-module-cov module:
    pytest --cov=intellicrack.{{module}} --cov-report=term-missing tests/unit/{{module}}

# Generate HTML coverage report
test-cov-html:
    pytest --cov=intellicrack --cov-report=html tests/
    @echo "Coverage report generated in coverage_html_report/"

# Run tests in parallel
test-parallel:
    pytest -n auto tests/

# Test only failed tests from last run
test-failed:
    pytest --lf tests/

# Test with verbose output
test-verbose:
    pytest -vvv tests/

# Clean test artifacts
test-clean:
    rm -rf .pytest_cache
    rm -rf coverage_html_report
    rm -rf .coverage
    rm -rf *.pyc
    find . -type d -name __pycache__ -exec rm -rf {} +

# Install test dependencies
test-install:
    pip install pytest pytest-cov pytest-benchmark pytest-asyncio pytest-qt pytest-xdist pytest-mock

# Verify no mocks or fake data
test-verify-real:
    python scripts/verify_no_mocks.py
    @echo "All tests use REAL data ✓"

# Lint code with ruff
lint:
    ruff check intellicrack/
    ruff format --check intellicrack/

# Fix linting issues automatically
lint-fix:
    ruff check --fix intellicrack/
    ruff format intellicrack/