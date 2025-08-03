# Intellicrack Testing Commands
# ALL TESTS MUST USE REAL DATA - NO MOCKS ALLOWED

# Default recipe
default:
    @just --list

# Quick unit tests - validates REAL functionality
test:
    pytest tests/unit -v --tb=short

# Test specific module with REAL data  
test-module module:
    pytest tests/unit/{{module}} -v

# Full test suite - comprehensive REAL data validation
test-all:
    pytest tests/ -v

# Coverage report - ensures 95%+ REAL code coverage
test-coverage:
    pytest --cov=intellicrack --cov-report=html --cov-report=term --cov-fail-under=95 tests/

# Performance benchmarks on REAL operations
test-bench:
    pytest tests/performance --benchmark-only -v

# Security tests with REAL attack vectors
test-security:
    pytest tests/security -v

# Integration tests with REAL workflows
test-integration:
    pytest tests/integration -v

# Functional tests with REAL scenarios
test-functional:
    pytest tests/functional -v

# AI tests with REAL models
test-ai:
    pytest tests/unit/ai tests/integration/ai_integration -v

# Network tests with REAL protocols
test-network:
    pytest tests/unit/network tests/integration/network_integration -v

# GUI tests with REAL Qt interactions
test-gui:
    pytest tests/unit/gui -v

# Binary analysis tests with REAL binaries
test-binary:
    pytest tests/unit/analysis tests/functional/binary_analysis -v

# Exploitation tests with REAL exploits
test-exploit:
    pytest tests/unit/exploitation tests/functional/exploit_generation -v

# Standalone tests with REAL operations
test-standalone:
    pytest tests/standalone -v

# Utilities tests with REAL functionality
test-utilities:
    pytest tests/utilities -v

# Plugin tests with REAL plugin operations
test-plugins:
    pytest tests/plugins -v

# Verify no mock usage in tests
verify-no-mocks:
    python scripts/verify_no_mocks.py

# Run specific test markers
test-marker marker:  
    pytest -m {{marker}} -v

# Clean test artifacts
clean-test:
    rm -rf .pytest_cache/ htmlcov/ .coverage coverage.xml tests.log
    find . -name "*.pyc" -delete
    find . -name "__pycache__" -type d -exec rm -rf {} +

# Install test dependencies
install-test-deps:
    pip install pytest pytest-cov pytest-benchmark pytest-asyncio pytest-qt pytest-mock pytest-xdist

# Setup pre-commit hooks
setup-precommit:
    pip install pre-commit
    pre-commit install

# Run all pre-commit hooks
pre-commit:
    pre-commit run --all-files

# Performance profile tests
profile-tests:
    pytest tests/performance --profile -v

# Test with different Python versions (if available)
test-python version:
    python{{version}} -m pytest tests/ -v

# Continuous testing (watch for changes)
test-watch:
    pytest-watch tests/ --runner="pytest -v"

# Generate test report
test-report:
    pytest tests/ --html=reports/test_report.html --self-contained-html

# Test specific file
test-file file:
    pytest {{file}} -v

# Debug failing test
debug-test test:
    pytest {{test}} -v -s --pdb

# Show test coverage in browser
show-coverage:
    pytest --cov=intellicrack --cov-report=html tests/
    @echo "Opening coverage report in browser..."
    @python -c "import webbrowser; webbrowser.open('htmlcov/index.html')"

# Stress test with multiple workers
test-stress:
    pytest tests/ -n auto --dist=worksteal -v

# Test memory usage
test-memory:
    pytest tests/ --memray -v

# Create test fixtures
create-fixtures:
    python scripts/create_test_fixtures.py

# Validate test fixtures
validate-fixtures:
    python scripts/validate_test_fixtures.py

# Update test data - COMPREHENSIVE
update-test-data:
    @echo "Updating test binaries..."
    python scripts/update_test_binaries.py
    @echo "Updating network captures..."  
    python scripts/update_network_captures.py
    @echo "Test data updated successfully!"

# Comprehensive binary acquisition - Real commercial software, protection schemes
acquire-comprehensive-binaries:
    @echo "Acquiring comprehensive binary collection..."
    python scripts/comprehensive_binary_acquisition.py
    @echo "Comprehensive binary acquisition completed!"

# Advanced network protocol testing - Modern DRM, enterprise licensing
test-advanced-protocols:
    @echo "Testing advanced network protocols..."
    python scripts/advanced_network_protocol_testing.py
    @echo "Advanced protocol testing completed!"

# Enhanced AI testing - Multi-model consensus, large binary analysis
test-enhanced-ai:
    @echo "Running enhanced AI testing suite..."
    python scripts/enhanced_ai_testing_system.py
    @echo "Enhanced AI testing completed!"

# Advanced exploitation testing - Modern techniques, ROP/JOP, protection bypass
test-advanced-exploits:
    @echo "Running advanced exploitation testing..."
    python scripts/advanced_exploitation_testing.py
    @echo "Advanced exploitation testing completed!"

# Enhanced protection scheme generation - Modern licensing and DRM protection samples
generate-protection-schemes:
    @echo "Generating enhanced protection scheme samples..."
    python scripts/enhanced_protection_scheme_generator.py
    @echo "Enhanced protection scheme generation completed!"

# Complete testing infrastructure setup
setup-comprehensive-testing:
    @echo "Setting up comprehensive testing infrastructure..."
    just acquire-comprehensive-binaries
    just generate-protection-schemes
    just test-advanced-protocols
    just test-enhanced-ai
    just test-advanced-exploits
    just validate-fixtures
    @echo "🎉 Comprehensive testing infrastructure setup completed!"

# Validate comprehensive testing coverage
validate-comprehensive-coverage:
    @echo "Validating comprehensive testing coverage..."
    just verify-no-mocks
    python scripts/validate_test_fixtures.py
    pytest --cov=intellicrack --cov-fail-under=95 tests/ -q
    @echo "✅ Comprehensive testing coverage validated!"

# MASTER COMMAND: Complete comprehensive testing infrastructure orchestration
orchestrate-comprehensive-testing:
    @echo "🎯 Starting comprehensive testing infrastructure orchestration..."
    python scripts/comprehensive_testing_orchestrator.py
    @echo "🎉 Comprehensive testing infrastructure orchestration completed!"

# Run tests in Docker (if available)
test-docker:
    docker run --rm -v $(pwd):/app intellicrack:test pytest tests/ -v

# Check test quality
check-tests:
    @echo "Checking for REAL data usage..."
    just verify-no-mocks
    @echo "Checking test coverage..."
    pytest --cov=intellicrack --cov-fail-under=95 --quiet tests/
    @echo "Checking test performance..."
    pytest tests/performance --benchmark-skip -v --tb=no -q
    @echo "All test quality checks passed!"