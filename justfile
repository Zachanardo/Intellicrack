# Intellicrack Testing Commands

# Quick unit tests - validates REAL functionality
test:
    pixi run pytest tests/unit -v --tb=short

# Full test suite - comprehensive REAL data validation
test-all:
    pixi run pytest tests/ -v

# Coverage report - ensures 95%+ REAL code coverage
test-coverage:
    pixi run pytest --cov=intellicrack --cov-report=html --cov-report=term --cov-fail-under=95 tests/

# Test specific module with REAL data
test-module module:
    pixi run pytest tests/unit/{{module}} -v

# Performance benchmarks on REAL operations
test-bench:
    pixi run pytest tests/performance --benchmark-only

# Security tests with REAL attack vectors
test-security:
    pixi run pytest tests/security -v

# Integration tests with REAL workflows
test-integration:
    pixi run pytest tests/integration -v -m integration

# Functional tests with REAL binaries
test-functional:
    pixi run pytest tests/functional -v -m functional

# Quick smoke test
test-smoke:
    pixi run pytest tests/unit -k "not slow" --tb=short -v

# Test with coverage for specific module
test-module-cov module:
    pixi run pytest --cov=intellicrack.{{module}} --cov-report=term-missing tests/unit/{{module}}

# Generate HTML coverage report
test-cov-html:
    pixi run pytest --cov=intellicrack --cov-report=html tests/
    @echo "Coverage report generated in coverage_html_report/"

# Run tests in parallel
test-parallel:
    pixi run pytest -n auto tests/

# Test only failed tests from last run
test-failed:
    pixi run pytest --lf tests/

# Test with verbose output
test-verbose:
    pixi run pytest -vvv tests/

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
    pixi run python tests/utils/verify_no_mocks.py
    @echo "All tests use REAL data ✓"

# Lint code with ruff
lint:
    pixi run ruff check intellicrack/
    pixi run ruff format --check intellicrack/

# Fix linting issues automatically
lint-fix:
    pixi run ruff check --fix intellicrack/
    pixi run ruff format intellicrack/

# Lint JavaScript files with ESLint
lint-js:
    pixi run npx eslint . --ext .js

# Fix JavaScript linting issues automatically
lint-js-fix:
    pixi run npx eslint . --ext .js --fix

# Lint Java files with Checkstyle
lint-java:
    pixi run ./tools/checkstyle/checkstyle -c ./tools/checkstyle/intellicrack_checks.xml $(find . -name "*.java" -not -path "./tools/*" -not -path "./.venv*/*" -not -path "./.pixi/*" -not -path "./build/*" -not -path "./dist/*")

# Lint Markdown files with markdownlint
lint-md:
    pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Fix Markdown linting issues automatically
lint-md-fix:
    pixi run markdownlint "**/*.md" --fix --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Lint all supported file types
lint-all: lint lint-js lint-java lint-md lint-rust-all
    @echo "All linting complete ✓"

# Lint Rust code with clippy
lint-rust:
    cd intellicrack-launcher && pixi run cargo clippy -- -D warnings

# Format Rust code with rustfmt
lint-rust-fmt:
    cd intellicrack-launcher && pixi run cargo fmt -- --force

# Check Rust formatting without applying changes
lint-rust-fmt-check:
    cd intellicrack-launcher && pixi run cargo fmt -- --force --write-mode diff

# Fix Rust linting issues automatically
lint-rust-fix:
    cd intellicrack-launcher && pixi run cargo clippy --fix --allow-dirty --allow-staged -- -D warnings

# All Rust linting and formatting
lint-rust-all: lint-rust lint-rust-fmt-check
    @echo "Rust linting and formatting complete ✓"

# Fix all auto-fixable linting issues
lint-all-fix: lint-fix lint-js-fix lint-md-fix lint-rust-fix lint-rust-fmt
    @echo "All auto-fixable linting issues resolved ✓"

# ==================== DOCUMENTATION ====================

# Generate Sphinx documentation
docs-build:
    cd docs && pixi run sphinx-build -b html source build/html

# Clean documentation build
docs-clean:
    cd docs && rm -rf build/*

# Regenerate API documentation from code
docs-apidoc:
    cd docs && pixi run sphinx-apidoc -f -o source ../intellicrack

# Full documentation rebuild
docs-rebuild: docs-clean docs-apidoc docs-build
    @echo "Documentation rebuilt in docs/build/html/index.html"

# Open documentation in browser (Windows)
docs-open:
    start docs/build/html/index.html

# Build PDF documentation
docs-pdf:
    cd docs && pixi run sphinx-build -b latex source build/latex
    @echo "LaTeX files generated in docs/build/latex/"

# Check documentation links
docs-linkcheck:
    cd docs && pixi run sphinx-build -b linkcheck source build/linkcheck
    @echo "Link check results in docs/build/linkcheck/output.txt"
