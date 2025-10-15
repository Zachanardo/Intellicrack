# Intellicrack Testing Commands

# Configure shell for Windows
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

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
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .pytest_cache
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue coverage_html_report
    Remove-Item -Force -ErrorAction SilentlyContinue .coverage
    Remove-Item -Force -ErrorAction SilentlyContinue *.pyc
    Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force

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
    pixi run ./tools/checkstyle/checkstyle -c ./tools/checkstyle/intellicrack_checks.xml (Get-ChildItem -Recurse -Filter *.java | Where-Object { $_.FullName -notmatch '(tools|\.venv|\.pixi|build|dist)' } | Select-Object -ExpandProperty FullName)

# Lint Markdown files with markdownlint
lint-md:
    pixi run markdownlint "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Fix Markdown linting issues automatically
lint-md-fix:
    pixi run markdownlint "**/*.md" --fix --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Lint all core file types (Python + Rust)
lint-all:
    -@just lint
    -@just lint-rust-all
    @echo "All core linting complete ✓"

# Lint all file types including optional linters (requires setup-all first)
lint-all-extended:
    -@just lint
    -@just lint-js
    -@just lint-java
    -@just lint-md
    -@just lint-rust-all
    @echo "All extended linting complete ✓"

# Lint Rust code with clippy
lint-rust:
    pixi run cargo clippy --manifest-path intellicrack-launcher/Cargo.toml -- -D warnings

# Format Rust code with rustfmt
lint-rust-fmt:
    cd intellicrack-launcher; pixi run cargo fmt

# Check Rust formatting without applying changes
lint-rust-fmt-check:
    cd intellicrack-launcher; pixi run cargo fmt -- --write-mode=diff

# Fix Rust linting issues automatically
lint-rust-fix:
    pixi run cargo clippy --manifest-path intellicrack-launcher/Cargo.toml --fix --allow-dirty --allow-staged -- -D warnings

# All Rust linting and formatting
lint-rust-all: lint-rust lint-rust-fmt-check
    @echo "Rust linting and formatting complete ✓"

# Fix all core auto-fixable linting issues (Python + Rust)
lint-all-fix:
    -@just lint-fix
    -@just lint-rust-fix
    -@just lint-rust-fmt
    @echo "All core auto-fixable linting issues resolved ✓"

# Fix all auto-fixable linting issues including optional linters
lint-all-fix-extended:
    -@just lint-fix
    -@just lint-js-fix
    -@just lint-md-fix
    -@just lint-rust-fix
    -@just lint-rust-fmt
    @echo "All extended auto-fixable linting issues resolved ✓"

# ==================== DOCUMENTATION ====================

# Generate Sphinx documentation
docs-build:
    pixi run sphinx-build -b html docs/source docs/build/html

# Clean documentation build
docs-clean:
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*

# Regenerate API documentation from code
docs-apidoc:
    pixi run sphinx-apidoc -f -o docs/source intellicrack

# Full documentation rebuild
docs-rebuild: docs-clean docs-apidoc docs-build
    Write-Output "Documentation rebuilt in docs/build/html/index.html"

# Open documentation in browser (Windows)
docs-open:
    Start-Process docs\build\html\index.html

# Build PDF documentation
docs-pdf:
    pixi run sphinx-build -b latex docs/source docs/build/latex
    Write-Output "LaTeX files generated in docs/build/latex/"

# Check documentation links
docs-linkcheck:
    pixi run sphinx-build -b linkcheck docs/source docs/build/linkcheck
    Write-Output "Link check results in docs/build/linkcheck/output.txt"
