# Makefile for Intellicrack Project

# Variables
PYTHON := python3
PIP := pip3
PROJECT := intellicrack
LINT_DIRS := intellicrack tests scripts setup.py
TEST_PATH := tests
DOC_SOURCE := docs
DOC_BUILD := docs/_build

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: help install install-dev install-full lint format test test-cov clean build docs run run-cli run-gui check security profile

help:
	@echo "$(BLUE)Intellicrack Development Makefile$(NC)"
	@echo ""
	@echo "$(GREEN)Installation:$(NC)"
	@echo "  make install      Install the package and core dependencies"
	@echo "  make install-dev  Install package with development dependencies"
	@echo "  make install-full Install package with ALL optional dependencies"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make lint         Run all linters (flake8, mypy, pylint)"
	@echo "  make format       Format code (black, isort)"
	@echo "  make test         Run unit tests"
	@echo "  make test-cov     Run tests with coverage report"
	@echo "  make check        Run all checks (lint + test)"
	@echo "  make security     Run security checks (bandit, safety)"
	@echo ""
	@echo "$(GREEN)Running:$(NC)"
	@echo "  make run          Run the GUI application"
	@echo "  make run-cli      Run the CLI (requires binary path)"
	@echo "  make run-gui      Run the GUI explicitly"
	@echo ""
	@echo "$(GREEN)Documentation:$(NC)"
	@echo "  make docs         Build documentation"
	@echo "  make docs-serve   Build and serve documentation"
	@echo ""
	@echo "$(GREEN)Building:$(NC)"
	@echo "  make build        Build distribution packages"
	@echo "  make clean        Clean all generated files"
	@echo "  make clean-all    Clean everything including venv"
	@echo ""
	@echo "$(GREEN)Profiling:$(NC)"
	@echo "  make profile      Run performance profiling"
	@echo ""

# Installation targets
install:
	@echo "$(BLUE)Installing $(PROJECT) and core dependencies...$(NC)"
	$(PIP) install -e .
	@echo "$(GREEN)Installation complete!$(NC)"

install-dev: install
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install -e ".[dev]"
	@echo "$(GREEN)Development installation complete!$(NC)"

install-full: install
	@echo "$(BLUE)Installing ALL optional dependencies...$(NC)"
	$(PIP) install -e ".[full,ml,network,dev]"
	@echo "$(GREEN)Full installation complete!$(NC)"

# Code quality targets
lint:
	@echo "$(BLUE)Running linters...$(NC)"
	@echo "$(YELLOW)Running flake8...$(NC)"
	-$(PYTHON) -m flake8 $(LINT_DIRS)
	@echo "$(YELLOW)Running mypy...$(NC)"
	-$(PYTHON) -m mypy $(PROJECT)
	@echo "$(YELLOW)Running pylint...$(NC)"
	-$(PYTHON) -m pylint $(PROJECT)
	@echo "$(YELLOW)Checking import order...$(NC)"
	$(PYTHON) -m isort --check-only $(LINT_DIRS)
	@echo "$(YELLOW)Checking code formatting...$(NC)"
	$(PYTHON) -m black --check $(LINT_DIRS)
	@echo "$(GREEN)Linting complete!$(NC)"

format:
	@echo "$(BLUE)Formatting code...$(NC)"
	$(PYTHON) -m isort $(LINT_DIRS)
	$(PYTHON) -m black $(LINT_DIRS)
	@echo "$(GREEN)Formatting complete!$(NC)"

# Testing targets
test:
	@echo "$(BLUE)Running tests...$(NC)"
	$(PYTHON) -m pytest $(TEST_PATH) -v

test-cov:
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(PYTHON) -m pytest $(TEST_PATH) --cov=$(PROJECT) --cov-report=html --cov-report=term
	@echo "$(GREEN)Coverage report generated in htmlcov/index.html$(NC)"

test-fast:
	@echo "$(BLUE)Running fast tests (no integration tests)...$(NC)"
	$(PYTHON) -m pytest $(TEST_PATH) -v -m "not slow"

# Combined checks
check: lint test
	@echo "$(GREEN)All checks passed!$(NC)"

# Security checks
security:
	@echo "$(BLUE)Running security checks...$(NC)"
	@echo "$(YELLOW)Running bandit...$(NC)"
	-$(PYTHON) -m bandit -r $(PROJECT) -x tests
	@echo "$(YELLOW)Checking dependencies with safety...$(NC)"
	-$(PYTHON) -m safety check
	@echo "$(GREEN)Security checks complete!$(NC)"

# Running the application
run: run-gui

run-gui:
	@echo "$(BLUE)Starting Intellicrack GUI...$(NC)"
	$(PYTHON) -m $(PROJECT)

run-cli:
	@echo "$(BLUE)Starting Intellicrack CLI...$(NC)"
	@echo "Usage: make run-cli BINARY=<path/to/binary>"
	@if [ -z "$(BINARY)" ]; then \
		echo "$(RED)ERROR: Please specify BINARY=<path>$(NC)"; \
		echo "Example: make run-cli BINARY=/bin/ls"; \
		exit 1; \
	fi
	$(PYTHON) scripts/run_analysis_cli.py "$(BINARY)"

# Documentation
docs:
	@echo "$(BLUE)Building documentation...$(NC)"
	@if [ ! -d "$(DOC_SOURCE)" ]; then \
		echo "$(YELLOW)Creating docs directory...$(NC)"; \
		sphinx-quickstart -q -p $(PROJECT) -a "Intellicrack Team" --ext-autodoc --ext-viewcode --makefile $(DOC_SOURCE); \
	fi
	cd $(DOC_SOURCE) && $(MAKE) html
	@echo "$(GREEN)Documentation built in $(DOC_BUILD)/html/index.html$(NC)"

docs-serve: docs
	@echo "$(BLUE)Serving documentation on http://localhost:8000...$(NC)"
	cd $(DOC_BUILD)/html && python3 -m http.server 8000

# Building distribution
build:
	@echo "$(BLUE)Building distribution packages...$(NC)"
	$(PYTHON) -m build
	@echo "$(GREEN)Build complete! Packages in dist/$(NC)"

# Cleaning
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .pytest_cache/ .coverage coverage.xml htmlcov/ .mypy_cache/
	rm -rf $(DOC_BUILD)
	rm -f .coverage.* intellicrack_error.log
	@echo "$(GREEN)Clean complete!$(NC)"

clean-all: clean
	@echo "$(BLUE)Cleaning everything including virtual environment...$(NC)"
	rm -rf .venv venv env
	rm -rf .tox .nox
	rm -rf node_modules
	@echo "$(GREEN)Deep clean complete!$(NC)"

# Performance profiling
profile:
	@echo "$(BLUE)Running performance profiling...$(NC)"
	@if [ -z "$(BINARY)" ]; then \
		echo "$(YELLOW)Using default test binary...$(NC)"; \
		PROF_BINARY="/bin/ls"; \
	else \
		PROF_BINARY="$(BINARY)"; \
	fi
	$(PYTHON) -m cProfile -o profile.prof -m $(PROJECT).utils.binary_analysis analyze_binary "$$PROF_BINARY"
	$(PYTHON) -m snakeviz profile.prof
	@echo "$(GREEN)Profiling complete!$(NC)"

# Development helpers
.PHONY: venv
venv:
	@echo "$(BLUE)Creating virtual environment...$(NC)"
	$(PYTHON) -m venv .venv
	@echo "$(GREEN)Virtual environment created!$(NC)"
	@echo "Activate with: source .venv/bin/activate (Linux/macOS) or .venv\\Scripts\\activate (Windows)"

.PHONY: update-deps
update-deps:
	@echo "$(BLUE)Updating dependencies...$(NC)"
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install --upgrade -r requirements.txt
	@echo "$(GREEN)Dependencies updated!$(NC)"

.PHONY: freeze
freeze:
	@echo "$(BLUE)Freezing current dependencies...$(NC)"
	$(PIP) freeze > requirements-frozen.txt
	@echo "$(GREEN)Dependencies frozen to requirements-frozen.txt$(NC)"

# Docker support (if needed)
.PHONY: docker-build docker-run
docker-build:
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t $(PROJECT):latest .

docker-run:
	@echo "$(BLUE)Running in Docker container...$(NC)"
	docker run -it --rm -v $(PWD):/app $(PROJECT):latest

# Quick development cycle
.PHONY: dev
dev: format test
	@echo "$(GREEN)Quick development cycle complete!$(NC)"

# Release preparation
.PHONY: release-prep
release-prep: clean check security build
	@echo "$(GREEN)Release preparation complete!$(NC)"
	@echo "Don't forget to:"
	@echo "  1. Update version in pyproject.toml and setup.py"
	@echo "  2. Update CHANGELOG.md"
	@echo "  3. Tag the release: git tag -a v0.1.0 -m 'Release v0.1.0'"
	@echo "  4. Push tags: git push origin --tags"