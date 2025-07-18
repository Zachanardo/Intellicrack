#!/bin/bash
# Script to check all dependency conflicts at once

echo "=== Method 1: Using pip-compile to check conflicts ==="
echo "Creating temporary requirements file..."
cp requirements.txt requirements_check.in

echo "Running pip-compile..."
source test_venv/bin/activate
pip-compile requirements_check.in -o requirements_compiled.txt --resolver=backtracking 2>&1 | grep -A5 -B5 "conflict"

echo -e "\n=== Method 2: Using pip install --dry-run ==="
pip install --dry-run -r requirements.txt 2>&1 | grep -E "(ERROR:|Conflict|incompatible|Cannot install)" -A 3

echo -e "\n=== Method 3: Using pipdeptree ==="
pip install pipdeptree > /dev/null 2>&1
pipdeptree --warn fail 2>&1 | grep -E "(conflicting|Warning)" -A 2

# Cleanup
rm -f requirements_check.in requirements_compiled.txt