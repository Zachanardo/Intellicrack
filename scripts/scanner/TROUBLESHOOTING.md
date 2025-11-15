# Scanner Troubleshooting Guide

This guide helps you understand scanner findings, handle false positives, and use the scanner effectively.

## Table of Contents

1. [Understanding Scanner Results](#understanding-scanner-results)
2. [Pattern Recognition System](#pattern-recognition-system)
3. [Handling False Positives](#handling-false-positives)
4. [Using Scanner-Ignore Comments](#using-scanner-ignore-comments)
5. [Code Examples](#code-examples)
6. [FAQ](#faq)

---

## Understanding Scanner Results

### Confidence Levels

The scanner assigns confidence scores based on detected evidence:

- **CRITICAL** (≥100 points): High probability of non-production code, requires immediate attention
- **HIGH** (≥75 points): Strong indicators of issues, should be reviewed
- **MEDIUM** (≥55 points): Moderate concerns, may need investigation
- **LOW** (≥35 points): Minor issues or potential concerns
- **INFO** (<35 points): Informational findings

### Adjusting Sensitivity

Use the `-c` flag to filter results:

```bash
# Show only critical issues
./scanner -c critical

# Show high and critical
./scanner -c high

# Show medium and above (default)
./scanner -c medium

# Show all findings
./scanner -c low
```

### Issue Types

- **stub_detection**: Functions with minimal or no implementation
- **empty_function**: Functions that appear to do nothing meaningful
- **hardcoded_return**: Functions returning hardcoded values without computation
- **naive_implementation**: Overly simplistic implementations for complex operations
- **weak_validation**: Validators that don't perform adequate checks

---

## Pattern Recognition System

The scanner automatically recognizes and handles several legitimate code patterns:

### Abstract Methods (Completely Excluded)

Abstract methods are **never flagged** as issues:

```python
from abc import ABC, abstractmethod

class ModelLoader(ABC):
    @abstractmethod
    def load_model(self):
        """Subclasses must implement."""
        pass
```

**Why excluded?** Abstract methods are intentionally unimplemented base class methods.

### CLI Framework Commands (Completely Excluded)

CLI framework decorators are **never flagged**:

```python
import click

@click.group()
def cli():
    """Main CLI group."""
    pass

@cli.command()
def analyze():
    """Analysis command."""
    pass
```

**Why excluded?** Click, Typer, and argparse command groups are legitimate framework patterns.

### Orchestration Patterns (50% Confidence Reduction)

High-level workflow coordinators receive **reduced confidence scores**:

```python
def run_full_analysis(binary_path):
    """Orchestrates multiple analysis steps."""
    logger.info("Starting analysis")

    # Multiple function calls coordinating workflow
    results = {}
    results['binary'] = analyze_binary(binary_path)
    results['protection'] = detect_protection(binary_path)
    results['strings'] = extract_strings(binary_path)

    logger.info(f"Analysis complete: {len(results)} steps")
    return aggregate_results(results)
```

**Why reduced?** These functions coordinate work rather than implement it directly.

### Delegation Patterns (50% Confidence Reduction)

Value-adding wrapper functions receive **reduced confidence scores**:

```python
def safe_read_file(path):
    """Wrapper with error handling."""
    try:
        return read_file_content(path)
    except Exception as e:
        logger.error(f"Failed to read {path}: {e}")
        return None
```

**Why reduced?** Delegation is legitimate when it adds error handling, logging, or validation.

### Enhanced Validation Detection

Functions with validation logic receive **deduction points**:

```python
def validate_binary(path):
    """Validation with multiple checks."""
    if not isinstance(path, (str, Path)):
        raise TypeError("Path must be string or Path")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    if not path.is_file():
        raise ValueError(f"Not a file: {path}")

    return True
```

**Why deductions?** Validators legitimately have simple implementations with multiple checks.

---

## Handling False Positives

### Step 1: Verify the Finding

Before dismissing a finding, ask:

1. **Is this actually production-ready code?**
   - Does it handle real inputs and edge cases?
   - Is error handling adequate?
   - Would it work against real binaries/protections?

2. **Is this a recognized pattern?**
   - Abstract methods → Should be auto-excluded
   - CLI commands → Should be auto-excluded
   - Orchestration → Should have reduced confidence
   - Delegation with value-add → Should have reduced confidence

3. **Is the confidence level appropriate?**
   - Use `-c high` or `-c critical` to focus on serious issues
   - LOW/MEDIUM findings may be acceptable for certain code

### Step 2: Determine the Appropriate Action

**If the code is genuinely production-ready:**
- Use scanner-ignore comment (see below)
- Consider if the pattern should be added to scanner exclusions

**If the code needs improvement:**
- Implement the missing functionality
- Add proper error handling
- Use real implementations instead of placeholders

**If it's a pattern mismatch:**
- Report as a scanner bug if it should be auto-detected
- Use scanner-ignore comment for now

---

## Using Scanner-Ignore Comments

### Syntax

Place a comment with `scanner-ignore` on the line **before** the function definition:

```python
# scanner-ignore: This is LLM delegation pattern
def analyze_with_ai(code):
    return llm_backend.chat(prompt=f"Analyze: {code}")
```

### When to Use Scanner-Ignore

**Appropriate uses:**

1. **LLM Delegation Patterns** (not yet auto-detected):
   ```python
   # scanner-ignore: LLM-based analysis
   def analyze_binary_with_ai(binary_path):
       prompt = create_analysis_prompt(binary_path)
       return llm.generate(prompt)
   ```

2. **External Tool Integration** (subprocess calls):
   ```python
   # scanner-ignore: Delegates to radare2
   def analyze_with_r2(binary):
       return subprocess.run(['r2', '-q', binary], capture_output=True)
   ```

3. **Configuration Getters/Setters**:
   ```python
   # scanner-ignore: Simple config getter
   def get_timeout(self):
       return self._timeout
   ```

4. **Test Helper Functions**:
   ```python
   # scanner-ignore: Test fixture
   def create_test_binary():
       return b'\x90' * 100
   ```

**Inappropriate uses:**

1. **Hiding real stubs/placeholders**:
   ```python
   # DON'T DO THIS - Fix the code instead
   # scanner-ignore: TODO implement later
   def crack_protection(binary):
       return True  # This is a stub!
   ```

2. **Suppressing legitimate issues**:
   ```python
   # DON'T DO THIS - Fix the validation
   # scanner-ignore: Works fine
   def validate_input(x):
       return True  # No actual validation!
   ```

---

## Code Examples

### ✅ Correctly Excluded: Abstract Method

```python
from abc import ABC, abstractmethod

class ProtectionAnalyzer(ABC):
    @abstractmethod
    def detect_protection(self, binary_path: str) -> dict:
        """Detect protection scheme in binary."""
        pass
```

**Scanner action:** Completely excluded, never appears in report

---

### ✅ Correctly Excluded: CLI Command

```python
import click

@click.command()
def keygen():
    """Generate license key."""
    pass
```

**Scanner action:** Completely excluded, never appears in report

---

### ✅ Correctly Reduced: Orchestration

```python
def run_crack_workflow(binary_path):
    """Orchestrates cracking workflow."""
    logger.info("Starting crack workflow")

    protection = detect_protection(binary_path)
    weaknesses = find_weaknesses(protection)
    patches = generate_patches(weaknesses)

    logger.info(f"Generated {len(patches)} patches")
    return apply_patches(binary_path, patches)
```

**Scanner action:** 50% confidence reduction applied, appears at lower severity

---

### ✅ Correctly Reduced: Delegation

```python
def safe_patch_binary(binary_path, patches):
    """Wrapper with validation and backup."""
    if not validate_patches(patches):
        raise ValueError("Invalid patches")

    backup_file(binary_path)

    try:
        return apply_patches(binary_path, patches)
    except Exception as e:
        restore_backup(binary_path)
        raise
```

**Scanner action:** 50% confidence reduction applied, deductions for validation

---

### ❌ Correctly Flagged: Stub Function

```python
def crack_vmprotect(binary_path):
    """Crack VMProtect-protected binary."""
    return True
```

**Scanner finding:** CRITICAL - hardcoded return, no implementation

**Action needed:** Implement real VMProtect analysis or remove the function

---

### ❌ Correctly Flagged: Weak Validator

```python
def validate_keygen_output(key):
    """Validate generated key."""
    return len(key) > 0
```

**Scanner finding:** CRITICAL - validator with no verification calls

**Action needed:** Add proper key format validation, checksum verification, etc.

---

### ❌ Correctly Flagged: Naive Implementation

```python
def find_license_check(binary_data):
    """Find license validation routine."""
    return "license" in binary_data.decode('latin1', errors='ignore')
```

**Scanner finding:** HIGH - naive implementation, string matching only

**Action needed:** Implement proper binary analysis with pattern matching

---

### ⚠️ False Positive: LLM Delegation

```python
def analyze_protection_with_ai(binary_path):
    """Use LLM to analyze protection scheme."""
    binary_info = extract_binary_metadata(binary_path)
    prompt = f"Analyze protection: {binary_info}"
    return llm_backend.chat(prompt)
```

**Scanner finding:** HIGH - function calls external service

**Action:** Add scanner-ignore comment (LLM patterns not yet auto-detected)

---

## FAQ

### Why is my production code being flagged?

**Q:** My function is production-ready but the scanner flags it. Why?

**A:** Several possible reasons:

1. **Pattern not recognized**: If it's a legitimate pattern like LLM delegation, use `scanner-ignore`
2. **Confidence too sensitive**: Try `-c high` or `-c critical` to focus on serious issues
3. **Missing evidence**: Add validation, error handling, or complexity to reduce score
4. **True positive**: The code may actually need improvement

### What's the difference between excluded and reduced confidence?

**Q:** Why are some patterns completely excluded while others just get reduced confidence?

**A:**

- **Completely excluded** (abstract methods, CLI commands):
  - These patterns are NEVER wrong in their context
  - Abstract methods must be unimplemented
  - CLI groups can be empty

- **Reduced confidence** (orchestration, delegation):
  - These patterns can be legitimate OR problematic
  - Scanner reduces confidence but still reports them
  - Allows you to decide if they're acceptable

### How do I know if it's a true positive?

**Q:** How can I tell if a finding is legitimate or a false positive?

**A:** Ask these questions:

1. **Would this code work on real binaries?**
   - If you tested it on actual protected software, would it succeed?

2. **Is the implementation complete?**
   - Are there TODOs, placeholders, or hardcoded values?

3. **Does it handle edge cases?**
   - What happens with malformed input, errors, or unusual binaries?

4. **Is it production-grade?**
   - Would you ship this to users without concern?

If any answer is "no", it's likely a true positive.

### Can I adjust confidence thresholds?

**Q:** Can I change what the scanner considers CRITICAL vs HIGH?

**A:** The thresholds are hardcoded in the scanner, but you can:

1. **Filter output**: Use `-c critical` to see only ≥100 point findings
2. **Modify source**: Edit `production_scanner.rs` confidence mappings (requires rebuild)
3. **Request feature**: File an issue for configurable thresholds

Current thresholds:
- CRITICAL: ≥100 points
- HIGH: ≥75 points
- MEDIUM: ≥55 points
- LOW: ≥35 points

### What if the scanner misses real issues?

**Q:** The scanner didn't catch a stub in my code. What should I do?

**A:**

1. **Verify it's actually a stub**: Check if it's a recognized pattern
2. **Report as bug**: File an issue with the code example
3. **Manual review**: Don't rely solely on the scanner

The scanner is a tool to assist code review, not replace it.

### How often should I run the scanner?

**Q:** When should I run scans?

**A:** Recommended workflow:

- **Before commits**: Quick scan of changed files
- **Before PRs**: Full scan to catch issues early
- **After merges**: Verify no issues introduced
- **Weekly**: Regular full scans to maintain quality
- **Before releases**: Comprehensive scan as quality gate

Use `--no-cache` for accurate results after code changes:

```bash
./scanner --no-cache
```

### Why do I see duplicate issues?

**Q:** Some functions appear multiple times in the report with identical findings.

**A:** This is a known issue in the scanner. Duplicates occur when:

- Functions are analyzed multiple times during AST traversal
- Evidence collection happens in different contexts

**Workaround:** Look at line numbers to identify unique findings. Duplicates will have identical line numbers.

**Status:** Being tracked for fix in future scanner version.

### Can I exclude entire files or directories?

**Q:** How do I tell the scanner to ignore certain files?

**A:** Currently, the scanner uses `.gitignore` patterns to exclude files. For additional exclusions:

1. **Add to .gitignore**: Files in `.gitignore` are automatically skipped
2. **Use scanner-ignore comments**: Add to specific functions
3. **Filter output**: Use `grep` or other tools to filter TODO.md

**Future feature:** Dedicated `.scannerignore` file is planned.

---

## Getting Help

If you encounter issues not covered in this guide:

1. **Check README.md**: See if your question is answered in the main documentation
2. **Review INTEGRATION_REPORT.md**: Technical details about scanner behavior
3. **Examine scanner source**: `production_scanner.rs` contains all detection logic
4. **File an issue**: Report bugs or request features

For questions about the scanner implementation, see the inline documentation in `production_scanner.rs`.
