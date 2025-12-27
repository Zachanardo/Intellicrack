# Intellicrack Testing Coverage Workflow

## Phase 1: Analysis (3 Parallel Explore Agents)

Launch 3 Explore agents in parallel. Each agent analyzes only its assigned group and writes findings to testing-todo{N}.md (where N = 1-3) in project root.

### Group Assignments

| Agent | Scope                                                                                                                                                                                                                                            |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1     | `**/radare2*`, `**/frida*`, `handlers/*`, `hexview/*`, `analysis/*` (root), `core/analysis/*`, `utils/binary/*`, `utils/analysis/*`, `protection/*`, `core/protection_bypass/*`, `core/anti_analysis/*`, `core/certificate/*`, `core/patching/*` |
| 2     | `ai/*`, `ml/*`, `core/ml/*`, `core/exploitation/*`, `core/vulnerability_research/*`, `ui/*`, `utils/ui/*`, `cli/*`, `dashboard/*`, `core/monitoring/*`, `core/reporting/*`                                                                       |
| 3     | `core/*` (root), `core/processing/*`, `core/network/*`, `core/orchestration/*`, `core/logging/*`, `core/resources/*`, `intellicrack/*` (root), `scripts/*`, `data/*`, `utils/*` (remaining subdirs), `plugins/*`, `models/*`                     |

### Agent Task Template

```
Analyze testing coverage for Intellicrack Group {N}.

SCOPE: Files matching: {GROUP_PATHS}

REQUIREMENTS:
1. For each source file, identify corresponding test file(s) in tests/
2. Evaluate existing tests: Do they GENUINELY validate the code's ability to perform its intended function at a sophisticated, production-ready level? Or are they superficial/mock-based?
3. Document ALL shortcomings - missing tests, inadequate tests, mock-only tests, untested edge cases

OUTPUT: Write to `testing-todo{N}.md` in project root using this format:

# Testing Coverage: Group {N}

## Missing Tests
- [ ] `path/to/file.py` - No test coverage exists
- [ ] `path/to/file.py::ClassName` - Class untested

## Inadequate Tests
- [ ] `path/to/file.py::function_name` - Test exists but only uses mocks, doesn't validate real functionality
- [ ] `path/to/file.py::ClassName::method` - Test doesn't cover error handling/edge cases

## Recommendations
- [ ] `description of what genuine test should validate`

Be EXHAUSTIVE. Missing findings are unacceptable.
```

---

## Phase 2: Verify Analysis

After all 3 complete:

1. Read each testing-todo{N}.md
2. Verify: comprehensive scope coverage, proper todo format, actionable items
3. If inadequate: restart that agent with explicit corrections
4. Repeat until all 3 pass verification

---

## Phase 3: Remediation (3 Parallel Test-Writer Agents)

Launch 3 test-writer agents in parallel, one per testing-todo{N}.md.

### Agent Task Template

```
Implement testing fixes from `testing-todo{N}.md`.

REQUIREMENTS:
1. Work through each unchecked item sequentially
2. Write production-ready tests that GENUINELY validate functionality against real operations
3. After completing each item, edit the markdown to mark it `[x]` complete
4. Continue until all items are checked

Tests must:
- Use real data/binaries where applicable
- Validate actual functionality, not mocked behavior
- Cover edge cases and error conditions
- Be immediately runnable with pytest
```

---

## Phase 4: Review (3 Parallel Test-Reviewer Agents)

After all 3 test-writer agents complete, launch 3 test-reviewer agents in parallel. Each reviewer validates the corresponding test-writer's output.

### Agent Task Template

```
Review tests written for Group {N} from `testing-todo{N}.md`.

SCOPE: All test files created/modified by the test-writer agent for Group {N}

REQUIREMENTS:
1. For each test file, verify it meets ALL production-ready criteria:
   - NO mocks, stubs, or simulated functionality
   - Tests validate REAL operations against actual binaries/data
   - Comprehensive edge case coverage
   - Proper error handling validation
   - Tests would FAIL if the tested code doesn't perform at production level
   - Code follows project standards (type hints, no placeholders, Windows compatibility)

2. Run `pixi run ruff check` on each test file - all linting issues must be resolved

3. Evaluate test effectiveness:
   - Would this test catch real bugs in licensing crack functionality?
   - Does it validate genuine capability, not just code paths?
   - Are assertions meaningful and specific?

OUTPUT: Write findings to `testing-review{N}.md` in project root:

# Test Review: Group {N}

## Passed Review
- [x] `tests/path/to/test_file.py` - Production-ready, validates real functionality

## Failed Review
- [ ] `tests/path/to/test_file.py` - ISSUE: Uses mocks for X instead of real validation
- [ ] `tests/path/to/test_file.py` - ISSUE: Missing edge cases for Y
- [ ] `tests/path/to/test_file.py` - ISSUE: Linting errors not resolved

## Required Fixes
For each failed test, provide SPECIFIC instructions:
- `tests/path/to/test_file.py`: Replace mock_binary_analyzer with real BinaryAnalyzer instance operating on test fixtures
- `tests/path/to/test_file.py`: Add test cases for corrupted binary input, permission errors, timeout scenarios

Be STRICT. Tests that wouldn't catch real bugs in production code FAIL review.
```

---

## Phase 5: Analyze Review Results

After all 3 reviewers complete:

1. Read each testing-review{N}.md
2. For each group, check if ALL tests passed review
3. Compile list of groups requiring remediation fixes

---

## Phase 6: Targeted Remediation Loop

For each group with failed reviews:

1. **Identify failures**: Extract specific issues from testing-review{N}.md

2. **Relaunch test-writer agent** with targeted fix instructions:

```
Fix failing tests identified in `testing-review{N}.md`.

FAILURES TO ADDRESS:
{List each failed test file with its specific issues from the review}

REQUIREMENTS:
1. Address ONLY the specific issues identified - do not rewrite passing tests
2. For each fix:
   - Remove any mocks/stubs and replace with real implementations
   - Add missing edge case coverage
   - Resolve all linting errors with `pixi run ruff check`
   - Ensure tests validate genuine production functionality

3. After fixing each test file, verify by asking: "Would this test FAIL if the code it tests was broken?"

4. Update `testing-todo{N}.md` to reflect completed fixes
```

3. **Re-review**: After the targeted test-writer completes, launch a test-reviewer agent to re-validate ONLY the fixed tests

4. **Repeat** until all tests pass review or maximum 3 iterations reached

---

## Phase 7: Final Verification

After all groups pass review (or max iterations):

1. **Compile final status report** showing:
    - Total tests written/fixed per group
    - Any tests that couldn't be brought to production quality (with reasons)
    - Overall coverage improvement metrics

2. **Run full test suite**: `pixi run pytest tests/ -v --tb=short`

3. **Document any remaining failures** for manual follow-up
