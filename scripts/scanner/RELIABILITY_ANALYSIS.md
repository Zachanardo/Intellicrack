# Scanner Reliability Analysis

## Current State (2025-11-14)

**Total Issues:** 478 (at threshold 200 - CRITICAL only)
**Baseline:** 657 issues (at threshold 50)
**Reduction:** 27.2% through pattern detection and deductions

## Critical Bugs Blocking Reliability

### 1. DUPLICATE FUNCTION EXTRACTION (CRITICAL)

**Symptom:** Functions appear 2x in output (e.g., synchronize() at line 162 appears twice)
**Root Cause:** Tree-sitter query patterns are not mutually exclusive
**Impact:** Tool reports 2x the actual issues, completely unreliable

**Current Query:**
```rust
; Match decorated module-level functions
(module (decorated_definition definition: (function_definition) @function))

; Match bare module-level functions (not decorated)
(module (function_definition) @function)  // MATCHES CLASS METHODS TOO!

; Match decorated class methods
(class_definition body: (block (decorated_definition definition: (function_definition) @method)))

; Match bare class methods (not decorated)
(class_definition body: (block (function_definition) @method))
```

**Problem:** Pattern 2 `(module (function_definition))` matches ANY function_definition inside module, including class methods.

**Fix Required:** Use immediate child syntax `(module . (function_definition))` or dedup at AST extraction level.

### 2. FALSE POSITIVE DESIGN FLAW (CRITICAL)

**Approach:** Scanner looks for ABSENCE of patterns (no loops, no conditionals, short length)
**Reality:** Production code has many legitimate short/simple functions:
- Delegators (3-5 lines calling other functions)
- Property getters/setters
- Event handlers (on_*, handle_*)
- CLI command functions
- Configuration loaders
- Wrapper functions

**Manual Review Result:** 80% false positive rate (8/10 flagged functions were production-ready)

**Root Cause:** Scanner doesn't understand CODE CONTEXT or ARCHITECTURE PATTERNS

### 3. DEDUCTION SYSTEM INSUFFICIENT

**Current Deductions:**
- Abstract methods: 200 points
- CLI framework: 200 points
- Orchestration: 80 points
- LLM delegation: 100 points
- Validation checks (2+): 130 points
- Byte manipulation: 70 points

**Problem:** Even with deductions, scores of 200-300 still common
**Threshold at 200:** Still 478 issues
**Conclusion:** Deductions are band-aids, not solutions

---

## What's Needed for Minimal False Positives

### Phase 1: Fix Critical Bugs (IMMEDIATE)

1. **Fix duplicate extraction:**
   - Modify tree-sitter query to use immediate child syntax
   - OR: Dedup by (file_path, line_number, function_name) at extraction level
   - Verify: scan should show 1 issue for synchronize(), not 2

2. **Verify deduplication works:**
   - Add logging for duplicate detection
   - Ensure HashMap dedup is functioning
   - Test against known single-function files

### Phase 2: Rethink Detection Strategy (CORE FIX)

**Current:** Look for ABSENCE of complexity (negative detection)
**Needed:** Look for PRESENCE of problems (positive detection)

**Shift from:**
- "No loops" → Flag as stub
- "No conditionals" → Flag as incomplete
- "Short function" → Flag as trivial

**Shift to:**
- Contains literal "TODO" or "FIXME" → Flag
- Returns hardcoded placeholder ("TODO", "Not implemented") → Flag
- Raises NotImplementedError → Flag
- Has pass/... as only statement → Flag
- Has explicit stub markers (# stub, # placeholder) → Flag

**Keep only:**
- Domain-specific checks (keygen without crypto, patcher without backup)
- Semantic issues (processer without loops when name implies batch)
- Actual incomplete markers in code

### Phase 3: Comprehensive Pattern Library

**Legitimate Patterns to NEVER Flag:**

1. **Delegation Functions:**
```python
def analyze_protection(binary):
    return self.engine.analyze(binary)  # 1 line - LEGITIMATE
```

2. **Property Access:**
```python
def get_status(self):
    return self._status  # 1 line - LEGITIMATE
```

3. **Event Handlers:**
```python
def on_message(self, msg):
    self.queue.put(msg)  # 1-2 lines - LEGITIMATE
```

4. **Configuration Loaders:**
```python
def load_config(self):
    return json.load(open('config.json'))  # 1 line - LEGITIMATE
```

5. **CLI Command Functions:**
```python
@click.command()
def patch(binary, offset):
    apply_patch(binary, offset)  # Delegates to real impl - LEGITIMATE
```

6. **Library Wrappers:**
```python
def synchronize(self):
    if GPU_AVAILABLE:
        gpu.synchronize()  # Wraps library - LEGITIMATE
```

7. **Factory Functions:**
```python
def create_analyzer(type):
    return ANALYZERS[type]()  # 1 line - LEGITIMATE
```

**Implementation:**
- Create `is_delegator_pattern()` - checks if function just calls another function
- Create `is_property_accessor()` - checks if function just returns attribute
- Create `is_wrapper_pattern()` - checks if function wraps library call
- Create `is_factory_pattern()` - checks if function returns constructed object

### Phase 4: Context-Aware Analysis

**File-Level Context:**
- If file has 20+ functions and only 2 are flagged → likely false positives
- If file is in `utils/`, `helpers/`, `cli/` → expect short delegator functions
- If file is in `core/`, `engine/`, `analysis/` → expect more complex logic

**Module-Level Context:**
- If function is imported and used by 10+ other files → probably not a stub
- If function is called by tests → probably has real implementation
- If function is part of ABC interface → different rules

**Architectural Patterns:**
- Recognize MVC pattern (Controllers delegate to Models)
- Recognize CLI pattern (Commands delegate to Services)
- Recognize Facade pattern (Simple interface wraps complex subsystem)

### Phase 5: Test-Driven Calibration

**Process:**
1. Select 100 random functions from codebase
2. Manually classify each as REAL_ISSUE or FALSE_POSITIVE
3. Run scanner, compare results
4. Calculate precision = TP / (TP + FP)
5. Iterate on patterns until precision >95%

**Acceptance Criteria:**
- Precision (accuracy of flags) >95%
- Recall (catching real issues) >90%
- False positive rate <5%

### Phase 6: Production-Grade Features

**Confidence Scoring Overhaul:**
- Score 200+ = Definite stub/placeholder (literal "TODO" found)
- Score 150-199 = Very likely issue (no implementation and no delegation)
- Score 100-149 = Possible issue (suspicious pattern)
- Score 50-99 = Low confidence (might be legitimate)
- Score <50 = Don't report

**Suppression System:**
- `# scanner-ignore: <reason>` comments
- `.scannerignore` file (already exists)
- `--exclude-pattern` CLI flag

**Actionable Output:**
- Show specific fix suggestions
- Link to examples of proper implementation
- Explain WHY it was flagged

---

## Recommended Action Plan

**Week 1: Fix Critical Bugs**
- [ ] Fix duplicate extraction bug
- [ ] Verify deduplication works end-to-end
- [ ] Add comprehensive logging

**Week 2: Rethink Strategy**
- [ ] Remove "absence of complexity" checks
- [ ] Keep only "presence of problems" checks
- [ ] Implement 7 common delegator patterns

**Week 3: Test & Calibrate**
- [ ] Manual classification of 100 functions
- [ ] Measure precision/recall
- [ ] Iterate until >95% precision

**Week 4: Polish & Deploy**
- [ ] Improve output formatting
- [ ] Add suppression system
- [ ] Write documentation

---

## Immediate Next Steps

1. Fix duplicate bug in tree-sitter query
2. Remove threshold-based filtering (artificial solution)
3. Keep threshold at 200 but fix root causes
4. Implement delegator pattern detection
5. Re-run and verify issues drop to <100
