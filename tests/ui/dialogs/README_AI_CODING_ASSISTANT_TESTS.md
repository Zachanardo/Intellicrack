# AI Coding Assistant Dialog Tests

## Overview

Comprehensive production-grade tests for `intellicrack/ui/dialogs/ai_coding_assistant_dialog.py` (4,615 lines).

**Test File:** `tests/ui/dialogs/test_ai_coding_assistant_dialog.py`

**Test Statistics:**

- **15 Test Classes**
- **52 Test Methods**
- **Coverage Focus:** UI components, AI code generation, syntax validation, LLM integration

## Critical Testing Principles

### 1. Real Implementation Testing

- **NO MOCKS** - All tests use real PyQt6 widgets, real AI APIs, real code generation
- Tests validate actual AI-generated code compiles and executes
- File operations use real filesystem with temporary directories
- LLM integration tests make real API calls (when credentials available)

### 2. Failure Validation

Tests are designed to **FAIL** when:

- Generated code has syntax errors
- Generated code doesn't compile
- Generated code doesn't execute successfully
- UI components don't respond correctly
- File operations fail
- AI integration breaks

### 3. Production Readiness

- All code must execute successfully in production environments
- Syntax validation via Python compilation
- Execution validation via subprocess execution
- Performance benchmarks for responsive UI

## Test Class Organization

### UI Component Tests

#### `TestFileTreeWidget` (6 tests)

Tests file navigation and project management:

- Widget initialization with default configuration
- Loading project directory structure
- File selection signal emission
- Supported file extension filtering (`.py`, `.js`, `.md`, etc.)
- Tree refresh preserving expansion state
- Project file system watching

**Key Validations:**

- File tree displays actual directory contents
- Selection signals emit correct file paths
- Refresh preserves user interaction state

#### `TestCodeEditor` (7 tests)

Tests code editor with syntax highlighting:

- Editor initialization with monospace font
- Loading Python files with syntax highlighting
- Loading JavaScript files with Frida highlighting
- File save operations with content validation
- Modification tracking (dirty state)
- Text insertion at cursor position
- Syntax highlighter application verification

**Key Validations:**

- Files load with correct syntax highlighting
- Content saves match original content
- Modification state tracks changes accurately
- Syntax highlighters apply to correct file types

#### `TestChatWidget` (7 tests)

Tests AI chat interface:

- Widget initialization with UI components
- Message sending and history tracking
- Message formatting (user vs AI messages)
- Quick action buttons (Explain, Optimize, Debug)
- Conversation history clearing
- AI model discovery from API providers
- Model list refresh functionality

**Key Validations:**

- Messages appear in chat history with correct formatting
- Model discovery finds available AI models
- Quick actions send predefined messages

### Main Widget Tests

#### `TestAICodingAssistantWidget` (3 tests)

Tests main widget functionality:

- Widget initialization with all components (file tree, editor, chat)
- AI tools initialization
- File selection handling with editor tab creation
- New research file creation

**Key Validations:**

- All child widgets initialize correctly
- AI tools connect successfully
- File operations create editor tabs

#### `TestAICodingAssistantDialog` (1 test)

Tests dialog wrapper:

- Dialog initialization as QDialog with embedded widget
- Window size and title configuration

### AI Code Generation Tests (CRITICAL)

#### `TestRealAICodeGeneration` (4 tests)

**Tests REAL AI code generation - requires API keys**

Tests validate AI generates working code:

1. **Python Keygen Generation**
    - AI generates syntactically valid Python keygen
    - Code contains function/class definitions
    - Code compiles without syntax errors

2. **Registry Bypass Generation**
    - AI generates executable registry bypass code
    - Code passes Python compilation (`py_compile`)
    - Generated code has no syntax errors

3. **Frida Hook Script Generation**
    - AI generates valid JavaScript Frida hooks
    - Code contains Interceptor or Frida-specific syntax
    - Script structure matches Frida requirements

4. **License Analysis Chat**
    - AI responds to license protection queries
    - Chat history records AI responses
    - Responses contain technical analysis

**Execution Mode:**

- Tests skip if `SKIP_AI_TESTS=1` environment variable set
- Tests skip if AI not configured (no API keys)
- Tests use REAL LLM API calls (OpenAI, Anthropic, etc.)

**Validation Methods:**

- Syntax validation via `compile(code, '<string>', 'exec')`
- Compilation validation via `subprocess.run([sys.executable, '-m', 'py_compile'])`
- Content validation via keyword search
- Execution validation via script running

#### `TestCodeExecutionValidation` (3 tests)

Tests generated code ACTUALLY EXECUTES:

1. **Valid Python Script Execution**
    - Execute valid bypass script
    - Verify successful execution output
    - Confirm chat displays success message

2. **Invalid Code Failure Detection**
    - Execute syntactically invalid code
    - Verify error detection
    - Confirm chat displays error message

3. **Keygen Output Validation**
    - Execute keygen script
    - Validate license key format
    - Verify key generation algorithm correctness
    - Confirm assertion-based validation passes

**Critical:** These tests prove generated code is production-ready

### Bypass Type Generation Tests

#### `TestBypassTypeGeneration` (4 tests)

Tests different bypass type templates:

1. **Keygen Algorithm** - Valid Python keygen template with function definitions
2. **Hardware ID Spoofer** - Code contains HWID/UUID spoofing logic
3. **License Server Emulator** - Network server code with socket/HTTP handling
4. **Registry Patcher** - Windows registry manipulation code

**Key Validations:**

- Each template generates syntactically valid code
- Code compiles without errors
- Template contains type-specific keywords

### Syntax Highlighting Tests

#### `TestSyntaxHighlighting` (3 tests)

Tests multi-language syntax highlighting:

1. **Python Highlighting** - Verify PythonHighlighter applied to `.py` files
2. **JavaScript Highlighting** - Verify JavaScriptHighlighter applied to `.js` files
3. **Highlighter Switching** - Verify highlighter changes when loading different file types

**Key Validations:**

- Correct highlighter class instantiated
- Highlighter applied to QTextDocument
- Highlighter updates on file type change

### Project Management Tests

#### `TestProjectManagement` (3 tests)

Tests project and file management:

1. **Load Project Directory** - File tree populates with directory structure
2. **Multiple File Tabs** - Multiple files open in separate tabs
3. **Close Tab** - Tab removal from editor widget

### Error Handling Tests

#### `TestErrorHandling` (3 tests)

Tests error scenarios:

1. **Non-existent File** - Loading missing file shows error
2. **Empty Script Execution** - Empty script shows appropriate message
3. **AI Unavailable Fallback** - Fallback generation when AI unavailable

### Integration Workflow Tests

#### `TestIntegrationWorkflows` (2 tests)

Tests complete end-to-end workflows:

1. **Complete Keygen Generation Workflow**
    - Load project → AI generation → Code compilation → Execution
    - Validates entire pipeline works

2. **Chat and Code Generation Integration**
    - Chat queries trigger code generation
    - Messages integrate with generation system

### Performance Tests

#### `TestPerformance` (2 tests)

Tests performance characteristics:

1. **Large File Loading** - 10,000+ line file loads in <5 seconds
2. **Tab Switching** - Multiple tab switching is responsive

### Code Analysis Integration Tests

#### `TestCodeAnalysisIntegration` (2 tests)

Tests AI code analysis:

1. **AI Code Analysis** - AI provides code insights
2. **Language Detection** - Correctly identifies Python, JavaScript, etc.

### Protection Analysis Context Tests

#### `TestProtectionAnalysisContext` (2 tests)

Tests license protection analysis features:

1. **License Context Display** - Updates with loaded binary
2. **Analyze Button** - Triggers protection analysis

## Running the Tests

### Prerequisites

1. **PyQt6 Installation Required:**

    ```bash
    pixi install pyqt6
    ```

2. **AI Testing (Optional):**
   Set API keys for AI code generation tests:

    ```bash
    export OPENAI_API_KEY="your-key"
    export ANTHROPIC_API_KEY="your-key"
    ```

    Or skip AI tests:

    ```bash
    export SKIP_AI_TESTS=1
    ```

### Run All Tests

```bash
cd D:\Intellicrack
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py -v
```

### Run Specific Test Classes

```bash
# UI component tests only
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py::TestFileTreeWidget -v

# AI code generation tests only (requires API keys)
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py::TestRealAICodeGeneration -v

# Code execution validation tests
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py::TestCodeExecutionValidation -v
```

### Run with Coverage

```bash
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py \
    --cov=intellicrack.ui.dialogs.ai_coding_assistant_dialog \
    --cov-report=html \
    --cov-report=term
```

### Run Performance Tests Only

```bash
pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py::TestPerformance -v
```

## Test Fixtures

### `qapp` (module scope)

- Creates QApplication instance for Qt tests
- Reuses application across all tests in module
- Handles offscreen rendering via `QT_QPA_PLATFORM=offscreen`

### `temp_project_dir` (function scope)

- Creates temporary project directory with sample files
- Includes: `keygen.py`, `frida_hook.js`, `README.md`
- Automatically cleaned up after test

### `temp_workspace` (function scope)

- Provides clean temporary directory for test operations
- Used for file creation, script execution
- Automatically cleaned up after test

### `ai_assistant` (function scope)

- Creates AIAssistant instance for code analysis
- Used for AI integration tests
- Skips if AI not available

## Coverage Goals

### Target Metrics

- **Line Coverage:** 85%+
- **Branch Coverage:** 80%+
- **All critical paths tested**

### Coverage Areas

**Well Covered:**

- UI widget initialization
- File loading and saving
- Syntax highlighting application
- Chat message handling
- Model discovery

**AI-Dependent Coverage:**

- AI code generation (requires API keys)
- LLM integration
- Real code execution validation

**Performance Coverage:**

- Large file handling
- Tab switching responsiveness

## Validation Methodology

### Code Generation Validation

1. **Syntax Check:** `compile(code, '<string>', 'exec')`
2. **Compilation Check:** `subprocess.run([sys.executable, '-m', 'py_compile', file])`
3. **Execution Check:** `subprocess.run([sys.executable, script], capture_output=True)`
4. **Output Validation:** Parse stdout/stderr for expected results

### UI Validation

1. **Widget Existence:** `assert widget is not None`
2. **Property Values:** `assert widget.property == expected_value`
3. **Signal Emission:** Connect to signals and verify emission
4. **State Changes:** Verify state transitions on user interaction

### Integration Validation

1. **Component Communication:** Verify signals/slots connections
2. **Data Flow:** Verify data flows between components
3. **State Synchronization:** Verify UI state matches internal state

## Known Limitations

### Environment Dependencies

- **PyQt6 Required:** Tests skip if PyQt6 not available
- **AI APIs Optional:** AI tests skip if no API keys configured
- **Windows Platform:** Some features (registry patching) Windows-specific

### AI Test Variability

- AI-generated code may vary between runs
- Tests validate structure and syntax, not specific implementation
- Rate limiting may affect AI test execution

### Performance Baselines

- Performance tests use reasonable thresholds (5s for large files)
- May need adjustment based on hardware capabilities

## Continuous Integration

### CI Configuration

Tests designed for CI/CD pipelines:

```yaml
# Example .gitlab-ci.yml
test_ai_dialog:
    script:
        - pixi install
        - export QT_QPA_PLATFORM=offscreen
        - export SKIP_AI_TESTS=1 # Skip AI in CI
        - pixi run python -m pytest tests/ui/dialogs/test_ai_coding_assistant_dialog.py -v --tb=short
```

### Recommended CI Strategy

1. **Fast Tests:** Run UI component tests on every commit
2. **AI Tests:** Run on scheduled basis (nightly) with API keys
3. **Performance Tests:** Run on merge requests
4. **Integration Tests:** Run on release candidates

## Troubleshooting

### PyQt6 Import Errors

```
ModuleNotFoundError: No module named 'PyQt6.QtCore'
```

**Solution:** Ensure PyQt6 installed: `pixi install pyqt6`

### AI Tests Skipped

```
SKIPPED [1] AI tests require API keys
```

**Solution:** Set API keys or set `SKIP_AI_TESTS=1` to acknowledge skip

### Test Timeout

```
ERROR timeout exceeded
```

**Solution:** Increase timeout for AI tests: `pytest --timeout=300`

## Contributing

### Adding New Tests

1. **Follow naming convention:** `test_<feature>_<scenario>_<expected_outcome>`
2. **Add to appropriate test class**
3. **Use real implementations only**
4. **Validate actual behavior**
5. **Document expected outcomes**

### Test Quality Checklist

- [ ] Test has descriptive docstring
- [ ] Test uses real components (no mocks)
- [ ] Test validates actual behavior
- [ ] Test fails when code is broken
- [ ] Test is deterministic (or documented as variable)
- [ ] Test has reasonable execution time (<30s)
- [ ] Test cleans up resources

## Security Testing Context

These tests validate Intellicrack's AI coding assistant for **defensive security research**:

- **Purpose:** Help developers strengthen their software licensing protections
- **Scope:** License bypass generation for authorized security testing
- **Use Case:** Developers testing their own software's protection mechanisms
- **Environment:** Controlled research environments only

All generated code is for educational and authorized security research purposes.

## References

- **Dialog Source:** `intellicrack/ui/dialogs/ai_coding_assistant_dialog.py`
- **AI Tools:** `intellicrack/ai/code_analysis_tools.py`
- **Syntax Highlighters:** `intellicrack/ui/widgets/syntax_highlighters.py`
- **LLM Manager:** `intellicrack/ai/llm_config_manager.py`
- **Model Discovery:** `intellicrack/ai/model_discovery_service.py`

---

**Last Updated:** 2025-11-23
**Test File Version:** 1.0
**Total Test Coverage:** 52 tests across 15 test classes
