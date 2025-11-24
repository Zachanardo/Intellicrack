# CLI Test Coverage Documentation

## Overview

Comprehensive production-grade tests for `intellicrack\cli\cli.py` (2,791 lines).

**Total Test File Size:** 792 lines
**Total Test Classes:** 15
**Total Test Functions:** 67
**Test Coverage:** All major CLI commands, subcommands, options, and workflows

## Test Philosophy

These tests validate **REAL CLI functionality** against actual binaries:

- **NO mocks** - All tests use real subprocess execution of CLI commands
- **Real binaries** - Tests operate on actual protected binaries from fixtures
- **Real validation** - Tests verify command output, JSON files, patched binaries
- **Must FAIL** - If CLI commands break, these tests FAIL (no false positives)

## Test Classes and Coverage

### 1. TestCLIBasicExecution (5 tests)
**Purpose:** Validate core CLI functionality and help system

- `test_cli_main_help_displays` - Main --help displays usage information
- `test_cli_version_info_available` - Version information accessible
- `test_cli_verbose_flag_accepted` - --verbose flag works
- `test_cli_quiet_flag_accepted` - --quiet flag works
- `test_cli_invalid_command_fails` - Invalid commands return errors

**Coverage:** Entry point, argument parsing, help system, global flags

### 2. TestAnalyzeCommand (10 tests)
**Purpose:** Validate binary analysis command execution

- `test_analyze_basic_mode_executes` - Basic analysis mode on real binary
- `test_analyze_comprehensive_mode_executes` - Comprehensive analysis mode
- `test_analyze_protection_mode_detects_protections` - Protection detection mode
- `test_analyze_outputs_binary_type` - Binary type reported (PE/ELF)
- `test_analyze_outputs_architecture` - Architecture reported (x86/x64)
- `test_analyze_with_json_output` - JSON output file created and valid
- `test_analyze_deep_mode_executes` - Deep analysis flag works
- `test_analyze_with_no_ai_flag` - --no-ai disables AI integration
- `test_analyze_verbose_output_detailed` - Verbose flag increases detail
- `test_analyze_nonexistent_binary_fails` - Error handling for missing files

**Coverage:** Analysis modes, output formats, flags, error handling

### 3. TestScanCommand (5 tests)
**Purpose:** Validate vulnerability scanning functionality

- `test_scan_basic_executes` - Basic security scan execution
- `test_scan_with_vulns_flag` - Vulnerability analysis with --vulns
- `test_scan_outputs_protections` - Security feature detection
- `test_scan_with_json_output` - JSON output generation
- `test_scan_verbose_mode` - Verbose output mode

**Coverage:** Security scanning, vulnerability detection, output formats

### 4. TestStringsCommand (5 tests)
**Purpose:** Validate string extraction from binaries

- `test_strings_extraction_executes` - String extraction works
- `test_strings_with_min_length` - Minimum length parameter honored
- `test_strings_encoding_options` - Multiple encodings (ascii/utf8/utf16/all)
- `test_strings_with_output_file` - String output to file
- `test_strings_with_filter_pattern` - Regex filtering of strings

**Coverage:** String extraction, encoding options, filtering, file output

### 5. TestPatchCommand (3 tests)
**Purpose:** Validate binary patching functionality

- `test_patch_with_offset_and_data` - Patch at specific offset with hex data
- `test_patch_with_nop_range` - NOP instruction range patching
- `test_patch_without_patches_fails` - Error when no patches specified

**Coverage:** Binary patching, offset patching, NOP filling, validation

### 6. TestPayloadCommands (5 tests)
**Purpose:** Validate payload generation commands

- `test_payload_generate_reverse_shell` - Reverse shell payload generation
- `test_payload_generate_bind_shell` - Bind shell payload generation
- `test_payload_generate_different_architectures` - Multi-arch support (x86/x64)
- `test_payload_generate_different_formats` - Output formats (raw/exe)
- `test_payload_list_templates` - Template listing functionality

**Coverage:** Payload generation, architectures, formats, templates

### 7. TestCertificateBypassCommands (6 tests)
**Purpose:** Validate certificate bypass functionality

- `test_cert_detect_on_binary` - Certificate validation detection
- `test_cert_detect_with_report_output` - JSON report generation
- `test_cert_detect_verbose_mode` - Verbose detection output
- `test_cert_detect_with_min_confidence` - Confidence threshold filtering
- `test_cert_bypass_auto_method` - Automatic bypass method selection
- `test_cert_test_on_binary` - Bypass effectiveness testing

**Coverage:** Certificate detection, bypass methods, validation, reporting

### 8. TestAdvancedCommands (3 tests)
**Purpose:** Validate advanced research and exploitation commands

- `test_advanced_research_run_binary_analysis` - Research analysis execution
- `test_advanced_research_with_ai_guidance` - AI-guided research mode
- `test_advanced_research_with_output_dir` - Output directory management

**Coverage:** Advanced research workflows, AI integration, result storage

### 9. TestAICommands (5 tests)
**Purpose:** Validate AI-powered script generation and analysis

- `test_ai_analyze_binary` - AI binary analysis execution
- `test_ai_analyze_with_deep_mode` - Deep AI analysis mode
- `test_ai_analyze_json_output` - JSON format output
- `test_ai_generate_frida_script` - Frida script generation
- `test_ai_generate_ghidra_script` - Ghidra script generation

**Coverage:** AI analysis, script generation, output formats

### 10. TestRealWorldWorkflows (3 tests)
**Purpose:** Validate complete multi-step workflows

- `test_workflow_analyze_scan_patch` - Complete analysis → scan → patch workflow
- `test_workflow_detect_bypass_test_certificate` - Certificate detection → bypass → test
- `test_workflow_comprehensive_analysis_with_all_modes` - All analysis modes in sequence

**Coverage:** End-to-end workflows, command chaining, multi-step operations

### 11. TestErrorHandling (5 tests)
**Purpose:** Validate error handling and edge cases

- `test_analyze_invalid_file_path` - Invalid path error handling
- `test_scan_corrupted_binary_path` - Corrupted file handling
- `test_patch_invalid_hex_data` - Invalid hex data rejection
- `test_payload_generate_missing_required_args` - Missing argument validation
- `test_strings_invalid_encoding` - Invalid encoding rejection

**Coverage:** Error messages, graceful failures, input validation

### 12. TestOutputFormatting (4 tests)
**Purpose:** Validate output formatting and display

- `test_analyze_output_is_readable` - Human-readable output formatting
- `test_scan_output_categorizes_findings` - Finding categorization by severity
- `test_verbose_output_more_detailed` - Verbose produces more output
- `test_quiet_output_suppressed` - Quiet suppresses non-essential output

**Coverage:** Output formatting, severity categorization, verbosity levels

### 13. TestPerformance (2 tests)
**Purpose:** Validate performance on different binary sizes

- `test_analyze_small_binary_completes_quickly` - Small binary analysis speed
- `test_scan_medium_binary_reasonable_time` - Medium binary performance

**Coverage:** Performance benchmarks, timeout handling

### 14. TestProtectionDetection (3 tests)
**Purpose:** Validate detection of specific protection schemes

- `test_detect_upx_packer` - UPX packer detection
- `test_detect_vmprotect` - VMProtect detection
- `test_detect_themida` - Themida protection detection

**Coverage:** Protection scheme identification, packer detection

### 15. TestCommandAliases (3 tests)
**Purpose:** Validate command aliases work correctly

- `test_cert_detect_alias_cd` - 'cd' alias for cert-detect
- `test_cert_bypass_alias_cb` - 'cb' alias for cert-bypass
- `test_cert_test_alias_ct` - 'ct' alias for cert-test

**Coverage:** Command aliases, shorthand commands

## Test Fixtures

Tests utilize real protected binaries from `tests/fixtures/`:

### Protected Binaries
- UPX packed executables
- VMProtect protected binaries
- Themida protected binaries
- Enigma, Obsidium, ASPack, PECompact protected samples

### Legitimate Binaries
- 7-Zip
- Notepad++
- VLC Media Player
- Firefox

### Vulnerable Samples
- Buffer overflow samples
- Format string vulnerabilities
- Integer overflow samples
- Heap overflow samples
- Race condition samples

### Size Categories
- Tiny (4KB) - Performance testing
- Small (1MB) - Standard testing
- Medium (100MB) - Stress testing

## Test Execution Strategy

### Subprocess Execution
All tests execute CLI via subprocess:
```python
result = run_cli_command(["analyze", str(binary_path)])
```

### Real Binary Analysis
Tests operate on actual binaries:
```python
assert "upx" in result.stdout.lower()  # Real detection
assert output_file.exists()            # Real file created
```

### Environment Isolation
Test environment variables prevent interference:
```python
env["INTELLICRACK_TESTING"] = "1"
env["DISABLE_AI_WORKERS"] = "1"
```

## Validation Criteria

### Tests PASS When:
- CLI commands execute successfully (returncode == 0)
- Expected output appears in stdout/stderr
- JSON files created with valid structure
- Protections detected in protected binaries
- Errors returned for invalid inputs

### Tests FAIL When:
- CLI commands crash or hang
- Output format invalid or missing
- Protection detection fails on known samples
- Error handling missing or incorrect
- Performance exceeds acceptable limits

## Coverage Metrics

### Command Coverage
- ✅ `analyze` - 10 tests
- ✅ `scan` - 5 tests
- ✅ `strings` - 5 tests
- ✅ `patch` - 3 tests
- ✅ `payload generate` - 5 tests
- ✅ `payload list-templates` - 1 test
- ✅ `cert-detect` - 4 tests
- ✅ `cert-bypass` - 1 test
- ✅ `cert-test` - 1 test
- ✅ `advanced research run` - 3 tests
- ✅ `ai analyze` - 3 tests
- ✅ `ai generate` - 2 tests

### Option Coverage
- ✅ `--help` - Basic execution tests
- ✅ `--verbose` / `-v` - Multiple tests
- ✅ `--quiet` / `-q` - Output formatting tests
- ✅ `--output` / `-o` - JSON output tests
- ✅ `--mode` - Analysis mode tests
- ✅ `--deep` / `-d` - Deep analysis tests
- ✅ `--no-ai` - AI disable tests
- ✅ `--vulns` - Vulnerability scan tests
- ✅ `--encoding` - String encoding tests
- ✅ `--filter` - String filtering tests
- ✅ `--min-length` - String length tests
- ✅ `--type` - Payload type tests
- ✅ `--arch` - Architecture tests
- ✅ `--format` - Output format tests
- ✅ `--method` - Bypass method tests
- ✅ `--report` - Report generation tests

### Workflow Coverage
- ✅ Single command execution
- ✅ Multi-step workflows
- ✅ Command chaining
- ✅ Error recovery
- ✅ Output file generation
- ✅ Performance validation

## Running the Tests

### Run All CLI Tests
```bash
pixi run python -m pytest tests/cli/test_cli.py -v
```

### Run Specific Test Class
```bash
pixi run python -m pytest tests/cli/test_cli.py::TestAnalyzeCommand -v
```

### Run Single Test
```bash
pixi run python -m pytest tests/cli/test_cli.py::TestAnalyzeCommand::test_analyze_basic_mode_executes -v
```

### Run with Coverage
```bash
pixi run python -m pytest tests/cli/test_cli.py --cov=intellicrack.cli.cli --cov-report=html
```

## Test Dependencies

### Required Fixtures
- Protected binary samples in `tests/fixtures/binaries/protected/`
- Legitimate binaries in `tests/fixtures/binaries/pe/legitimate/`
- Vulnerable samples in `tests/fixtures/vulnerable_samples/`

### Environment Requirements
- Windows platform (primary target)
- Python 3.10+
- All CLI dependencies installed via pixi
- Sufficient disk space for test outputs

## Known Limitations

### Platform-Specific
- Some tests may behave differently on non-Windows platforms
- Certificate bypass tests require Windows-specific APIs

### Binary Availability
- Tests skip if fixture binaries not present
- Large binaries may be excluded from repository

### Timeout Constraints
- Long-running analysis limited to 60 seconds
- AI operations may timeout on slow systems

## Future Enhancements

### Additional Test Coverage
- [ ] Interactive mode testing
- [ ] GUI launch testing (--gui flag)
- [ ] Progress bar validation
- [ ] Color output testing
- [ ] Parallel execution testing

### Integration Tests
- [ ] CLI + GUI integration
- [ ] CLI + Database integration
- [ ] CLI + Remote API integration

### Performance Tests
- [ ] Benchmark suite for large binaries
- [ ] Memory usage profiling
- [ ] Concurrent execution testing

## Maintenance

### Adding New Tests
1. Create test function with descriptive name
2. Use real binaries from fixtures
3. Execute via `run_cli_command()`
4. Validate actual output/behavior
5. Ensure test FAILS when functionality broken

### Updating Tests
1. Update when CLI commands change
2. Maintain backward compatibility checks
3. Update fixtures as needed
4. Document breaking changes

### Test Hygiene
- Keep tests independent
- Clean up temporary files
- Use appropriate fixtures
- Document edge cases
- Maintain performance targets
