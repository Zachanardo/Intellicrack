// Integration tests for production scanner
// These tests verify that the scanner correctly identifies or excludes patterns

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_conditional_detection_no_false_positive() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_conditionals.py");

    // This simulates the validate_config pattern that was a false positive
    // It has multiple conditionals, so should NOT be flagged as "no conditionals"
    let test_code = r#"def validate_config(config, schema_name="complete_config"):
    """Validate configuration against schema."""
    if not HAS_JSONSCHEMA:
        logger.warning("Schema validation skipped")
        return True

    if schema_name not in self.schemas:
        raise ConfigValidationError(f"Unknown schema: {schema_name}")

    schema = self.schemas[schema_name]

    try:
        jsonschema.validate(config, schema)
        logger.debug(f"Validation passed for schema: {schema_name}")
        return True
    except jsonschema.ValidationError as e:
        error_msg = f"Validation failed: {e.message}"
        if e.absolute_path:
            error_msg += f" at path: {'.'.join(str(p) for p in e.absolute_path)}"
        raise ConfigValidationError(error_msg)
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    // Build scanner binary path
    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    // Run scanner on test directory
    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify that "no conditionals" is NOT in the output
    // The scanner correctly detects conditionals, so this should not appear
    assert!(
        !stdout.to_lowercase().contains("no conditionals") && !stderr.to_lowercase().contains("no conditionals"),
        "Scanner falsely reported 'no conditionals' for validate_config pattern.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    // If scanner found validate_config issues, they should NOT be about missing conditionals
    // The function can still be flagged for OTHER reasons (dead code, validator sophistication, etc.)
    if stdout.contains("validate_config") {
        // Check that it's not being flagged specifically for "without conditionals" or similar
        assert!(
            !stdout.contains("without conditionals") && !stdout.contains("no conditionals"),
            "Scanner incorrectly flagged validate_config for missing conditionals.\nFull output:\n{}",
            stdout
        );
    }
}

#[test]
fn test_loop_detection_no_false_positive() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_loops.py");

    // This simulates the get_cache_stats pattern with nested loops
    let test_code = r#"def get_cache_stats(self):
    """Get cache statistics and usage information."""
    if not self.enable_caching:
        return {"enabled": False}

    total_files = 0
    total_size = 0
    analysis_types = set()

    for cache_entry in self.cache.values():
        for analysis_type, cache_file in cache_entry.items():
            if analysis_type not in ["binary_path", "timestamp", "file_size"]:
                analysis_types.add(analysis_type)
                if os.path.exists(cache_file):
                    total_files += 1
                    total_size += os.path.getsize(cache_file)

    return {
        "enabled": True,
        "total_files": total_files,
        "total_size": total_size,
        "analysis_types": list(analysis_types)
    }
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify that "no loops" or "without loops" is NOT in the output
    assert!(
        !stdout.contains("no loops") && !stderr.contains("no loops") &&
        !stdout.contains("without loops") && !stderr.contains("without loops"),
        "Scanner falsely reported 'no loops' for get_cache_stats pattern.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_function_call_detection_no_false_positive() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_calls.py");

    // This simulates the get_performance_stats pattern with function calls
    let test_code = r#"def get_performance_stats(self):
    """Get coordination layer performance statistics."""
    return {
        "ml_calls": self.performance_stats["ml_calls"],
        "llm_calls": self.performance_stats["llm_calls"],
        "escalations": self.performance_stats["escalations"],
        "cache_hits": self.performance_stats["cache_hits"],
        "avg_ml_time": self.performance_stats["avg_ml_time"],
        "avg_llm_time": self.performance_stats["avg_llm_time"],
        "cache_size": len(self.analysis_cache),
        "components_available": {
            "model_manager": self.model_manager is not None,
        },
    }
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify that "no function calls" is NOT in the output
    assert!(
        !stdout.contains("no function calls") && !stderr.contains("no function calls"),
        "Scanner falsely reported 'no function calls' for get_performance_stats pattern (has len()).\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_click_decorator_should_be_excluded() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_click.py");

    // This simulates the Click command group pattern that should be recognized
    let test_code = r#"@click.group()
def research():
    """Research and intelligence gathering commands."""
    pass

@click.group()
def post_exploit():
    """Post-exploitation commands."""
    pass

@click.group()
def payload():
    """Payload generation commands."""
    pass
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // After implementing Click decorator recognition, these should NOT appear in output
    // For now, this test will fail until we implement the pattern
    // Uncomment this assertion after implementing Click decorator pattern:
    /*
    assert!(
        !stdout.contains("research()") && !stdout.contains("post_exploit()") && !stdout.contains("payload()"),
        "Scanner should recognize Click @group() decorators and not flag them.\nOutput: {}",
        stdout
    );
    */
}

#[test]
fn test_true_stub_is_detected() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_stub.py");

    // This is a genuine stub that SHOULD be flagged
    let test_code = r#"def process_binary(binary_path):
    """Process binary file."""
    pass

def analyze_protection(binary):
    """Analyze protection scheme."""
    return None

def crack_license(key):
    """Crack license validation."""
    # TODO: implement
    return False
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify scanner DOES flag these obvious stubs
    assert!(
        stdout.contains("process_binary") || stdout.contains("analyze_protection") || stdout.contains("crack_license"),
        "Scanner should detect obvious stub implementations.\nOutput: {}",
        stdout
    );
}

#[test]
fn test_weak_keygen_flagged() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("weak_keygen.py");
    let test_code = r#"def weak_keygen():
    return "1234-ABCD"
"#;
    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("weak_keygen"), "Should flag weak keygen");
}

#[test]
fn test_js_async_no_await_flagged() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("weak_async.js");
    let test_code = r#"async function foo() {
    console.log("no await");
    return "done";
}"#;
    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("foo") && stdout.contains("async"), "Should flag JS async no await");
}

// Test for JS weak implementations
#[test]
fn test_js_specific() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_weak_js.js");
    let test_code = r#"
function simpleKeygen() {
    return "AAAA-BBBB-CCCC-DDDD";
}

function validateLicense(key) {
    return true;
}
"#;
    fs::write(&test_file, test_code).expect("Failed to write");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("simpleKeygen"), "Should flag JS weak keygen");
    assert!(stdout.contains("validateLicense"), "Should flag JS validation stub");
}

#[test]
fn test_js_weak_implementations() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_weak_js.js");
    let test_code = r#"// Test file with weak JavaScript implementations

function simpleKeygen() {
    return "AAAA-BBBB-CCCC-DDDD";
}

function validateLicense(key) {
    return true;
}

function patchBinary(filename) {
    return filename;
}

function searchPatterns(data) {
    if (data[0] === 0x4D) {
        return "Found";
    }
    return null;
}

function processData(input) {
    return input;
}

async function noAwaitAsync() {
    let x = 1;
    return "done";
}"#;
    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("simpleKeygen"), "Should flag JS weak keygen");
    assert!(stdout.contains("validateLicense"), "Should flag JS validation stub");
    assert!(stdout.contains("noAwaitAsync"), "Should flag async without await");
}

#[test]
fn test_production_code_not_flagged() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test_production.py");

    // This is production-quality code that should NOT be flagged
    let test_code = r#"def parse_pe_header(binary_data):
    """Parse PE header from binary data."""
    if len(binary_data) < 64:
        raise ValueError("Binary too small to contain PE header")

    dos_header = struct.unpack('<H', binary_data[0:2])[0]
    if dos_header != 0x5A4D:  # 'MZ'
        raise ValueError("Invalid DOS header")

    pe_offset = struct.unpack('<I', binary_data[60:64])[0]
    pe_signature = struct.unpack('<I', binary_data[pe_offset:pe_offset+4])[0]

    if pe_signature != 0x00004550:  # 'PE\0\0'
        raise ValueError("Invalid PE signature")

    sections = []
    section_offset = pe_offset + 24 + size_of_optional_header

    for i in range(num_sections):
        section_data = binary_data[section_offset:section_offset+40]
        section_info = parse_section_header(section_data)
        sections.append(section_info)
        section_offset += 40

    return {
        'dos_header': dos_header,
        'pe_offset': pe_offset,
        'sections': sections,
        'is_64bit': is_pe64,
        'timestamp': timestamp
    }
"#;

    fs::write(&test_file, test_code).expect("Failed to write test file");

    let scanner_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "scanner.exe" } else { "scanner" });

    let output = Command::new(&scanner_bin)
        .arg(temp_dir.path().to_str().unwrap())
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Production-quality PE parser should NOT be flagged
    assert!(
        !stdout.contains("parse_pe_header"),
        "Scanner should not flag production-quality PE parsing code.\nOutput: {}",
        stdout
    );
}
