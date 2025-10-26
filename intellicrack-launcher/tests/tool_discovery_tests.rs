use intellicrack_launcher::tool_discovery::{ToolCache, ToolInfo};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn test_tool_info_creation() {
    let path = PathBuf::from("/usr/bin/radare2");
    let version = Some("5.8.8".to_string());

    let tool_info = ToolInfo::new(path.clone(), version.clone());

    assert_eq!(tool_info.path, path);
    assert_eq!(tool_info.version, version);
    assert!(tool_info.verified_at > 0, "Timestamp should be set");
}

#[test]
fn test_tool_cache_creation() {
    let cache = ToolCache::new();

    assert_eq!(cache.version, 1);
    assert!(cache.timestamp > 0);
    assert!(cache.tools.is_empty());
}

#[test]
fn test_tool_cache_with_tools() {
    let mut tools = HashMap::new();
    tools.insert(
        "radare2".to_string(),
        ToolInfo::new(PathBuf::from("/usr/bin/radare2"), Some("5.8.8".to_string())),
    );

    let cache = ToolCache::with_tools(tools.clone());

    assert_eq!(cache.version, 1);
    assert!(cache.timestamp > 0);
    assert_eq!(cache.tools.len(), 1);
    assert!(cache.tools.contains_key("radare2"));
}

#[test]
fn test_discover_and_cache_tools_completes() {
    let result = intellicrack_launcher::tool_discovery::discover_and_cache_tools();

    assert!(result.is_ok(), "Tool discovery should complete without errors");
}

#[test]
fn test_discover_and_cache_tools_is_idempotent() {
    let result1 = intellicrack_launcher::tool_discovery::discover_and_cache_tools();
    let result2 = intellicrack_launcher::tool_discovery::discover_and_cache_tools();

    assert!(result1.is_ok(), "First call should succeed");
    assert!(result2.is_ok(), "Second call should succeed (cached)");
}

#[test]
fn test_discover_tools_performance_warm() {
    let _ = intellicrack_launcher::tool_discovery::discover_and_cache_tools();

    let start = std::time::Instant::now();
    let result = intellicrack_launcher::tool_discovery::discover_and_cache_tools();
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Should use cached results");
    assert!(
        elapsed.as_millis() < 20,
        "Warm start should be very fast (<20ms), took {:?}",
        elapsed
    );
}

#[test]
fn test_environment_variables_set_after_discovery() {
    let _ = intellicrack_launcher::tool_discovery::discover_and_cache_tools();

    let expected_vars = vec![
        "RADARE2_PATH",
        "R2_PATH",
        "GHIDRA_PATH",
        "FRIDA_PATH",
        "CAPSTONE_PATH",
    ];

    for var_name in expected_vars {
        if let Ok(value) = std::env::var(var_name) {
            assert!(!value.is_empty(), "{} should not be empty", var_name);
        }
    }
}

#[test]
fn test_tool_info_serialization() {
    let tool_info = ToolInfo::new(
        PathBuf::from("/usr/bin/test"),
        Some("1.0.0".to_string()),
    );

    let serialized = serde_json::to_string(&tool_info).unwrap();
    let deserialized: ToolInfo = serde_json::from_str(&serialized).unwrap();

    assert_eq!(tool_info, deserialized);
}

#[test]
fn test_tool_cache_serialization() {
    let mut tools = HashMap::new();
    tools.insert(
        "test_tool".to_string(),
        ToolInfo::new(PathBuf::from("/usr/bin/test"), None),
    );

    let cache = ToolCache::with_tools(tools);

    let serialized = serde_json::to_string_pretty(&cache).unwrap();
    let deserialized: ToolCache = serde_json::from_str(&serialized).unwrap();

    assert_eq!(cache.version, deserialized.version);
    assert_eq!(cache.tools.len(), deserialized.tools.len());
}

#[test]
fn test_cache_handles_missing_tools_gracefully() {
    let result = intellicrack_launcher::tool_discovery::discover_and_cache_tools();

    assert!(result.is_ok(), "Should succeed even if some tools are missing");
}

#[test]
fn test_concurrent_tool_discovery() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                intellicrack_launcher::tool_discovery::discover_and_cache_tools()
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join();
        assert!(result.is_ok(), "Thread should not panic");
        assert!(result.unwrap().is_ok(), "Discovery should succeed");
    }
}

#[test]
fn test_tool_discovery_does_not_panic() {
    for _ in 0..5 {
        let _ = intellicrack_launcher::tool_discovery::discover_and_cache_tools();
    }
}
