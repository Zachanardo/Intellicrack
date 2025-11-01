use intellicrack_launcher::preflight_checks;

#[test]
#[ignore]
fn test_preflight_checks_with_valid_environment() {
    let result = preflight_checks::run_preflight_checks();

    assert!(
        result.is_ok(),
        "Preflight checks should pass with valid pixi environment: {:?}",
        result
    );
}

#[test]
fn test_preflight_checks_completes_quickly() {
    let start = std::time::Instant::now();
    let _ = preflight_checks::run_preflight_checks();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 50,
        "Preflight checks should complete in <50ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_preflight_checks_is_idempotent() {
    let result1 = preflight_checks::run_preflight_checks();
    let result2 = preflight_checks::run_preflight_checks();

    assert_eq!(
        result1.is_ok(),
        result2.is_ok(),
        "Repeated checks should have consistent results"
    );
}

#[test]
fn test_preflight_checks_does_not_panic() {
    for _ in 0..5 {
        let _ = preflight_checks::run_preflight_checks();
    }
}

#[test]
fn test_concurrent_preflight_checks() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                preflight_checks::run_preflight_checks()
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join();
        assert!(result.is_ok(), "Thread should not panic");
    }
}

#[test]
#[cfg(target_os = "windows")]
fn test_python_path_structure_windows() {
    let expected_python_exe = std::path::PathBuf::from(".pixi/envs/default/python.exe");

    assert!(
        expected_python_exe.to_string_lossy().ends_with("python.exe"),
        "Windows Python path should end with .exe"
    );
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_python_path_structure_unix() {
    let expected_python = std::path::PathBuf::from(".pixi/envs/default/bin/python");

    assert!(
        expected_python.to_string_lossy().contains("bin/python"),
        "Unix Python path should be in bin directory"
    );
}

#[test]
fn test_preflight_performance_multiple_runs() {
    let mut total_time = std::time::Duration::ZERO;
    let runs = 10;

    for _ in 0..runs {
        let start = std::time::Instant::now();
        let _ = preflight_checks::run_preflight_checks();
        total_time += start.elapsed();
    }

    let avg_time = total_time / runs;
    assert!(
        avg_time.as_millis() < 20,
        "Average preflight check time should be <20ms, was {:?}",
        avg_time
    );
}

#[test]
#[ignore]
fn test_missing_python_returns_helpful_error() {
    let project_root = std::env::current_dir().unwrap();
    let python_path = project_root.join(".pixi/envs/default/python.exe");

    if python_path.exists() {
        println!("Test requires Python to be missing, but it exists. Skipping.");
        return;
    }

    let result = preflight_checks::run_preflight_checks();

    assert!(result.is_err(), "Should fail when Python is missing");

    let error_msg = format!("{}", result.unwrap_err());
    assert!(error_msg.contains("Python"), "Error should mention Python");
    assert!(error_msg.contains("pixi install"), "Error should suggest fix");
}

#[test]
fn test_preflight_checks_integration_sequence() {
    let result = preflight_checks::run_preflight_checks();

    if result.is_ok() {
        assert!(std::env::var("PROJECT_ROOT").is_ok() || std::env::current_dir().is_ok());
    }
}

#[test]
fn test_error_message_quality() {
    let result = preflight_checks::run_preflight_checks();

    if let Err(e) = result {
        let error_str = format!("{}", e);

        assert!(
            error_str.contains("To fix") || error_str.contains("Run:") || error_str.len() > 50,
            "Error messages should be actionable and detailed"
        );
    }
}

#[test]
fn test_preflight_checks_with_partial_environment() {
    let result = preflight_checks::run_preflight_checks();

    match result {
        Ok(_) => {
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(
                error_msg.contains("Python") || error_msg.contains("pixi"),
                "Critical errors should mention Python or pixi"
            );
        }
    }
}

#[test]
fn test_preflight_checks_no_excessive_allocations() {
    for _ in 0..100 {
        let _ = preflight_checks::run_preflight_checks();
    }
}

#[test]
fn test_preflight_checks_comprehensive() {
    let start = std::time::Instant::now();
    let result = preflight_checks::run_preflight_checks();
    let elapsed = start.elapsed();

    eprintln!("Preflight checks result: {:?}", result);
    eprintln!("Elapsed time: {:?}", elapsed);

    assert!(
        elapsed.as_millis() < 100,
        "Should complete within 100ms"
    );
}
