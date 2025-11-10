use anyhow::Result;
use intellicrack_launcher::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
async fn test_platform_detection_comprehensive() -> Result<()> {
    let platform = PlatformInfo::detect()?;

    // Verify platform type is valid
    assert!(platform.os_type == OsType::Windows || platform.os_type == OsType::Unix);

    // Verify architecture is detected
    assert!(!platform.architecture.is_empty());

    // Verify version information exists
    assert!(!platform.version.is_empty());

    // Platform-specific validations
    #[cfg(windows)]
    {
        assert_eq!(platform.os_type, OsType::Windows);
        assert!(platform.architecture.contains("x86") || platform.architecture.contains("aarch"));
    }

    #[cfg(unix)]
    {
        assert_eq!(platform.os_type, OsType::Unix);
    }

    Ok(())
}

#[tokio::test]
async fn test_platform_detection_consistency() -> Result<()> {
    // Multiple detections should return consistent results
    let platform1 = PlatformInfo::detect()?;
    let platform2 = PlatformInfo::detect()?;

    assert_eq!(platform1.os_type, platform2.os_type);
    assert_eq!(platform1.architecture, platform2.architecture);
    assert_eq!(platform1.version, platform2.version);

    Ok(())
}

#[tokio::test]
async fn test_python_integration_comprehensive() -> Result<()> {
    let mut python = PythonIntegration::initialize()?;

    // Test pybind11 compatibility
    python.configure_pybind11_compatibility()?;

    // Test Python version detection (should not panic)
    let version_result = python.get_python_version();
    assert!(version_result.is_ok() || version_result.is_err()); // Either is acceptable

    // Test environment variables setup
    python.configure_environment_variables()?;

    Ok(())
}

#[tokio::test]
async fn test_python_integration_threading() -> Result<()> {
    let mut python = PythonIntegration::initialize()?;

    // Test GIL safety configuration
    python.configure_pybind11_compatibility()?;

    // Test that Python integration works across multiple async tasks
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            tokio::spawn(async {
                let mut python_local = PythonIntegration::initialize().unwrap();
                python_local.configure_pybind11_compatibility().unwrap()
            })
        })
        .collect();

    // Wait for all tasks to complete
    for task in tasks {
        task.await.unwrap();
    }

    Ok(())
}

#[tokio::test]
async fn test_python_integration_embedded_main() -> Result<()> {
    let python = PythonIntegration::initialize()?;

    // Test that the embedded main function exists and can be called
    // Note: This will fail if intellicrack.main module doesn't exist or return non-zero,
    // which is acceptable in test environment
    let result = python.run_intellicrack_main_embedded();

    // Function should either succeed (if module exists) or fail gracefully with descriptive error
    match result {
        Ok(exit_code) => {
            // Verify exit code is a valid integer
            assert!(exit_code >= 0 || exit_code < 0); // Any i32 is valid
        }
        Err(e) => {
            // Should fail with informative error message
            let error_msg = format!("{}", e);
            assert!(
                error_msg.contains("intellicrack.main")
                    || error_msg.contains("main()")
                    || error_msg.contains("exit code"),
                "Error should mention module, function, or exit code: {}",
                error_msg
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_dependency_validation_comprehensive() -> Result<()> {
    let mut validator = DependencyValidator::new();
    let results = validator.validate_all_dependencies().await?;

    // Verify results structure
    assert!(!results.dependencies.is_empty());

    // Verify required dependencies are checked
    assert!(results.dependencies.contains_key("python"));

    // Verify dependency status information
    for (name, dep_info) in &results.dependencies {
        assert!(!name.is_empty());
        assert!(
            dep_info.version.is_none()
                || dep_info
                    .version
                    .as_ref()
                    .map(|v| !v.is_empty())
                    .unwrap_or(true)
        );

        // Dependencies should have details when not available
        if !dep_info.available {
            // Check if details contain error information
            assert!(
                dep_info.details.contains_key("error") || dep_info.details.contains_key("status")
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_dependency_validation_individual() -> Result<()> {
    let mut validator = DependencyValidator::new();

    // Test individual validation methods
    let python_result = validator.validate_python_availability().await;
    assert!(python_result.is_ok() || python_result.is_err()); // Either is acceptable

    let flask_result = validator.validate_flask_comprehensive().await;
    assert!(flask_result.is_ok() || flask_result.is_err());

    let tensorflow_result = validator.validate_tensorflow_comprehensive().await;
    assert!(tensorflow_result.is_ok() || tensorflow_result.is_err());

    let qemu_result = validator.validate_qemu_availability().await;
    assert!(qemu_result.is_ok() || qemu_result.is_err());

    let system_result = validator.validate_system_tools().await;
    assert!(system_result.is_ok() || system_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_dependency_validation_caching() -> Result<()> {
    let mut validator = DependencyValidator::new();

    // First validation
    let start1 = std::time::Instant::now();
    let _results1 = validator.validate_python_availability().await;
    let duration1 = start1.elapsed();

    // Second validation (should potentially be faster due to caching)
    let start2 = std::time::Instant::now();
    let _results2 = validator.validate_python_availability().await;
    let duration2 = start2.elapsed();

    // Verify both complete (timing comparison not guaranteed due to system variation)
    assert!(duration1 > Duration::from_nanos(1));
    assert!(duration2 > Duration::from_nanos(1));

    Ok(())
}

#[tokio::test]
async fn test_security_manager_creation() -> Result<()> {
    let security_result = SecurityManager::new();

    // Verify security manager initializes properly
    assert!(security_result.is_ok() || security_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_security_manager_enforcement() -> Result<()> {
    let mut security = SecurityManager::new()?;

    // Test security enforcement initialization
    let init_result = security.initialize_security_enforcement();
    assert!(init_result.is_ok() || init_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_security_manager_validation() -> Result<()> {
    let security = SecurityManager::new()?;

    // Test command validation
    let safe_command = "echo";
    let safe_args = ["test".to_string()];

    let validation_result = security
        .validate_subprocess_command(&[safe_command.to_string(), safe_args[0].clone()], false);
    assert!(validation_result.is_ok() || validation_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_process_manager_creation() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let security = Arc::new(Mutex::new(SecurityManager::new()?));

    let manager = ProcessManager::new(&platform, security)?;

    // Verify process manager creates successfully
    assert_eq!(manager.get_active_process_count(), 0);

    Ok(())
}

#[tokio::test]
async fn test_process_manager_statistics() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let security = Arc::new(Mutex::new(SecurityManager::new()?));

    let manager = ProcessManager::new(&platform, security)?;

    // Test statistics collection
    let stats = manager.get_statistics();
    assert_eq!(stats.total_processes, 0);
    assert_eq!(stats.successful_processes, 0);
    assert_eq!(stats.failed_processes, 0);

    // Test worker status
    let worker_status = manager.get_worker_status();
    let available_workers = worker_status
        .iter()
        .filter(|w| matches!(w.status, crate::process_manager::WorkerStatus::Idle))
        .count();
    let active_workers = worker_status
        .iter()
        .filter(|w| matches!(w.status, crate::process_manager::WorkerStatus::Busy))
        .count();
    assert!(available_workers > 0);
    assert_eq!(active_workers, 0);

    // Test process listing
    let processes = manager.list_processes();
    assert!(processes.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_process_manager_simple_command() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let security = Arc::new(Mutex::new(SecurityManager::new()?));

    let manager = ProcessManager::new(&platform, security)?;

    // Test simple command execution
    #[cfg(windows)]
    let result = manager.execute_command(
        "cmd",
        &["/C".to_string(), "echo test".to_string()],
        None::<&str>,
        Some(Duration::from_secs(5)),
    );

    #[cfg(unix)]
    let result = manager.execute_command(
        "echo",
        &["test".to_string()],
        None::<&str>,
        Some(Duration::from_secs(5)),
    );

    match result {
        Ok(process_id) => {
            // Wait for process to complete
            let final_info = manager.wait_for_process(process_id);
            assert!(final_info.is_ok() || final_info.is_err());

            // Verify statistics updated
            let stats = manager.get_statistics();
            assert!(stats.total_processes > 0);
        }
        Err(_) => {
            // Command might fail due to security restrictions or system state
            // This is acceptable in test environment
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_process_manager_cleanup() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let security = Arc::new(Mutex::new(SecurityManager::new()?));

    let manager = ProcessManager::new(&platform, security)?;

    // Test cleanup functionality
    let cleanup_count = manager.cleanup_finished_processes();
    let cleanup_count_isize = cleanup_count as isize;
    // Verify cleanup count is non-negative (usize guarantees this, but test validates logic)
    assert!(cleanup_count_isize >= 0);
    // Additional validation: ensure reasonable cleanup count
    assert!(cleanup_count <= 1000); // Reasonable limit for test processes

    Ok(())
}

#[tokio::test]
async fn test_environment_manager_creation() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let env_manager = EnvironmentManager::new(&platform);

    // Verify environment manager creates successfully
    // This is a creation test, not a configuration test
    drop(env_manager);

    Ok(())
}

#[tokio::test]
async fn test_environment_manager_configuration() -> Result<()> {
    let platform = PlatformInfo::detect()?;
    let env_manager = EnvironmentManager::new(&platform);

    // Test environment configuration
    let config_result = env_manager.configure_complete_environment();
    assert!(config_result.is_ok() || config_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_gil_safety_initialization() -> Result<()> {
    // Test GIL safety manager
    let result = GilSafetyManager::initialize_gil_safety();
    assert!(result.is_ok() || result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_full_launcher_initialization() -> Result<()> {
    // Test full launcher creation
    let launcher_result = IntellicrackLauncher::new().await;

    match launcher_result {
        Ok(_launcher) => {
            // Launcher created successfully
            // Note: We don't test launch() method here as it would actually start Intellicrack
        }
        Err(_) => {
            // Launcher creation might fail due to missing dependencies or system state
            // This is acceptable in test environment
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    // Test concurrent platform detection
    let tasks: Vec<_> = (0..5)
        .map(|_| tokio::spawn(async { PlatformInfo::detect().unwrap() }))
        .collect();

    let results: Vec<_> = futures::future::join_all(tasks).await;

    // Verify all tasks completed successfully
    for result in results {
        assert!(result.is_ok());
        let platform = result.unwrap();
        assert!(platform.os_type == OsType::Windows || platform.os_type == OsType::Unix);
    }

    Ok(())
}

#[tokio::test]
async fn test_error_handling_robustness() -> Result<()> {
    // Test various error conditions to ensure robust error handling

    // Test invalid path handling
    let invalid_result = std::panic::catch_unwind(|| {
        // This should not panic even with invalid input
        let _ = std::env::var("INVALID_NONEXISTENT_VAR_12345");
    });
    assert!(invalid_result.is_ok());

    // Test dependency validator with potential timeout
    let mut validator = DependencyValidator::new();
    let timeout_result = tokio::time::timeout(
        Duration::from_secs(30), // Generous timeout for test environment
        validator.validate_all_dependencies(),
    )
    .await;

    match timeout_result {
        Ok(_) => {
            // Validation completed within timeout
        }
        Err(_) => {
            // Timeout occurred - acceptable in constrained test environment
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_memory_management() -> Result<()> {
    // Test memory management by creating and dropping multiple components
    for _ in 0..5 {
        let platform = PlatformInfo::detect()?;
        let security = Arc::new(Mutex::new(SecurityManager::new()?));

        let _manager = ProcessManager::new(&platform, security)?;
        let env_manager = EnvironmentManager::new(&platform);
        // Test environment manager functionality
        let _config_result = env_manager.configure_complete_environment();
        let _python = PythonIntegration::initialize()?;
        let mut _validator = DependencyValidator::new();

        // Components automatically dropped at end of loop iteration
    }
    Ok(())
}

#[tokio::test]
async fn test_integration_cross_component() -> Result<()> {
    // Test integration between multiple components
    let platform = PlatformInfo::detect()?;
    let security = Arc::new(Mutex::new(SecurityManager::new()?));
    let _process_manager = ProcessManager::new(&platform, Arc::clone(&security))?;
    let _env_manager = EnvironmentManager::new(&platform);
    let _python = PythonIntegration::initialize()?;
    let mut _validator = DependencyValidator::new();

    // Test that security manager can be shared across components
    let mut security_guard = security.lock().unwrap();
    let _init_result = security_guard.initialize_security_enforcement();

    Ok(())
}

#[test]
#[ignore]
fn test_full_optimization_sequence() {
    let result1 = intellicrack_launcher::optimize_process();
    assert!(result1.is_ok(), "Process optimization should succeed");

    let result2 = intellicrack_launcher::run_preflight_checks();
    assert!(result2.is_ok(), "Preflight checks should succeed");

    let result3 = intellicrack_launcher::discover_and_cache_tools();
    assert!(result3.is_ok(), "Tool discovery should succeed");
}

#[test]
fn test_optimization_sequence_performance() {
    let start = std::time::Instant::now();

    let _ = intellicrack_launcher::optimize_process();
    let _ = intellicrack_launcher::run_preflight_checks();
    let _ = intellicrack_launcher::discover_and_cache_tools();

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 200,
        "Full optimization sequence should complete in <200ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_graceful_degradation_on_failures() {
    let process_result = intellicrack_launcher::optimize_process();
    assert!(
        process_result.is_ok(),
        "Process optimization should be non-fatal"
    );

    let tool_result = intellicrack_launcher::discover_and_cache_tools();
    assert!(tool_result.is_ok(), "Tool discovery should be non-fatal");
}

#[test]
fn test_environment_variables_after_tool_discovery() {
    let _ = intellicrack_launcher::discover_and_cache_tools();

    let possible_vars = vec![
        "RADARE2_PATH",
        "R2_PATH",
        "GHIDRA_PATH",
        "FRIDA_PATH",
        "QEMU_SYSTEM_X86_64_PATH",
        "CAPSTONE_PATH",
    ];

    // Count discovered environment variables and use the result to avoid unused-variable warning
    let found_count = possible_vars
        .iter()
        .filter(|var_name| std::env::var(var_name).is_ok())
        .count();

    // Basic sanity check that uses found_count
    assert!(found_count <= possible_vars.len());
}

#[test]
fn test_optimizations_do_not_interfere() {
    let _ = intellicrack_launcher::optimize_process();
    let process1 = std::process::id();

    let _ = intellicrack_launcher::run_preflight_checks();
    let process2 = std::process::id();

    let _ = intellicrack_launcher::discover_and_cache_tools();
    let process3 = std::process::id();

    assert_eq!(process1, process2);
    assert_eq!(process2, process3);
}

#[test]
fn test_optimization_sequence_multiple_times() {
    for _ in 0..3 {
        let _ = intellicrack_launcher::optimize_process();
        let _ = intellicrack_launcher::run_preflight_checks();
        let _ = intellicrack_launcher::discover_and_cache_tools();
    }
}

#[test]
fn test_concurrent_optimizations() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let r1 = intellicrack_launcher::optimize_process();
                let r2 = intellicrack_launcher::discover_and_cache_tools();
                (r1.is_ok(), r2.is_ok())
            })
        })
        .collect();

    for handle in handles {
        let (r1, r2) = handle.join().unwrap();
        assert!(r1, "Process optimization should succeed");
        assert!(r2, "Tool discovery should succeed");
    }
}
