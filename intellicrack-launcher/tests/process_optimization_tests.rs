use intellicrack_launcher::process_optimization;

#[test]
#[cfg(target_os = "windows")]
fn test_optimize_process_priority_succeeds_on_windows() {
    let result = process_optimization::optimize_process_priority();

    assert!(result.is_ok(), "Process priority optimization should succeed on Windows");
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_optimize_process_priority_noops_on_unix() {
    let start = std::time::Instant::now();
    let result = process_optimization::optimize_process_priority();
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Process priority optimization should return Ok on Unix");
    assert!(elapsed.as_millis() < 10, "Should return immediately (<10ms)");
}

#[test]
fn test_optimize_process_completes_without_panic() {
    let result = process_optimization::optimize_process();

    assert!(result.is_ok(), "Process optimization should not panic");
}

#[test]
fn test_optimize_process_is_idempotent() {
    let result1 = process_optimization::optimize_process();
    let result2 = process_optimization::optimize_process();

    assert!(result1.is_ok(), "First optimization should succeed");
    assert!(result2.is_ok(), "Second optimization should also succeed (idempotent)");
}

#[test]
#[cfg(target_os = "windows")]
fn test_process_priority_actually_changed() {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::processthreadsapi::GetPriorityClass;
    use winapi::um::winbase::ABOVE_NORMAL_PRIORITY_CLASS;

    let result = process_optimization::optimize_process_priority();
    assert!(result.is_ok(), "Should succeed");

    unsafe {
        let handle = GetCurrentProcess();
        let current_priority = GetPriorityClass(handle);

        assert_eq!(
            current_priority,
            ABOVE_NORMAL_PRIORITY_CLASS,
            "Process priority should be set to ABOVE_NORMAL"
        );
    }
}

#[test]
fn test_optimize_process_performance() {
    let start = std::time::Instant::now();
    let result = process_optimization::optimize_process();
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Should complete successfully");
    assert!(
        elapsed.as_millis() < 100,
        "Process optimization should complete within 100ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_cpu_topology_structure() {
    let p_cores = vec![0, 1, 2, 3];
    let e_cores = vec![4, 5, 6, 7];

    let topology = process_optimization::CpuTopology::new(p_cores.clone(), e_cores.clone());

    assert_eq!(topology.p_cores, p_cores);
    assert_eq!(topology.e_cores, e_cores);
    assert!(topology.is_hybrid, "Should detect hybrid CPU with both P and E cores");
}

#[test]
fn test_cpu_topology_non_hybrid() {
    let p_cores = vec![0, 1, 2, 3];
    let e_cores = vec![];

    let topology = process_optimization::CpuTopology::new(p_cores.clone(), e_cores.clone());

    assert_eq!(topology.p_cores, p_cores);
    assert!(topology.e_cores.is_empty());
    assert!(!topology.is_hybrid, "Should not detect hybrid CPU when E-cores are empty");
}

#[test]
fn test_optimization_does_not_crash_on_errors() {
    for _ in 0..10 {
        let _ = process_optimization::optimize_process();
    }
}

#[test]
fn test_multiple_concurrent_optimizations() {
    use std::sync::Arc;
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                process_optimization::optimize_process()
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join();
        assert!(result.is_ok(), "Thread should not panic");
        assert!(result.unwrap().is_ok(), "Optimization should succeed");
    }
}
