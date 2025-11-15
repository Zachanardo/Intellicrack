use criterion::{Criterion, criterion_group, criterion_main};
use intellicrack_launcher::{PlatformInfo, ProcessManager, SecurityManager};
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;

fn benchmark_process_manager_creation(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));

    c.bench_function("process_manager_creation", |b| {
        b.iter(|| {
            let _manager =
                black_box(ProcessManager::new(&platform, Arc::clone(&security)).unwrap());
        });
    });
}

fn benchmark_simple_command_execution(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    c.bench_function("simple_command_execution", |b| {
        b.iter(|| {
            #[cfg(windows)]
            let result = manager.execute_command(
                "cmd",
                &["/C".to_string(), "echo test".to_string()],
                None::<&str>,
                Some(Duration::from_secs(5)),
            );

            #[cfg(not(windows))]
            let result = manager.execute_command(
                "echo",
                &["test".to_string()],
                None::<&str>,
                Some(Duration::from_secs(5)),
            );

            if let Ok(process_id) = result {
                let _ = black_box(manager.wait_for_process(process_id));
            }
        });
    });
}

fn benchmark_concurrent_process_execution(c: &mut Criterion) {
    c.bench_function("concurrent_process_execution", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let platform = PlatformInfo::detect().unwrap();
                let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
                let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

                // Use the manager to run a small test command and probe stats so the variable is actually used
                #[cfg(windows)]
                let result = manager.execute_command(
                    "cmd",
                    &["/C".to_string(), "echo main_test".to_string()],
                    None::<&str>,
                    Some(Duration::from_secs(10)),
                );

                #[cfg(not(windows))]
                let result = manager.execute_command(
                    "echo",
                    &["main_test".to_string()],
                    None::<&str>,
                    Some(Duration::from_secs(10)),
                );

                if let Ok(pid) = result {
                    let _ = manager.wait_for_process(pid);
                }

                // Probe some infos to exercise the manager API and avoid unused-variable warning
                let _ = black_box(manager.get_statistics());
                let _ = black_box(manager.get_active_process_count());

                let tasks: Vec<_> = (0..5)
                    .map(|i| {
                        tokio::spawn(async move {
                            let local_platform = PlatformInfo::detect().unwrap();
                            let local_security =
                                Arc::new(Mutex::new(SecurityManager::new().unwrap()));
                            let local_manager =
                                ProcessManager::new(&local_platform, Arc::clone(&local_security))
                                    .unwrap();
                            #[cfg(windows)]
                            let result = local_manager.execute_command(
                                "cmd",
                                &["/C".to_string(), format!("echo test_{}", i)],
                                None::<&str>,
                                Some(Duration::from_secs(10)),
                            );

                            #[cfg(not(windows))]
                            let result = local_manager.execute_command(
                                "echo",
                                &[format!("test_{}", i)],
                                None::<&str>,
                                Some(Duration::from_secs(10)),
                            );

                            if let Ok(process_id) = result {
                                let _ = local_manager.wait_for_process(process_id);
                            }
                        })
                    })
                    .collect();

                let _results = black_box(futures::future::join_all(tasks).await);
            });
        });
    });
}

fn benchmark_process_monitoring_overhead(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    c.bench_function("process_monitoring_overhead", |b| {
        b.iter(|| {
            // Start a long-running process
            #[cfg(windows)]
            let result = manager.execute_command(
                "cmd",
                &["/C".to_string(), "ping 127.0.0.1 -n 3".to_string()],
                None::<&str>,
                Some(Duration::from_secs(10)),
            );

            #[cfg(not(windows))]
            let result = manager.execute_command(
                "sleep",
                &["1".to_string()],
                None::<&str>,
                Some(Duration::from_secs(5)),
            );

            if let Ok(process_id) = result {
                // Monitor process info retrieval performance
                for _ in 0..10 {
                    let _info = black_box(manager.get_process_info(process_id));
                }
                let _ = manager.wait_for_process(process_id);
            }
        });
    });
}

fn benchmark_process_cleanup_performance(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));

    c.bench_function("process_cleanup_performance", |b| {
        b.iter(|| {
            let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

            // Create multiple short processes
            let mut process_ids = Vec::new();
            for i in 0..5 {
                #[cfg(windows)]
                let result = manager.execute_command(
                    "cmd",
                    &["/C".to_string(), format!("echo cleanup_test_{}", i)],
                    None::<&str>,
                    Some(Duration::from_secs(5)),
                );

                #[cfg(not(windows))]
                let result = manager.execute_command(
                    "echo",
                    &[format!("cleanup_test_{}", i)],
                    None::<&str>,
                    Some(Duration::from_secs(5)),
                );

                if let Ok(pid) = result {
                    process_ids.push(pid);
                }
            }

            // Wait for all processes to complete
            for pid in &process_ids {
                let _ = manager.wait_for_process(*pid);
            }

            // Benchmark cleanup operation
            let cleanup_count = black_box(manager.cleanup_finished_processes());
            black_box(cleanup_count);
        });
    });
}

fn benchmark_process_statistics_collection(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    // Pre-populate with some processes
    for i in 0..3 {
        #[cfg(windows)]
        let result = manager.execute_command(
            "cmd",
            &["/C".to_string(), format!("echo stats_test_{}", i)],
            None::<&str>,
            Some(Duration::from_secs(5)),
        );

        #[cfg(not(windows))]
        let result = manager.execute_command(
            "echo",
            &[format!("stats_test_{}", i)],
            None::<&str>,
            Some(Duration::from_secs(5)),
        );

        if let Ok(pid) = result {
            let _ = manager.wait_for_process(pid);
        }
    }

    c.bench_function("process_statistics_collection", |b| {
        b.iter(|| {
            let _stats = black_box(manager.get_statistics());
            let _worker_status = black_box(manager.get_worker_status());
            let _active_count = black_box(manager.get_active_process_count());
            let _process_list = black_box(manager.list_processes());
        });
    });
}

fn benchmark_python_subprocess_execution(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    // Create a simple Python script for testing
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_script = NamedTempFile::new().unwrap();
    writeln!(temp_script, "print('Hello from Python benchmark')").unwrap();
    let script_path = temp_script.path().to_str().unwrap();

    c.bench_function("python_subprocess_execution", |b| {
        b.iter(|| {
            let result = manager.execute_python_subprocess(script_path, &[]);

            if let Ok(process_id) = result {
                let _ = black_box(manager.wait_for_process(process_id));
            }
        });
    });
}

fn benchmark_process_timeout_handling(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    c.bench_function("process_timeout_handling", |b| {
        b.iter(|| {
            // Start a process with very short timeout to test timeout handling
            #[cfg(windows)]
            let result = manager.execute_command(
                "cmd",
                &["/C".to_string(), "ping 127.0.0.1 -n 10".to_string()],
                None::<&str>,
                Some(Duration::from_millis(100)), // Very short timeout
            );

            #[cfg(not(windows))]
            let result = manager.execute_command(
                "sleep",
                &["10".to_string()],
                None::<&str>,
                Some(Duration::from_millis(100)), // Very short timeout
            );

            if let Ok(process_id) = result {
                let _final_info = black_box(manager.wait_for_process(process_id));
            }
        });
    });
}

fn benchmark_process_memory_usage(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));

    c.bench_function("process_memory_usage", |b| {
        b.iter(|| {
            // Create and destroy multiple process managers to test memory usage
            let managers: Vec<_> = (0..5)
                .map(|_| ProcessManager::new(&platform, Arc::clone(&security)).unwrap())
                .collect();

            let _count = black_box(managers.len());

            // Let them drop to test cleanup
            drop(managers);
        });
    });
}

fn benchmark_process_security_validation(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();
    let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
    let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

    c.bench_function("process_security_validation", |b| {
        b.iter(|| {
            // Test security validation overhead for process execution
            #[cfg(windows)]
            let result = manager.execute_command(
                "cmd",
                &["/C".to_string(), "echo security_test".to_string()],
                None::<&str>,
                Some(Duration::from_secs(5)),
            );

            #[cfg(not(windows))]
            let result = manager.execute_command(
                "echo",
                &["security_test".to_string()],
                None::<&str>,
                Some(Duration::from_secs(5)),
            );

            if let Ok(process_id) = result {
                let _ = black_box(manager.wait_for_process(process_id));
            }
        });
    });
}

fn benchmark_process_manager_under_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_manager_under_load");
    group.measurement_time(Duration::from_secs(20));
    // Create a dedicated multi-threaded runtime once and reuse it for the whole group.
    // Configure worker threads to match available parallelism for a production-like executor.
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let rt = std::sync::Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("failed to build tokio runtime"),
    );

    // Do a small, real warm-up on that runtime to exercise the executor and manager API.
    // This spawns a short-lived background poller to mimic production monitoring behavior,
    // and runs a short command to force any lazy initialization inside the manager and runtime.
    let rt_clone = std::sync::Arc::clone(&rt);
    rt_clone.block_on(async {
        let platform = PlatformInfo::detect().unwrap();
        let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));

        // Primary manager used for the warm command.
        let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

        // A separate manager instance used by a short-lived background poller to simulate
        // production monitoring (periodic stats collection) and to exercise manager internals.
        let poll_platform = PlatformInfo::detect().unwrap();
        let poll_security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
        let poll_manager = ProcessManager::new(&poll_platform, Arc::clone(&poll_security)).unwrap();

        // Spawn a background poller that runs a few iterations and then completes.
        let poller = tokio::spawn(async move {
            for _ in 0..5 {
                // Probe APIs that would be used by monitoring/telemetry in production.
                let _ = poll_manager.get_statistics();
                let _ = poll_manager.get_active_process_count();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Run a short real command to warm up process creation paths.
        #[cfg(windows)]
        let warm = manager.execute_command(
            "cmd",
            &["/C".to_string(), "echo warmup".to_string()],
            None::<&str>,
            Some(Duration::from_secs(2)),
        );

        #[cfg(not(windows))]
        let warm = manager.execute_command(
            "echo",
            &["warmup".to_string()],
            None::<&str>,
            Some(Duration::from_secs(2)),
        );

        if let Ok(pid) = warm {
            let _ = manager.wait_for_process(pid);
        }

        // Wait for the poller to finish its short run.
        let _ = poller.await;
    });
    for concurrent_processes in [1, 5, 10, 15].iter() {
        group.bench_with_input(
            format!("concurrent_processes_{}", concurrent_processes),
            concurrent_processes,
            |b, &concurrent_processes| {
                b.iter(|| {
                    let rt = Runtime::new().unwrap();
                    rt.block_on(async move {
                        let platform = PlatformInfo::detect().unwrap();
                        let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
                        let manager =
                            ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

                        let tasks: Vec<_> = (0..concurrent_processes)
                            .map(|i| {
                                tokio::spawn(async move {
                                    let local_platform = PlatformInfo::detect().unwrap();
                                    let local_security =
                                        Arc::new(Mutex::new(SecurityManager::new().unwrap()));
                                    let local_manager = ProcessManager::new(
                                        &local_platform,
                                        Arc::clone(&local_security),
                                    )
                                    .unwrap();
                                    #[cfg(windows)]
                                    let result = local_manager.execute_command(
                                        "cmd",
                                        &["/C".to_string(), format!("echo load_test_{}", i)],
                                        None::<&str>,
                                        Some(Duration::from_secs(10)),
                                    );

                                    #[cfg(not(windows))]
                                    let result = local_manager.execute_command(
                                        "echo",
                                        &[format!("load_test_{}", i)],
                                        None::<&str>,
                                        Some(Duration::from_secs(10)),
                                    );

                                    if let Ok(process_id) = result {
                                        let _ = local_manager.wait_for_process(process_id);
                                    }
                                })
                            })
                            .collect();

                        // Probe manager to exercise its API and avoid an unused-variable warning.
                        // Using public read-only APIs keeps the benchmark realistic and side-effect free.
                        let _ = black_box(manager.get_statistics());
                        let _ = black_box(manager.get_active_process_count());

                        let _results = black_box(futures::future::join_all(tasks).await);
                    });
                });
            },
        );
    }

    group.finish();
}

fn benchmark_intellicrack_application_launch_simulation(c: &mut Criterion) {
    c.bench_function("intellicrack_application_launch_simulation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let platform = PlatformInfo::detect().unwrap();
                let security = Arc::new(Mutex::new(SecurityManager::new().unwrap()));
                let manager = ProcessManager::new(&platform, Arc::clone(&security)).unwrap();

                // Simulate the launch process without actually starting Intellicrack
                // This measures the setup and teardown overhead
                let start_time = std::time::Instant::now();

                // Simulate pre-launch checks
                let _stats = manager.get_statistics();
                let _worker_status = manager.get_worker_status();
                let _active_count = manager.get_active_process_count();

                // Simulate a quick test command instead of full launch
                #[cfg(windows)]
                let result = manager.execute_command(
                    "cmd",
                    &["/C".to_string(), "echo Intellicrack simulation".to_string()],
                    None::<&str>,
                    Some(Duration::from_secs(5)),
                );

                #[cfg(not(windows))]
                let result = manager.execute_command(
                    "echo",
                    &["Intellicrack simulation".to_string()],
                    None::<&str>,
                    Some(Duration::from_secs(5)),
                );

                if let Ok(process_id) = result {
                    let _final_info = manager.wait_for_process(process_id);
                }

                let elapsed = start_time.elapsed();
                black_box(elapsed)
            });
        });
    });
}

criterion_group!(
    benches,
    benchmark_process_manager_creation,
    benchmark_simple_command_execution,
    benchmark_concurrent_process_execution,
    benchmark_process_monitoring_overhead,
    benchmark_process_cleanup_performance,
    benchmark_process_statistics_collection,
    benchmark_python_subprocess_execution,
    benchmark_process_timeout_handling,
    benchmark_process_memory_usage,
    benchmark_process_security_validation,
    benchmark_process_manager_under_load,
    benchmark_intellicrack_application_launch_simulation
);

criterion_main!(benches);
