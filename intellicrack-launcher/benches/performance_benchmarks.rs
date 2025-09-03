use criterion::{black_box, criterion_group, criterion_main, Criterion};
use intellicrack_launcher::{
    EnvironmentManager, GilSafetyManager, PlatformInfo, PythonIntegration, SecurityManager,
};
use std::time::Duration;
use tokio::runtime::Runtime;

fn benchmark_platform_detection(c: &mut Criterion) {
    c.bench_function("platform_detection", |b| {
        b.iter(|| {
            let _platform = black_box(PlatformInfo::detect().unwrap());
        });
    });
}

fn benchmark_environment_setup(c: &mut Criterion) {
    let platform = PlatformInfo::detect().unwrap();

    c.bench_function("environment_setup", |b| {
        b.iter(|| {
            let env_manager = black_box(EnvironmentManager::new(&platform));
            let _result = black_box(env_manager.configure_complete_environment());
        });
    });
}

fn benchmark_python_integration_init(c: &mut Criterion) {
    c.bench_function("python_integration_init", |b| {
        b.iter(|| {
            let python = black_box(PythonIntegration::initialize().unwrap());
            let _result = black_box(python.configure_pybind11_compatibility());
        });
    });
}

fn benchmark_security_manager_creation(c: &mut Criterion) {
    c.bench_function("security_manager_creation", |b| {
        b.iter(|| {
            let _security = black_box(SecurityManager::new().unwrap());
        });
    });
}

fn benchmark_security_initialization(c: &mut Criterion) {
    c.bench_function("security_initialization", |b| {
        b.iter(|| {
            let mut security = SecurityManager::new().unwrap();
            let _result = black_box(security.initialize_security_enforcement());
        });
    });
}

fn benchmark_gil_safety_init(c: &mut Criterion) {
    c.bench_function("gil_safety_init", |b| {
        b.iter(|| {
            let _result = black_box(GilSafetyManager::initialize_gil_safety());
        });
    });
}

fn benchmark_full_launcher_initialization(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("full_launcher_init", |b| {
        b.to_async(&rt).iter(|| async {
            let _launcher = black_box(
                intellicrack_launcher::IntellicrackLauncher::new()
                    .await
                    .unwrap(),
            );
        });
    });
}

fn benchmark_concurrent_platform_detection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("concurrent_platform_detection", |b| {
        b.to_async(&rt).iter(|| async {
            let handles: Vec<_> = (0..10)
                .map(|_| tokio::spawn(async { PlatformInfo::detect().unwrap() }))
                .collect();

            let _results: Vec<_> = black_box(futures::future::join_all(handles).await);
        });
    });
}

fn benchmark_memory_usage_tracking(c: &mut Criterion) {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

    struct TrackingAllocator;

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = System.alloc(layout);
            if !ptr.is_null() {
                ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
            ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
        }
    }

    c.bench_function("memory_usage_platform_detection", |b| {
        b.iter(|| {
            let before = ALLOCATED.load(Ordering::SeqCst);
            let _platform = black_box(PlatformInfo::detect().unwrap());
            let after = ALLOCATED.load(Ordering::SeqCst);
            black_box(after.saturating_sub(before))
        });
    });
}

fn benchmark_error_handling_performance(c: &mut Criterion) {
    c.bench_function("error_handling_performance", |b| {
        b.iter(|| {
            // Test error path performance by attempting invalid operations
            let result = std::panic::catch_unwind(|| {
                // This should trigger error handling paths
                let invalid_path = "/nonexistent/path/that/does/not/exist";
                let _env = std::env::var(invalid_path);
            });
            black_box(result)
        });
    });
}

fn benchmark_configuration_loading(c: &mut Criterion) {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("intellicrack_config.json");

    let config_content = r#"{
        "security": {
            "sandbox_analysis": true,
            "allow_network_access": false,
            "log_sensitive_data": false,
            "encrypt_config": false,
            "hashing": {
                "default_algorithm": "sha256",
                "allow_md5_for_security": false
            },
            "subprocess": {
                "allow_shell_true": false,
                "shell_whitelist": []
            },
            "serialization": {
                "default_format": "json",
                "restrict_pickle": true
            },
            "input_validation": {
                "strict_mode": true,
                "max_file_size": null,
                "allowed_extensions": null
            }
        }
    }"#;

    fs::write(&config_path, config_content).unwrap();

    c.bench_function("configuration_loading", |b| {
        b.iter(|| {
            let _config = black_box(fs::read_to_string(&config_path).unwrap());
            let _parsed: serde_json::Value = black_box(serde_json::from_str(&_config).unwrap());
        });
    });
}

fn benchmark_multithreaded_operations(c: &mut Criterion) {
    c.bench_function("multithreaded_platform_detection", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..num_cpus::get())
                .map(|_| std::thread::spawn(|| PlatformInfo::detect().unwrap()))
                .collect();

            let _results: Vec<_> =
                black_box(handles.into_iter().map(|h| h.join().unwrap()).collect());
        });
    });
}

fn benchmark_startup_sequence_components(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("startup_components");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("platform_detection", |b| {
        b.iter(|| {
            let _platform = black_box(PlatformInfo::detect().unwrap());
        });
    });

    group.bench_function("environment_configuration", |b| {
        let platform = PlatformInfo::detect().unwrap();
        b.iter(|| {
            let env_manager = EnvironmentManager::new(&platform);
            let _result = black_box(env_manager.configure_complete_environment());
        });
    });

    group.bench_function("python_integration", |b| {
        b.iter(|| {
            let python = PythonIntegration::initialize().unwrap();
            let _result = black_box(python.configure_pybind11_compatibility());
        });
    });

    group.bench_function("security_setup", |b| {
        b.iter(|| {
            let mut security = SecurityManager::new().unwrap();
            let _result = black_box(security.initialize_security_enforcement());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_platform_detection,
    benchmark_environment_setup,
    benchmark_python_integration_init,
    benchmark_security_manager_creation,
    benchmark_security_initialization,
    benchmark_gil_safety_init,
    benchmark_full_launcher_initialization,
    benchmark_concurrent_platform_detection,
    benchmark_memory_usage_tracking,
    benchmark_error_handling_performance,
    benchmark_configuration_loading,
    benchmark_multithreaded_operations,
    benchmark_startup_sequence_components
);

criterion_main!(benches);
