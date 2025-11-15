use criterion::{Criterion, criterion_group, criterion_main};
use intellicrack_launcher::{DependencyValidator, ValidationSummary};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

fn benchmark_dependency_validator_creation(c: &mut Criterion) {
    c.bench_function("dependency_validator_creation", |b| {
        b.iter(|| {
            let _validator = black_box(DependencyValidator::new());
        });
    });
}

fn benchmark_python_dependency_check(c: &mut Criterion) {
    c.bench_function("python_dependency_check", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result = black_box(validator.validate_python_availability().await);
            });
        });
    });
}

fn benchmark_flask_validation(c: &mut Criterion) {
    c.bench_function("flask_validation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result = black_box(validator.validate_flask_comprehensive().await);
            });
        });
    });
}

fn benchmark_tensorflow_validation(c: &mut Criterion) {
    c.bench_function("tensorflow_validation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result = black_box(validator.validate_tensorflow_comprehensive().await);
            });
        });
    });
}

fn benchmark_qemu_detection(c: &mut Criterion) {
    c.bench_function("qemu_detection", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result = black_box(validator.validate_qemu_availability().await);
            });
        });
    });
}

fn benchmark_system_tools_validation(c: &mut Criterion) {
    c.bench_function("system_tools_validation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result = black_box(validator.validate_system_tools().await);
            });
        });
    });
}

fn benchmark_full_dependency_validation(c: &mut Criterion) {
    c.bench_function("full_dependency_validation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let _result: ValidationSummary =
                    black_box(validator.validate_all_dependencies().await.unwrap());
            });
        });
    });
}

fn benchmark_concurrent_dependency_checks(c: &mut Criterion) {
    c.bench_function("concurrent_dependency_checks", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let validator = DependencyValidator::new();

                let python_task = tokio::spawn({
                    let mut v = validator.clone();
                    async move { v.validate_python_availability().await }
                });

                let flask_task = tokio::spawn({
                    let mut v = validator.clone();
                    async move { v.validate_flask_comprehensive().await }
                });

                let tensorflow_task = tokio::spawn({
                    let mut v = validator.clone();
                    async move { v.validate_tensorflow_comprehensive().await }
                });

                let qemu_task = tokio::spawn({
                    let mut v = validator.clone();
                    async move { v.validate_qemu_availability().await }
                });

                let system_task = tokio::spawn({
                    let mut v = validator.clone();
                    async move { v.validate_system_tools().await }
                });

                let _results = black_box(tokio::try_join!(
                    python_task,
                    flask_task,
                    tensorflow_task,
                    qemu_task,
                    system_task
                ));
            });
        });
    });
}

fn benchmark_dependency_validation_caching(c: &mut Criterion) {
    c.bench_function("dependency_validation_caching", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();

                // First validation (cache miss)
                let _first = black_box(validator.validate_python_availability().await);

                // Second validation (should be faster if cached)
                let _second = black_box(validator.validate_python_availability().await);
            });
        });
    });
}

fn benchmark_validation_result_processing(c: &mut Criterion) {
    c.bench_function("validation_result_processing", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();
                let results = validator.validate_all_dependencies().await.unwrap();

                // Process results like the real application would
                let _available_count = black_box(
                    results
                        .dependencies
                        .values()
                        .filter(|dep| dep.available)
                        .count(),
                );

                let _unavailable_count = black_box(
                    results
                        .dependencies
                        .values()
                        .filter(|dep| !dep.available)
                        .count(),
                );

                let _success_rate = black_box(
                    results
                        .dependencies
                        .values()
                        .filter(|dep| dep.available)
                        .count() as f64
                        / results.dependencies.len() as f64,
                );
            });
        });
    });
}

fn benchmark_validation_error_handling(c: &mut Criterion) {
    c.bench_function("validation_error_handling", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();

                // Test error handling paths by attempting invalid operations
                let _result = black_box(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || {
                        // Simulate potential error conditions
                        let rt = tokio::runtime::Handle::current();
                        rt.block_on(async { validator.validate_python_availability().await })
                    },
                )));
            });
        });
    });
}

fn benchmark_validation_with_timeout(c: &mut Criterion) {
    c.bench_function("validation_with_timeout", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut validator = DependencyValidator::new();

                let _result = black_box(
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        validator.validate_all_dependencies(),
                    )
                    .await,
                );
            });
        });
    });
}

fn benchmark_memory_usage_during_validation(c: &mut Criterion) {
    c.bench_function("memory_usage_during_validation", |b| {
        b.iter(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                // Create multiple validators to stress test memory usage
                let validators: Vec<_> = (0..10).map(|_| DependencyValidator::new()).collect();

                let tasks: Vec<_> = validators
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut validator)| {
                        tokio::spawn(async move {
                            if i % 2 == 0 {
                                validator.validate_python_availability().await
                            } else {
                                validator.validate_flask_comprehensive().await
                            }
                        })
                    })
                    .collect();

                let _results = black_box(futures::future::join_all(tasks).await);
            });
        });
    });
}

fn benchmark_validation_under_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation_under_load");
    group.measurement_time(Duration::from_secs(15));

    for load_factor in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            format!("load_factor_{}", load_factor),
            load_factor,
            |b, &load_factor| {
                b.iter(|| {
                    let rt = Runtime::new().unwrap();
                    rt.block_on(async move {
                        let tasks: Vec<_> = (0..load_factor)
                            .map(|_| {
                                tokio::spawn(async {
                                    let mut validator = DependencyValidator::new();
                                    validator.validate_all_dependencies().await
                                })
                            })
                            .collect();

                        let _results = black_box(futures::future::join_all(tasks).await);
                    });
                });
            },
        );
    }

    group.finish();
}

fn benchmark_validation_result_serialization(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let validation_results = rt.block_on(async {
        let mut validator = DependencyValidator::new();
        validator.validate_all_dependencies().await.unwrap()
    });

    c.bench_function("validation_result_serialization", |b| {
        b.iter(|| {
            let _json = black_box(serde_json::to_string(&validation_results).unwrap());
            let _pretty_json =
                black_box(serde_json::to_string_pretty(&validation_results).unwrap());
        });
    });
}

criterion_group!(
    benches,
    benchmark_dependency_validator_creation,
    benchmark_python_dependency_check,
    benchmark_flask_validation,
    benchmark_tensorflow_validation,
    benchmark_qemu_detection,
    benchmark_system_tools_validation,
    benchmark_full_dependency_validation,
    benchmark_concurrent_dependency_checks,
    benchmark_dependency_validation_caching,
    benchmark_validation_result_processing,
    benchmark_validation_error_handling,
    benchmark_validation_with_timeout,
    benchmark_memory_usage_during_validation,
    benchmark_validation_under_load,
    benchmark_validation_result_serialization
);

criterion_main!(benches);
