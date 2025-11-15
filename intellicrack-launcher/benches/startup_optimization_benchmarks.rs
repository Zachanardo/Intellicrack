use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use intellicrack_launcher::{discover_and_cache_tools, optimize_process, run_preflight_checks};
use std::hint::black_box;
use std::time::Duration;

fn bench_process_optimization(c: &mut Criterion) {
    c.bench_function("process_optimization", |b| {
        b.iter(|| black_box(optimize_process().unwrap()));
    });
}

fn bench_process_optimization_detailed(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_optimization_detailed");

    group.bench_function("cold_start", |b| {
        b.iter(|| black_box(optimize_process().unwrap()));
    });

    group.bench_function("repeated_calls", |b| {
        let _ = optimize_process();
        b.iter(|| black_box(optimize_process().unwrap()));
    });

    group.finish();
}

fn bench_tool_discovery_cold(c: &mut Criterion) {
    c.bench_function("tool_discovery_cold", |b| {
        b.iter_batched(
            || {
                let cache_path = dirs::cache_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from(".cache"))
                    .join("intellicrack")
                    .join("tool_cache.json");
                let _ = std::fs::remove_file(&cache_path);
                ()
            },
            |_| black_box(discover_and_cache_tools().unwrap()),
            criterion::BatchSize::PerIteration,
        );
    });
}

fn bench_tool_discovery_warm(c: &mut Criterion) {
    let _ = discover_and_cache_tools();

    c.bench_function("tool_discovery_warm", |b| {
        b.iter(|| black_box(discover_and_cache_tools().unwrap()));
    });
}

fn bench_tool_discovery_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("tool_discovery_comparison");

    group.bench_function("warm_cached", |b| {
        let _ = discover_and_cache_tools();
        b.iter(|| black_box(discover_and_cache_tools().unwrap()));
    });

    group.finish();
}

fn bench_preflight_checks(c: &mut Criterion) {
    c.bench_function("preflight_checks", |b| {
        b.iter(|| {
            let _ = black_box(run_preflight_checks());
        });
    });
}

fn bench_preflight_checks_detailed(c: &mut Criterion) {
    let mut group = c.benchmark_group("preflight_checks_detailed");

    group.bench_function("first_run", |b| {
        b.iter(|| {
            let _ = black_box(run_preflight_checks());
        });
    });

    group.bench_function("repeated_runs", |b| {
        let _ = run_preflight_checks();
        b.iter(|| {
            let _ = black_box(run_preflight_checks());
        });
    });

    group.finish();
}

fn bench_full_startup_with_optimizations(c: &mut Criterion) {
    c.bench_function("full_startup_optimizations", |b| {
        b.iter(|| {
            black_box(optimize_process().unwrap());
            let _ = black_box(run_preflight_checks());
            black_box(discover_and_cache_tools().unwrap());
        });
    });
}

fn bench_full_startup_warm(c: &mut Criterion) {
    let _ = discover_and_cache_tools();

    c.bench_function("full_startup_warm", |b| {
        b.iter(|| {
            black_box(optimize_process().unwrap());
            let _ = black_box(run_preflight_checks());
            black_box(discover_and_cache_tools().unwrap());
        });
    });
}

fn bench_optimization_sequence_breakdown(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_sequence");

    group.bench_function("process_only", |b| {
        b.iter(|| black_box(optimize_process().unwrap()));
    });

    group.bench_function("preflight_only", |b| {
        b.iter(|| {
            let _ = black_box(run_preflight_checks());
        });
    });

    group.bench_function("tool_discovery_only_warm", |b| {
        let _ = discover_and_cache_tools();
        b.iter(|| black_box(discover_and_cache_tools().unwrap()));
    });

    group.bench_function("all_three_warm", |b| {
        let _ = discover_and_cache_tools();
        b.iter(|| {
            black_box(optimize_process().unwrap());
            let _ = black_box(run_preflight_checks());
            black_box(discover_and_cache_tools().unwrap());
        });
    });

    group.finish();
}

fn bench_concurrent_optimizations(c: &mut Criterion) {
    use std::thread;

    c.bench_function("concurrent_process_optimization", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| thread::spawn(|| optimize_process().unwrap()))
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

fn bench_optimization_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_overhead");

    group.bench_function("no_optimization", |b| {
        b.iter(|| black_box(()));
    });

    group.bench_function("with_optimizations", |b| {
        b.iter(|| {
            black_box(optimize_process().unwrap());
            let _ = black_box(run_preflight_checks());
            black_box(discover_and_cache_tools().unwrap());
        });
    });

    group.finish();
}

fn bench_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_performance");

    let _ = discover_and_cache_tools();

    for run_count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(run_count),
            run_count,
            |b, &count| {
                b.iter(|| {
                    for _ in 0..count {
                        black_box(discover_and_cache_tools().unwrap());
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_startup_time_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("startup_time_comparison");

    group.bench_function("baseline_minimal", |b| {
        b.iter(|| black_box(std::time::Instant::now()));
    });

    group.bench_function("with_process_opt", |b| {
        b.iter(|| black_box(optimize_process().unwrap()));
    });

    group.bench_function("with_preflight", |b| {
        b.iter(|| {
            let _ = black_box(run_preflight_checks());
        });
    });

    group.bench_function("with_tool_discovery", |b| {
        let _ = discover_and_cache_tools();
        b.iter(|| black_box(discover_and_cache_tools().unwrap()));
    });

    group.bench_function("complete_sequence", |b| {
        let _ = discover_and_cache_tools();
        b.iter(|| {
            black_box(optimize_process().unwrap());
            let _ = black_box(run_preflight_checks());
            black_box(discover_and_cache_tools().unwrap());
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        bench_process_optimization,
        bench_process_optimization_detailed,
        bench_tool_discovery_cold,
        bench_tool_discovery_warm,
        bench_tool_discovery_comparison,
        bench_preflight_checks,
        bench_preflight_checks_detailed,
        bench_full_startup_with_optimizations,
        bench_full_startup_warm,
        bench_optimization_sequence_breakdown,
        bench_concurrent_optimizations,
        bench_optimization_overhead,
        bench_cache_performance,
        bench_startup_time_comparison
}

criterion_main!(benches);
