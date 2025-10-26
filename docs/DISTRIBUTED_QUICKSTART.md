# Distributed Analysis Quick Start Guide

## 5-Minute Quick Start

### Local Mode (Single Machine)

Analyze a binary using all your CPU cores:

```python
from intellicrack.core.processing import create_distributed_manager, TaskPriority

# Create and start manager
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

# Analyze binary
task_ids = manager.submit_binary_analysis("C:\\sample.exe", priority=TaskPriority.HIGH)

# Wait and get results
manager.wait_for_completion(task_ids, timeout=300.0)
summary = manager.get_results_summary()

print(f"Analysis complete: {summary['total_results']} results")

# Export and cleanup
manager.export_results("results.json")
manager.shutdown()
```

## Common Tasks

### Find License Strings

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

task_id = manager.submit_task(
    task_type="pattern_search",
    binary_path="C:\\software\\protected.exe",
    params={
        "patterns": [b"license", b"serial", b"activation", b"trial"],
        "chunk_start": 0,
        "chunk_size": 10 * 1024 * 1024
    },
    priority=TaskPriority.CRITICAL
)

result = manager.get_task_result(task_id, timeout=60.0)

for match in result.get("matches", []):
    print(f"Found: {match['pattern']} at 0x{match['offset']:08x}")

manager.shutdown()
```

### Detect Packed Sections

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

task_id = manager.submit_task(
    task_type="entropy_analysis",
    binary_path="C:\\malware\\packed.exe",
    params={"chunk_start": 0, "chunk_size": 5 * 1024 * 1024},
    priority=TaskPriority.HIGH
)

result = manager.get_task_result(task_id, timeout=30.0)

if result['overall_entropy'] > 7.0:
    print("WARNING: High entropy detected - likely packed/encrypted")
    print(f"High entropy regions: {result['high_entropy_regions']}")

manager.shutdown()
```

### Extract All Strings

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

task_id = manager.submit_task(
    task_type="string_extraction",
    binary_path="C:\\sample.exe",
    params={"chunk_start": 0, "chunk_size": 10 * 1024 * 1024, "min_length": 4},
    priority=TaskPriority.NORMAL
)

result = manager.get_task_result(task_id, timeout=60.0)

print(f"Extracted {result['total_strings']} strings")
for s in result['strings'][:20]:  # First 20 strings
    print(f"  {s['string']}")

manager.shutdown()
```

### Analyze Imports

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

task_id = manager.submit_task(
    task_type="import_analysis",
    binary_path="C:\\sample.exe",
    params={},
    priority=TaskPriority.NORMAL
)

result = manager.get_task_result(task_id, timeout=30.0)

print(f"Imported DLLs: {result['dll_count']}")
for imp in result['imports']:
    print(f"\n{imp['dll']}:")
    for func in imp['functions'][:10]:  # First 10 functions
        print(f"  - {func['name']}")

manager.shutdown()
```

### Detect Cryptography

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

task_id = manager.submit_task(
    task_type="crypto_detection",
    binary_path="C:\\sample.exe",
    params={"chunk_start": 0, "chunk_size": 10 * 1024 * 1024},
    priority=TaskPriority.HIGH
)

result = manager.get_task_result(task_id, timeout=30.0)

if result['algorithms_found'] > 0:
    print("Cryptographic algorithms detected:")
    for detection in result['detections']:
        print(f"  {detection['algorithm']} at 0x{detection['offset']:08x}")

manager.shutdown()
```

## Cluster Mode Setup

For cluster mode, you can implement a coordinator and worker system using the `DistributedManager` API:

```python
# Coordinator setup
from intellicrack.core.processing import create_distributed_manager

coordinator = create_distributed_manager(mode="cluster", enable_networking=True)
coordinator.start_cluster(port=9876)

# Worker setup (on same or different machine)
worker = create_distributed_manager(mode="worker", enable_networking=True)
worker.connect_to_coordinator(host="coordinator_ip", port=9876)
```

## Performance Tips

### Optimal Configuration

```python
import multiprocessing

config = {
    "num_workers": multiprocessing.cpu_count(),  # Use all cores
    "chunk_size": 5 * 1024 * 1024  # 5MB chunks for good parallelization
}

manager = create_distributed_manager(mode="local", config=config, enable_networking=False)
```

### Large Files

For files > 100 MB:

```python
# Increase chunk size
task_ids = manager.submit_binary_analysis(
    binary_path="large_file.exe",
    chunk_size=50 * 1024 * 1024,  # 50MB chunks
    priority=TaskPriority.HIGH
)
```

### Priority Usage

```python
# Critical: License cracking tasks
critical_task = manager.submit_task(
    "pattern_search",
    binary_path,
    {"patterns": [b"license"]},
    priority=TaskPriority.CRITICAL
)

# Normal: General analysis
normal_task = manager.submit_task(
    "entropy_analysis",
    binary_path,
    {},
    priority=TaskPriority.NORMAL
)

# Low: Optional analysis
low_task = manager.submit_task(
    "string_extraction",
    binary_path,
    {},
    priority=TaskPriority.LOW
)
```

## Monitoring

### Real-time Status

```python
import time

manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

# Submit tasks
task_ids = manager.submit_binary_analysis("sample.exe")

# Monitor progress
while True:
    status = manager.get_cluster_status()

    pending = status['tasks']['pending']
    running = status['tasks']['running']
    completed = status['tasks']['completed']
    total = status['tasks']['total']

    if pending + running == 0:
        break

    print(f"Progress: {completed}/{total} ({completed/total*100:.1f}%)")
    time.sleep(2.0)

print("Analysis complete!")
manager.shutdown()
```

### Check Individual Task

```python
task_id = manager.submit_task("entropy_analysis", binary_path, {})

# Poll task status
while True:
    status = manager.get_task_status(task_id)

    if status['status'] == 'completed':
        result = manager.get_task_result(task_id)
        print(f"Result: {result}")
        break
    elif status['status'] == 'failed':
        print(f"Failed: {status['error']}")
        break

    print(f"Status: {status['status']}")
    time.sleep(1.0)
```

## Error Handling

### Robust Analysis

```python
manager = create_distributed_manager(mode="local", enable_networking=False)
manager.start_cluster()

try:
    task_ids = manager.submit_binary_analysis("sample.exe")

    completion = manager.wait_for_completion(task_ids, timeout=300.0)

    if completion['status'] == 'completed':
        summary = manager.get_results_summary()
        print(f"Success: {summary['total_results']} results")

        manager.export_results("results.json")
    else:
        print(f"Timeout: {completion['remaining_tasks']} tasks incomplete")

except FileNotFoundError as e:
    print(f"Binary not found: {e}")
except Exception as e:
    print(f"Analysis failed: {e}")
finally:
    manager.shutdown()
```

### Retry Failed Tasks

```python
# Tasks automatically retry up to 3 times
task_id = manager.submit_task(
    "angr_analysis",
    binary_path,
    {},
    priority=TaskPriority.HIGH
)

result = manager.get_task_result(task_id, timeout=120.0)

if result and "error" in result:
    print(f"Task failed after retries: {result['error']}")
else:
    print("Task succeeded")
```

## Complete Example

### Comprehensive Binary Analysis

```python
from intellicrack.core.processing import create_distributed_manager, TaskPriority
import json

def analyze_binary_comprehensive(binary_path: str):
    """Perform comprehensive distributed analysis of a binary."""

    # Create manager
    manager = create_distributed_manager(
        mode="local",
        config={"num_workers": 8},
        enable_networking=False
    )

    try:
        # Start cluster
        manager.start_cluster()
        print(f"Cluster started with {manager.get_cluster_status()['node_count']} nodes")

        # Submit all analysis tasks
        print("Submitting analysis tasks...")
        task_ids = manager.submit_binary_analysis(
            binary_path=binary_path,
            chunk_size=5 * 1024 * 1024,
            priority=TaskPriority.HIGH
        )

        # Add critical pattern search
        license_task = manager.submit_task(
            task_type="pattern_search",
            binary_path=binary_path,
            params={
                "patterns": [
                    b"license", b"serial", b"activation",
                    b"registration", b"trial", b"demo"
                ],
                "chunk_start": 0,
                "chunk_size": 50 * 1024 * 1024
            },
            priority=TaskPriority.CRITICAL
        )
        task_ids.append(license_task)

        print(f"Submitted {len(task_ids)} tasks")

        # Wait for completion
        print("Waiting for analysis to complete...")
        completion = manager.wait_for_completion(task_ids, timeout=600.0)

        if completion['status'] == 'completed':
            print(f"Analysis completed in {completion['total_time']:.2f} seconds")

            # Get results
            summary = manager.get_results_summary()
            print(f"\nResults Summary:")
            print(f"  Total results: {summary['total_results']}")
            print(f"  Task types: {', '.join(summary['task_types'])}")

            # Export results
            output_file = f"{binary_path}.analysis.json"
            if manager.export_results(output_file):
                print(f"\nDetailed results exported to: {output_file}")

                # Load and display key findings
                with open(output_file, 'r') as f:
                    data = json.load(f)

                print("\nKey Findings:")

                # License strings
                for task_id, result in data['completed_results'].items():
                    if result.get('task_type') == 'pattern_search':
                        if result.get('matches'):
                            print("\n[!] License-related strings found:")
                            for match in result['matches'][:10]:
                                print(f"    - '{match['pattern']}' at 0x{match['offset']:08x}")

                    # High entropy regions
                    elif result.get('task_type') == 'entropy_analysis':
                        if result.get('overall_entropy', 0) > 7.0:
                            print(f"\n[!] High entropy detected: {result['overall_entropy']:.4f}")
                            print(f"    Potential packing/encryption")

                    # Crypto detection
                    elif result.get('task_type') == 'crypto_detection':
                        if result.get('detections'):
                            print("\n[!] Cryptographic algorithms detected:")
                            for det in result['detections'][:5]:
                                print(f"    - {det['algorithm']} at 0x{det['offset']:08x}")

                print("\nAnalysis complete!")
                return True
        else:
            print(f"Analysis timed out")
            return False

    except Exception as e:
        print(f"Error during analysis: {e}")
        return False
    finally:
        manager.shutdown()

# Run analysis
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python script.py <binary_path>")
        sys.exit(1)

    analyze_binary_comprehensive(sys.argv[1])
```

## Next Steps

1. **Review full documentation**: See `DISTRIBUTED_ANALYSIS.md` for complete details
2. **Run tests**: Execute integration tests with `pytest tests/integration/test_distributed_manager.py`
3. **Configure cluster**: Set up multi-machine cluster for large-scale analysis
4. **Integrate with tools**: Combine with Frida, radare2, angr for advanced analysis

## Troubleshooting

**Problem**: Tasks not executing

**Solution**: Check cluster status and logs
```python
status = manager.get_cluster_status()
print(f"Running: {status['running']}")
print(f"Nodes: {status['node_count']}")
```

**Problem**: Slow performance

**Solution**: Increase workers or chunk size
```python
config = {
    "num_workers": 16,  # More workers
    "chunk_size": 10 * 1024 * 1024  # Larger chunks
}
```

**Problem**: Out of memory

**Solution**: Reduce chunk size
```python
task_ids = manager.submit_binary_analysis(
    binary_path,
    chunk_size=1 * 1024 * 1024  # Smaller 1MB chunks
)
```

## Support

For issues or questions:
- Review documentation in `docs/DISTRIBUTED_ANALYSIS.md`
- Run tests to verify installation
- Review logs for error messages
