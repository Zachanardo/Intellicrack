# Distributed Analysis Manager

## Overview

The **Distributed Analysis Manager** provides sophisticated capabilities for scaling binary analysis across multiple machines. It supports both local multi-processing and network-based clustering with task distribution, fault tolerance, and result aggregation for large-scale software protection testing.

## Features

### Core Capabilities

- **Cluster Management**
  - Automatic worker node registration and discovery
  - Real-time health monitoring with heartbeat protocol
  - Node capability detection and resource tracking
  - Graceful degradation to single-machine mode

- **Task Distribution**
  - Priority-based task scheduling (CRITICAL, HIGH, NORMAL, LOW, BACKGROUND)
  - Intelligent load balancing across worker nodes
  - Capability-aware task assignment
  - Dynamic workload distribution

- **Fault Tolerance**
  - Automatic task retry with configurable limits
  - Failed node detection and task reassignment
  - Timeout handling for stuck tasks
  - Robust error recovery mechanisms

- **Result Aggregation**
  - Centralized result collection from distributed workers
  - Real-time task status tracking
  - Comprehensive performance metrics
  - JSON export for analysis results

- **Execution Modes**
  - **Local Mode**: Multi-processing on single machine (no network)
  - **Cluster Mode**: Network-based distributed processing
  - **Auto Mode**: Automatic mode selection based on configuration

### Supported Analysis Tasks

The distributed manager supports the following task types:

1. **Pattern Search** - Find byte patterns in binaries (license strings, API calls)
2. **Entropy Analysis** - Detect packed/encrypted sections
3. **Section Analysis** - Analyze PE sections and characteristics
4. **String Extraction** - Extract ASCII/Unicode strings
5. **Import Analysis** - Analyze imported DLLs and functions
6. **Crypto Detection** - Detect cryptographic constants (AES, RSA, SHA, etc.)
7. **Frida Analysis** - Dynamic instrumentation tasks
8. **Radare2 Analysis** - Static analysis with radare2
9. **Angr Analysis** - Symbolic execution and CFG generation
10. **Generic Analysis** - Custom analysis tasks

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                  Coordinator Node                        │
│  ┌────────────────────────────────────────────────┐    │
│  │         Task Queue (Priority Heap)              │    │
│  │  - CRITICAL tasks                               │    │
│  │  - HIGH priority tasks                          │    │
│  │  - NORMAL tasks                                 │    │
│  │  - LOW priority tasks                           │    │
│  └────────────────────────────────────────────────┘    │
│                         │                               │
│         ┌───────────────┴───────────────┐              │
│         │      Task Scheduler            │              │
│         │  - Load balancing              │              │
│         │  - Capability matching         │              │
│         │  - Node selection              │              │
│         └───────────────┬───────────────┘              │
│                         │                               │
└─────────────────────────┼───────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │  Worker 1  │   │  Worker 2  │   │  Worker 3  │
    │ (Windows)  │   │  (Linux)   │   │ (Windows)  │
    │            │   │            │   │            │
    │ Capabilities│   │Capabilities│   │Capabilities│
    │ - Frida    │   │ - Radare2  │   │ - Angr     │
    │ - Pefile   │   │ - LIEF     │   │ - Pefile   │
    └────────────┘   └────────────┘   └────────────┘
```

### Communication Protocol

- **Protocol**: Binary message protocol over TCP sockets
- **Serialization**: Pickle for Python object transmission
- **Message Types**:
  - `register`: Worker registration with capabilities
  - `heartbeat`: Periodic health check (every 5 seconds)
  - `task_assigned`: Task assignment to worker
  - `task_result`: Successful task completion
  - `task_failed`: Task failure notification
  - `request_task`: Worker requesting next task

### Node Selection Algorithm

The coordinator selects the best node for each task based on:

1. **Load Factor** (40% weight) - Nodes with lower current load preferred
2. **Capability Match** (30% weight) - Nodes with required tools/libraries
3. **Platform Preference** (20% weight) - Windows nodes preferred for PE analysis
4. **Reliability** (10% weight) - Nodes with lower failure rates

Score calculation:
```python
score = (load_factor * 10.0) + (capability_match * 5.0) +
        (platform_bonus * 2.0) - (failure_rate * 3.0)
```

## Usage Examples

### Local Mode (Single Machine)

```python
from intellicrack.core.processing.distributed_manager import (
    create_distributed_manager,
    TaskPriority
)

# Create manager in local mode (no networking)
manager = create_distributed_manager(
    mode="local",
    config={"num_workers": 8},
    enable_networking=False
)

# Start the cluster
manager.start_cluster()

# Submit comprehensive binary analysis
task_ids = manager.submit_binary_analysis(
    binary_path="C:\\malware\\sample.exe",
    chunk_size=5 * 1024 * 1024,  # 5MB chunks
    priority=TaskPriority.HIGH
)

# Wait for completion
completion = manager.wait_for_completion(task_ids, timeout=300.0)

if completion["status"] == "completed":
    # Get results summary
    summary = manager.get_results_summary()
    print(f"Analyzed {summary['total_results']} results")

    # Export to JSON
    manager.export_results("analysis_results.json")

# Shutdown
manager.shutdown()
```

### Cluster Mode (Coordinator)

```python
from intellicrack.core.processing.distributed_manager import (
    create_distributed_manager
)

# Start coordinator on port 9876
manager = create_distributed_manager(
    mode="cluster",
    config={"port": 9876},
    enable_networking=True
)

manager.start_cluster(port=9876)

# Monitor cluster status
status = manager.get_cluster_status()
print(f"Cluster has {status['node_count']} workers")

# Keep coordinator running
# (Workers will connect and process tasks)
```

### Cluster Mode (Worker)

```python
from intellicrack.core.processing.distributed_manager import (
    create_distributed_manager
)

# Connect to coordinator
manager = create_distributed_manager(
    mode="cluster",
    config={
        "coordinator_host": "192.168.1.100",
        "coordinator_port": 9876,
        "num_workers": 4
    },
    enable_networking=True
)

manager.is_coordinator = False
manager.start_cluster()

# Worker will automatically process tasks from coordinator
```

### Submit Custom Tasks

```python
# Pattern search for license strings
task_id = manager.submit_task(
    task_type="pattern_search",
    binary_path="C:\\software\\protected.exe",
    params={
        "patterns": [b"license", b"serial", b"activation", b"registration"],
        "chunk_start": 0,
        "chunk_size": 10 * 1024 * 1024
    },
    priority=TaskPriority.CRITICAL,
    timeout=600.0
)

# Get result with timeout
result = manager.get_task_result(task_id, timeout=60.0)

if result and "matches" in result:
    for match in result["matches"]:
        print(f"Found '{match['pattern']}' at offset 0x{match['offset']:08x}")
```

### Entropy Analysis

```python
# Detect packed/encrypted sections
task_id = manager.submit_task(
    task_type="entropy_analysis",
    binary_path="C:\\malware\\packed.exe",
    params={
        "chunk_start": 0,
        "chunk_size": 5 * 1024 * 1024,
        "window_size": 1024
    },
    priority=TaskPriority.HIGH
)

result = manager.get_task_result(task_id, timeout=30.0)

if result:
    print(f"Overall entropy: {result['overall_entropy']:.4f}")
    print(f"High entropy regions: {result['high_entropy_regions']}")
```

### Cryptographic Detection

```python
# Detect crypto constants
task_id = manager.submit_task(
    task_type="crypto_detection",
    binary_path="C:\\malware\\sample.exe",
    params={
        "chunk_start": 0,
        "chunk_size": 10 * 1024 * 1024
    },
    priority=TaskPriority.NORMAL
)

result = manager.get_task_result(task_id, timeout=30.0)

if result and "detections" in result:
    print(f"Cryptographic algorithms detected:")
    for detection in result["detections"]:
        print(f"  {detection['algorithm']} at 0x{detection['offset']:08x}")
```

## Command-Line Interface

### Local Analysis

```bash
# Analyze binary using local multi-processing
python examples/distributed_analysis_local.py C:\malware\sample.exe

# Output:
# - Pattern matches
# - Entropy analysis
# - String extraction
# - Crypto detection
# - Import analysis
# - Section analysis
# - Results exported to sample.analysis.json
```

### Cluster Setup

```bash
# Terminal 1: Start coordinator
python examples/distributed_analysis_cluster.py coordinator --port 9876

# Terminal 2-N: Start workers
python examples/distributed_analysis_cluster.py worker --host localhost --port 9876

# Terminal N+1: Submit analysis job
python examples/distributed_analysis_cluster.py analyze C:\malware\sample.exe --host localhost --port 9876
```

## Configuration

### Local Mode Configuration

```python
config = {
    "num_workers": 8,              # Number of worker processes
    "chunk_size": 1024 * 1024,     # Default chunk size (1MB)
    "port": 9876                   # Port for local IPC
}
```

### Cluster Mode Configuration

```python
# Coordinator configuration
config = {
    "port": 9876,                  # Listening port
    "num_workers": 4,              # Local workers
    "max_nodes": 50                # Maximum worker nodes
}

# Worker configuration
config = {
    "coordinator_host": "192.168.1.100",  # Coordinator IP
    "coordinator_port": 9876,              # Coordinator port
    "num_workers": 8                       # Local processing capacity
}
```

## Performance Tuning

### Optimal Chunk Size

For different file sizes:

- **Small files (< 10 MB)**: Single task, no chunking
- **Medium files (10-100 MB)**: 5-10 MB chunks
- **Large files (100 MB - 1 GB)**: 10-50 MB chunks
- **Very large files (> 1 GB)**: 50-100 MB chunks

### Worker Count

- **CPU-bound tasks**: `num_workers = CPU_count`
- **I/O-bound tasks**: `num_workers = CPU_count * 2`
- **Mixed workload**: `num_workers = CPU_count * 1.5`

### Task Priority Guidelines

- **CRITICAL**: License validation bypass, critical protection detection
- **HIGH**: Main analysis tasks, complete binary scans
- **NORMAL**: Standard analysis, string extraction, entropy
- **LOW**: Supplementary analysis, metadata extraction
- **BACKGROUND**: Logging, statistics, optional tasks

## Monitoring and Debugging

### Cluster Status

```python
status = manager.get_cluster_status()

print(f"Mode: {status['mode']}")
print(f"Nodes: {status['node_count']}")
print(f"Tasks pending: {status['tasks']['pending']}")
print(f"Tasks running: {status['tasks']['running']}")
print(f"Tasks completed: {status['tasks']['completed']}")

for node_id, node in status['nodes'].items():
    print(f"\nNode {node_id}:")
    print(f"  Host: {node['hostname']}")
    print(f"  Status: {node['status']}")
    print(f"  Load: {node['current_load']}/{node['max_load']}")
    print(f"  Capabilities: {node['capabilities']}")
```

### Task Status Tracking

```python
# Check individual task
task_status = manager.get_task_status(task_id)
print(f"Status: {task_status['status']}")
print(f"Assigned to: {task_status['assigned_node']}")
print(f"Retry count: {task_status['retry_count']}")

# Wait for specific tasks
completion = manager.wait_for_completion(
    task_ids=[task1, task2, task3],
    timeout=120.0
)
```

### Performance Metrics

```python
status = manager.get_cluster_status()
metrics = status['performance']

print(f"Tasks submitted: {metrics['tasks_submitted']}")
print(f"Tasks completed: {metrics['tasks_completed']}")
print(f"Tasks failed: {metrics['tasks_failed']}")
print(f"Total processing time: {metrics['total_processing_time']:.2f}s")
print(f"Average task time: {metrics['average_task_time']:.2f}s")
print(f"Task distribution: {metrics['task_distribution']}")
```

## Fault Tolerance

### Automatic Retry

Tasks automatically retry on failure:

- **Default**: 3 retry attempts
- **Configurable**: Set `max_retries` per task
- **Exponential backoff**: Increasing delay between retries
- **Node reassignment**: Failed tasks assigned to different nodes

```python
task_id = manager.submit_task(
    task_type="angr_analysis",
    binary_path="difficult.exe",
    params={},
    priority=TaskPriority.HIGH
)

# Task will retry up to 3 times on failure
```

### Node Failure Handling

When a node fails:

1. Node marked as **OFFLINE** after missing heartbeats (30s timeout)
2. All tasks on failed node marked for **RETRY**
3. Tasks automatically reassigned to available nodes
4. Coordinator maintains cluster operation

### Graceful Degradation

- **Network failure**: Falls back to local processing
- **Partial cluster**: Continues with available nodes
- **Resource exhaustion**: Queues tasks until capacity available

## Security Considerations

### Network Security

- **Trusted networks only**: Use on isolated research networks
- **Firewall rules**: Restrict coordinator port access
- **No encryption**: Current version uses unencrypted sockets
- **Authentication**: No authentication in current version

**Recommended deployment:**
- Isolated lab network
- VPN for remote workers
- Firewall rules limiting coordinator access

### Resource Limits

Prevent resource exhaustion:

```python
config = {
    "max_tasks_per_node": 10,      # Limit concurrent tasks
    "max_queue_size": 1000,        # Limit pending tasks
    "task_timeout": 3600.0,        # Maximum task runtime
    "max_retries": 3               # Limit retry attempts
}
```

## Troubleshooting

### Common Issues

**Workers not connecting:**
- Check firewall rules for coordinator port
- Verify coordinator IP/hostname
- Ensure coordinator started before workers

**Tasks timing out:**
- Increase `timeout` parameter
- Check binary file accessibility
- Verify worker has required capabilities

**High failure rate:**
- Check binary format compatibility
- Verify required libraries installed
- Review error messages in task results

**Performance issues:**
- Reduce chunk size for better parallelization
- Increase worker count
- Check network bandwidth for cluster mode

### Logging

Enable detailed logging:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Detailed logs for:
# - Task scheduling
# - Node communication
# - Error conditions
# - Performance metrics
```

## Windows-Specific Notes

### Path Handling

Always use proper Windows paths:

```python
binary_path = r"C:\malware\sample.exe"
# or
binary_path = "C:\\malware\\sample.exe"
# or
from pathlib import Path
binary_path = Path("C:/malware/sample.exe")
```

### Firewall Configuration

Windows Firewall may block network clustering:

```powershell
# Allow Python through firewall
New-NetFirewallRule -DisplayName "Python Distributed Analysis" `
    -Direction Inbound -Program "C:\Python\python.exe" `
    -Action Allow -Protocol TCP -LocalPort 9876
```

### Performance Optimization

On Windows:
- Use SSD for binary storage
- Disable real-time antivirus scanning on analysis directories
- Increase process priority for coordinator

```python
import psutil
import os

# Increase process priority
p = psutil.Process(os.getpid())
p.nice(psutil.HIGH_PRIORITY_CLASS)
```

## API Reference

### DistributedAnalysisManager

Main class for distributed analysis management.

**Methods:**

- `start_cluster(port)` - Start cluster coordinator or worker
- `submit_task(task_type, binary_path, params, priority, timeout)` - Submit single task
- `submit_binary_analysis(binary_path, chunk_size, priority)` - Submit complete analysis
- `get_task_status(task_id)` - Get task status
- `get_task_result(task_id, timeout)` - Get task result
- `wait_for_completion(task_ids, timeout)` - Wait for tasks
- `get_cluster_status()` - Get cluster status
- `get_results_summary()` - Get results summary
- `export_results(output_path)` - Export results to JSON
- `shutdown()` - Shutdown manager

### Task Types

- `pattern_search` - Search for byte patterns
- `entropy_analysis` - Analyze entropy distribution
- `section_analysis` - Analyze PE sections
- `string_extraction` - Extract strings
- `import_analysis` - Analyze imports
- `crypto_detection` - Detect crypto constants
- `frida_analysis` - Frida dynamic analysis
- `radare2_analysis` - Radare2 static analysis
- `angr_analysis` - Angr symbolic execution
- `generic_analysis` - Custom analysis

### Priority Levels

- `TaskPriority.CRITICAL` - Highest priority
- `TaskPriority.HIGH` - High priority
- `TaskPriority.NORMAL` - Normal priority (default)
- `TaskPriority.LOW` - Low priority
- `TaskPriority.BACKGROUND` - Background tasks

## Integration with Existing Components

### ParallelProcessingManager

Distributed manager uses `ParallelProcessingManager` for local multi-processing:

```python
# Automatically used in local mode
manager = create_distributed_manager(mode="local")
# Internally uses ParallelProcessingManager
```

### Binary Analyzer

Integrate with binary analyzer for comprehensive analysis:

```python
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer

analyzer = BinaryAnalyzer()
manager = create_distributed_manager(mode="local")
manager.start_cluster()

# Submit tasks based on binary type
binary_info = analyzer.analyze(binary_path)
if binary_info.get("format") == "PE":
    # PE-specific analysis tasks
    manager.submit_task("import_analysis", binary_path, {})
    manager.submit_task("section_analysis", binary_path, {})
```

## Future Enhancements

Planned features:

- **Authentication and encryption** for network communication
- **Web-based monitoring dashboard** for cluster visualization
- **Docker container support** for easy worker deployment
- **Kubernetes orchestration** for cloud-scale clusters
- **Result caching** to avoid redundant analysis
- **Task dependencies** for complex analysis workflows
- **Real-time progress streaming** for long-running tasks
- **GPU acceleration support** for crypto analysis

## License

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Licensed under GNU General Public License v3.0
