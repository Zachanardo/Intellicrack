# Radare2 Session Manager

Production-ready r2pipe session pooling and lifecycle management for Intellicrack.

## Overview

The Radare2 Session Manager provides efficient, thread-safe session pooling for r2pipe connections, enabling:

- **Session Pooling**: Reuse r2pipe sessions across operations for better performance
- **Thread Safety**: Safe concurrent access to radare2 from multiple threads
- **Automatic Lifecycle Management**: Sessions are automatically created, reused, and cleaned up
- **Connection Resilience**: Automatic reconnection and error recovery
- **Performance Monitoring**: Comprehensive metrics tracking for all sessions

## Architecture

### Components

1. **R2SessionWrapper**: Thread-safe wrapper around a single r2pipe session
   - Manages connection lifecycle (connect, disconnect, reconnect)
   - Tracks metrics (commands executed, execution time, errors)
   - Provides health checking and state management

2. **R2SessionPool**: Session pool with automatic management
   - Maintains a pool of reusable sessions
   - Enforces session limits
   - Background cleanup of idle sessions
   - Thread-safe session acquisition and release

3. **Session Helpers**: Convenience functions for easy integration
   - `get_r2_session()`: Context manager for pooled sessions
   - `execute_r2_command()`: Execute single commands
   - `R2CommandBatch`: Batch multiple commands efficiently

## Usage

### Basic Usage with Context Manager

```python
from intellicrack.core.analysis.radare2_session_manager import r2_session_pooled

# Use pooled session with automatic cleanup
with r2_session_pooled("path/to/binary.exe") as session:
    # Execute commands
    version = session.execute("?V")

    # Get binary info as JSON
    info = session.execute("ij", expect_json=True)

    # Get functions
    functions = session.execute("aflj", expect_json=True)
```

### Using Session Helpers

```python
from intellicrack.core.analysis.radare2_session_helpers import (
    get_r2_session,
    execute_r2_command,
    R2CommandBatch
)

# Simple command execution
result = execute_r2_command("binary.exe", "ij", expect_json=True)

# Batch multiple commands
batch = R2CommandBatch("binary.exe")
batch.add_command("?V")
batch.add_command("ij", expect_json=True)
batch.add_command("aflj", expect_json=True)

results = batch.execute_all()
```

### Integration with Existing Code

The session manager seamlessly integrates with existing radare2_utils:

```python
from intellicrack.utils.tools.radare2_utils import r2_session

# Automatically uses pooling if available
with r2_session("binary.exe") as r2:
    functions = r2.get_functions()
    strings = r2.get_strings()
    imports = r2.get_imports()
```

### Advanced Pool Configuration

```python
from intellicrack.core.analysis.radare2_session_manager import R2SessionPool

# Create custom pool
pool = R2SessionPool(
    max_sessions=20,           # Maximum concurrent sessions
    max_idle_time=600.0,       # Idle timeout (seconds)
    session_timeout=60.0,      # Command timeout (seconds)
    auto_analyze=True,         # Auto-run analysis on connect
    analysis_level="aaa",      # Analysis level (a, aa, aaa, aaaa)
    cleanup_interval=120.0     # Cleanup thread interval
)

# Use the pool
with pool.session("binary.exe") as session:
    result = session.execute("aflj", expect_json=True)

# Get pool statistics
stats = pool.get_pool_stats()
print(f"Active sessions: {stats['active_sessions']}")
print(f"Total commands: {stats['total_commands_executed']}")

# Shutdown when done
pool.shutdown()
```

### Global Pool Usage

```python
from intellicrack.core.analysis.radare2_session_manager import (
    get_global_pool,
    shutdown_global_pool
)
from intellicrack.core.analysis.radare2_session_helpers import (
    configure_global_pool,
    get_pool_statistics
)

# Configure global pool
configure_global_pool(
    max_sessions=15,
    max_idle_time=300.0,
    analysis_level="aaa"
)

# Sessions automatically use global pool
with r2_session_pooled("binary.exe") as session:
    session.execute("aaa")

# Get statistics
stats = get_pool_statistics()

# Clean up on shutdown
shutdown_global_pool()
```

## Session States

Sessions transition through the following states:

- **IDLE**: Session created but not connected
- **ACTIVE**: Connected and ready for commands
- **RECONNECTING**: Attempting to reconnect after failure
- **CLOSED**: Session closed
- **ERROR**: Session in error state

## Metrics and Monitoring

### Session Metrics

Each session tracks comprehensive metrics:

```python
with r2_session_pooled("binary.exe") as session:
    session.execute("aflj", expect_json=True)

    metrics = session.get_metrics()
    print(f"Commands executed: {metrics['commands_executed']}")
    print(f"Average execution time: {metrics['avg_execution_time']}")
    print(f"Errors: {metrics['errors_count']}")
    print(f"Reconnections: {metrics['reconnections']}")
    print(f"Idle time: {metrics['idle_time']}")
```

### Pool Statistics

```python
from intellicrack.core.analysis.radare2_session_helpers import (
    get_pool_statistics,
    get_all_session_metrics
)

# Get pool-level statistics
pool_stats = get_pool_statistics()
print(f"Total sessions: {pool_stats['total_sessions']}")
print(f"Active sessions: {pool_stats['active_sessions']}")
print(f"Error rate: {pool_stats['error_rate']:.2%}")

# Get per-session metrics
all_metrics = get_all_session_metrics()
for metrics in all_metrics:
    print(f"Session {metrics['session_id']}: {metrics['commands_executed']} commands")
```

## Thread Safety

The session manager is fully thread-safe:

```python
import threading
from intellicrack.core.analysis.radare2_session_manager import r2_session_pooled

def worker(binary_path, worker_id):
    with r2_session_pooled(binary_path) as session:
        functions = session.execute("aflj", expect_json=True)
        print(f"Worker {worker_id} found {len(functions)} functions")

# Safe concurrent usage
threads = []
for i in range(10):
    t = threading.Thread(target=worker, args=("binary.exe", i))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

## Error Handling

The session manager provides robust error handling:

```python
from intellicrack.core.analysis.radare2_session_manager import r2_session_pooled

try:
    with r2_session_pooled("binary.exe") as session:
        # Execute commands
        result = session.execute("aflj", expect_json=True)

except RuntimeError as e:
    print(f"Session error: {e}")
    # Session automatically cleaned up

except Exception as e:
    print(f"Command error: {e}")
    # Session returns to pool for reuse
```

### Automatic Reconnection

Sessions automatically attempt reconnection on failure:

```python
with r2_session_pooled("binary.exe") as session:
    # If session dies, it will attempt reconnection
    session.execute("aflj", expect_json=True)

    # Check health
    if not session.is_alive():
        session.reconnect()
```

## Migration Guide

### From Direct r2pipe Usage

**Before:**
```python
import r2pipe

r2 = r2pipe.open("binary.exe")
r2.cmd("aaa")
functions = r2.cmdj("aflj")
r2.quit()
```

**After:**
```python
from intellicrack.core.analysis.radare2_session_manager import r2_session_pooled

with r2_session_pooled("binary.exe") as session:
    session.execute("aaa")
    functions = session.execute("aflj", expect_json=True)
# Automatic cleanup
```

### From radare2_utils.R2Session

**Before:**
```python
from intellicrack.utils.tools.radare2_utils import r2_session

with r2_session("binary.exe", use_pooling=False) as r2:
    functions = r2.get_functions()
```

**After:**
```python
from intellicrack.utils.tools.radare2_utils import r2_session

# Now automatically uses pooling
with r2_session("binary.exe") as r2:
    functions = r2.get_functions()
```

## Performance Optimization

### Session Reuse

Sessions are automatically reused for the same binary:

```python
# First call creates session
with r2_session_pooled("binary.exe") as session:
    session.execute("aflj", expect_json=True)

# Second call reuses existing session (much faster)
with r2_session_pooled("binary.exe") as session:
    session.execute("izzj", expect_json=True)
```

### Batch Commands

Use `R2CommandBatch` for multiple commands:

```python
from intellicrack.core.analysis.radare2_session_helpers import R2CommandBatch

batch = R2CommandBatch("binary.exe")
batch.add_command("aflj", expect_json=True)
batch.add_command("izzj", expect_json=True)
batch.add_command("iij", expect_json=True)

# Executes all in single session
results = batch.execute_all()
```

### Cleanup Management

```python
from intellicrack.core.analysis.radare2_session_helpers import cleanup_idle_sessions

# Force cleanup of idle sessions to free resources
cleanup_idle_sessions()
```

## Configuration Options

### Session Wrapper Options

- `binary_path`: Path to binary file
- `session_id`: Unique session identifier
- `flags`: r2pipe flags (default: `["-2"]`)
- `timeout`: Command timeout in seconds (default: 30.0)
- `auto_analyze`: Auto-run analysis on connect (default: True)
- `analysis_level`: Analysis level: a, aa, aaa, aaaa (default: "aaa")

### Pool Options

- `max_sessions`: Maximum concurrent sessions (default: 10)
- `max_idle_time`: Idle timeout in seconds (default: 300.0)
- `session_timeout`: Command timeout in seconds (default: 30.0)
- `auto_analyze`: Auto-analyze on connect (default: True)
- `analysis_level`: Default analysis level (default: "aaa")
- `cleanup_interval`: Cleanup thread interval (default: 60.0)

## Best Practices

1. **Use Context Managers**: Always use `with` statements for automatic cleanup
2. **Leverage Pooling**: Let the pool manage session lifecycle
3. **Batch Commands**: Group related commands for efficiency
4. **Monitor Metrics**: Track performance with session metrics
5. **Configure Appropriately**: Set pool limits based on your workload
6. **Handle Errors**: Use try/except for robust error handling
7. **Shutdown Gracefully**: Call `shutdown_global_pool()` on exit

## Troubleshooting

### Session Limit Reached

```python
# Increase pool size
from intellicrack.core.analysis.radare2_session_helpers import configure_global_pool

configure_global_pool(max_sessions=20)
```

### Idle Sessions Not Cleaned

```python
# Reduce idle timeout
configure_global_pool(max_idle_time=60.0)

# Or force cleanup
from intellicrack.core.analysis.radare2_session_helpers import cleanup_idle_sessions
cleanup_idle_sessions()
```

### Session Not Responding

```python
# Check session health
with r2_session_pooled("binary.exe") as session:
    if not session.is_alive():
        session.reconnect()
```

## API Reference

See inline documentation in:
- `intellicrack/core/analysis/radare2_session_manager.py`
- `intellicrack/core/analysis/radare2_session_helpers.py`
- `intellicrack/utils/tools/radare2_utils.py`

## Examples

See `tests/integration/test_radare2_session_manager.py` for comprehensive usage examples.
