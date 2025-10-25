"""Demonstration of r2pipe session management capabilities.

This script demonstrates the production-ready session pooling and management
system for radare2 integration in Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.radare2_session_helpers import (
    R2CommandBatch,
    execute_r2_command,
    get_pool_statistics,
    get_r2_session,
)
from intellicrack.core.analysis.radare2_session_manager import (
    R2SessionPool,
    R2SessionWrapper,
    r2_session_pooled,
    shutdown_global_pool,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def demo_basic_session():
    """Demonstrate basic session creation and usage."""
    print("\n" + "=" * 60)
    print("DEMO 1: Basic Session Creation and Usage")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    session = R2SessionWrapper(
        binary_path=binary_path,
        session_id="demo_session",
        auto_analyze=False
    )

    print(f"\n✓ Created session: {session.session_id}")
    print(f"  State: {session.state.value}")
    print(f"  Binary: {session.binary_path}")

    if session.connect():
        print("\n✓ Connected successfully")
        print(f"  State: {session.state.value}")

        version = session.execute("?V")
        print("\n✓ Executed command: ?V")
        print(f"  Result: {version.strip()}")

        info = session.execute("ij", expect_json=True)
        print("\n✓ Executed command: ij (JSON)")
        print(f"  Binary info: {info.get('core', {}).get('file', 'N/A')}")

        metrics = session.get_metrics()
        print("\n✓ Session metrics:")
        print(f"  Commands executed: {metrics['commands_executed']}")
        print(f"  Total execution time: {metrics['total_execution_time']:.3f}s")
        print(f"  Average execution time: {metrics['avg_execution_time']:.3f}s")

        session.disconnect()
        print("\n✓ Disconnected")
        print(f"  State: {session.state.value}")


def demo_session_pool():
    """Demonstrate session pooling."""
    print("\n" + "=" * 60)
    print("DEMO 2: Session Pool Management")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    pool = R2SessionPool(
        max_sessions=5,
        max_idle_time=60.0,
        auto_analyze=False
    )

    print("\n✓ Created session pool")
    print(f"  Max sessions: {pool.max_sessions}")

    print("\n→ Getting session from pool...")
    session1 = pool.get_session(binary_path)
    print(f"✓ Got session: {session1.session_id}")
    print(f"  State: {session1.state.value}")

    session1.execute("?V")
    print("✓ Executed command on session1")

    pool.return_session(session1)
    print("✓ Returned session1 to pool")

    print("\n→ Getting session from pool again...")
    session2 = pool.get_session(binary_path)
    print(f"✓ Got session: {session2.session_id}")

    if session1.session_id == session2.session_id:
        print("✓ Session reused! Same session ID")
    else:
        print("✗ Different session (unexpected)")

    pool.return_session(session2)

    stats = pool.get_pool_stats()
    print("\n✓ Pool statistics:")
    print(f"  Total sessions: {stats['total_sessions']}")
    print(f"  Active sessions: {stats['active_sessions']}")
    print(f"  Available sessions: {stats['available_sessions']}")
    print(f"  Total sessions created: {stats['total_sessions_created']}")
    print(f"  Total commands executed: {stats['total_commands_executed']}")

    pool.shutdown()
    print("\n✓ Pool shutdown complete")


def demo_context_managers():
    """Demonstrate context manager usage."""
    print("\n" + "=" * 60)
    print("DEMO 3: Context Manager Usage")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    print("\n→ Using r2_session_pooled context manager...")
    with r2_session_pooled(binary_path) as session:
        print(f"✓ Got session: {session.session_id}")
        result = session.execute("?V")
        print("✓ Executed command")
        print(f"  Result: {result.strip()}")

    print("✓ Session automatically returned to pool")

    print("\n→ Using get_r2_session helper...")
    with get_r2_session(binary_path, use_pooling=True, auto_analyze=False) as session:
        print(f"✓ Got session: {session.session_id}")
        info = session.execute("ij", expect_json=True)
        print("✓ Executed command")
        print(f"  Binary: {info.get('core', {}).get('file', 'N/A')}")

    print("✓ Session automatically returned to pool")

    stats = get_pool_statistics()
    print("\n✓ Global pool statistics:")
    print(f"  Total sessions: {stats['total_sessions']}")
    print(f"  Total commands executed: {stats['total_commands_executed']}")

    shutdown_global_pool()
    print("✓ Global pool shutdown")


def demo_batch_execution():
    """Demonstrate batch command execution."""
    print("\n" + "=" * 60)
    print("DEMO 4: Batch Command Execution")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    print("\n→ Creating command batch...")
    batch = R2CommandBatch(binary_path, use_pooling=True)

    batch.add_command("?V")
    batch.add_command("ij", expect_json=True)
    batch.add_command("iIj", expect_json=True)

    print("✓ Added 3 commands to batch")

    print("\n→ Executing all commands in single session...")
    start = time.time()
    results = batch.execute_all()
    elapsed = time.time() - start

    print(f"✓ Batch executed in {elapsed:.3f}s")
    print(f"  Results received: {len(results)}")

    for i, result in enumerate(results, 1):
        if isinstance(result, dict) and "error" in result:
            print(f"  Command {i}: Error - {result['error']}")
        elif isinstance(result, dict):
            print(f"  Command {i}: JSON result ({len(result)} keys)")
        elif isinstance(result, str):
            print(f"  Command {i}: String result ({len(result)} chars)")

    shutdown_global_pool()


def demo_helper_functions():
    """Demonstrate helper function usage."""
    print("\n" + "=" * 60)
    print("DEMO 5: Helper Functions")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    print("\n→ Using execute_r2_command helper...")
    result = execute_r2_command(binary_path, "?V", use_pooling=True)
    print("✓ Command executed")
    print(f"  Result: {result.strip()}")

    print("\n→ Executing JSON command...")
    info = execute_r2_command(binary_path, "ij", expect_json=True, use_pooling=True)
    print("✓ Command executed")
    print(f"  Binary: {info.get('core', {}).get('file', 'N/A')}")
    print(f"  Format: {info.get('bin', {}).get('bintype', 'N/A')}")
    print(f"  Arch: {info.get('bin', {}).get('arch', 'N/A')}")

    stats = get_pool_statistics()
    print("\n✓ Pool statistics:")
    print(f"  Total sessions: {stats['total_sessions']}")
    print(f"  Active sessions: {stats['active_sessions']}")
    print(f"  Total commands: {stats['total_commands_executed']}")

    shutdown_global_pool()


def demo_error_handling():
    """Demonstrate error handling and recovery."""
    print("\n" + "=" * 60)
    print("DEMO 6: Error Handling and Recovery")
    print("=" * 60)

    binary_path = "C:/Windows/System32/notepad.exe"

    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    pool = R2SessionPool(max_sessions=5, auto_analyze=False)

    with pool.session(binary_path) as session:
        print(f"\n✓ Got session: {session.session_id}")

        session.execute("?V")
        print("✓ Executed valid command")

        print("\n→ Executing invalid command...")
        try:
            session.execute("invalid_command_xyz_123")
        except Exception as e:
            print(f"✗ Command failed (expected): {type(e).__name__}")

        print("\n→ Executing valid command after error...")
        result = session.execute("?V")
        print("✓ Session still functional after error")
        print(f"  Result: {result.strip()}")

        metrics = session.get_metrics()
        print("\n✓ Session metrics:")
        print(f"  Commands executed: {metrics['commands_executed']}")
        print(f"  Errors: {metrics['errors_count']}")
        print(f"  Error rate: {metrics['errors_count'] / max(1, metrics['commands_executed']):.1%}")

    pool.shutdown()


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 60)
    print("R2PIPE SESSION MANAGEMENT DEMONSTRATION")
    print("=" * 60)

    demos = [
        demo_basic_session,
        demo_session_pool,
        demo_context_managers,
        demo_batch_execution,
        demo_helper_functions,
        demo_error_handling,
    ]

    for demo in demos:
        try:
            demo()
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
