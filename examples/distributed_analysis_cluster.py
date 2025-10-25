"""Example: Network-based distributed cluster analysis.

This example demonstrates using the distributed analysis manager in cluster mode
for coordinating binary analysis across multiple networked machines.
"""

import argparse
import logging
import sys
from pathlib import Path

from intellicrack.core.processing.distributed_manager import (
    TaskPriority,
    create_distributed_manager,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


def start_coordinator(port: int = 9876):
    """Start cluster coordinator node.

    Args:
        port: Port number for cluster communication

    """
    logger.info("Starting cluster coordinator...")

    config = {
        "num_workers": 4,
        "port": port
    }

    manager = create_distributed_manager(
        mode="cluster",
        config=config,
        enable_networking=True
    )

    try:
        if not manager.start_cluster(port=port):
            logger.error("Failed to start coordinator")
            return

        logger.info(f"Coordinator started on port {port}")
        logger.info("Waiting for worker nodes to connect...")

        input("\nPress Enter to view cluster status or Ctrl+C to shutdown...\n")

        while True:
            status = manager.get_cluster_status()
            logger.info("\nCluster Status:")
            logger.info(f"  Nodes: {status['node_count']}")
            logger.info(f"  Tasks pending: {status['tasks']['pending']}")
            logger.info(f"  Tasks running: {status['tasks']['running']}")
            logger.info(f"  Tasks completed: {status['tasks']['completed']}")
            logger.info(f"  Tasks failed: {status['tasks']['failed']}")

            for node_id, node_info in status['nodes'].items():
                logger.info(f"\n  Node {node_id}:")
                logger.info(f"    Hostname: {node_info['hostname']}")
                logger.info(f"    Status: {node_info['status']}")
                logger.info(f"    Load: {node_info['current_load']}/{node_info['max_load']}")
                logger.info(f"    Active tasks: {node_info['active_tasks']}")
                logger.info(f"    Completed: {node_info['completed_tasks']}")

            input("\nPress Enter to refresh or Ctrl+C to shutdown...\n")

    except KeyboardInterrupt:
        logger.info("\nShutdown requested")
    finally:
        manager.shutdown()
        logger.info("Coordinator shutdown complete")


def start_worker(coordinator_host: str, coordinator_port: int = 9876):
    """Start cluster worker node.

    Args:
        coordinator_host: Hostname/IP of coordinator
        coordinator_port: Port of coordinator

    """
    logger.info(f"Starting worker node connecting to {coordinator_host}:{coordinator_port}")

    config = {
        "num_workers": 8,
        "coordinator_host": coordinator_host,
        "coordinator_port": coordinator_port
    }

    manager = create_distributed_manager(
        mode="cluster",
        config=config,
        enable_networking=True
    )

    manager.is_coordinator = False

    try:
        if not manager.start_cluster():
            logger.error("Failed to start worker")
            return

        logger.info("Worker connected to coordinator")
        logger.info("Ready to process tasks...")

        input("\nPress Enter to view status or Ctrl+C to shutdown...\n")

        while True:
            status = manager.get_cluster_status()
            logger.info("\nWorker Status:")
            logger.info(f"  Node ID: {status['node_id']}")
            logger.info(f"  Active tasks: {status['tasks']['running']}")
            logger.info(f"  Completed tasks: {status['tasks']['completed']}")

            input("\nPress Enter to refresh or Ctrl+C to shutdown...\n")

    except KeyboardInterrupt:
        logger.info("\nShutdown requested")
    finally:
        manager.shutdown()
        logger.info("Worker shutdown complete")


def analyze_with_cluster(binary_path: str, coordinator_host: str = "localhost", coordinator_port: int = 9876):
    """Submit analysis job to cluster.

    Args:
        binary_path: Path to binary to analyze
        coordinator_host: Hostname/IP of coordinator
        coordinator_port: Port of coordinator

    """
    logger.info(f"Submitting analysis of {binary_path} to cluster")

    config = {
        "num_workers": 1,
        "coordinator_host": coordinator_host,
        "coordinator_port": coordinator_port
    }

    manager = create_distributed_manager(
        mode="cluster",
        config=config,
        enable_networking=True
    )

    manager.is_coordinator = False

    try:
        if not manager.start_cluster():
            logger.error("Failed to connect to cluster")
            return

        logger.info("Connected to cluster coordinator")

        logger.info("Submitting analysis tasks...")
        task_ids = manager.submit_binary_analysis(
            binary_path=binary_path,
            chunk_size=10 * 1024 * 1024,
            priority=TaskPriority.HIGH
        )

        logger.info(f"Submitted {len(task_ids)} tasks")

        critical_patterns = manager.submit_task(
            task_type="pattern_search",
            binary_path=binary_path,
            params={
                "patterns": [
                    b"GetProcAddress",
                    b"VirtualProtect",
                    b"CreateRemoteThread",
                    b"license",
                    b"serial",
                    b"activation"
                ],
                "chunk_start": 0,
                "chunk_size": 50 * 1024 * 1024
            },
            priority=TaskPriority.CRITICAL
        )
        task_ids.append(critical_patterns)

        logger.info("Waiting for results...")
        completion = manager.wait_for_completion(task_ids, timeout=600.0)

        if completion["status"] == "completed":
            logger.info(f"Analysis completed in {completion['total_time']:.2f} seconds")

            summary = manager.get_results_summary()
            logger.info(f"\nResults: {summary['total_results']} total")

            for task_type in summary['task_types']:
                results = summary['results_by_type'][task_type]
                logger.info(f"\n{task_type}: {len(results)} results")

            output_file = Path(binary_path).with_suffix(".cluster_analysis.json")
            if manager.export_results(str(output_file)):
                logger.info(f"\nResults exported to {output_file}")
        else:
            logger.warning("Analysis timed out")

    finally:
        manager.shutdown()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Distributed cluster analysis for binary analysis"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    coord_parser = subparsers.add_parser("coordinator", help="Start cluster coordinator")
    coord_parser.add_argument("--port", type=int, default=9876, help="Port for cluster communication")

    worker_parser = subparsers.add_parser("worker", help="Start cluster worker")
    worker_parser.add_argument("--host", default="localhost", help="Coordinator hostname/IP")
    worker_parser.add_argument("--port", type=int, default=9876, help="Coordinator port")

    analyze_parser = subparsers.add_parser("analyze", help="Submit analysis job to cluster")
    analyze_parser.add_argument("binary", help="Path to binary to analyze")
    analyze_parser.add_argument("--host", default="localhost", help="Coordinator hostname/IP")
    analyze_parser.add_argument("--port", type=int, default=9876, help="Coordinator port")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "coordinator":
        start_coordinator(port=args.port)
    elif args.command == "worker":
        start_worker(coordinator_host=args.host, coordinator_port=args.port)
    elif args.command == "analyze":
        if not Path(args.binary).exists():
            logger.error(f"Binary not found: {args.binary}")
            sys.exit(1)
        analyze_with_cluster(binary_path=args.binary, coordinator_host=args.host, coordinator_port=args.port)


if __name__ == "__main__":
    main()
