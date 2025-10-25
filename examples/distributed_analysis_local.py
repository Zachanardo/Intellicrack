"""Example: Local distributed analysis using multi-processing.

This example demonstrates using the distributed analysis manager in local mode
for analyzing binaries across multiple CPU cores without network clustering.
"""

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


def analyze_binary_local(binary_path: str):
    """Analyze a binary using local distributed processing.

    Args:
        binary_path: Path to the binary file to analyze

    """
    logger.info(f"Starting local distributed analysis of {binary_path}")

    config = {
        "num_workers": 8,
        "port": 9876
    }

    manager = create_distributed_manager(
        mode="local",
        config=config,
        enable_networking=False
    )

    try:
        if not manager.start_cluster():
            logger.error("Failed to start cluster")
            return

        logger.info("Cluster started successfully")
        status = manager.get_cluster_status()
        logger.info(f"Cluster status: {status['node_count']} nodes available")

        logger.info("Submitting comprehensive binary analysis tasks...")
        task_ids = manager.submit_binary_analysis(
            binary_path=binary_path,
            chunk_size=5 * 1024 * 1024,
            priority=TaskPriority.HIGH
        )

        logger.info(f"Submitted {len(task_ids)} analysis tasks")

        logger.info("Additional targeted analysis tasks...")
        pattern_task = manager.submit_task(
            task_type="pattern_search",
            binary_path=binary_path,
            params={
                "patterns": [b"license", b"serial", b"activation", b"registration"],
                "chunk_start": 0,
                "chunk_size": 10 * 1024 * 1024
            },
            priority=TaskPriority.CRITICAL
        )
        task_ids.append(pattern_task)

        logger.info("Waiting for task completion...")
        completion = manager.wait_for_completion(task_ids, timeout=300.0)

        if completion["status"] == "completed":
            logger.info(f"All tasks completed in {completion['total_time']:.2f} seconds")

            summary = manager.get_results_summary()
            logger.info(f"Results summary: {summary['total_results']} results")
            logger.info(f"Task types: {summary['task_types']}")

            for task_type, results in summary['results_by_type'].items():
                logger.info(f"\n{task_type}: {len(results)} results")

                if task_type == "pattern_search":
                    for result in results:
                        if "matches" in result and result["matches"]:
                            logger.info(f"  Found {len(result['matches'])} pattern matches")
                            for match in result["matches"][:5]:
                                logger.info(f"    - {match['pattern']} at offset 0x{match['offset']:08x}")

                elif task_type == "entropy_analysis":
                    for result in results:
                        logger.info(f"  Overall entropy: {result.get('overall_entropy', 0):.4f}")
                        logger.info(f"  High entropy regions: {result.get('high_entropy_regions', 0)}")

                elif task_type == "string_extraction":
                    for result in results:
                        logger.info(f"  Extracted {result.get('total_strings', 0)} strings")

                elif task_type == "crypto_detection":
                    for result in results:
                        if result.get("detections"):
                            logger.info("  Cryptographic algorithms detected:")
                            for detection in result["detections"][:10]:
                                logger.info(f"    - {detection['algorithm']} at 0x{detection['offset']:08x}")

                elif task_type == "import_analysis":
                    for result in results:
                        logger.info(f"  Imported DLLs: {result.get('dll_count', 0)}")
                        logger.info(f"  Total imports: {result.get('total_imports', 0)}")

                elif task_type == "section_analysis":
                    for result in results:
                        logger.info(f"  Sections analyzed: {result.get('section_count', 0)}")
                        for section in result.get("sections", []):
                            logger.info(f"    - {section['name']}: entropy={section.get('entropy', 0):.4f}")

            output_file = Path(binary_path).with_suffix(".analysis.json")
            if manager.export_results(str(output_file)):
                logger.info(f"\nDetailed results exported to {output_file}")

        else:
            logger.warning(f"Task completion timed out: {completion}")

        final_status = manager.get_cluster_status()
        logger.info("\nFinal cluster statistics:")
        logger.info(f"  Total tasks: {final_status['tasks']['total']}")
        logger.info(f"  Completed: {final_status['tasks']['completed']}")
        logger.info(f"  Failed: {final_status['tasks']['failed']}")
        logger.info(f"  Performance: {final_status['performance']}")

    finally:
        logger.info("Shutting down cluster...")
        manager.shutdown()
        logger.info("Analysis complete")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python distributed_analysis_local.py <binary_path>")
        print("\nExample:")
        print("  python distributed_analysis_local.py C:\\Windows\\System32\\notepad.exe")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not Path(binary_path).exists():
        logger.error(f"Binary not found: {binary_path}")
        sys.exit(1)

    analyze_binary_local(binary_path)


if __name__ == "__main__":
    main()
