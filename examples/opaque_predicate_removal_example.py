"""Example demonstrating advanced opaque predicate removal capabilities.

This example shows how to use the enhanced control flow deobfuscation module
to detect and remove opaque predicates from obfuscated binaries using:
- Constant propagation analysis
- Symbolic execution with Z3
- Pattern recognition
- Dead code elimination

Copyright (C) 2025 Zachary Flint
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.control_flow_deobfuscation import ControlFlowDeobfuscator
from intellicrack.utils.logger import logger


def analyze_function_with_opaque_predicates(binary_path: str, function_address: int) -> None:
    """Analyze a function and remove opaque predicates.

    Args:
        binary_path: Path to the binary containing the obfuscated function
        function_address: Address of the function to deobfuscate

    """
    logger.info(f"Analyzing function at 0x{function_address:x} in {binary_path}")

    try:
        deobfuscator = ControlFlowDeobfuscator(binary_path)

        logger.info(f"Architecture detected: {deobfuscator.architecture}")
        logger.info(
            f"Advanced opaque analyzer available: {deobfuscator.opaque_analyzer is not None}"
        )

        result = deobfuscator.deobfuscate_function(function_address)

        logger.info("\n=== Deobfuscation Results ===")
        logger.info(f"Original CFG: {result.metrics['original_blocks']} blocks")
        logger.info(f"Deobfuscated CFG: {result.metrics['deobfuscated_blocks']} blocks")
        logger.info(f"Blocks removed: {result.metrics['blocks_removed']}")
        logger.info(f"Complexity reduction: {result.metrics.get('complexity_reduction', 0):.2f}%")
        logger.info(f"Confidence: {result.confidence:.2f}")

        if result.opaque_predicates:
            logger.info(f"\n=== Detected {len(result.opaque_predicates)} Opaque Predicates ===")
            for i, pred in enumerate(result.opaque_predicates, 1):
                logger.info(f"\nPredicate #{i}:")
                logger.info(f"  Address: 0x{pred['address']:x}")
                logger.info(f"  Instruction: {pred['instruction']}")
                logger.info(f"  Type: {pred['type']}")
                logger.info(f"  Always evaluates to: {pred.get('always_value')}")
                logger.info(f"  Analysis method: {pred.get('analysis_method', 'unknown')}")
                logger.info(f"  Confidence: {pred.get('confidence', 0):.2f}")

                if pred.get("dead_branch"):
                    logger.info(f"  Dead branch: 0x{pred['dead_branch']:x}")

                if pred.get("symbolic_proof"):
                    logger.info(f"  Symbolic proof: {pred['symbolic_proof']}")

        if result.dispatcher_info:
            logger.info(
                f"\n=== Detected {len(result.dispatcher_info)} Control Flow Dispatchers ==="
            )
            for i, disp in enumerate(result.dispatcher_info, 1):
                logger.info(f"\nDispatcher #{i}:")
                logger.info(f"  Address: 0x{disp.dispatcher_address:x}")
                logger.info(f"  Type: {disp.switch_type}")
                logger.info(f"  Controlled blocks: {len(disp.controlled_blocks)}")
                logger.info(f"  State variable: {disp.state_variable_type}")

        output_dot = Path(binary_path).with_suffix(".deobf.dot")
        if deobfuscator.export_deobfuscated_cfg(result, output_dot):
            logger.info(f"\nExported deobfuscated CFG to: {output_dot}")

        output_bin = Path(binary_path).with_suffix(Path(binary_path).suffix + ".deobf")
        if deobfuscator.apply_patches(result, output_bin):
            logger.info(f"Created patched binary: {output_bin}")

    except Exception as e:
        logger.error(f"Deobfuscation failed: {e}", exc_info=True)


def analyze_common_opaque_patterns() -> None:
    """Demonstrate detection of common opaque predicate patterns."""
    logger.info("\n=== Common Opaque Predicate Patterns ===\n")

    patterns = [
        {
            "name": "Self XOR",
            "example": "xor eax, eax; test eax, eax; jz next",
            "description": "x XOR x always equals 0",
        },
        {
            "name": "Self Comparison",
            "example": "cmp eax, eax; je always_taken",
            "description": "x == x is always true",
        },
        {
            "name": "Square Non-Negative",
            "example": "imul eax, eax; test eax, eax; jge always_taken",
            "description": "(x * x) >= 0 for all x",
        },
        {
            "name": "Modulo Invariant",
            "example": "and eax, 1; cmp eax, 1; jle always_taken",
            "description": "(x % 2) is always <= 1",
        },
        {
            "name": "Zero Masking",
            "example": "and eax, 0; test eax, eax; jz always_taken",
            "description": "(x & 0) == 0 for all x",
        },
    ]

    for pattern in patterns:
        logger.info(f"Pattern: {pattern['name']}")
        logger.info(f"  Assembly: {pattern['example']}")
        logger.info(f"  Property: {pattern['description']}\n")


def main() -> None:
    """Main entry point for opaque predicate removal example."""
    logger.info("=== Intellicrack Opaque Predicate Removal Example ===\n")

    if len(sys.argv) < 3:
        logger.info("Usage: python opaque_predicate_removal_example.py <binary_path> <function_address>")
        logger.info("\nThis example demonstrates advanced opaque predicate removal using:")
        logger.info("  - Constant propagation to track values through CFG")
        logger.info("  - Symbolic execution with Z3 to prove predicates")
        logger.info("  - Pattern recognition for common opaque constructs")
        logger.info("  - Dead code elimination after predicate removal")
        logger.info("\nSupported architectures: x86, x86_64, ARM, ARM64")
        logger.info("\nExample:")
        logger.info("  python opaque_predicate_removal_example.py sample.exe 0x401000")

        analyze_common_opaque_patterns()
        return

    binary_path = sys.argv[1]
    try:
        function_address = int(sys.argv[2], 16 if sys.argv[2].startswith("0x") else 10)
    except ValueError:
        logger.error(f"Invalid function address: {sys.argv[2]}")
        return

    if not Path(binary_path).exists():
        logger.error(f"Binary not found: {binary_path}")
        return

    analyze_function_with_opaque_predicates(binary_path, function_address)


if __name__ == "__main__":
    main()
