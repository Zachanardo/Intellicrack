"""Demonstration of control flow deobfuscation capabilities.

This example demonstrates how to use Intellicrack's control flow deobfuscation
engine to analyze and defeat control flow flattening in protected binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GPL v3.0
"""

import sys
from pathlib import Path

from intellicrack.core.analysis import CFGExplorer, ControlFlowDeobfuscator


def demo_basic_deobfuscation(binary_path: str):
    """Demonstrate basic control flow deobfuscation."""
    print("=" * 70)
    print("DEMO 1: Basic Control Flow Deobfuscation")
    print("=" * 70)

    deobf = ControlFlowDeobfuscator(binary_path)

    function_address = 0x401000

    print(f"\nDeobfuscating function at 0x{function_address:x}...")
    result = deobf.deobfuscate_function(function_address)

    print("\nResults:")
    print(f"  Confidence Score: {result.confidence:.2%}")
    print(f"  Dispatchers Found: {len(result.dispatcher_info)}")
    print(f"  Opaque Predicates: {len(result.opaque_predicates)}")
    print(f"  Bogus Blocks Removed: {len(result.removed_blocks)}")
    print(f"  Edges Recovered: {len(result.recovered_edges)}")

    print("\nMetrics:")
    print(f"  Original Blocks: {result.metrics['original_blocks']}")
    print(f"  Deobfuscated Blocks: {result.metrics['deobfuscated_blocks']}")
    print(f"  Complexity Reduction: {result.metrics.get('complexity_reduction', 0):.2f}%")

    output_dir = Path("deobf_results")
    output_dir.mkdir(exist_ok=True)

    cfg_path = output_dir / f"function_{function_address:x}_deobf.dot"
    if deobf.export_deobfuscated_cfg(result, cfg_path):
        print(f"\nExported deobfuscated CFG to: {cfg_path}")


def demo_dispatcher_analysis(binary_path: str):
    """Demonstrate dispatcher detection and analysis."""
    print("\n" + "=" * 70)
    print("DEMO 2: Dispatcher Detection and Analysis")
    print("=" * 70)

    deobf = ControlFlowDeobfuscator(binary_path)
    result = deobf.deobfuscate_function(0x401000)

    if result.dispatcher_info:
        print(f"\nFound {len(result.dispatcher_info)} dispatcher(s):\n")

        for idx, dispatcher in enumerate(result.dispatcher_info, 1):
            print(f"Dispatcher {idx}:")
            print(f"  Address: 0x{dispatcher.dispatcher_address:x}")
            print(f"  Type: {dispatcher.switch_type}")
            print(f"  State Variable Type: {dispatcher.state_variable_type}")
            print(f"  State Variable Location: 0x{dispatcher.state_variable_location:x}")
            print(f"  Controlled Blocks: {len(dispatcher.controlled_blocks)}")
            print(f"  Case Mappings: {len(dispatcher.case_mappings)}")

            if dispatcher.case_mappings:
                print("  Sample Case Mappings:")
                for case_val, target in list(dispatcher.case_mappings.items())[:5]:
                    print(f"    Case {case_val} -> 0x{target:x}")
            print()
    else:
        print("\nNo dispatchers detected in this function.")


def demo_opaque_predicate_detection(binary_path: str):
    """Demonstrate opaque predicate detection."""
    print("=" * 70)
    print("DEMO 3: Opaque Predicate Detection")
    print("=" * 70)

    deobf = ControlFlowDeobfuscator(binary_path)
    result = deobf.deobfuscate_function(0x401000)

    if result.opaque_predicates:
        print(f"\nFound {len(result.opaque_predicates)} opaque predicate(s):\n")

        for idx, predicate in enumerate(result.opaque_predicates, 1):
            print(f"Opaque Predicate {idx}:")
            print(f"  Address: 0x{predicate['address']:x}")
            print(f"  Type: {predicate['type']}")
            print(f"  Instruction: {predicate['instruction']}")
            if predicate.get('always_value') is not None:
                print(f"  Always Evaluates To: {predicate['always_value']}")
            print()
    else:
        print("\nNo opaque predicates detected.")


def demo_integrated_analysis(binary_path: str):
    """Demonstrate integration with CFG Explorer."""
    print("=" * 70)
    print("DEMO 4: Integrated CFG Analysis and Deobfuscation")
    print("=" * 70)

    print("\nStep 1: Load binary with CFG Explorer...")
    explorer = CFGExplorer(binary_path)
    if not explorer.load_binary():
        print("Failed to load binary")
        return

    print(f"Loaded {len(explorer.functions)} functions")

    print("\nStep 2: Identify license validation functions...")
    license_functions = []

    for func_name, func_data in explorer.functions.items():
        if any(keyword in func_name.lower() for keyword in ['license', 'validate', 'check', 'serial']):
            license_functions.append({
                'name': func_name,
                'address': func_data['addr'],
                'complexity': func_data.get('complexity', 0)
            })

    if license_functions:
        print(f"Found {len(license_functions)} license-related functions:")
        for func in license_functions:
            print(f"  - {func['name']} at 0x{func['address']:x} (complexity: {func['complexity']})")

        print("\nStep 3: Deobfuscate license functions...")
        deobf = ControlFlowDeobfuscator(binary_path)

        for func in license_functions[:3]:
            print(f"\n  Deobfuscating {func['name']}...")
            result = deobf.deobfuscate_function(func['address'])

            print(f"    Confidence: {result.confidence:.2%}")
            print(f"    Complexity Reduction: {result.metrics.get('complexity_reduction', 0):.2f}%")

            if result.confidence > 0.5:
                cfg_path = f"deobf_results/{func['name']}_deobf.dot"
                deobf.export_deobfuscated_cfg(result, cfg_path)
                print(f"    Exported to: {cfg_path}")
    else:
        print("No license-related functions found")


def demo_patch_generation(binary_path: str):
    """Demonstrate patch generation and application."""
    print("\n" + "=" * 70)
    print("DEMO 5: Patch Generation and Application")
    print("=" * 70)

    deobf = ControlFlowDeobfuscator(binary_path)
    result = deobf.deobfuscate_function(0x401000)

    print(f"\nGenerated {len(result.patch_info)} patches:")

    for idx, patch in enumerate(result.patch_info, 1):
        print(f"\nPatch {idx}:")
        print(f"  Type: {patch['type']}")
        print(f"  Address: 0x{patch['address']:x}")
        print(f"  Description: {patch['description']}")

        if patch['type'] == 'nop_dispatcher':
            print(f"  Size: {patch['size']} bytes")
        elif patch['type'] == 'redirect_edge':
            print(f"  Target: 0x{patch['target']:x}")

    if result.confidence > 0.7:
        print("\n✓ High confidence - patches can be safely applied")
        print("  Use: deobf.apply_patches(result, 'output.exe')")
    else:
        print("\n⚠ Low confidence - manual review recommended before patching")


def demo_batch_processing(binary_path: str):
    """Demonstrate batch deobfuscation of multiple functions."""
    print("\n" + "=" * 70)
    print("DEMO 6: Batch Processing Multiple Functions")
    print("=" * 70)

    function_addresses = [0x401000, 0x402000, 0x403000]

    print(f"\nProcessing {len(function_addresses)} functions...\n")

    deobf = ControlFlowDeobfuscator(binary_path)
    results = []

    for addr in function_addresses:
        try:
            print(f"Processing 0x{addr:x}...")
            result = deobf.deobfuscate_function(addr)
            results.append({
                'address': addr,
                'result': result,
                'success': True
            })
            print(f"  ✓ Success (confidence: {result.confidence:.2%})")
        except Exception as e:
            results.append({
                'address': addr,
                'error': str(e),
                'success': False
            })
            print(f"  ✗ Failed: {e}")

    print("\n" + "=" * 70)
    print("BATCH PROCESSING SUMMARY")
    print("=" * 70)

    successful = sum(1 for r in results if r['success'])
    failed = len(results) - successful

    print(f"Total Functions: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")

    if successful > 0:
        avg_confidence = sum(
            r['result'].confidence for r in results if r['success']
        ) / successful
        print(f"Average Confidence: {avg_confidence:.2%}")


def main():
    """Main demonstration entry point."""
    if len(sys.argv) < 2:
        print("Usage: python control_flow_deobfuscation_demo.py <binary_path>")
        print("\nExample:")
        print("  python control_flow_deobfuscation_demo.py protected.exe")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not Path(binary_path).exists():
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("INTELLICRACK CONTROL FLOW DEOBFUSCATION DEMONSTRATION")
    print("=" * 70)
    print(f"\nTarget Binary: {binary_path}")

    try:
        demo_basic_deobfuscation(binary_path)

        demo_dispatcher_analysis(binary_path)

        demo_opaque_predicate_detection(binary_path)

        demo_patch_generation(binary_path)

        print("\n" + "=" * 70)
        print("All demonstrations completed successfully!")
        print("=" * 70)

        print("\nNext Steps:")
        print("  1. Review generated DOT files in deobf_results/")
        print("  2. Visualize with: dot -Tsvg file.dot -o file.svg")
        print("  3. Apply patches to create deobfuscated binary")
        print("  4. Verify deobfuscated binary maintains functionality")

    except Exception as e:
        print(f"\n\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
