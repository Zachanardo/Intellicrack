"""Demonstration of Intelligent Patch Point Selection.

This example shows how to use the intelligent patch point selection system
to analyze and patch license checks in binaries with minimal side effects.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.patching.license_check_remover import LicenseCheckRemover


def demonstrate_cfg_analysis(binary_path: str):
    """Demonstrate control flow graph analysis."""
    print("=" * 80)
    print("CONTROL FLOW GRAPH ANALYSIS DEMONSTRATION")
    print("=" * 80)
    print(f"\nAnalyzing: {binary_path}\n")

    remover = LicenseCheckRemover(binary_path)

    print("CFG Analyzer Configuration:")
    print("  Disassembler: Capstone")
    print(f"  CFG Graph Engine: {'NetworkX' if remover.cfg_analyzer.cfg_graph else 'Internal'}")
    print()

    checks = remover.analyze()

    if remover.cfg_analyzer and remover.cfg_analyzer.basic_blocks:
        print("CFG Statistics:")
        print(f"  Total Basic Blocks: {len(remover.cfg_analyzer.basic_blocks)}")

        block_types = {}
        for block in remover.cfg_analyzer.basic_blocks.values():
            block_types[block.block_type] = block_types.get(block.block_type, 0) + 1

        print("  Block Types:")
        for btype, count in sorted(block_types.items()):
            print(f"    {btype}: {count}")

        validation_branches = remover.cfg_analyzer.find_validation_branches()
        print(f"  Validation Branches: {len(validation_branches)}")

        error_handlers = remover.cfg_analyzer.find_error_handlers()
        print(f"  Error Handlers: {len(error_handlers)}")

    return remover, checks


def demonstrate_patch_point_selection(remover, checks):
    """Demonstrate intelligent patch point selection."""
    print("\n" + "=" * 80)
    print("INTELLIGENT PATCH POINT SELECTION")
    print("=" * 80)

    if not checks:
        print("\nNo license checks detected.")
        return

    print(f"\nFound {len(checks)} license checks\n")

    for i, check in enumerate(checks[:3], 1):
        print(f"Check #{i}: {check.check_type.value}")
        print(f"  Address: 0x{check.address:08X}")
        print(f"  Confidence: {check.confidence:.1%}")
        print(f"  Instructions: {len(check.instructions)}")

        if check.instructions:
            print("  Code:")
            for addr, mnem, ops in check.instructions[:3]:
                print(f"    0x{addr:08X}: {mnem:8s} {ops}")

        if check.patch_points:
            print(f"\n  Patch Points Found: {len(check.patch_points)}")
            print("  Ranked by Safety Score:\n")

            for j, point in enumerate(check.patch_points[:3], 1):
                print(f"    #{j}. Address: 0x{point.address:08X}")
                print(f"        Type: {point.patch_type}")
                print(f"        Safety Score: {point.safety_score:.2f}")

                if point.side_effects:
                    print(f"        Side Effects: {', '.join(point.side_effects)}")
                else:
                    print("        Side Effects: None")

                if point.registers_modified:
                    print(f"        Registers Modified: {', '.join(point.registers_modified)}")

                print(f"        Flags Modified: {point.flags_modified}")

                if point.can_use_nop:
                    print("        ✓ Can use NOP")
                if point.can_use_jump:
                    print("        ✓ Can redirect jump")
                if point.can_modify_return:
                    print("        ✓ Can modify return value")

                if point.alternative_points:
                    print(f"        Alternative Targets: {len(point.alternative_points)}")

                print()

            if check.control_flow_context:
                ctx = check.control_flow_context
                print("  Control Flow Context:")
                print(f"    Best Patch Point: 0x{ctx['best_patch_point']:08X}")
                print(f"    Strategy: {ctx['patch_type']}")
                print(f"    Safety: {ctx['safety_score']:.2f}")

                if ctx.get("alternative_points"):
                    print(f"    Alternatives: {len(ctx['alternative_points'])}")
        else:
            print("\n  No optimal patch points identified (using default patching)")

        print()


def demonstrate_safety_comparison(remover, checks):
    """Compare safety of different patching approaches."""
    print("=" * 80)
    print("SAFETY COMPARISON: INTELLIGENT VS LEGACY PATCHING")
    print("=" * 80)

    if not checks:
        return

    print("\nAnalyzing patch safety for each check:\n")

    for check in checks[:3]:
        print(f"Check at 0x{check.address:08X}:")
        print(f"  Type: {check.check_type.value}")

        print("\n  Legacy Patching:")
        print(f"    Strategy: {check.patch_strategy}")
        print(f"    Patch Size: {len(check.patched_bytes)} bytes")
        print("    Method: Pattern-based replacement")
        print("    Safety Analysis: None")

        if check.patch_points:
            best_point = check.patch_points[0]
            print("\n  Intelligent Patching:")
            print(f"    Strategy: {best_point.patch_type}")
            print(f"    Target Address: 0x{best_point.address:08X}")
            print(f"    Safety Score: {best_point.safety_score:.2f}")
            print(f"    Side Effect Analysis: {len(best_point.side_effects)} effects identified")

            if best_point.side_effects:
                print(f"    Side Effects: {', '.join(best_point.side_effects)}")

            improvement = "Significant" if best_point.safety_score >= 0.9 else "Moderate"
            print(f"\n    Safety Improvement: {improvement}")

        print()


def demonstrate_intelligent_patching(remover, checks, apply_patches=False):
    """Demonstrate applying intelligent patches."""
    print("=" * 80)
    print("INTELLIGENT PATCH APPLICATION")
    print("=" * 80)

    if not checks:
        print("\nNo checks to patch.")
        return

    checks_with_points = [c for c in checks if c.patch_points]

    print(f"\nChecks with intelligent patch points: {len(checks_with_points)}/{len(checks)}")

    if not checks_with_points:
        print("No intelligent patch points available. Use legacy patching.")
        return

    if apply_patches:
        print("\nApplying intelligent patches...")
        success = remover.apply_intelligent_patches(checks_with_points)

        if success:
            print("✓ Patches applied successfully")
            print(f"✓ Backup created at: {remover.binary_path}.bak")
        else:
            print("✗ Patching failed")
    else:
        print("\nDry run - showing what would be patched:")
        for check in checks_with_points[:5]:
            best_point = check.patch_points[0]
            print(f"  0x{best_point.address:08X}: {best_point.patch_type} (safety: {best_point.safety_score:.2f})")


def main():
    """Main demonstration function."""
    if len(sys.argv) < 2:
        print("Usage: python intelligent_patching_demo.py <binary_path> [--patch]")
        print("\nOptions:")
        print("  --patch    Actually apply patches (default: dry run)")
        sys.exit(1)

    binary_path = sys.argv[1]
    apply_patches = "--patch" in sys.argv

    if not Path(binary_path).exists():
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    try:
        remover, checks = demonstrate_cfg_analysis(binary_path)

        demonstrate_patch_point_selection(remover, checks)

        demonstrate_safety_comparison(remover, checks)

        demonstrate_intelligent_patching(remover, checks, apply_patches)

        print("\n" + "=" * 80)
        print("FULL REPORT")
        print("=" * 80)
        print()
        print(remover.generate_report())

    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
