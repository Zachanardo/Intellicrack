"""Example usage of Advanced Anti-Debug Bypass system.

This example demonstrates how to use the advanced anti-debug bypass
functionality to defeat sophisticated anti-debugging protections including
ScyllaHide-resistant checks.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import sys
from pathlib import Path

from intellicrack.core.anti_analysis import (
    AdvancedDebuggerBypass,
    install_advanced_bypass,
)
from intellicrack.utils.logger import logger


def example_basic_bypass():
    """Example 1: Basic bypass installation."""
    logger.info("=" * 60)
    logger.info("Example 1: Basic Bypass Installation")
    logger.info("=" * 60)

    bypass = AdvancedDebuggerBypass()

    logger.info("Installing full bypass suite...")
    results = bypass.install_full_bypass()

    logger.info("\n--- Installation Results ---")
    logger.info(f"Overall Success: {results['overall_success']}")

    logger.info("\nKernel Hooks:")
    for hook_name, success in results["kernel_hooks"].items():
        status = "✓" if success else "✗"
        logger.info(f"  {status} {hook_name}: {success}")

    logger.info("\nHypervisor:")
    for feature, value in results["hypervisor"].items():
        if isinstance(value, dict):
            logger.info(f"  {feature}:")
            for sub_feature, sub_value in value.items():
                status = "✓" if sub_value else "✗"
                logger.info(f"    {status} {sub_feature}: {sub_value}")
        else:
            status = "✓" if value else "✗"
            logger.info(f"  {status} {feature}: {value}")

    logger.info("\nTiming Neutralization:")
    for method, success in results["timing"].items():
        status = "✓" if success else "✗"
        logger.info(f"  {status} {method}: {success}")

    status = bypass.get_bypass_status()
    logger.info("\n--- Bypass Status ---")
    logger.info(f"Active: {status['active']}")
    logger.info(f"Kernel Hooks Installed: {status['kernel_hooks']}")
    logger.info(f"Timing Hooks Installed: {status['timing_hooks']}")
    logger.info(f"VMX Enabled: {status['hypervisor_vmx']}")
    logger.info(f"EPT Enabled: {status['hypervisor_ept']}")

    bypass.remove_all_bypasses()
    logger.info("\nBypass removed successfully")


def example_scyllahide_resistant():
    """Example 2: ScyllaHide-resistant bypass."""
    logger.info("\n" + "=" * 60)
    logger.info("Example 2: ScyllaHide-Resistant Bypass")
    logger.info("=" * 60)

    results = install_advanced_bypass(scyllahide_resistant=True)

    logger.info("\n--- ScyllaHide-Resistant Installation ---")

    scyllahide_results = results.get("scyllahide_resistant", {})
    logger.info("\nScyllaHide Bypass Techniques:")
    for technique, success in scyllahide_results.items():
        if technique != "error":
            status = "✓" if success else "✗"
            logger.info(f"  {status} {technique}: {success}")

    status = results.get("status", {})
    logger.info("\n--- Final Status ---")
    logger.info(f"Active: {status.get('active', False)}")

    if "kernel_hook_details" in status:
        logger.info("\nActive Kernel Hooks:")
        for hook, active in status["kernel_hook_details"].items():
            status_symbol = "✓" if active else "✗"
            logger.info(f"  {status_symbol} {hook}")

    if "virtualization_support" in status:
        logger.info("\nVirtualization Support:")
        for feature, supported in status["virtualization_support"].items():
            status_symbol = "✓" if supported else "✗"
            logger.info(f"  {status_symbol} {feature}: {supported}")


def example_targeted_bypass():
    """Example 3: Defeating specific anti-debug techniques."""
    logger.info("\n" + "=" * 60)
    logger.info("Example 3: Targeted Technique Bypass")
    logger.info("=" * 60)

    bypass = AdvancedDebuggerBypass()

    techniques_to_defeat = [
        "PEB.BeingDebugged",
        "PEB.NtGlobalFlag",
        "ProcessDebugPort",
        "ThreadHideFromDebugger",
        "RDTSC",
        "QueryPerformanceCounter",
        "HardwareBreakpoints",
    ]

    logger.info("\nDefeating specific anti-debug techniques:")

    for technique in techniques_to_defeat:
        success = bypass.defeat_anti_debug_technique(technique)
        status = "✓" if success else "✗"
        logger.info(f"  {status} {technique}: {success}")

    status = bypass.get_bypass_status()
    logger.info("\n--- Bypass Status ---")
    logger.info(f"Active Techniques: {status['kernel_hooks'] + status['timing_hooks']}")

    bypass.remove_all_bypasses()


def example_component_access():
    """Example 4: Direct component access and control."""
    logger.info("\n" + "=" * 60)
    logger.info("Example 4: Component-Level Control")
    logger.info("=" * 60)

    bypass = AdvancedDebuggerBypass()

    logger.info("\n--- Kernel Hooks Component ---")
    kernel_hooks = bypass.kernel_hooks

    logger.info("Installing NtQueryInformationProcess hook...")
    success = kernel_hooks.hook_ntquery_information_process()
    logger.info(f"  Result: {success}")

    logger.info("Installing NtSetInformationThread hook...")
    success = kernel_hooks.hook_ntset_information_thread()
    logger.info(f"  Result: {success}")

    logger.info("Installing NtQuerySystemInformation hook...")
    success = kernel_hooks.hook_ntquery_system_information()
    logger.info(f"  Result: {success}")

    logger.info(f"\nInstalled kernel hooks: {len(kernel_hooks.hooks)}")
    for hook_name in kernel_hooks.hooks.keys():
        logger.info(f"  - {hook_name}")

    logger.info("\n--- Hypervisor Component ---")
    hypervisor = bypass.hypervisor

    logger.info("Checking virtualization support...")
    vt_support = hypervisor.check_virtualization_support()
    for feature, supported in vt_support.items():
        status = "✓" if supported else "✗"
        logger.info(f"  {status} {feature}: {supported}")

    if vt_support.get("vmx") or vt_support.get("svm"):
        logger.info("\nSetting up VMCS shadowing...")
        success = hypervisor.setup_vmcs_shadowing()
        logger.info(f"  Result: {success}")

        if vt_support.get("ept"):
            logger.info("Setting up EPT hooks...")
            success = hypervisor.setup_ept_hooks()
            logger.info(f"  Result: {success}")

        logger.info("\nManipulating hardware breakpoints...")
        breakpoints = {0: 0x00401000, 1: 0x00402000}
        success = hypervisor.manipulate_hardware_breakpoints(breakpoints)
        logger.info(f"  Result: {success}")
    else:
        logger.info("\nHardware virtualization not supported")

    logger.info("\n--- Timing Neutralizer Component ---")
    timing = bypass.timing_neutralizer

    logger.info("Neutralizing RDTSC...")
    success = timing.neutralize_rdtsc()
    logger.info(f"  Result: {success}")

    logger.info("Hooking QueryPerformanceCounter...")
    success = timing.hook_query_performance_counter()
    logger.info(f"  Result: {success}")

    logger.info("Hooking GetTickCount...")
    success = timing.hook_get_tick_count()
    logger.info(f"  Result: {success}")

    logger.info(f"\nTiming hooks installed: {len(timing.hooked_functions)}")
    for func_name in timing.hooked_functions.keys():
        logger.info(f"  - {func_name}")

    logger.info("\nNormalizing timing values...")
    test_times = [50.0, 500.0, 2000.0]
    for test_time in test_times:
        normalized = timing.normalize_timing(test_time)
        logger.info(f"  {test_time}ms -> {normalized}ms")

    bypass.remove_all_bypasses()


def example_frida_integration():
    """Example 5: Frida script integration."""
    logger.info("\n" + "=" * 60)
    logger.info("Example 5: Frida Script Integration")
    logger.info("=" * 60)

    logger.info("\nLoading Frida script for runtime bypass...")

    try:
        import frida

        from intellicrack.core.analysis.frida_script_manager import FridaScriptManager

        FridaScriptManager()

        script_path = Path(__file__).parent.parent / "intellicrack" / "scripts" / "frida" / "advanced_anti_debug_bypass.js"

        logger.info(f"Script path: {script_path}")

        if script_path.exists():
            logger.info("Frida script found")
            logger.info("\nTo inject into a process:")
            logger.info("  1. Start target process")
            logger.info("  2. Get process name or PID")
            logger.info("  3. Use FridaScriptManager to inject:")
            logger.info("     manager = FridaScriptManager()")
            logger.info("     script = manager.load_script('advanced_anti_debug_bypass.js')")
            logger.info("     manager.inject_script(script, process_name='target.exe')")

            logger.info("\nFrida bypass features:")
            logger.info("  ✓ Kernel-level hooks (NtQueryInformationProcess, NtSetInformationThread, etc.)")
            logger.info("  ✓ RDTSC/RDTSCP patching")
            logger.info("  ✓ Timing normalization (QPC, GetTickCount)")
            logger.info("  ✓ CPUID spoofing")
            logger.info("  ✓ Deep PEB manipulation")
            logger.info("  ✓ Exception handler bypass")
            logger.info("  ✓ Integrity check bypass")

            logger.info("\nRPC exports available:")
            logger.info("  - getStatus(): Get current bypass status")
            logger.info("  - disableHook(hookName): Disable specific hook")

        else:
            logger.warning(f"Frida script not found at {script_path}")

    except ImportError:
        logger.warning("Frida not installed. Install with: pip install frida")


def example_production_workflow():
    """Example 6: Production workflow for analyzing protected software."""
    logger.info("\n" + "=" * 60)
    logger.info("Example 6: Production Workflow")
    logger.info("=" * 60)

    logger.info("\nTypical workflow for analyzing protected software:")

    logger.info("\n1. Initialize bypass system")
    bypass = AdvancedDebuggerBypass()

    logger.info("\n2. Check system capabilities")
    vt_support = bypass.hypervisor.check_virtualization_support()
    if vt_support.get("vmx") or vt_support.get("svm"):
        logger.info("   ✓ Hardware virtualization available")
        use_hypervisor = True
    else:
        logger.info("   ✗ Hardware virtualization not available")
        use_hypervisor = False

    logger.info("\n3. Install appropriate bypass level")
    if use_hypervisor:
        logger.info("   Installing full bypass with hypervisor support...")
        bypass.install_full_bypass()
    else:
        logger.info("   Installing ScyllaHide-resistant bypass...")
        bypass.install_scyllahide_resistant_bypass()

    logger.info("\n4. Verify installation")
    status = bypass.get_bypass_status()
    logger.info(f"   Active: {status['active']}")
    logger.info(f"   Techniques: {status['kernel_hooks'] + status['timing_hooks']}")

    logger.info("\n5. Launch target process with bypass active")
    logger.info("   (Target process would be launched here)")

    logger.info("\n6. Monitor bypass effectiveness")
    logger.info("   (Bypass automatically handles anti-debug checks)")

    logger.info("\n7. Perform analysis")
    logger.info("   (Analysis tools can now work without anti-debug interference)")

    logger.info("\n8. Cleanup on completion")
    bypass.remove_all_bypasses()
    logger.info("   ✓ Bypasses removed")

    logger.info("\nWorkflow complete!")


def main():
    """Run all examples."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    logger.info("=" * 60)
    logger.info("Advanced Anti-Debug Bypass Examples")
    logger.info("=" * 60)
    logger.info("\nThese examples demonstrate production-ready anti-debug")
    logger.info("bypass techniques for defeating modern protections.")
    logger.info("")

    try:
        example_basic_bypass()

        example_scyllahide_resistant()

        example_targeted_bypass()

        example_component_access()

        example_frida_integration()

        example_production_workflow()

        logger.info("\n" + "=" * 60)
        logger.info("All Examples Completed Successfully")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"\nError running examples: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
