"""Example Usage of Frida Stalker Integration for Licensing Analysis.

This script demonstrates how to use the Stalker integration to perform
comprehensive dynamic analysis of software licensing protections.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.stalker_manager import StalkerSession


def basic_stalker_trace(binary_path: str) -> None:
    """Perform basic Stalker tracing on a binary.

    Args:
        binary_path: Path to target binary

    """
    print(f"[*] Starting basic Stalker trace for: {binary_path}")

    with StalkerSession(binary_path) as session:
        print("[*] Session started, beginning trace...")
        session.start_stalking()

        print("[*] Trace running for 10 seconds...")
        time.sleep(10)

        print("[*] Stopping trace and collecting results...")
        session.stop_stalking()

        stats = session.get_stats()
        print("\n[*] Trace Statistics:")
        print(f"    Total Instructions: {stats.total_instructions:,}")
        print(f"    Unique Blocks: {stats.unique_blocks:,}")
        print(f"    Coverage Entries: {stats.coverage_entries:,}")
        print(f"    Licensing Routines: {stats.licensing_routines}")
        print(f"    API Calls: {stats.api_calls:,}")
        print(f"    Duration: {stats.trace_duration:.2f}s")

        licensing = session.get_licensing_routines()
        if licensing:
            print(f"\n[*] Identified {len(licensing)} licensing-related routines:")
            for routine in licensing[:10]:
                print(f"    - {routine}")

        results_file = session.export_results()
        print(f"\n[*] Results exported to: {results_file}")


def trace_specific_function(binary_path: str, module: str, function: str) -> None:
    """Trace execution of a specific function.

    Args:
        binary_path: Path to target binary
        module: Module name containing the function
        function: Function name to trace

    """
    print(f"[*] Tracing function: {module}!{function}")

    with StalkerSession(binary_path) as session:
        print("[*] Starting function trace...")
        session.trace_function(module, function)

        print("[*] Waiting for function execution...")
        time.sleep(15)

        stats = session.get_stats()
        print(f"\n[*] Collected {stats.total_instructions:,} instruction traces")


def analyze_module_coverage(binary_path: str, module_name: str) -> None:
    """Collect code coverage for a specific module.

    Args:
        binary_path: Path to target binary
        module_name: Name of module to analyze

    """
    print(f"[*] Collecting coverage for module: {module_name}")

    with StalkerSession(binary_path) as session:
        print("[*] Starting coverage collection...")
        session.collect_module_coverage(module_name)

        print("[*] Running for 10 seconds...")
        time.sleep(10)

        coverage = session.get_coverage_summary()
        print("\n[*] Coverage Summary:")
        print(f"    Total Entries: {coverage['total_entries']}")
        print(f"    Licensing Entries: {coverage['licensing_entries']}")

        if coverage['top_hotspots']:
            print("\n[*] Top Execution Hotspots:")
            for hotspot in coverage['top_hotspots'][:5]:
                print(
                    f"    {hotspot['module']}+{hotspot['offset']}: "
                    f"{hotspot['hit_count']} hits"
                )


def comprehensive_licensing_analysis(binary_path: str) -> None:
    """Perform comprehensive licensing protection analysis.

    Args:
        binary_path: Path to target binary

    """
    print("[*] Starting comprehensive licensing analysis...")

    output_dir = Path(binary_path).parent / "stalker_analysis"
    output_dir.mkdir(exist_ok=True)

    session = StalkerSession(
        binary_path=binary_path,
        output_dir=str(output_dir),
    )

    try:
        if not session.start():
            print("[-] Failed to start session")
            return

        print("[*] Session active, configuring for licensing focus...")
        session.set_config({
            "traceInstructions": True,
            "traceAPICalls": True,
            "collectCoverage": True,
            "focusOnLicensing": True,
        })

        print("[*] Starting comprehensive trace...")
        session.start_stalking()

        print("[*] Collecting data for 20 seconds...")
        for i in range(20):
            time.sleep(1)
            if (i + 1) % 5 == 0:
                stats = session.get_stats()
                print(
                    f"    Progress: {stats.total_instructions:,} instructions, "
                    f"{stats.licensing_routines} licensing routines"
                )

        print("\n[*] Stopping trace...")
        session.stop_stalking()

        print("\n[*] Analyzing results...")

        stats = session.get_stats()
        print("\n=== Trace Statistics ===")
        print(f"Total Instructions: {stats.total_instructions:,}")
        print(f"Unique Blocks: {stats.unique_blocks:,}")
        print(f"Coverage Entries: {stats.coverage_entries:,}")
        print(f"Licensing Routines: {stats.licensing_routines}")
        print(f"API Calls: {stats.api_calls:,}")
        print(f"Duration: {stats.trace_duration:.2f}s")

        licensing_routines = session.get_licensing_routines()
        print(f"\n=== Licensing Routines ({len(licensing_routines)}) ===")
        for routine in licensing_routines[:20]:
            print(f"  - {routine}")

        coverage = session.get_coverage_summary()
        print("\n=== Coverage Analysis ===")
        print(f"Total Coverage Entries: {coverage['total_entries']}")
        print(f"Licensing-Related: {coverage['licensing_entries']}")

        if coverage['licensing_hotspots']:
            print("\n=== Licensing Hotspots ===")
            for hotspot in coverage['licensing_hotspots']:
                print(
                    f"  {hotspot['module']}+{hotspot['offset']}: "
                    f"{hotspot['hit_count']} hits"
                )

        api_summary = session.get_api_summary()
        print("\n=== API Call Summary ===")
        print(f"Total API Calls: {api_summary['total_calls']:,}")
        print(f"Unique APIs: {api_summary['unique_apis']}")
        print(f"Licensing-Related Calls: {api_summary['licensing_calls']}")

        if api_summary['top_apis']:
            print("\n=== Most Called APIs ===")
            for api_info in api_summary['top_apis'][:10]:
                print(f"  {api_info['api']}: {api_info['count']} calls")

        results_file = session.export_results()
        print(f"\n[*] Full results exported to: {results_file}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[-] Error during analysis: {e}")
    finally:
        session.cleanup()
        print("[*] Session cleaned up")


def targeted_licensing_trace(binary_path: str, suspected_modules: list) -> None:
    """Perform targeted tracing of suspected licensing modules.

    Args:
        binary_path: Path to target binary
        suspected_modules: List of module names suspected to contain licensing code

    """
    print("[*] Starting targeted licensing trace...")
    print(f"[*] Target modules: {', '.join(suspected_modules)}")

    with StalkerSession(binary_path) as session:
        session.set_config({
            "filterByModule": suspected_modules,
            "focusOnLicensing": True,
            "excludeModules": [],
        })

        session.start_stalking()

        print("[*] Tracing for 15 seconds...")
        time.sleep(15)

        session.stop_stalking()

        licensing = session.get_licensing_routines()
        coverage = session.get_coverage_summary()

        print(f"\n[*] Found {len(licensing)} licensing routines")
        print(f"[*] Coverage entries: {coverage['total_entries']}")

        if coverage['licensing_hotspots']:
            print("\n[*] Licensing hotspots in target modules:")
            for hotspot in coverage['licensing_hotspots']:
                print(
                    f"    {hotspot['module']}+{hotspot['offset']}: "
                    f"{hotspot['hit_count']} hits"
                )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Frida Stalker Integration Examples for Licensing Analysis"
    )
    parser.add_argument("binary", help="Path to target binary")
    parser.add_argument(
        "--mode",
        choices=["basic", "function", "coverage", "comprehensive", "targeted"],
        default="comprehensive",
        help="Analysis mode",
    )
    parser.add_argument("--module", help="Module name (for function/coverage modes)")
    parser.add_argument("--function", help="Function name (for function mode)")
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Target module names (for targeted mode)",
    )

    args = parser.parse_args()

    if not Path(args.binary).exists():
        print(f"[-] Binary not found: {args.binary}")
        sys.exit(1)

    print("[*] Frida Stalker Integration Example")
    print(f"[*] Target: {args.binary}")
    print(f"[*] Mode: {args.mode}\n")

    try:
        if args.mode == "basic":
            basic_stalker_trace(args.binary)

        elif args.mode == "function":
            if not args.module or not args.function:
                print("[-] --module and --function required for function mode")
                sys.exit(1)
            trace_specific_function(args.binary, args.module, args.function)

        elif args.mode == "coverage":
            if not args.module:
                print("[-] --module required for coverage mode")
                sys.exit(1)
            analyze_module_coverage(args.binary, args.module)

        elif args.mode == "comprehensive":
            comprehensive_licensing_analysis(args.binary)

        elif args.mode == "targeted":
            if not args.targets:
                print("[-] --targets required for targeted mode")
                sys.exit(1)
            targeted_licensing_trace(args.binary, args.targets)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
