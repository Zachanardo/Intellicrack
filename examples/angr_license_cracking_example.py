"""Production-ready example demonstrating Angr enhancements for license cracking.

This example shows how to use the enhanced symbolic execution capabilities
to analyze and crack software licensing protections.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError:
    logger.error("Angr not available. Please install: pip install angr")
    ANGR_AVAILABLE = False
    sys.exit(1)

from intellicrack.core.analysis.angr_enhancements import (
    LicenseValidationDetector,
    create_enhanced_simgr,
    install_license_simprocedures,
)
from intellicrack.core.analysis.concolic_obfuscation_handler import ObfuscationAwareConcolicEngine


def analyze_license_validation(binary_path: str, max_steps: int = 100) -> dict:
    """Analyze binary for license validation routines using enhanced symbolic execution.

    Args:
        binary_path: Path to the binary to analyze
        max_steps: Maximum exploration steps

    Returns:
        dict: Analysis results including found license checks and bypass strategies

    """
    logger.info(f"Starting license validation analysis of: {binary_path}")

    if not Path(binary_path).exists():
        logger.error(f"Binary not found: {binary_path}")
        return {"error": "Binary not found"}

    try:
        project = angr.Project(binary_path, auto_load_libs=False, support_selfmodifying_code=True)
        logger.info(f"Loaded binary: {project.arch.name}, entry: {hex(project.entry)}")

        installed_hooks = install_license_simprocedures(project)
        logger.info(f"Installed {installed_hooks} custom simprocedures for license API hooking")

        symbolic_serial = claripy.BVS("license_serial", 128)
        symbolic_key = claripy.BVS("license_key", 256)

        initial_state = project.factory.entry_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_CONSTRAINT_ACTIONS,
            }
        )

        initial_state.globals['symbolic_license_data'] = {
            'serial': symbolic_serial,
            'key': symbolic_key,
        }

        simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=True)
        logger.info("Created enhanced symbolic execution manager with license-focused techniques")

        detector = LicenseValidationDetector()

        results = {
            "binary": binary_path,
            "arch": str(project.arch.name),
            "entry": hex(project.entry),
            "license_checks_found": [],
            "bypass_strategies": [],
            "explored_states": 0,
            "license_files_accessed": [],
        }

        logger.info(f"Beginning symbolic exploration (max {max_steps} steps)...")

        for step in range(max_steps):
            if not simgr.active:
                logger.info("No active states remaining")
                break

            simgr.step()
            results["explored_states"] += 1

            for state in simgr.active[:5]:
                validation_info = detector.analyze_state(state)

                if validation_info["validation_type"] and validation_info["confidence"] > 0.5:
                    check_info = {
                        "type": validation_info["validation_type"],
                        "confidence": validation_info["confidence"],
                        "address": hex(state.addr),
                        "evidence": validation_info["evidence"],
                    }
                    results["license_checks_found"].append(check_info)

                    logger.info(
                        f"Found {validation_info['validation_type']} validation "
                        f"at {hex(state.addr)} (confidence: {validation_info['confidence']:.2%})"
                    )

                if hasattr(state, 'license_files') and state.license_files:
                    for filename in state.license_files.keys():
                        if filename not in results["license_files_accessed"]:
                            results["license_files_accessed"].append(filename)
                            logger.info(f"License file accessed: {filename}")

                if hasattr(state, 'license_messages') and state.license_messages:
                    for message in state.license_messages:
                        logger.info(f"License message box: {message}")

            if (step + 1) % 10 == 0:
                logger.info(
                    f"Step {step + 1}/{max_steps}: "
                    f"{len(simgr.active)} active, "
                    f"{len(simgr.deadended)} deadended, "
                    f"{len(results['license_checks_found'])} license checks found"
                )

        if results["license_checks_found"]:
            logger.info("\n=== License Validation Analysis Results ===")
            logger.info(f"Total license checks found: {len(results['license_checks_found'])}")

            validation_types = {}
            for check in results["license_checks_found"]:
                vtype = check["type"]
                validation_types[vtype] = validation_types.get(vtype, 0) + 1

            for vtype, count in validation_types.items():
                logger.info(f"  - {vtype}: {count} instances")

            results["bypass_strategies"] = generate_bypass_strategies(results["license_checks_found"])

            logger.info("\n=== Recommended Bypass Strategies ===")
            for strategy in results["bypass_strategies"]:
                logger.info(f"  - {strategy['method']}: {strategy['description']}")

        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return {"error": str(e)}


def generate_bypass_strategies(license_checks: list) -> list:
    """Generate bypass strategies based on detected license checks.

    Args:
        license_checks: List of detected license validation checks

    Returns:
        list: Recommended bypass strategies

    """
    strategies = []

    validation_types = {check["type"] for check in license_checks}

    if "serial_check" in validation_types:
        strategies.append(
            {
                "method": "Keygen Creation",
                "description": "Extract serial validation algorithm and create key generator",
                "technique": "Symbolic execution can reveal the expected serial format and validation logic",
            }
        )

    if "trial_check" in validation_types:
        strategies.append(
            {
                "method": "Trial Period Bypass",
                "description": "Patch time checks or manipulate stored trial data",
                "technique": "Hook GetSystemTime/GetTickCount or modify registry trial timestamps",
            }
        )

    if "hardware_check" in validation_types:
        strategies.append(
            {
                "method": "Hardware ID Spoofing",
                "description": "Emulate expected hardware fingerprint",
                "technique": "Hook GetVolumeInformationW and related APIs to return consistent HWID",
            }
        )

    if "activation_check" in validation_types:
        strategies.append(
            {
                "method": "Activation Server Emulation",
                "description": "Create local activation server or patch online checks",
                "technique": "Hook network APIs (connect/send/recv) to return valid activation responses",
            }
        )

    if "online_check" in validation_types:
        strategies.append(
            {
                "method": "Offline Mode Patch",
                "description": "Force software to operate in offline mode",
                "technique": "Patch server connectivity checks to always return offline status",
            }
        )

    return strategies


def demonstrate_concolic_integration(binary_path: str):
    """Demonstrate integration with concolic obfuscation handler.

    Args:
        binary_path: Path to binary for analysis

    """
    logger.info("Demonstrating concolic execution with obfuscation handling...")

    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        initial_state = project.factory.entry_state()

        simgr = create_enhanced_simgr(project, initial_state)

        obfuscation_engine = ObfuscationAwareConcolicEngine(simgr)

        logger.info("Integrated obfuscation-aware concolic engine with symbolic execution")

        simgr.step()

        if simgr.active:
            state = simgr.active[0]

            if hasattr(state, "history") and state.history.bbl_addrs:
                for addr in state.history.bbl_addrs[-5:]:
                    obfuscation_analysis = obfuscation_engine.analyze_basic_block_obfuscation(addr, [])

                    if obfuscation_analysis["obfuscation_detected"]:
                        logger.info(
                            f"Obfuscation detected at {hex(addr)}: "
                            f"{', '.join(obfuscation_analysis['techniques'])}"
                        )

        report = obfuscation_engine.get_obfuscation_report()
        logger.info(f"Obfuscation analysis: {report['summary']}")

    except Exception as e:
        logger.error(f"Concolic integration demonstration failed: {e}")


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: python angr_license_cracking_example.py <binary_path> [max_steps]")
        print("\nExample:")
        print("  python angr_license_cracking_example.py /path/to/protected.exe 100")
        sys.exit(1)

    binary_path = sys.argv[1]
    max_steps = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    logger.info("=== Intellicrack - Angr License Cracking Example ===")
    logger.info("This tool analyzes license validation using symbolic execution")
    logger.info("with advanced path prioritization and Windows API simprocedures.\n")

    results = analyze_license_validation(binary_path, max_steps)

    if "error" not in results:
        logger.info("\n=== Analysis Complete ===")
        logger.info(f"Explored {results['explored_states']} states")
        logger.info(f"Found {len(results['license_checks_found'])} license validation points")
        logger.info(f"Accessed {len(results['license_files_accessed'])} license files")

        if results["bypass_strategies"]:
            logger.info(f"\nGenerated {len(results['bypass_strategies'])} bypass strategies")

        logger.info("\nDemonstrating concolic integration...")
        demonstrate_concolic_integration(binary_path)
    else:
        logger.error(f"Analysis failed: {results['error']}")


if __name__ == "__main__":
    main()
