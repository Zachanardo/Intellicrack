"""
Dynamic Mutation Tester for Phase 2.5 validation.
Tests Intellicrack's response to real-time protection mutations.
"""

import os
import time
import hashlib
import random
import shutil
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    import pefile
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
    import pefile

from commercial_binary_manager import CommercialBinaryManager
from phase2.detection_validator import DetectionValidator
from protection_variant_generator import ProtectionVariantGenerator, MutationType

logger = logging.getLogger(__name__)


@dataclass
class MutationTestResult:
    """Result of testing a dynamic mutation."""
    mutation_type: str
    original_binary: str
    mutated_binary: str
    original_hash: str
    mutated_hash: str
    detection_before: dict[str, Any]
    detection_after: dict[str, Any]
    adaptation_detected: bool
    bypass_persistence: bool
    success: bool
    error_message: str | None = None
    timestamp: str | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class DynamicMutationReport:
    """Comprehensive report of dynamic mutation testing."""
    mutation_type: str
    test_results: list[MutationTestResult]
    adaptation_rate: float
    persistence_rate: float
    overall_success: bool
    timestamp: str | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class DynamicMutationTester:
    """Tests Intellicrack's response to real-time protection mutations."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system") -> None:
        self.base_dir = Path(base_dir)
        self.mutations_dir = self.base_dir / "dynamic_mutations"
        self.mutations_dir.mkdir(exist_ok=True)
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        self.binary_manager = CommercialBinaryManager(base_dir)
        self.detection_validator = DetectionValidator(base_dir)
        self.variant_generator = ProtectionVariantGenerator(str(self.mutations_dir))

        # Define dynamic mutation types
        self.dynamic_mutations: dict[str, dict[str, str | Callable[[str, int], str]]] = {
            "changing_protection": {
                "description": "Protection that changes after each run",
                "implementation": self._create_changing_protection
            },
            "self_modifying": {
                "description": "Self-modifying protection code",
                "implementation": self._create_self_modifying_protection
            },
            "polymorphic": {
                "description": "Polymorphic protection routines",
                "implementation": self._create_polymorphic_protection
            }
        }

        # Track test results
        self.test_results: list[MutationTestResult] = []

    def _create_changing_protection(self, binary_path: str, run_count: int) -> str:
        """
        Create a protection that changes after each run.
        """
        output_path = str(Path(binary_path).parent / f"changing_protection_run_{run_count}.exe")
        shutil.copy2(binary_path, output_path)

        try:
            pe = pefile.PE(output_path)

            # Modify protection based on run count
            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Change protection constants based on run count
                    # This simulates a protection that evolves
                    magic_constant = 0xDEADBEEF + run_count
                    magic_bytes = struct.pack('<I', magic_constant)

                    # Find and replace a magic number
                    search_pattern = struct.pack('<I', 0xDEADBEEF)
                    offset = code_data.find(search_pattern)
                    if offset != -1:
                        code_data[offset:offset+4] = magic_bytes

                    # Add run-specific markers
                    marker = f"RUN_{run_count}_PROTECTION".encode()
                    if len(marker) < len(code_data) - 10:
                        pos = random.randint(10, len(code_data) - len(marker) - 10)
                        code_data[pos:pos+len(marker)] = marker

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(output_path)
            pe.close()

            logger.info(f"Created changing protection binary (run {run_count}): {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error creating changing protection: {e}")
            raise

    def _create_self_modifying_protection(self, binary_path: str, modification_id: int) -> str:
        """
        Create self-modifying protection code.
        """
        output_path = str(Path(binary_path).parent / f"self_modifying_{modification_id}.exe")
        shutil.copy2(binary_path, output_path)

        try:
            pe = pefile.PE(output_path)

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Add self-modifying code
                    self_modify_code = self._generate_self_modifying_code(modification_id)

                    if cave_offset := self.variant_generator._find_code_cave(
                        pe, len(self_modify_code)
                    ):
                        pe.set_bytes_at_offset(cave_offset, self_modify_code)

                    # Add markers
                    marker = f"SELF_MODIFY_{modification_id}".encode()
                    if len(marker) < len(code_data) - 10:
                        pos = random.randint(10, len(code_data) - len(marker) - 10)
                        code_data[pos:pos+len(marker)] = marker

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(output_path)
            pe.close()

            logger.info(f"Created self-modifying protection binary: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error creating self-modifying protection: {e}")
            raise

    def _create_polymorphic_protection(self, binary_path: str, variant_id: int) -> str:
        """
        Create polymorphic protection routines.
        """
        output_path = str(Path(binary_path).parent / f"polymorphic_{variant_id}.exe")
        shutil.copy2(binary_path, output_path)

        try:
            pe = pefile.PE(output_path)

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Add polymorphic code that changes form but not function
                    poly_code = self._generate_polymorphic_code(variant_id)

                    if cave_offset := self.variant_generator._find_code_cave(
                        pe, len(poly_code)
                    ):
                        pe.set_bytes_at_offset(cave_offset, poly_code)

                    # Add markers
                    marker = f"POLYMORPHIC_{variant_id}".encode()
                    if len(marker) < len(code_data) - 10:
                        pos = random.randint(10, len(code_data) - len(marker) - 10)
                        code_data[pos:pos+len(marker)] = marker

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(output_path)
            pe.close()

            logger.info(f"Created polymorphic protection binary: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error creating polymorphic protection: {e}")
            raise

    def _generate_self_modifying_code(self, modification_id: int) -> bytes:
        """Generate self-modifying code."""
        # This would be real assembly code in a production implementation
        code = bytearray([
            0x50,  # PUSH EAX
            0x51,  # PUSH ECX
            0x52,  # PUSH EDX

            # MOV EAX, target_address
            0xB8,
            0x00, 0x10, 0x40, 0x00,  # Address to modify

            # MOV ECX, new_value
            0xB9,
            modification_id & 0xFF, (modification_id >> 8) & 0xFF,
            (modification_id >> 16) & 0xFF, (modification_id >> 24) & 0xFF,

            # MOV [EAX], ECX (self-modification)
            0x89, 0x08,

            0x5A,  # POP EDX
            0x59,  # POP ECX
            0x58,  # POP EAX
            0xC3   # RET
        ])
        return bytes(code)

    def _generate_polymorphic_code(self, variant_id: int) -> bytes:
        """Generate polymorphic code with equivalent functionality."""
        # Create different implementations of the same logic
        if variant_id % 3 == 0:
            # Version 1: Direct calculation
            code = bytearray([
                0x50,  # PUSH EAX
                0xB8, variant_id & 0xFF, (variant_id >> 8) & 0xFF,
                (variant_id >> 16) & 0xFF, (variant_id >> 24) & 0xFF,  # MOV EAX, imm32
                0x05, 0x01, 0x00, 0x00, 0x00,  # ADD EAX, 1
                0x58   # POP EAX
            ])
        elif variant_id % 3 == 1:
            # Version 2: Using XOR
            code = bytearray([
                0x50,  # PUSH EAX
                0x31, 0xC0,  # XOR EAX, EAX
                0x05, variant_id & 0xFF, (variant_id >> 8) & 0xFF,
                (variant_id >> 16) & 0xFF, (variant_id >> 24) & 0xFF,  # ADD EAX, imm32
                0x05, 0x01, 0x00, 0x00, 0x00,  # ADD EAX, 1
                0x58   # POP EAX
            ])
        else:
            # Version 3: Using NEG
            code = bytearray([
                0x50,  # PUSH EAX
                0xB8, -(variant_id + 1) & 0xFFFFFFFF,  # MOV EAX, -imm32
                0xF7, 0xD8,  # NEG EAX
                0x58   # POP EAX
            ])

        # Add RET
        code.extend([0xC3])
        return bytes(code)

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def test_dynamic_mutation(self, mutation_type: str, base_binary: str) -> MutationTestResult:
        """
        Test Intellicrack's response to a dynamic mutation.
        """
        logger.info(f"Testing dynamic mutation: {mutation_type}")

        try:
            # Create mutated binary
            if mutation_type not in self.dynamic_mutations:
                raise ValueError(f"Unknown mutation type: {mutation_type}")

            implementation = self.dynamic_mutations[mutation_type]["implementation"]
            if not callable(implementation):
                raise TypeError(f"Implementation for {mutation_type} is not callable")

            # For changing protection, use run count
            # For others, use random ID
            if mutation_type == "changing_protection":
                mutated_binary = implementation(base_binary, int(time.time()) % 100)
            else:
                mutated_binary = implementation(base_binary, random.randint(1, 1000))

            # Calculate hashes
            original_hash = self._calculate_hash(base_binary)
            mutated_hash = self._calculate_hash(mutated_binary)

            # Run detection before mutation (on base binary)
            detection_before = self.detection_validator.validate_detection(
                base_binary,
                "Base Binary",
                "Original Protection"
            )

            # Run detection after mutation (on mutated binary)
            detection_after = self.detection_validator.validate_detection(
                mutated_binary,
                f"Mutated Binary - {mutation_type}",
                f"Mutated Protection ({mutation_type})"
            )

            # Check if Intellicrack adapts or reports mutation detected
            # This is a simplified check - in reality, we'd need more sophisticated analysis
            protections_before = len(detection_before.get("protections", []))
            protections_after = len(detection_after.get("protections", []))

            # Adaptation detected if it can still analyze the mutated binary
            adaptation_detected = protections_after > 0

            # Bypass persistence would require actual bypass testing
            # For now, we'll assume it's not persistent
            bypass_persistence = False

            result = MutationTestResult(
                mutation_type=mutation_type,
                original_binary=base_binary,
                mutated_binary=mutated_binary,
                original_hash=original_hash,
                mutated_hash=mutated_hash,
                detection_before=detection_before,
                detection_after=detection_after,
                adaptation_detected=adaptation_detected,
                bypass_persistence=bypass_persistence,
                success=True
            )

            self.test_results.append(result)
            return result

        except Exception as e:
            logger.error(f"Failed to test dynamic mutation {mutation_type}: {e}")
            result = MutationTestResult(
                mutation_type=mutation_type,
                original_binary=base_binary,
                mutated_binary="",
                original_hash="",
                mutated_hash="",
                detection_before={},
                detection_after={},
                adaptation_detected=False,
                bypass_persistence=False,
                success=False,
                error_message=str(e)
            )

            self.test_results.append(result)
            return result

    def test_mutation_sequence(self, base_binary: str, mutation_types: list[str],
                              sequence_length: int = 5) -> list[MutationTestResult]:
        """
        Test a sequence of mutations on a binary.
        """
        results = []
        current_binary = base_binary

        for i in range(sequence_length):
            # Select a mutation type (rotate through the list)
            mutation_type = mutation_types[i % len(mutation_types)]

            # Test the mutation
            result = self.test_dynamic_mutation(mutation_type, current_binary)
            results.append(result)

            # Use the mutated binary for the next iteration if successful
            if result.success and result.mutated_binary:
                current_binary = result.mutated_binary

        return results

    def generate_comprehensive_report(self) -> str:
        """
        Generate a comprehensive report of all dynamic mutation tests.
        """
        if not self.test_results:
            return "No tests have been run yet."

        report_lines = [
            "Dynamic Mutation Testing Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Tests: {len(self.test_results)}",
            ""
        ]

        # Group results by mutation type
        mutation_results: dict[str, list[MutationTestResult]] = {}
        for result in self.test_results:
            if result.mutation_type not in mutation_results:
                mutation_results[result.mutation_type] = []
            mutation_results[result.mutation_type].append(result)

        # Report for each mutation type
        for mutation_type, results in mutation_results.items():
            mutation_desc = self.dynamic_mutations.get(mutation_type, {}).get("description", "Unknown")
            report_lines.append(f"Mutation Type: {mutation_type}")
            report_lines.extend((f"Description: {mutation_desc}", "-" * 30))
            successful_tests = sum(bool(r.success)
                               for r in results)
            adaptation_detected = sum(bool(r.adaptation_detected)
                                  for r in results)

            report_lines.extend(
                (
                    f"  Successful Tests: {successful_tests}/{len(results)}",
                    f"  Adaptation Detected: {adaptation_detected}/{len(results)}",
                )
            )
            for result in results:
                report_lines.extend(
                    (
                        f"    Test: {Path(result.original_binary).name} -> {Path(result.mutated_binary).name if result.mutated_binary else 'FAILED'}",
                        f"      Success: {result.success}",
                    )
                )
                if result.success:
                    report_lines.extend(
                        (
                            f"      Adaptation Detected: {result.adaptation_detected}",
                            f"      Hash Changed: {result.original_hash[:8]}... -> {result.mutated_hash[:8]}...",
                        )
                    )
                else:
                    report_lines.append(f"      Error: {result.error_message}")
                report_lines.append("")

        return "\n".join(report_lines)

    def save_report(self, report_data: dict[str, Any], filename: str | None = None) -> str:
        """
        Save a dynamic mutation test report to a JSON file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dynamic_mutation_test_report_{timestamp}.json"

        report_path = self.reports_dir / filename

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"Saved dynamic mutation test report to {report_path}")
        return str(report_path)


# Add the missing import at the top
import struct

if __name__ == "__main__":
    # Test the dynamic mutation tester
    tester = DynamicMutationTester()

    print("Dynamic Mutation Tester initialized")
    print("Supported dynamic mutations:")
    for mutation_name, mutation_info in tester.dynamic_mutations.items():
        print(f"  {mutation_name}: {mutation_info['description']}")

    # Test with real binaries if available
    try:
        if binaries := tester.binary_manager.list_acquired_binaries():
            print(f"\nFound {len(binaries)} acquired binaries:")
            for binary in binaries:
                print(f"  - {binary.get('software_name')}: {binary.get('protection')} {binary.get('version')}")

            # Run tests on the first available binary
            if binaries:
                first_binary = binaries[0]
                binary_path = first_binary.get("file_path")
                software_name = first_binary.get("software_name", "Unknown")

                print(f"\nRunning dynamic mutation tests on {software_name}...")

                # Test all mutation types
                mutation_types = list(tester.dynamic_mutations.keys())
                results = []

                for mutation_type in mutation_types:
                    result = tester.test_dynamic_mutation(mutation_type, binary_path)
                    results.append(result)
                    print(f"  Tested {mutation_type}: {'SUCCESS' if result.success else 'FAILED'}")

                # Test mutation sequence
                print(f"\nRunning mutation sequence test...")
                sequence_results = tester.test_mutation_sequence(binary_path, mutation_types, 3)
                results.extend(sequence_results)
                print(f"  Completed sequence of {len(sequence_results)} mutations")

                # Generate and save report
                report_text = tester.generate_comprehensive_report()
                print("\nTest Report:")
                print(report_text)

                # Save detailed report
                report_data = {
                    "timestamp": datetime.now().isoformat(),
                    "binary_tested": binary_path,
                    "software_name": software_name,
                    "results": [asdict(result) for result in results]
                }
                report_path = tester.save_report(report_data)
                print(f"\nDetailed report saved to: {report_path}")
        else:
            print("\nNo binaries acquired yet. Please acquire binaries using commercial_binary_manager.py")
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()
