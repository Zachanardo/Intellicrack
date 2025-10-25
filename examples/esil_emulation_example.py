"""Example usage of RadareESILEmulator for license check analysis.

This example demonstrates how to use the ESIL emulator to:
1. Emulate code execution without running the binary
2. Track register and memory state changes
3. Set breakpoints with conditions
4. Find potential license validation routines
5. Extract API calls and control flow

Usage:
    python esil_emulation_example.py <binary_path> [example_name]

Examples:
    python esil_emulation_example.py binary.exe basic
    python esil_emulation_example.py binary.exe breakpoints
    python esil_emulation_example.py binary.exe license_checks

Copyright (C) 2025 Zachary Flint

"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from intellicrack.core.analysis.radare2_esil_emulator import RadareESILEmulator
from intellicrack.core.analysis.radare2_session_manager import get_global_pool

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def example_basic_emulation(binary_path: str, num_steps: int = 10):
    """Basic ESIL emulation example.

    Args:
        binary_path: Path to binary file to analyze
        num_steps: Number of instructions to execute

    """
    logger.info("=== Basic Emulation Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            logger.info(f"Architecture: {emulator.arch}-{emulator.bits}")
            logger.info(f"Entry point: 0x{emulator.entry_point:x}")

            for i in range(num_steps):
                try:
                    step = emulator.step_instruction()
                    logger.info(f"\nStep {i+1}:")
                    logger.info(f"  Address: 0x{step['address']:x}")
                    logger.info(f"  Instruction: {step['instruction']}")
                    logger.info(f"  ESIL: {step['esil']}")

                    if step['changed_registers']:
                        logger.info("  Changed registers:")
                        for reg, change in step['changed_registers'].items():
                            logger.info(f"    {reg}: 0x{change['old']:x} -> 0x{change['new']:x}")

                    if step['memory_accesses']:
                        logger.info(f"  Memory accesses: {len(step['memory_accesses'])}")

                    if step['control_flow']:
                        cf = step['control_flow']
                        logger.info(f"  Control flow: {cf['type']} (0x{cf['from']:x} -> 0x{cf['to']:x})")

                except RuntimeError as e:
                    logger.error(f"Failed to step: {e}")
                    break

    except Exception as e:
        logger.error(f"Emulation failed: {e}")
        raise


def example_with_breakpoints(binary_path: str, target_addr: Optional[int] = None):
    """Example using breakpoints and callbacks.

    Args:
        binary_path: Path to binary file to analyze
        target_addr: Optional target address for breakpoint

    """
    logger.info("=== Breakpoint Example ===")
    logger.info(f"Binary: {binary_path}")

    def breakpoint_callback(emulator, inst_info):
        """Called when breakpoint is hit."""
        logger.info(f"\n>>> Breakpoint hit at 0x{inst_info['offset']:x}")
        try:
            regs = emulator._get_register_state()
            for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'eax', 'ebx', 'r0', 'r1']:
                if reg_name in regs:
                    logger.info(f"  {reg_name.upper()} = 0x{regs[reg_name]:x}")
        except Exception as e:
            logger.warning(f"Could not read registers: {e}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            if target_addr is None:
                target_addr = emulator.entry_point + 0x100

            logger.info(f"Setting breakpoint at 0x{target_addr:x}")
            emulator.add_breakpoint(target_addr, callback=breakpoint_callback)

            logger.info(f"Running until 0x{target_addr:x}...")
            trace = emulator.run_until(target_addr, max_steps=1000)

            logger.info("\nExecution summary:")
            logger.info(f"  Instructions executed: {len(trace)}")
            logger.info(f"  Final state: {emulator.state.value}")
            logger.info(f"  Call stack depth: {len(emulator.call_stack)}")

    except Exception as e:
        logger.error(f"Breakpoint example failed: {e}")
        raise


def example_find_license_checks(binary_path: str):
    """Example finding potential license validation code.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== License Check Detection Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            logger.info("Searching for potential license validation routines...")
            license_checks = emulator.find_license_checks()

            logger.info(f"\nFound {len(license_checks)} potential license check locations:")

            for i, check in enumerate(license_checks[:20]):
                logger.info(f"\n{i+1}. Address: 0x{check['address']:x}")
                logger.info(f"   Type: {check['type']}")
                logger.info(f"   Pattern: {check['pattern']}")

                if check.get('true_path'):
                    logger.info(f"   True branch: 0x{check['true_path']:x}")
                if check.get('false_path'):
                    logger.info(f"   False branch: 0x{check['false_path']:x}")

            if len(license_checks) > 20:
                logger.info(f"\n... and {len(license_checks) - 20} more")

    except Exception as e:
        logger.error(f"License check detection failed: {e}")
        raise


def example_memory_and_registers(binary_path: str):
    """Example manipulating memory and registers.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== Memory/Register Manipulation Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            logger.info("Setting up test environment...")

            try:
                emulator.set_register("rax", 0x1337)
                emulator.set_register("rbx", 0x4242)
                logger.info("Set RAX=0x1337, RBX=0x4242")
            except Exception:
                try:
                    emulator.set_register("eax", 0x1337)
                    emulator.set_register("ebx", 0x4242)
                    logger.info("Set EAX=0x1337, EBX=0x4242")
                except Exception as e:
                    logger.warning(f"Could not set x86 registers: {e}")

            test_data_addr = 0x500000
            injected_serial = b"PROD-1234-5678-ABCD-EFGH"
            emulator.set_memory(test_data_addr, injected_serial)
            logger.info(f"Injected test serial at 0x{test_data_addr:x}: {injected_serial.decode('ascii')}")

            logger.info("\nExecuting instructions and monitoring comparisons...")
            for _i in range(50):
                try:
                    step = emulator.step_instruction()

                    if "cmp" in step['instruction'].lower() or "test" in step['instruction'].lower():
                        logger.info(f"\nComparison at 0x{step['address']:x}:")
                        logger.info(f"  Instruction: {step['instruction']}")
                        logger.info(f"  ESIL: {step['esil']}")

                        for mem_access in step['memory_accesses']:
                            if mem_access.address == test_data_addr:
                                logger.info("  >>> Accessed our injected serial data!")
                            elif test_data_addr <= mem_access.address < test_data_addr + len(injected_serial):
                                offset = mem_access.address - test_data_addr
                                logger.info(f"  >>> Accessed serial byte at offset {offset}")

                except RuntimeError:
                    break

    except Exception as e:
        logger.error(f"Memory/register example failed: {e}")
        raise


def example_taint_analysis(binary_path: str):
    """Example using taint analysis to track data flow.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== Taint Analysis Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            user_input_addr = 0x600000
            user_input = b"USER_INPUT_DATA_HERE"

            logger.info(f"Setting up taint source at 0x{user_input_addr:x}")
            emulator.set_memory(user_input_addr, user_input)
            emulator.add_taint_source(user_input_addr, size=len(user_input))

            target = emulator.entry_point + 0x500
            logger.info(f"Running until 0x{target:x}...")
            trace = emulator.run_until(target, max_steps=500)

            tainted_regs = [
                reg for reg, state in emulator.registers.items()
                if state.tainted
            ]

            logger.info("\nTaint analysis results:")
            logger.info(f"  Instructions executed: {len(trace)}")
            logger.info(f"  Tainted registers: {tainted_regs}")

            logger.info("\nInstructions using tainted data:")
            for step in trace:
                if any(reg in tainted_regs for reg in step['changed_registers']):
                    logger.info(f"  0x{step['address']:x}: {step['instruction']}")

    except Exception as e:
        logger.error(f"Taint analysis failed: {e}")
        raise


def example_api_call_extraction(binary_path: str):
    """Example extracting API calls and arguments.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== API Call Extraction Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            target = emulator.entry_point + 0x1000
            logger.info(f"Emulating to 0x{target:x}...")
            emulator.run_until(target, max_steps=1000)

            api_calls = emulator.extract_api_calls()

            logger.info(f"\nExtracted {len(api_calls)} API calls:")
            for call in api_calls[:30]:
                logger.info(f"\n  0x{call['address']:x}: {call['api']}")
                logger.info(f"    Stack pointer: 0x{call['stack_ptr']:x}")
                if call['arguments']:
                    logger.info("    Arguments:")
                    for i, arg in enumerate(call['arguments']):
                        logger.info(f"      arg{i}: 0x{arg:x}")

            if len(api_calls) > 30:
                logger.info(f"\n... and {len(api_calls) - 30} more API calls")

    except Exception as e:
        logger.error(f"API call extraction failed: {e}")
        raise


def example_path_constraints(binary_path: str, target_addr: Optional[int] = None):
    """Example generating path constraints for symbolic execution.

    Args:
        binary_path: Path to binary file to analyze
        target_addr: Optional target address

    """
    logger.info("=== Path Constraints Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            if target_addr is None:
                target_addr = emulator.entry_point + 0x200

            logger.info(f"Generating path constraints to reach 0x{target_addr:x}...")
            constraints = emulator.generate_path_constraints(target_addr)

            logger.info(f"\nPath constraints ({len(constraints)} total):")
            for i, constraint in enumerate(constraints[:20]):
                logger.info(f"  {i+1}. {constraint}")

            if len(constraints) > 20:
                logger.info(f"\n... and {len(constraints) - 20} more constraints")

    except Exception as e:
        logger.error(f"Path constraint generation failed: {e}")
        raise


def example_with_session_pool(binary_path: str):
    """Example using session pool for efficiency.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== Session Pool Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        pool = get_global_pool(max_sessions=5)
        logger.info("Using global session pool for resource efficiency")

        with RadareESILEmulator(binary_path, session_pool=pool) as emulator:
            target = emulator.entry_point + 0x100
            trace = emulator.run_until(target, max_steps=100)

            logger.info(f"\nExecuted {len(trace)} instructions")
            logger.info(f"Final state: {emulator.state.value}")

            output_file = Path("esil_trace_output.json")
            emulator.dump_execution_trace(str(output_file))
            logger.info(f"Execution trace saved to {output_file}")

            logger.info("\nTrace summary:")
            with open(output_file, 'r') as f:
                trace_data = json.load(f)
                logger.info(f"  Binary: {trace_data['binary']}")
                logger.info(f"  Architecture: {trace_data['architecture']}")
                logger.info(f"  Instructions: {trace_data['instruction_count']}")
                logger.info(f"  API calls: {len(trace_data['api_calls'])}")
                logger.info(f"  Memory accesses: {len(trace_data['memory_accesses'])}")

    except Exception as e:
        logger.error(f"Session pool example failed: {e}")
        raise


def example_reset_and_reuse(binary_path: str):
    """Example resetting emulator state for multiple analyses.

    Args:
        binary_path: Path to binary file to analyze

    """
    logger.info("=== Reset and Reuse Example ===")
    logger.info(f"Binary: {binary_path}")

    try:
        with RadareESILEmulator(binary_path) as emulator:
            target = emulator.entry_point + 0x500

            logger.info("\nFirst run - testing success condition")
            try:
                emulator.set_register("rax", 1)
            except Exception:
                try:
                    emulator.set_register("eax", 1)
                except Exception:
                    logger.warning("Could not set success register")

            trace1 = emulator.run_until(target, max_steps=500)
            logger.info(f"  Success path: {len(trace1)} instructions")

            logger.info("\nResetting emulator state...")
            emulator.reset()

            logger.info("Second run - testing failure condition")
            try:
                emulator.set_register("rax", 0)
            except Exception:
                try:
                    emulator.set_register("eax", 0)
                except Exception:
                    logger.warning("Could not set failure register")

            trace2 = emulator.run_until(target, max_steps=500)
            logger.info(f"  Failure path: {len(trace2)} instructions")

            logger.info("\nPath comparison:")
            logger.info(f"  Instructions difference: {abs(len(trace1) - len(trace2))}")

    except Exception as e:
        logger.error(f"Reset and reuse example failed: {e}")
        raise


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ESIL Emulation Examples for License Check Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available examples:
  basic           - Basic step-by-step instruction emulation
  breakpoints     - Conditional breakpoints with callbacks
  license_checks  - Find potential license validation routines
  memory_regs     - Memory and register manipulation
  taint           - Taint analysis for data flow tracking
  api_calls       - API call extraction with arguments
  constraints     - Path constraint generation
  session_pool    - Efficient session pool usage
  reset           - Reset and reuse emulator
  all             - Run all examples

Examples:
  python esil_emulation_example.py binary.exe basic
  python esil_emulation_example.py binary.exe license_checks
  python esil_emulation_example.py binary.exe all
        """
    )

    parser.add_argument(
        'binary_path',
        help='Path to binary file to analyze'
    )
    parser.add_argument(
        'example',
        nargs='?',
        default='basic',
        choices=[
            'basic', 'breakpoints', 'license_checks', 'memory_regs',
            'taint', 'api_calls', 'constraints', 'session_pool',
            'reset', 'all'
        ],
        help='Example to run (default: basic)'
    )
    parser.add_argument(
        '--steps',
        type=int,
        default=10,
        help='Number of steps for basic example (default: 10)'
    )
    parser.add_argument(
        '--target',
        type=lambda x: int(x, 0),
        help='Target address (hex or decimal)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    binary_path = Path(args.binary_path)
    if not binary_path.exists():
        logger.error(f"Binary file not found: {binary_path}")
        return 1

    try:
        examples = {
            'basic': lambda: example_basic_emulation(str(binary_path), args.steps),
            'breakpoints': lambda: example_with_breakpoints(str(binary_path), args.target),
            'license_checks': lambda: example_find_license_checks(str(binary_path)),
            'memory_regs': lambda: example_memory_and_registers(str(binary_path)),
            'taint': lambda: example_taint_analysis(str(binary_path)),
            'api_calls': lambda: example_api_call_extraction(str(binary_path)),
            'constraints': lambda: example_path_constraints(str(binary_path), args.target),
            'session_pool': lambda: example_with_session_pool(str(binary_path)),
            'reset': lambda: example_reset_and_reuse(str(binary_path))
        }

        if args.example == 'all':
            for name, func in examples.items():
                logger.info(f"\n{'='*60}")
                logger.info(f"Running example: {name}")
                logger.info(f"{'='*60}\n")
                try:
                    func()
                except Exception as e:
                    logger.error(f"Example '{name}' failed: {e}")
                logger.info("\n")
        else:
            examples[args.example]()

        return 0

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
