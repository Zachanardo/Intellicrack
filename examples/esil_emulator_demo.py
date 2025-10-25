"""ESIL Emulator Demonstration.

This example demonstrates the complete functionality of the RadareESILEmulator
for analyzing software licensing protections.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.radare2_esil_emulator import (
    ESILState,
    RadareESILEmulator,
)
from intellicrack.core.analysis.radare2_session_manager import R2SessionPool


def demo_basic_emulation(binary_path: str):
    """Demonstrate basic ESIL emulation."""
    print("=" * 60)
    print("DEMO 1: Basic Emulation")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print(f"\nBinary: {emulator.binary_path}")
        print(f"Architecture: {emulator.arch}-{emulator.bits}")
        print(f"Entry Point: 0x{emulator.entry_point:x}")
        print(f"Registers: {len(emulator.registers)}")

        print("\n--- Single Step Execution ---")
        step_info = emulator.step_instruction()

        print(f"Address: 0x{step_info['address']:x}")
        print(f"Instruction: {step_info['instruction']}")
        print(f"ESIL: {step_info['esil']}")

        if step_info['changed_registers']:
            print("Changed Registers:")
            for reg, changes in step_info['changed_registers'].items():
                print(f"  {reg}: 0x{changes['old']:x} → 0x{changes['new']:x}")

        print("\n--- Bulk Emulation ---")
        target = emulator.entry_point + 0x20
        trace = emulator.run_until(target, max_steps=100)

        print(f"Executed {len(trace)} instructions")
        print(f"Final State: {emulator.state}")


def demo_register_operations(binary_path: str):
    """Demonstrate register operations."""
    print("\n" + "=" * 60)
    print("DEMO 2: Register Operations")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Setting Register Values ---")
        emulator.set_register("rax", 0xDEADBEEF)
        emulator.set_register("rbx", 0xCAFEBABE)

        rax = emulator.get_register("rax")
        rbx = emulator.get_register("rbx")

        print(f"RAX: 0x{rax:x}")
        print(f"RBX: 0x{rbx:x}")

        print("\n--- Symbolic Register ---")
        emulator.set_register("rcx", 0x1234, symbolic=True)
        print("RCX marked as symbolic")
        print(f"Symbolic: {emulator.registers['rcx'].symbolic}")
        print(f"Constraints: {emulator.registers['rcx'].constraints}")


def demo_memory_operations(binary_path: str):
    """Demonstrate memory operations."""
    print("\n" + "=" * 60)
    print("DEMO 3: Memory Operations")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Reading Entry Point ---")
        code = emulator.get_memory(emulator.entry_point, 16)
        print(f"Code bytes: {code.hex()}")

        print("\n--- Writing Memory ---")
        test_addr = 0x200000
        test_data = b"LICENSE-KEY-12345"

        emulator.set_memory(test_addr, test_data)
        retrieved = emulator.get_memory(test_addr, len(test_data))

        print(f"Written: {test_data}")
        print(f"Read: {retrieved}")
        print(f"Match: {test_data == retrieved}")

        print("\n--- Symbolic Memory ---")
        emulator.set_memory(test_addr + 0x100, b"\xAA\xBB\xCC\xDD", symbolic=True)
        print(f"Symbolic memory regions: {len(emulator.symbolic_memory)}")


def demo_breakpoints(binary_path: str):
    """Demonstrate breakpoint system."""
    print("\n" + "=" * 60)
    print("DEMO 4: Breakpoint System")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        bp_hits = []

        def breakpoint_callback(emu, inst):
            bp_hits.append(inst)
            print(f"  Breakpoint hit at 0x{inst.get('offset', 0):x}")

        print("\n--- Adding Breakpoint ---")
        bp_addr = emulator.entry_point + 0x8
        bp = emulator.add_breakpoint(bp_addr, callback=breakpoint_callback)

        print(f"Breakpoint at 0x{bp_addr:x}")

        print("\n--- Running Until Breakpoint ---")
        emulator.run_until(0xFFFFFFFF, max_steps=100)

        if emulator.state == ESILState.BREAKPOINT:
            print(f"\nBreakpoint triggered {bp.hit_count} times")
        else:
            print("\nExecution completed without hitting breakpoint")


def demo_license_check_detection(binary_path: str):
    """Demonstrate license check detection."""
    print("\n" + "=" * 60)
    print("DEMO 5: License Check Detection")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Finding License Checks ---")
        checks = emulator.find_license_checks()

        print(f"Found {len(checks)} potential license checks")

        for i, check in enumerate(checks[:5]):
            print(f"\nCheck {i+1}:")
            print(f"  Address: 0x{check['address']:x}")
            print(f"  Type: {check['type']}")
            print(f"  Pattern: {check['pattern']}")

            if check['type'] == 'conditional_branch':
                if check.get('true_path'):
                    print(f"  True Path: 0x{check['true_path']:x}")
                if check.get('false_path'):
                    print(f"  False Path: 0x{check['false_path']:x}")


def demo_taint_analysis(binary_path: str):
    """Demonstrate taint analysis."""
    print("\n" + "=" * 60)
    print("DEMO 6: Taint Analysis")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Setting Up Taint Source ---")
        serial_addr = 0x200000
        serial = b"TEST-1234-5678"

        emulator.set_memory(serial_addr, serial)
        emulator.add_taint_source(serial_addr, size=len(serial))

        print(f"Taint source at 0x{serial_addr:x}")
        print(f"Input: {serial}")

        print("\n--- Emulating with Taint Tracking ---")
        trace = emulator.run_until(emulator.entry_point + 0x30, max_steps=100)

        tainted_regs = [reg for reg, state in emulator.registers.items()
                        if state.tainted]

        print(f"Executed {len(trace)} instructions")
        print(f"Tainted registers: {tainted_regs}")
        print(f"Symbolic memory locations: {len(emulator.symbolic_memory)}")


def demo_api_call_extraction(binary_path: str):
    """Demonstrate API call extraction."""
    print("\n" + "=" * 60)
    print("DEMO 7: API Call Extraction")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Emulating Code ---")
        trace = emulator.run_until(emulator.entry_point + 0x50, max_steps=200)

        print(f"Executed {len(trace)} instructions")

        print("\n--- Extracting API Calls ---")
        api_calls = emulator.extract_api_calls()

        print(f"Found {len(api_calls)} API calls")

        for call in api_calls[:10]:
            print(f"\n  {call['api']}")
            print(f"    Address: 0x{call['address']:x}")
            print(f"    Stack Ptr: 0x{call['stack_ptr']:x}")

            if call.get('arguments'):
                for i, arg in enumerate(call['arguments'][:4]):
                    print(f"    Arg {i}: 0x{arg:x}")


def demo_path_constraints(binary_path: str):
    """Demonstrate path constraint generation."""
    print("\n" + "=" * 60)
    print("DEMO 8: Path Constraint Generation")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        target = emulator.entry_point + 0x20

        print(f"\n--- Generating Constraints to 0x{target:x} ---")
        constraints = emulator.generate_path_constraints(target)

        print(f"Generated {len(constraints)} constraints")

        for i, constraint in enumerate(constraints[:5]):
            print(f"  {i+1}. {constraint}")


def demo_execution_trace(binary_path: str):
    """Demonstrate execution trace export."""
    print("\n" + "=" * 60)
    print("DEMO 9: Execution Trace Export")
    print("=" * 60)

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print("\n--- Setting Up Analysis ---")
        emulator.add_breakpoint(emulator.entry_point + 0x10)
        emulator.add_taint_source(0x200000, size=16)

        print("\n--- Emulating ---")
        trace = emulator.run_until(emulator.entry_point + 0x30, max_steps=100)

        print(f"Executed {len(trace)} instructions")

        print("\n--- Exporting Trace ---")
        trace_file = "demo_trace.json"
        emulator.dump_execution_trace(trace_file)

        print(f"Trace saved to {trace_file}")
        print(f"  Instructions: {emulator.instruction_count}")
        print(f"  Memory accesses: {len(emulator.memory_accesses)}")
        print(f"  Call stack depth: {len(emulator.call_stack)}")


def demo_session_pool(binary_path: str):
    """Demonstrate session pool usage."""
    print("\n" + "=" * 60)
    print("DEMO 10: Session Pool Integration")
    print("=" * 60)

    print("\n--- Creating Session Pool ---")
    pool = R2SessionPool(max_sessions=3)

    print("Pool created with max_sessions=3")

    print("\n--- Using Pooled Sessions ---")
    for i in range(3):
        with RadareESILEmulator(binary_path=binary_path, session_pool=pool) as emulator:
            trace = emulator.run_until(emulator.entry_point + 0x10, max_steps=50)
            print(f"  Session {i+1}: Executed {len(trace)} instructions")

    print("\n--- Pool Statistics ---")
    stats = pool.get_pool_stats()
    print(f"Total sessions: {stats['total_sessions']}")
    print(f"Active sessions: {stats['active_sessions']}")
    print(f"Total commands: {stats['total_commands_executed']}")

    pool.shutdown()
    print("\nPool shutdown complete")


def main():
    """Run all demonstrations."""
    if len(sys.argv) < 2:
        print("Usage: python esil_emulator_demo.py <binary_path>")
        print("\nThis will demonstrate all ESIL emulator capabilities:")
        print("  1. Basic emulation")
        print("  2. Register operations")
        print("  3. Memory operations")
        print("  4. Breakpoint system")
        print("  5. License check detection")
        print("  6. Taint analysis")
        print("  7. API call extraction")
        print("  8. Path constraint generation")
        print("  9. Execution trace export")
        print("  10. Session pool integration")
        return 1

    binary_path = sys.argv[1]

    if not Path(binary_path).exists():
        print(f"Error: Binary not found: {binary_path}")
        return 1

    print("ESIL Emulator Demonstration")
    print("=" * 60)
    print(f"Target Binary: {binary_path}")
    print("=" * 60)

    try:
        demo_basic_emulation(binary_path)
        demo_register_operations(binary_path)
        demo_memory_operations(binary_path)
        demo_breakpoints(binary_path)
        demo_license_check_detection(binary_path)
        demo_taint_analysis(binary_path)
        demo_api_call_extraction(binary_path)
        demo_path_constraints(binary_path)
        demo_execution_trace(binary_path)
        demo_session_pool(binary_path)

        print("\n" + "=" * 60)
        print("All Demonstrations Complete!")
        print("=" * 60)

        print("\nESIL Emulator Features Demonstrated:")
        print("  ✅ ESIL VM Integration")
        print("  ✅ Code Emulation (single-step and bulk)")
        print("  ✅ State Tracking (registers, memory, execution)")
        print("  ✅ Breakpoint System (with callbacks)")
        print("  ✅ License Check Detection")
        print("  ✅ Taint Analysis")
        print("  ✅ API Call Extraction")
        print("  ✅ Path Constraint Generation")
        print("  ✅ Execution Trace Export")
        print("  ✅ Session Pool Integration")

        return 0

    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
