# ESIL Emulator Quick Start Guide

## Introduction

The RadareESILEmulator provides sophisticated ESIL (Evaluable Strings Intermediate Language) virtual machine capabilities for analyzing software licensing protections without execution. This guide shows you how to use it effectively.

## Basic Usage

### Simple Emulation

```python
from intellicrack.core.analysis.radare2_esil_emulator import RadareESILEmulator

# Create emulator (auto-analyzes binary)
with RadareESILEmulator(binary_path="target.exe") as emulator:
    # Single step
    step_info = emulator.step_instruction()
    print(f"Executed: {step_info['instruction']} at 0x{step_info['address']:x}")

    # Run until target
    trace = emulator.run_until(0x401234, max_steps=1000)
    print(f"Executed {len(trace)} instructions")
```

### With Session Pool (Recommended for Multiple Binaries)

```python
from intellicrack.core.analysis.radare2_session_manager import R2SessionPool
from intellicrack.core.analysis.radare2_esil_emulator import RadareESILEmulator

# Create session pool
pool = R2SessionPool(max_sessions=5)

# Analyze multiple binaries efficiently
for binary in ["app1.exe", "app2.exe", "app3.exe"]:
    with RadareESILEmulator(binary_path=binary, session_pool=pool) as emulator:
        checks = emulator.find_license_checks()
        print(f"{binary}: Found {len(checks)} license checks")

pool.shutdown()
```

## Register Operations

### Reading Registers

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Get register value
    rax = emulator.get_register("rax")
    print(f"RAX = 0x{rax:x}")

    # Get all register state
    regs = emulator._get_register_state()
    for name, value in regs.items():
        print(f"{name} = 0x{value:x}")
```

### Setting Registers

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Set concrete value
    emulator.set_register("rax", 0xDEADBEEF)

    # Set symbolic value for taint analysis
    emulator.set_register("rbx", 0x1234, symbolic=True)

    # Verify
    value = emulator.get_register("rax")
    assert value == 0xDEADBEEF
```

## Memory Operations

### Reading Memory

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Read from entry point
    code = emulator.get_memory(emulator.entry_point, 16)
    print(f"Entry point bytes: {code.hex()}")

    # Read specific address
    data = emulator.get_memory(0x402000, 256)
```

### Writing Memory

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Write concrete data
    emulator.set_memory(0x200000, b"LICENSE-KEY-12345")

    # Write symbolic data for tracking
    emulator.set_memory(0x200100, b"\x00" * 32, symbolic=True)

    # Verify
    data = emulator.get_memory(0x200000, 17)
    assert data == b"LICENSE-KEY-12345"
```

## Execution Control

### Single Stepping

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Step through instructions
    for i in range(10):
        step = emulator.step_instruction()

        print(f"Step {i}:")
        print(f"  Address: 0x{step['address']:x}")
        print(f"  Instruction: {step['instruction']}")
        print(f"  ESIL: {step['esil']}")

        # Check register changes
        if step['changed_registers']:
            for reg, changes in step['changed_registers'].items():
                print(f"  {reg}: 0x{changes['old']:x} → 0x{changes['new']:x}")

        # Check memory accesses
        for access in step['memory_accesses']:
            print(f"  {access.operation} 0x{access.address:x}: {access.value.hex()}")
```

### Running to Target

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Run until specific address
    target = 0x401234
    trace = emulator.run_until(target, max_steps=5000)

    print(f"Executed {len(trace)} instructions")
    print(f"Final state: {emulator.state}")

    # Analyze execution path
    for step in trace[-10:]:  # Last 10 instructions
        print(f"0x{step['address']:x}: {step['instruction']}")
```

## Breakpoint System

### Simple Breakpoints

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Add breakpoint
    bp = emulator.add_breakpoint(0x401234)

    # Run until breakpoint
    trace = emulator.run_until(0xFFFFFFFF, max_steps=10000)

    if emulator.state == ESILState.BREAKPOINT:
        print(f"Breakpoint hit {bp.hit_count} times")
```

### Conditional Breakpoints

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Break when RAX equals specific value
    emulator.add_breakpoint(0x401234, condition="rax == 0x42")

    # Run
    trace = emulator.run_until(0xFFFFFFFF, max_steps=10000)
```

### Breakpoint Callbacks

```python
def analyze_comparison(emu, inst):
    """Called when breakpoint hits."""
    rax = emu.get_register("rax")
    rbx = emu.get_register("rbx")
    print(f"Comparing: 0x{rax:x} vs 0x{rbx:x}")

    # Could modify state here
    if rax != rbx:
        emu.set_register("rax", rbx)  # Force equal

with RadareESILEmulator(binary_path="app.exe") as emulator:
    emulator.add_breakpoint(0x401234, callback=analyze_comparison)
    trace = emulator.run_until(0xFFFFFFFF, max_steps=10000)
```

## License Check Detection

### Finding License Checks

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Find potential license validation code
    checks = emulator.find_license_checks()

    for check in checks:
        print(f"\nLicense Check at 0x{check['address']:x}:")
        print(f"  Type: {check['type']}")
        print(f"  Pattern: {check['pattern']}")

        if check['type'] == 'conditional_branch':
            print(f"  Success path: 0x{check['true_path']:x}")
            print(f"  Fail path: 0x{check['false_path']:x}")

            # These are potential patch points!
```

### Analyzing Validation Logic

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    checks = emulator.find_license_checks()

    for check in checks:
        # Emulate from check point
        emulator.reset()
        emulator.session.execute(f"s {check['address']}")

        # Set up test conditions
        emulator.set_register("rax", 0x1)  # Valid
        trace1 = emulator.run_until(check['true_path'], max_steps=100)

        emulator.reset()
        emulator.session.execute(f"s {check['address']}")

        emulator.set_register("rax", 0x0)  # Invalid
        trace2 = emulator.run_until(check['false_path'], max_steps=100)

        print(f"Valid path: {len(trace1)} instructions")
        print(f"Invalid path: {len(trace2)} instructions")
```

## Taint Analysis

### Tracking User Input

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Mark serial number input as tainted
    serial_addr = 0x200000
    serial = b"TEST-1234-5678-9ABC"

    emulator.set_memory(serial_addr, serial)
    emulator.add_taint_source(serial_addr, size=len(serial))

    # Emulate validation routine
    trace = emulator.run_until(validation_end, max_steps=5000)

    # Find which registers were influenced by serial
    tainted_regs = [reg for reg, state in emulator.registers.items()
                    if state.tainted]

    print(f"Serial influenced registers: {tainted_regs}")

    # Find which memory locations were influenced
    tainted_mem = list(emulator.symbolic_memory.keys())
    print(f"Serial influenced {len(tainted_mem)} memory locations")
```

## API Call Extraction

### Capturing API Calls

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Emulate code
    trace = emulator.run_until(end_of_function, max_steps=5000)

    # Extract all API calls made
    api_calls = emulator.extract_api_calls()

    for call in api_calls:
        print(f"\n0x{call['address']:x}: {call['api']}")
        print(f"  Stack pointer: 0x{call['stack_ptr']:x}")

        # Print arguments (calling convention aware)
        for i, arg in enumerate(call['arguments']):
            print(f"  Arg {i}: 0x{arg:x}")
```

### Analyzing Licensing APIs

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    trace = emulator.run_until(end_of_validation, max_steps=5000)

    api_calls = emulator.extract_api_calls()

    # Look for licensing-related APIs
    licensing_apis = ["GetComputerNameW", "RegOpenKeyExW", "CryptHashData",
                      "InternetOpenW", "HttpSendRequestW"]

    for call in api_calls:
        if any(api in call['api'] for api in licensing_apis):
            print(f"Licensing API: {call['api']} at 0x{call['address']:x}")
```

## Path Constraint Generation

### Finding Valid Inputs

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Generate constraints to reach success path
    success_addr = 0x401500
    constraints = emulator.generate_path_constraints(success_addr)

    print("Path constraints to reach success:")
    for i, constraint in enumerate(constraints):
        print(f"  {i+1}. {constraint}")

    # These constraints can be fed to Z3 or other solvers
    # to generate valid license keys
```

## Execution Tracing

### Exporting Traces

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Add breakpoints at interesting locations
    emulator.add_breakpoint(0x401234)
    emulator.add_breakpoint(0x401500)

    # Add taint source
    emulator.set_memory(0x200000, b"INPUT-DATA")
    emulator.add_taint_source(0x200000, size=10)

    # Emulate
    trace = emulator.run_until(end_addr, max_steps=10000)

    # Export complete trace
    emulator.dump_execution_trace("validation_trace.json")

    print(f"Trace saved with {emulator.instruction_count} instructions")
```

### Analyzing Exported Traces

```python
import json

with open("validation_trace.json") as f:
    trace = json.load(f)

print(f"Binary: {trace['binary']}")
print(f"Architecture: {trace['architecture']}")
print(f"Instructions executed: {trace['instruction_count']}")

print("\nAPI Calls:")
for call in trace['api_calls']:
    print(f"  {call['api']}")

print("\nTainted Registers:")
for reg in trace['tainted_registers']:
    print(f"  {reg}")

print("\nPath Constraints:")
for constraint in trace['path_constraints']:
    print(f"  {constraint}")
```

## Hook System

### Memory Access Hooks

```python
access_log = []

def on_memory_write(emulator, address, size, value):
    access_log.append({
        'address': address,
        'size': size,
        'value': value,
        'instruction': emulator.instruction_count
    })

with RadareESILEmulator(binary_path="app.exe") as emulator:
    emulator.add_hook('mem_write', on_memory_write)

    trace = emulator.run_until(end_addr, max_steps=1000)

    print(f"Captured {len(access_log)} memory writes")
```

## Complete Example: License Validation Analysis

```python
from intellicrack.core.analysis.radare2_esil_emulator import (
    RadareESILEmulator, ESILState
)
from intellicrack.core.analysis.radare2_session_manager import R2SessionPool

def analyze_license_validation(binary_path, serial_input):
    """Complete license validation analysis."""

    with RadareESILEmulator(binary_path=binary_path) as emulator:
        print(f"Analyzing: {binary_path}")
        print(f"Architecture: {emulator.arch}-{emulator.bits}")
        print(f"Entry point: 0x{emulator.entry_point:x}")

        # Step 1: Find license checks
        print("\n[1] Finding license checks...")
        checks = emulator.find_license_checks()
        print(f"Found {len(checks)} potential license checks")

        for i, check in enumerate(checks[:5]):  # Show first 5
            print(f"  {i+1}. 0x{check['address']:x}: {check['pattern']}")

        # Step 2: Set up test input
        print("\n[2] Setting up test input...")
        serial_addr = 0x200000
        emulator.set_memory(serial_addr, serial_input.encode())
        emulator.add_taint_source(serial_addr, size=len(serial_input))

        # Step 3: Add breakpoint at first check
        if checks:
            first_check = checks[0]['address']
            hit_data = {'count': 0}

            def on_check(emu, inst):
                hit_data['count'] += 1
                rax = emu.get_register("rax")
                print(f"    Check hit: RAX = 0x{rax:x}")

            emulator.add_breakpoint(first_check, callback=on_check)
            print(f"Breakpoint at 0x{first_check:x}")

        # Step 4: Emulate
        print("\n[3] Emulating validation...")
        trace = emulator.run_until(0xFFFFFFFF, max_steps=5000)

        print(f"Executed {len(trace)} instructions")
        print(f"Final state: {emulator.state}")

        # Step 5: Extract API calls
        print("\n[4] Extracting API calls...")
        api_calls = emulator.extract_api_calls()
        print(f"Found {len(api_calls)} API calls")

        for call in api_calls[:10]:  # Show first 10
            print(f"  {call['api']}")

        # Step 6: Analyze taint propagation
        print("\n[5] Analyzing taint propagation...")
        tainted_regs = [r for r, s in emulator.registers.items() if s.tainted]
        print(f"Tainted registers: {tainted_regs}")

        # Step 7: Generate constraints
        if checks:
            print("\n[6] Generating path constraints...")
            target = checks[0].get('true_path', 0)
            if target:
                constraints = emulator.generate_path_constraints(target)
                print(f"Generated {len(constraints)} constraints")
                for constraint in constraints[:5]:
                    print(f"  {constraint}")

        # Step 8: Export trace
        print("\n[7] Exporting trace...")
        trace_file = "license_trace.json"
        emulator.dump_execution_trace(trace_file)
        print(f"Trace saved to {trace_file}")

        return {
            'checks': checks,
            'api_calls': api_calls,
            'tainted_registers': tainted_regs,
            'trace_length': len(trace)
        }

# Usage
if __name__ == "__main__":
    results = analyze_license_validation(
        "protected_app.exe",
        "TEST-1234-5678-ABCD"
    )

    print("\n=== Analysis Complete ===")
    print(f"License checks found: {len(results['checks'])}")
    print(f"API calls made: {len(results['api_calls'])}")
    print(f"Instructions executed: {results['trace_length']}")
```

## Performance Tips

### 1. Use Session Pooling

```python
# Good: Reuses sessions
pool = R2SessionPool()
for binary in binaries:
    with RadareESILEmulator(binary, session_pool=pool) as emu:
        analyze(emu)

# Bad: Creates new session each time
for binary in binaries:
    with RadareESILEmulator(binary) as emu:
        analyze(emu)
```

### 2. Limit Emulation Steps

```python
# Always set reasonable max_steps
trace = emulator.run_until(target, max_steps=10000)  # Good

# Avoid unlimited emulation
trace = emulator.run_until(target)  # May run forever
```

### 3. Reset State When Needed

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Test scenario 1
    emulator.set_register("rax", 0x1)
    trace1 = emulator.run_until(target, max_steps=1000)

    # Reset for scenario 2
    emulator.reset()

    # Test scenario 2
    emulator.set_register("rax", 0x0)
    trace2 = emulator.run_until(target, max_steps=1000)
```

### 4. Minimize Analysis Level When Appropriate

```python
# Fast initialization for simple analysis
emulator = RadareESILEmulator(
    binary_path="app.exe",
    analysis_level="aa"  # Basic analysis, faster
)

# Deep analysis when needed
emulator = RadareESILEmulator(
    binary_path="app.exe",
    analysis_level="aaaa"  # Full analysis, slower
)
```

## Common Patterns

### Pattern 1: Find and Patch License Checks

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    checks = emulator.find_license_checks()

    patch_points = []
    for check in checks:
        if check['type'] == 'conditional_branch':
            # This is a potential patch point
            patch_points.append({
                'address': check['address'],
                'true_path': check['true_path'],
                'false_path': check['false_path']
            })

    return patch_points
```

### Pattern 2: Reverse Engineer Serial Algorithm

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    # Try multiple serials
    results = []

    for serial in ["TEST-0000", "TEST-1111", "TEST-AAAA"]:
        emulator.reset()
        emulator.set_memory(serial_addr, serial.encode())

        trace = emulator.run_until(decision_point, max_steps=5000)

        result = emulator.get_register("rax")  # Validation result
        results.append((serial, result))

    # Analyze patterns
    for serial, result in results:
        print(f"{serial}: {'VALID' if result else 'INVALID'}")
```

### Pattern 3: Monitor Cryptographic Operations

```python
with RadareESILEmulator(binary_path="app.exe") as emulator:
    crypto_ops = []

    def detect_crypto(emu, inst):
        # Detect XOR, ROL, ROR patterns
        if any(op in inst.get('instruction', '') for op in ['xor', 'rol', 'ror']):
            crypto_ops.append(inst)

    # Hook instruction execution
    for _ in range(1000):
        step = emulator.step_instruction()
        detect_crypto(emulator, step)

    print(f"Detected {len(crypto_ops)} potential crypto operations")
```

## Troubleshooting

### Issue: Emulation Stops Early

```python
# Check trap conditions
if emulator.state == ESILState.TRAPPED:
    print("Emulation trapped - check memory accesses")
    # Review last memory access
    if emulator.memory_accesses:
        last = emulator.memory_accesses[-1]
        print(f"Last access: {last.operation} @ 0x{last.address:x}")
```

### Issue: Slow Emulation

```python
# Reduce analysis level
emulator = RadareESILEmulator(
    binary_path="app.exe",
    auto_analyze=False  # Skip initial analysis
)

# Or use faster analysis
emulator = RadareESILEmulator(
    binary_path="app.exe",
    analysis_level="a"  # Minimal analysis
)
```

### Issue: Memory Access Errors

```python
# Check if memory is mapped
try:
    data = emulator.get_memory(address, size)
except RuntimeError as e:
    print(f"Memory access failed: {e}")
    # Map memory region first
    emulator.session.execute(f"aeim {address} {size} custom_region")
```

## Additional Resources

- **ESIL Reference**: https://book.rada.re/disassembling/esil.html
- **Radare2 Commands**: https://book.rada.re/
- **Session Manager**: See `radare2_session_manager.py`
- **Test Examples**: See `tests/integration/test_radare2_esil_emulator.py`

---

**Ready to crack some licensing protections? Start emulating!**
