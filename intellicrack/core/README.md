# Intellicrack Core

The core module contains the fundamental components and engines that power Intellicrack's analysis capabilities.

## Architecture Overview

The core module is organized into specialized subsystems, each handling specific aspects of binary analysis and security research.

## Module Structure

### Analysis (`analysis/`)
Core analysis engines and algorithms:
- **cfg_explorer.py** - Control Flow Graph exploration and analysis
- **concolic_executor.py** - Concolic execution engine for path exploration
- **incremental_manager.py** - Incremental analysis management
- **multi_format_analyzer.py** - Multi-format binary analysis support
- **radare2_*.py** - Radare2 integration modules
- **rop_generator.py** - Return-Oriented Programming gadget generation
- **symbolic_executor.py** - Symbolic execution engine
- **taint_analyzer.py** - Taint analysis for data flow tracking
- **vulnerability_engine.py** - Vulnerability detection and classification

### Anti-Analysis (`anti_analysis/`)
Detection and bypass of anti-analysis techniques:
- **api_obfuscation.py** - API obfuscation detection
- **debugger_detector.py** - Anti-debugging technique detection
- **process_hollowing.py** - Process hollowing detection and analysis
- **sandbox_detector.py** - Sandbox evasion technique detection
- **timing_attacks.py** - Timing-based anti-analysis detection
- **vm_detector.py** - Virtual machine detection bypass

### Command & Control (`c2/`)
C2 infrastructure and communication:
- **base_c2.py** - Base C2 communication framework
- **beacon_manager.py** - Beacon management and coordination
- **c2_client.py** - C2 client implementation
- **c2_server.py** - C2 server infrastructure
- **communication_protocols.py** - Protocol handlers
- **encryption_manager.py** - Communication encryption
- **session_manager.py** - Session management and persistence

### Execution (`execution/`)
Script and payload execution management:
- **script_execution_manager.py** - Manages execution of analysis scripts

### Exploitation (`exploitation/`)
Exploitation tools and payload generation:
- **assembly_compiler.py** - Assembly code compilation
- **base_exploitation.py** - Base exploitation framework
- **base_persistence.py** - Persistence mechanism base
- **cfi_bypass.py** - Control Flow Integrity bypass
- **credential_harvester.py** - Credential extraction utilities
- **encoder_engine.py** - Payload encoding engine
- **lateral_movement.py** - Lateral movement techniques
- **payload_engine.py** - Advanced payload generation
- **polymorphic_engine.py** - Polymorphic payload generation
- **privilege_escalation.py** - Privilege escalation techniques
- **shellcode_generator.py** - Shellcode generation utilities

### Mitigation Bypass (`mitigation_bypass/`)
Modern mitigation bypass techniques:
- **bypass_engine.py** - General bypass engine
- **cfi_bypass.py** - Control Flow Integrity bypass
- **dep_bypass.py** - Data Execution Prevention bypass

### Network (`network/`)
Network analysis and interception:
- **base_network_analyzer.py** - Base network analysis framework
- **cloud_license_hooker.py** - Cloud license interception
- **dynamic_response_generator.py** - Dynamic response generation
- **license_protocol_handler.py** - License protocol analysis
- **license_server_emulator.py** - License server emulation
- **ssl_interceptor.py** - SSL/TLS interception
- **traffic_analyzer.py** - Network traffic analysis
- **traffic_interception_engine.py** - Traffic interception engine

### Patching (`patching/`)
Binary modification and patching:
- **adobe_injector.py** - Adobe-specific injection techniques
- **base_patcher.py** - Base patching framework
- **payload_generator.py** - Advanced payload generation for patches

### Processing (`processing/`)
Distributed and accelerated processing:
- **base_snapshot_handler.py** - Snapshot management
- **distributed_analysis_manager.py** - Distributed analysis coordination
- **distributed_manager.py** - General distributed processing
- **docker_container.py** - Docker containerization support
- **emulator_manager.py** - Emulator management and coordination
- **gpu_accelerator.py** - GPU acceleration support
- **memory_loader.py** - Efficient memory loading
- **memory_optimizer.py** - Memory usage optimization
- **qemu_emulator.py** - QEMU emulator integration
- **qiling_emulator.py** - Qiling framework integration

### Protection Bypass (`protection_bypass/`)
Protection mechanism bypass:
- **dongle_emulator.py** - Hardware dongle emulation
- **tpm_bypass.py** - TPM (Trusted Platform Module) bypass
- **vm_bypass.py** - Virtual machine detection bypass

### Reporting (`reporting/`)
Analysis result reporting:
- **pdf_generator.py** - PDF report generation

### Shared (`shared/`)
Common utilities and configuration:
- **bypass_config.py** - Bypass configuration management
- **result_utils.py** - Result processing utilities

### Vulnerability Research (`vulnerability_research/`)
Advanced vulnerability research tools:
- **base_analyzer.py** - Base vulnerability analyzer
- **binary_differ.py** - Binary diffing utilities
- **common_enums.py** - Common enumerations and constants
- **exploit_developer/** - Exploit development tools
- **fuzzing_engine.py** - Fuzzing engine implementation
- **patch_analyzer.py** - Patch analysis utilities
- **research_manager.py** - Research coordination
- **vulnerability_analyzer.py** - Comprehensive vulnerability analysis

## Configuration Management

- **config_manager.py** - Central configuration management
- **startup_checks.py** - System startup and validation checks

## Integration Points

The core module integrates with:
- **Frida** - Dynamic instrumentation (frida_*.py files)
- **Ghidra** - Static analysis integration
- **Radare2** - Reverse engineering framework
- **Qiling** - Binary emulation framework
- **QEMU** - System emulation

## Key Features

### Multi-Engine Analysis
- Supports multiple analysis engines (angr, radare2, custom)
- Automatic engine selection based on binary characteristics
- Fallback mechanisms for unsupported formats

### Advanced Execution
- Symbolic execution with constraint solving
- Concolic execution for path exploration
- Taint analysis for data flow tracking

### Modern Protections
- CFI bypass techniques
- DEP/ASLR bypass methods
- Anti-analysis detection and evasion

### Scalability
- Distributed processing support
- GPU acceleration for intensive operations
- Memory optimization for large binaries

## Usage

The core module is typically used through higher-level interfaces:

```python
from intellicrack.core.analysis import CoreAnalyzer
from intellicrack.core.vulnerability_research import VulnerabilityAnalyzer

# Initialize analyzers
analyzer = CoreAnalyzer()
vuln_analyzer = VulnerabilityAnalyzer()

# Perform analysis
results = analyzer.analyze_binary("target.exe")
vulnerabilities = vuln_analyzer.scan_binary("target.exe")
```

## Development

When extending the core module:
1. Follow the existing architectural patterns
2. Ensure proper error handling and logging
3. Add comprehensive unit tests
4. Document new APIs and interfaces
5. Consider cross-platform compatibility

## Dependencies

Core dependencies include:
- **angr** - Binary analysis platform
- **radare2** - Reverse engineering framework
- **capstone** - Disassembly engine
- **keystone** - Assembler engine
- **unicorn** - CPU emulator
- **pefile** - PE file parsing
- **pyelftools** - ELF file parsing

For a complete list, see `requirements/requirements.txt`.
