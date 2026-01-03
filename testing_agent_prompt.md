# Intellicrack Test Writing Agent Orchestration Prompt

## Instructions for Claude

You are tasked with orchestrating comprehensive test writing for the Intellicrack project. Read `D:\Intellicrack\testingtodo.md` to get the full list of 92 items requiring tests.

### Execution Model

1. **Launch 3 test-writer agents IN PARALLEL (foreground)**
2. **Each agent receives EXACTLY ONE item to write tests for**
3. **Wait for all 3 agents to complete**
4. **Repeat with the next 3 items**
5. **Continue until all 92 items have tests written**

### Critical Requirements

- **Foreground Execution**: All agents MUST run in foreground - DO NOT use `run_in_background: true`
- **Parallel Launch**: Launch all 3 agents in a SINGLE message with multiple Task tool calls
- **One Item Per Agent**: Each agent gets ONE file/item only
- **Production-Ready Tests**: NO mocks, stubs, or placeholders
- **Failure on Non-Compliance**: Tests MUST ALWAYS FAIL if code is not production-ready

---

## Item List (Process in Order)

### Batch 1 (Items 1-3)
1. `intellicrack/protection/themida_analyzer.py:100-300` - Themida CISC handlers
2. `intellicrack/protection/denuvo_ticket_analyzer.py:1-200` - Denuvo trigger detection
3. `intellicrack/core/analysis/vmprotect_detector.py:1-150` - VMProtect detection

### Batch 2 (Items 4-6)
4. `intellicrack/core/analysis/symbolic_devirtualizer.py:1-150` - angr integration
5. `intellicrack/core/analysis/behavioral_analysis.py:1-200` - QEMU integration
6. `intellicrack/core/license/keygen.py` - Key validation against binaries

### Batch 3 (Items 7-9)
7. `intellicrack/core/exploitation/keygen_generator.py:1577-1599` - RSA validation
8. `intellicrack/core/exploitation/keygen_generator.py:1562-1601` - Key validator
9. `intellicrack/core/trial_reset_engine.py:1606-2020` - Time freezing

### Batch 4 (Items 10-12)
10. `intellicrack/core/exploitation/bypass_engine.py:156-158` - Scope cleanup
11. `intellicrack/core/analysis/frida_advanced_hooks.py:143-318` - Stalker crash handling
12. `intellicrack/core/analysis/frida_protection_bypass.py:102-355` - Kernel anti-debug

### Batch 5 (Items 13-15)
13. `intellicrack/core/analysis/frida_protection_bypass.py:357-556` - Cert pinning
14. `intellicrack/core/analysis/frida_protection_bypass.py:778-1023` - VM detection bypass
15. `intellicrack/core/analysis/frida_protection_bypass.py:1378-1455` - VMProtect unpacker

### Batch 6 (Items 16-18)
16. `intellicrack/core/analysis/frida_protection_bypass.py:1457-1555` - Themida unpacker
17. `intellicrack/core/anti_analysis/` - Kernel bypass documentation
18. `intellicrack/core/network/ssl_interceptor.py:215` - mitmproxy fallback

### Batch 7 (Items 19-21)
19. `intellicrack/core/network/protocols/flexlm_parser.py:239-250` - Binary protocol
20. `intellicrack/core/network/protocols/hasp_parser.py:1-300` - HASP encryption
21. `intellicrack/core/network/dynamic_response_generator.py:70-162` - FlexLM signatures

### Batch 8 (Items 22-24)
22. `intellicrack/core/network/ssl_interceptor.py:150-223` - Cloud license handling
23. `intellicrack/core/hardware_spoofer.py:92-343` - Kernel driver code
24. `intellicrack/core/protection_bypass/dongle_emulator.py:1584+` - Frida script functions

### Batch 9 (Items 25-27)
25. `intellicrack/core/protection_bypass/tpm_bypass.py:1908-1935` - TPM unsealing
26. `intellicrack/core/protection_bypass/tpm_secure_enclave_bypass.py:2212` - Attestation key
27. `intellicrack/core/protection_bypass/tpm_secure_enclave_bypass.py:1662-1743` - Quote format

### Batch 10 (Items 28-30)
28. `intellicrack/plugins/custom_modules/vm_protection_unwrapper.py` - VM opcode emulation
29. `intellicrack/plugins/custom_modules/vm_protection_unwrapper.py:~150` - Key schedule
30. `intellicrack/core/hardware_spoofer.py` - Driver approach cleanup

### Batch 11 (Items 31-33)
31. `intellicrack/core/analysis/binary_pattern_detector.py:1-200` - Pattern matching
32. `intellicrack/core/analysis/binary_similarity_search.py:1-300` - Similarity algorithms
33. `intellicrack/core/analysis/cfg_explorer.py:1-200` - CFG recovery

### Batch 12 (Items 34-36)
34. `intellicrack/core/analysis/opaque_predicate_analyzer.py:1-150` - Predicate analysis
35. `intellicrack/core/analysis/dynamic_analyzer.py:1-200` - Dynamic instrumentation
36. `intellicrack/core/analysis/cryptographic_routine_detector.py:1-200` - Crypto detection

### Batch 13 (Items 37-39)
37. `intellicrack/core/analysis/` - Hardcoded signatures update mechanism
38. `intellicrack/protection/` - Post-2024 protection signatures
39. `intellicrack/core/exploitation/keygen_generator.py:385-410` - Weak crypto detection

### Batch 14 (Items 40-42)
40. `intellicrack/core/exploitation/keygen_generator.py:704-741` - Z3 constraint translation
41. `intellicrack/core/license/keygen.py:888-906` - Algorithm extraction
42. `intellicrack/core/license/keygen.py:935-957` - Algorithm types

### Batch 15 (Items 43-45)
43. `intellicrack/core/license/keygen.py:959-997` - CRC polynomial extraction
44. `intellicrack/core/license/keygen.py:1182-1184` - Iteration limits
45. `intellicrack/core/trial_reset_engine.py:1938-1990` - IAT hooking

### Batch 16 (Items 46-48)
46. `intellicrack/core/serial_generator.py:129-172` - Algorithm detection
47. `intellicrack/core/license_validation_bypass.py:67-99` - RSA patterns
48. Hardcoded constants extraction throughout serial/checksum code

### Batch 17 (Items 49-51)
49. `intellicrack/core/analysis/frida_advanced_hooks.py:416-591` - Heap tracker
50. `intellicrack/core/analysis/frida_analyzer.py:95-143` - Timeout handling
51. `intellicrack/core/analysis/frida_protection_bypass.py:558-776` - Integrity checks

### Batch 18 (Items 52-54)
52. `intellicrack/core/analysis/frida_protection_bypass.py:1300-1376` - UPX signatures
53. `intellicrack/core/analysis/frida_protection_bypass.py:1557-1707` - Unpack patterns
54. `intellicrack/core/analysis/frida_script_manager.py:366-473` - Script validation

### Batch 19 (Items 55-57)
55. `intellicrack/core/analysis/frida_script_manager.py:475-504` - Parameter injection
56. `intellicrack/core/anti_analysis/advanced_debugger_bypass.py:47-142` - Shellcode
57. `intellicrack/core/anti_analysis/debugger_bypass.py` - PEB flag clearing

### Batch 20 (Items 58-60)
58. `intellicrack/core/patching/memory_patcher.py:1-200` - Patching logic
59. `intellicrack/core/anti_analysis/timing_attacks.py:51-133` - Timing precision
60. `intellicrack/core/anti_analysis/` - COM-based debug detection

### Batch 21 (Items 61-63)
61. `intellicrack/core/network/traffic_interception_engine.py:985` - Timeout handling
62. `intellicrack/core/network/protocols/codemeter_parser.py:124-186` - Product discovery
63. `intellicrack/core/network/protocols/autodesk_parser.py:150-300` - Signature validation

### Batch 22 (Items 64-66)
64. `intellicrack/core/network/license_protocol_handler.py:312-326` - Protocol responses
65. `intellicrack/core/offline_activation_emulator.py:150-300` - Registry writing
66. `intellicrack/core/network_capture.py:30-150` - Protocol fingerprinting

### Batch 23 (Items 67-69)
67. `intellicrack/core/protection_bypass/cloud_license.py:142-150` - TLS interceptor
68. `intellicrack/core/network/` - Microsoft KMS implementation
69. `intellicrack/core/network/` - UDP protocol handling

### Batch 24 (Items 70-72)
70. `intellicrack/core/hardware_spoofer.py:1526` - Disk serial restoration
71. `intellicrack/core/protection_bypass/dongle_emulator.py:926-953` - HASP responses
72. `intellicrack/core/protection_bypass/tpm_bypass.py:2088-2135` - TPM detection

### Batch 25 (Items 73-75)
73. `intellicrack/core/protection_bypass/tpm_bypass.py:2311-2388` - Capability claims
74. `intellicrack/core/protection_bypass/tpm_secure_enclave_bypass.py:2358-2527` - Certificates
75. `intellicrack/core/protection_bypass/cloud_license_analyzer.py:1046-1111` - Request validation

### Batch 26 (Items 76-78)
76. `intellicrack/core/certificate/pinning_detector.py` - Dynamic pinning detection
77. `intellicrack/core/protection_bypass/integrity_check_defeat.py:2264-2307` - HMAC support
78. `intellicrack/core/protection_bypass/hardware_token.py:809-841` - Yubikey DLL

### Batch 27 (Items 79-81)
79. `intellicrack/core/protection_bypass/hardware_token.py:936-1092` - Key derivation
80. `intellicrack/core/protection_bypass/dongle_emulator.py` - Sentinel protocol
81. `intellicrack/core/protection_bypass/dongle_emulator.py` - CodeMeter protocol

### Batch 28 (Items 82-84) - Regression Tests
82. VMProtect detector instruction-level analysis (regression)
83. Themida RISC/FISH VM handler semantics (regression)
84. Denuvo activation triggers and integrity checks (regression)

### Batch 29 (Items 85-87) - Regression Tests
85. Symbolic devirtualizer angr integration (regression)
86. Behavioral analysis QEMU integration (regression)
87. RSA key extraction and validation (regression)

### Batch 30 (Items 88-90) - Regression Tests
88. Debugging/patching-based key validation (regression)
89. Time freezing module enumeration (regression)
90. Bypass engine scope cleanup verification (regression)

### Batch 31 (Items 91-92) - Final
91. Full integration test suite
92. Cross-module interaction tests

---

## Per-Item Agent Task Template

For each item, launch an agent with this prompt structure:

```
Read D:\Intellicrack\testingtodo.md and find the entry for:
[FILE_PATH] - [DESCRIPTION]

Write comprehensive production-ready tests for THIS SINGLE ITEM ONLY.

Expected Behavior from testingtodo.md:
[COPY THE EXPECTED BEHAVIOR SECTION FOR THIS ITEM]

REQUIREMENTS:
1. Tests MUST use real protected binaries or actual system resources
2. Tests MUST validate the expected behavior exactly as documented
3. Tests MUST FAIL if functionality is incomplete or non-functional
4. Tests MUST cover all edge cases listed in the expected behavior
5. NO mocks, stubs, or placeholder assertions
6. Place tests in the appropriate tests/ subdirectory
7. Include proper pytest fixtures and teardown

Write the complete test file now. Do not summarize or explain - just write the tests.
```

---

## Execution Loop

```
for batch in batches:
    # Launch 3 agents in ONE message (parallel, foreground)
    Task(subagent_type="test-writer", description="Test item {batch[0]}", prompt=<template for item>, run_in_background=false)
    Task(subagent_type="test-writer", description="Test item {batch[1]}", prompt=<template for item>, run_in_background=false)
    Task(subagent_type="test-writer", description="Test item {batch[2]}", prompt=<template for item>, run_in_background=false)

    # Wait for all 3 to complete
    # Move to next batch
```

---

## Test Quality Standards

Every test MUST:
1. **Be Immediately Executable**: Run with `pytest` without additional setup
2. **Use Real Targets**: Protected binaries, actual processes, real protocols
3. **Validate Actual Behavior**: Verify functionality, not just execution
4. **Fail on Non-Compliance**: Tests MUST fail if code doesn't work
5. **Cover Edge Cases**: All documented edge cases must have tests
6. **Include Meaningful Assertions**: No empty or trivial assertions

---

## Progress Tracking

After each batch completes, update progress:
- Items completed: X/92
- Tests written: [list of test files]
- Failures encountered: [any issues]

Continue until all 92 items have corresponding test files.

---

*One item per agent. Three agents per batch. Repeat until complete.*
