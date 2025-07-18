# Manual Review Template for Placeholder Classification

## Instructions
For each finding, determine:
1. Is this a legitimate exploit simulation? (Y/N)
2. Add notes explaining your reasoning

## Classification Guidelines

### Mark as "Y" (Exploit Simulation) if:
- Fake hardware IDs, serial numbers, or device identifiers for bypassing hardware locks
- Mock license servers or fake license responses for protection bypass
- Spoofed registry values or system information for anti-analysis evasion
- Dummy processes, DLLs, or APIs specifically for sandbox/VM detection bypass
- Fake network responses that are part of a bypass technique

### Mark as "N" (Missing Implementation) if:
- TODO, FIXME, or explicit placeholder comments
- Empty function/class bodies (pass statements) without bypass purpose
- NotImplementedError exceptions
- Silent error handlers (except: pass) that swallow errors
- Mock/stub code in non-exploit contexts (UI, logging, general features)
- Test infrastructure that should be in test directories
- Any functionality that should work but doesn't

## Review Process
1. Open the CSV file: `all_findings_for_review.csv`
2. For each row, examine the code and context
3. Mark Y or N in the "Is Exploit Simulation?" column
4. Add reasoning in "Classification Notes"
5. Save the reviewed CSV
6. Run the processing script to generate final lists

## Example Classifications

| Code | Classification | Reasoning |
|------|----------------|-----------|
| `fake_hwid = "ABCD-1234"` | Y | Hardware ID spoofing for license bypass |
| `class MockLicenseServer:` | Y | Part of license server emulation for bypass |
| `# TODO: Implement this` | N | Explicit TODO comment |
| `def process(): pass` | N | Empty implementation without bypass purpose |
| `except: pass` | N | Silent error handler - always problematic |
| `fake_android_id = "9774d56d682e549c"` | Y | Android ID spoofing for mobile app bypass |
| `class MockDataGenerator:` | N | Test infrastructure not for exploitation |
