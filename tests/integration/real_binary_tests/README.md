# Real Binary Integration Tests

## Purpose

These tests validate Intellicrack's **actual capability** to detect, analyze,
and bypass real software protections. Tests run against **genuine protected
binaries** and **FAIL** if Intellicrack doesn't work.

## Test Binary Directory Structure

```
tests/integration/real_binary_tests/
├── binaries/
│   ├── securom/
│   │   ├── v7/          # SecuROM v7.x protected executables
│   │   └── v8/          # SecuROM v8.x protected executables
│   ├── starforce/
│   │   ├── v3/          # StarForce v3.x protected executables
│   │   ├── v4/          # StarForce v4.x protected executables
│   │   └── v5/          # StarForce v5.x protected executables
│   ├── vmprotect/
│   │   ├── v1/          # VMProtect v1.x protected executables
│   │   ├── v2/          # VMProtect v2.x protected executables
│   │   └── v3/          # VMProtect v3.x protected executables
│   ├── themida/         # Themida protected executables
│   ├── winlicense/      # WinLicense protected executables
│   ├── hasp/
│   │   ├── hasp4/       # HASP4 dongle protected software
│   │   ├── hasp_hl/     # HASP HL protected software
│   │   └── sentinel/    # Sentinel dongle protected software
│   ├── flexlm/          # FlexLM/FlexNet licensed software
│   │   └── licenses/    # Real FlexLM license files (.lic, .dat)
│   ├── flexnet/         # FlexNet licensed software
│   ├── armadillo/       # Armadillo protected executables
│   ├── asprotect/       # ASProtect protected executables
│   ├── enigma/          # Enigma Protector protected executables
│   ├── safengine/       # Safengine protected executables
│   ├── obsidium/        # Obsidium protected executables
│   ├── packers/
│   │   ├── upx/         # UPX packed binaries
│   │   ├── pecompact/   # PECompact packed binaries
│   │   └── aspack/      # ASPack packed binaries
│   └── drivers/
│       ├── secdrv.sys   # Real SecuROM driver
│       ├── sfdrv01.sys  # Real StarForce driver
│       ├── akshasp.sys  # Real HASP driver
│       └── ...
└── manifests/
    ├── securom_v7_samples.json
    ├── securom_v8_samples.json
    ├── starforce_samples.json
    ├── vmprotect_samples.json
    ├── themida_samples.json
    ├── hasp_samples.json
    ├── flexlm_samples.json
    ├── armadillo_samples.json
    ├── asprotect_samples.json
    ├── enigma_samples.json
    ├── safengine_samples.json
    └── obsidium_samples.json
```

## Obtaining Test Binaries

### Legal Sources for Protected Software

1. **Abandonware (Protection Expired)**:
    - Old games with SecuROM/StarForce/Safedisc from 2000-2010
    - Legacy CAD/engineering software with FlexLM/HASP dongles
    - Many available legally from abandonware sites
    - Protection companies no longer support these versions

2. **Demo/Trial Software**:
    - Publicly available trial versions with protection
    - VMProtect/Themida trial versions often protected
    - Enigma Protector demo applications
    - Legal to download and possess

3. **Your Own Software**:
    - If you own protected games/software legally
    - Professional software you have licenses for
    - Copy executables to test directory
    - Document which version you're testing

4. **Protection Vendors' Own Demos**:
    - VMProtect includes protected demo executables
    - Themida/WinLicense provides sample protected apps
    - Enigma Protector trial includes examples
    - ASProtect/Armadillo legacy demo versions

5. **Public Malware Repositories** (for driver analysis):
    - VirusTotal samples (some protection drivers flagged as PUP)
    - MalwareBazaar public samples
    - theZoo malware repository

### Protection-Specific Sources

**SecuROM/StarForce**: Old retail game executables from 2000s **VMProtect**:
Security software, game protectors, commercial apps **Themida/WinLicense**:
Shareware applications, trial software **HASP/Sentinel**: Professional CAD
software, engineering tools, old dongle-protected apps **FlexLM/FlexNet**:
Academic software, engineering tools, simulation software **Armadillo**: Legacy
shareware from 2000s (protection discontinued) **Enigma Protector**: Modern
shareware and indie game protection **Packers (UPX/PECompact)**: Compressed
executables, can create your own test files

### Driver Files

Protection drivers can be extracted from:

- Existing installations on your system (`C:\Windows\System32\drivers\`)
- Uninstallers that leave drivers behind
- Driver packages from manufacturer websites
- Public malware repositories (many protection drivers are flagged)

### Creating Test Binary Manifests

For each binary you add, create a manifest entry:

```json
{
    "name": "Game Name v1.0",
    "file": "game_v1.0.exe",
    "protection": "securom",
    "version": "7.02.0000",
    "expected_drivers": ["secdrv.sys", "SR7.sys"],
    "expected_sections": [".securom"],
    "notes": "Retail release, disc check enabled"
}
```

## Running Real Tests

### With Test Binaries Present

```bash
# All real integration tests
pytest tests/integration/real_binary_tests/ -v

# Specific protection
pytest tests/integration/real_binary_tests/test_securom_real.py -v

# Specific version
pytest tests/integration/real_binary_tests/test_securom_real.py::TestSecuROMv7Real -v
```

### Without Test Binaries

Tests will **SKIP** with clear message:

```
SKIPPED [1] No real SecuROM v7 binaries found in tests/integration/real_binary_tests/binaries/securom/v7/
         Place protected executables in this directory to enable real capability validation.
         See tests/integration/real_binary_tests/README.md for sources.
```

## What Tests Actually Validate

### Detection Tests

- **Input**: Real protected executable
- **Action**: Run detector on actual binary
- **Validation**: Detector identifies correct protection and version
- **Failure**: Test FAILS if detector misses real protection

### Analysis Tests

- **Input**: Real protected executable
- **Action**: Extract activation mechanisms, keys, triggers
- **Validation**: Extracted data matches known characteristics
- **Failure**: Test FAILS if analysis returns no results

### Bypass Tests

- **Input**: Real protected executable
- **Action**: Patch binary to remove protection
- **Validation**: Patched binary runs without protection checks
- **Failure**: Test FAILS if bypass doesn't work or corrupts binary

## Example: Adding a SecuROM v7 Binary

1. Obtain protected executable (e.g., old game demo)
2. Place in `tests/integration/real_binary_tests/binaries/securom/v7/`
3. Create manifest entry in `manifests/securom_v7_samples.json`:
    ```json
    {
        "name": "Example Game Demo",
        "file": "example_demo.exe",
        "protection": "securom",
        "version": "7.38.0004",
        "expected_drivers": ["secdrv.sys"],
        "expected_sections": [".securom"],
        "sha256": "abc123...",
        "notes": "Demo version, activation disabled"
    }
    ```
4. Run tests:
   `pytest tests/integration/real_binary_tests/test_securom_real.py -v`
5. Test validates Intellicrack actually works on this real binary

## Continuous Integration

For CI/CD without real binaries:

- Tests automatically skip when binaries unavailable
- CI passes with skip warnings
- Manual validation required before release
- Internal CI can include real binaries in secure environment

## Legal Considerations

- **Use legally obtained software** (abandonware, demos, owned copies)
- **Don't redistribute** protected binaries publicly
- **Document sources** for transparency
- **Test in isolated environment** to avoid interfering with legitimate software

## Security Research Context

These tests validate Intellicrack serves its purpose as a defensive security
tool:

- Developers can test their own protection implementations
- Security researchers validate bypass techniques
- Protection vendors can assess vulnerabilities
- All testing occurs in controlled, authorized environments
