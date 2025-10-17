# Commercial Software Acquisition Guide for Intellicrack Validation System

## Overview

This document provides detailed instructions for acquiring legitimate commercial software binaries for validation testing of the Intellicrack security research tool. All acquisitions must be legal, documented, and cryptographically verified.

## Required Software List

### 1. Adobe Creative Cloud 2024
- **Protection**: Adobe Licensing v7
- **Executable**: Adobe Creative Cloud.exe
- **Version**: 2024
- **Acquisition Method**: Official Adobe website trial download
- **URL**: https://creativecloud.adobe.com/apps/download/creative-cloud
- **SHA-256 Verification**: Must match Adobe's published checksum

### 2. AutoCAD 2024
- **Protection**: FlexLM v11.16.2
- **Executable**: acad.exe
- **Version**: 2024
- **Acquisition Method**: Autodesk official trial
- **URL**: https://www.autodesk.com/products/autocad/free-trial
- **SHA-256 Verification**: Verify against Autodesk's checksum

### 3. MATLAB R2024a
- **Protection**: FlexLM + custom
- **Executable**: matlab.exe
- **Version**: R2024a
- **Acquisition Method**: MathWorks trial download
- **URL**: https://www.mathworks.com/products/get-matlab.html
- **SHA-256 Verification**: Match MathWorks published hash

### 4. SolidWorks 2024
- **Protection**: SNL FlexNet
- **Executable**: SLDWORKS.exe
- **Version**: 2024
- **Acquisition Method**: Dassault Systèmes trial
- **URL**: https://www.solidworks.com/sw/support/downloads.htm
- **SHA-256 Verification**: Verify with vendor checksum

### 5. VMware Workstation Pro
- **Protection**: Custom licensing
- **Executable**: vmware.exe
- **Version**: 17
- **Acquisition Method**: VMware official trial
- **URL**: https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html
- **SHA-256 Verification**: Match VMware's checksum

## Acquisition Process

### Step 1: Pre-Acquisition Setup

1. **Create Clean Environment**:
   ```powershell
   # Create acquisition workspace
   New-Item -Path "D:\\Intellicrack\tests\validation_system\downloads" -ItemType Directory -Force

   # Set up logging
   $logFile = "D:\\Intellicrack\tests\validation_system\logs\acquisition_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
   Start-Transcript -Path $logFile
   ```

2. **Document System State**:
   ```powershell
   # Record system information
   Get-ComputerInfo | Out-File "D:\\Intellicrack\tests\validation_system\logs\system_info.txt"

   # Record network configuration
   Get-NetIPConfiguration | Out-File "D:\\Intellicrack\tests\validation_system\logs\network_config.txt"
   ```

### Step 2: Download Software

1. **Use Official Sources Only**:
   - Navigate to vendor website using HTTPS
   - Verify SSL certificate is valid
   - Download trial/evaluation versions
   - Save to `downloads` directory

2. **Document Download Details**:
   ```python
   import json
   import hashlib
   from datetime import datetime, timezone
   from pathlib import Path

   def document_download(file_path, source_url, vendor_name):
       """Document download details for audit trail."""
       file_path = Path(file_path)

       # Calculate hash
       sha256_hash = hashlib.sha256()
       with file_path.open("rb") as f:
           for chunk in iter(lambda: f.read(8192), b""):
               sha256_hash.update(chunk)

       download_info = {
           "filename": file_path.name,
           "vendor": vendor_name,
           "source_url": source_url,
           "download_time": datetime.now(tz=timezone.utc).isoformat(),
           "file_size": file_path.stat().st_size,
           "sha256": sha256_hash.hexdigest(),
           "verified": False
       }

       # Save documentation
       doc_file = file_path.parent / f"{file_path.stem}_download_info.json"
       with doc_file.open("w") as f:
           json.dump(download_info, f, indent=2)

       return download_info
   ```

### Step 3: Verify Integrity

1. **Vendor Checksum Verification**:
   ```python
   from commercial_binary_manager import CommercialBinaryManager

   manager = CommercialBinaryManager()

   # Verify against vendor checksum
   binary_path = Path("<INTELLICRACK_ROOT>/tests/validation_system/downloads/installer.exe")
   vendor_checksum = "abc123..."  # From vendor website

   is_valid = manager.verify_vendor_checksum(
       binary_path=binary_path,
       vendor_checksum=vendor_checksum,
       checksum_type="sha256"
   )

   if not is_valid:
       raise ValueError("Checksum verification failed!")
   ```

2. **Digital Signature Verification** (Windows):
   ```powershell
   # Verify digital signature
   Get-AuthenticodeSignature -FilePath "C:\path\to\installer.exe"

   # Check certificate chain
   $cert = Get-AuthenticodeSignature -FilePath "C:\path\to\installer.exe"
   $cert.SignerCertificate | Format-List
   ```

### Step 4: Extract and Store Binaries

1. **Use CommercialBinaryManager**:
   ```python
   from pathlib import Path
   from commercial_binary_manager import CommercialBinaryManager

   manager = CommercialBinaryManager()

   # For installer packages
   installer_path = Path("C:/downloads/adobe_cc_installer.exe")
   success = manager.extract_from_installer(installer_path, "Adobe Creative Cloud 2024")

   # For direct executables
   exe_path = Path("C:/downloads/vmware.exe")
   success = manager.acquire_binary_from_path(exe_path, "VMware Workstation Pro")
   ```

2. **Document Protection Specifications**:
   ```python
   protection_details = {
       "algorithm": "Adobe Licensing v7",
       "key_validation": "RSA-2048 + AES-256",
       "license_server": "https://lm.licenses.adobe.com",
       "activation_method": "Online",
       "hardware_binding": ["CPU_ID", "MAC_ADDRESS", "DISK_SERIAL"],
       "anti_tamper": ["Code signing", "Integrity checks", "Obfuscation"],
       "vendor_documentation": "https://www.adobe.com/devnet/security.html"
   }

   manager.document_protection_specs("Adobe Creative Cloud 2024", protection_details)
   ```

### Step 5: Create Acquisition Report

```python
from commercial_binary_manager import CommercialBinaryManager

manager = CommercialBinaryManager()

# Generate comprehensive report
report = manager.generate_acquisition_report()

print(f"Total binaries acquired: {report['total_binaries']}")
print(f"Validation ready: {report['validation_ready']}")
print(f"Missing software: {', '.join(report['missing_software'])}")
```

## Security Requirements

### Chain of Custody

1. **Cryptographic Signing**:
   ```bash
   # Generate GPG key if not exists
   gpg --gen-key

   # Sign binary hash file
   gpg --sign --armor binary_hashes.txt

   # Verify signature
   gpg --verify binary_hashes.txt.asc
   ```

2. **Audit Trail**:
   - All downloads logged with timestamps
   - Network traffic captured during download
   - System state documented before/after
   - All operations logged to tamper-proof log

### Storage Security

1. **Access Control**:
   ```powershell
   # Set restrictive permissions
   $acl = Get-Acl "D:\\Intellicrack\tests\validation_system\commercial_binaries"
   $acl.SetAccessRuleProtection($true, $false)

   # Remove inherited permissions
   $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

   # Add only current user with read permission
   $permission = "$env:USERNAME", "Read", "Allow"
   $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
   $acl.SetAccessRule($accessRule)

   Set-Acl -Path "D:\\Intellicrack\tests\validation_system\commercial_binaries" -AclObject $acl
   ```

2. **Integrity Monitoring**:
   ```python
   import time
   from pathlib import Path
   from commercial_binary_manager import CommercialBinaryManager

   def monitor_integrity(binary_dir, interval=3600):
       """Monitor binary integrity periodically."""
       manager = CommercialBinaryManager()
       known_hashes = {}

       # Initial hash calculation
       for binary_file in Path(binary_dir).rglob("*.exe"):
           known_hashes[str(binary_file)] = manager.calculate_sha256(binary_file)

       while True:
           time.sleep(interval)

           # Check for modifications
           for binary_path, original_hash in known_hashes.items():
               current_hash = manager.calculate_sha256(Path(binary_path))
               if current_hash != original_hash:
                   raise SecurityError(f"Binary modified: {binary_path}")
   ```

## Legal Compliance

### Important Notes

1. **Trial Software Usage**:
   - Use only for security research and validation
   - Do not distribute acquired binaries
   - Comply with all vendor EULAs
   - Delete after validation testing complete

2. **Documentation Requirements**:
   - Record purpose of acquisition
   - Document research objectives
   - Maintain evidence of legitimate use
   - Store vendor license agreements

3. **Data Retention**:
   - Keep acquisition logs for 1 year minimum
   - Store cryptographic proofs permanently
   - Delete binaries after project completion
   - Maintain audit trail for compliance

## Automation Script

```python
#!/usr/bin/env python3
"""Automated commercial software acquisition script."""

import logging
from pathlib import Path
from commercial_binary_manager import CommercialBinaryManager

def main():
    """Main acquisition workflow."""
    # Setup
    manager = CommercialBinaryManager()
    downloads_dir = Path("<INTELLICRACK_ROOT>/tests/validation_system/downloads")

    # Software to acquire
    software_list = [
        ("Adobe Creative Cloud 2024", "adobe_cc_installer.exe"),
        ("AutoCAD 2024", "autocad_installer.exe"),
        ("MATLAB R2024a", "matlab_installer.exe"),
        ("SolidWorks 2024", "solidworks_installer.exe"),
        ("VMware Workstation Pro", "vmware_installer.exe"),
    ]

    # Process each software
    for software_name, installer_name in software_list:
        installer_path = downloads_dir / installer_name

        if not installer_path.exists():
            logging.warning(f"Installer not found: {installer_name}")
            continue

        # Extract and acquire
        success = manager.extract_from_installer(installer_path, software_name)

        if success:
            logging.info(f"Successfully acquired: {software_name}")
        else:
            logging.error(f"Failed to acquire: {software_name}")

    # Generate final report
    report = manager.generate_acquisition_report()

    if report["validation_ready"]:
        logging.info("All software acquired successfully!")
    else:
        missing = ", ".join(report["missing_software"])
        logging.warning(f"Missing software: {missing}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
```

## Verification Checklist

- [ ] All software downloaded from official sources
- [ ] Vendor checksums verified for each binary
- [ ] Digital signatures validated (where applicable)
- [ ] Chain of custody documented with timestamps
- [ ] Cryptographic hashes calculated and stored
- [ ] Protection specifications documented
- [ ] Audit trail complete and tamper-proof
- [ ] Access controls configured on storage directories
- [ ] Acquisition report generated successfully
- [ ] All code production-ready with no placeholders

## Contact Information

For questions about the acquisition process or legal compliance, contact the project security team.

---
*Document Version: 1.0*
*Last Updated: 2025-09-02*
*Classification: Internal Use Only*
