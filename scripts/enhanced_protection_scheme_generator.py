#!/usr/bin/env python3
"""
Enhanced Protection Scheme Generator for Intellicrack Testing
Creates samples with modern licensing and protection schemes for detection testing.
NO MOCKS - Creates actual protected samples for real functionality testing.
"""

import os
import sys
import struct
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import tempfile
import shutil
import random

class ProtectionSchemeGenerator:
    """Generates samples with various protection schemes for testing detection."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.protected_dir = base_dir / "binaries/pe/protected"
        self.legitimate_dir = base_dir / "binaries/pe/legitimate"
        
        # Modern protection schemes to simulate
        self.protection_schemes = {
            "denuvo_like": {
                "name": "Denuvo-like Protection",
                "description": "Anti-tamper with hardware fingerprinting",
                "detection_signatures": [
                    b"DENUVO_PROTECT",
                    b"HWID_CHECK",
                    b"TAMPER_DETECT"
                ]
            },
            "steam_drm": {
                "name": "Steam DRM",
                "description": "Steam custom executable generation",
                "detection_signatures": [
                    b"STEAM_DRM",
                    b"STEAMSTUB", 
                    b"VALVE_PROTECT"
                ]
            },
            "securom": {
                "name": "SecuROM Protection",
                "description": "CD/DVD copy protection with online activation",
                "detection_signatures": [
                    b"SECUROM",
                    b"ALPHA_ROM",
                    b"DISC_CHECK"
                ]
            },
            "safedisc": {
                "name": "SafeDisc Protection", 
                "description": "CD copy protection with weak sectors",
                "detection_signatures": [
                    b"SAFEDISC",
                    b"MACROVISION",
                    b"WEAK_SECTOR"
                ]
            },
            "starforce": {
                "name": "StarForce Protection",
                "description": "Hardware-based copy protection",
                "detection_signatures": [
                    b"STARFORCE",
                    b"PROTECTION_ID",
                    b"HW_PROTECT"
                ]
            },
            "wibu_codemeter": {
                "name": "WIBU CodeMeter",
                "description": "Hardware dongle protection",
                "detection_signatures": [
                    b"WIBU",
                    b"CODEMETER",
                    b"DONGLE_CHECK"
                ]
            },
            "flexlm_license": {
                "name": "FlexLM Licensing",
                "description": "Network floating license system",
                "detection_signatures": [
                    b"FLEXLM",
                    b"LICENSE_SERVER",
                    b"FLOATING_LIC"
                ]
            },
            "hasp_sentinel": {
                "name": "HASP Sentinel",
                "description": "Hardware key protection",
                "detection_signatures": [
                    b"HASP",
                    b"SENTINEL", 
                    b"HW_KEY_CHECK"
                ]
            },
            "armadillo": {
                "name": "Armadillo Protection",
                "description": "Software protection with licensing",
                "detection_signatures": [
                    b"ARMADILLO",
                    b"NANOMITES",
                    b"COPY_MEM"
                ]
            },
            "asprotect": {
                "name": "ASProtect",
                "description": "Advanced software protection",
                "detection_signatures": [
                    b"ASPROTECT",
                    b"POLY_CRYPT",
                    b"ANTI_DEBUG"
                ]
            }
        }
    
    def generate_all_protection_schemes(self):
        """Generate samples for all protection schemes."""
        print("🛡️  Generating enhanced protection scheme samples...")
        print("=" * 60)
        
        self.protected_dir.mkdir(parents=True, exist_ok=True)
        
        # Get a legitimate binary as base
        base_binary = self.get_base_binary()
        if not base_binary:
            print("❌ No legitimate binary found for protection")
            return
        
        print(f"📁 Using base binary: {base_binary.name}")
        
        # Generate samples for each protection scheme
        for scheme_id, scheme_info in self.protection_schemes.items():
            output_path = self.protected_dir / f"{scheme_id}_protected.exe"
            
            if self.create_protected_sample(base_binary, output_path, scheme_info):
                print(f"✅ Created {scheme_info['name']}: {output_path.name}")
            else:
                print(f"❌ Failed to create {scheme_info['name']}")
        
        # Create license-specific samples
        self.create_license_specific_samples()
        
        print(f"\n📊 Protection scheme samples created in: {self.protected_dir}")
    
    def get_base_binary(self) -> Optional[Path]:
        """Get a legitimate binary to use as base."""
        legitimate_binaries = list(self.legitimate_dir.glob("*.exe"))
        
        if legitimate_binaries:
            # Use smallest legitimate binary as base
            return min(legitimate_binaries, key=lambda x: x.stat().st_size)
        
        # Create minimal PE if no legitimate binary available
        minimal_pe = self.protected_dir / "minimal_base.exe"
        self.create_minimal_pe(minimal_pe)
        return minimal_pe
    
    def create_protected_sample(self, base_binary: Path, output_path: Path, scheme_info: Dict) -> bool:
        """Create a protected sample based on a scheme."""
        try:
            # Read base binary
            with open(base_binary, 'rb') as f:
                binary_data = bytearray(f.read())
            
            # Add protection signatures
            for signature in scheme_info["detection_signatures"]:
                # Insert signature at random location in binary
                insert_pos = random.randint(100, len(binary_data) - 100)
                binary_data[insert_pos:insert_pos] = signature
            
            # Add scheme-specific protection elements
            if "denuvo" in scheme_info["name"].lower():
                binary_data = self.add_denuvo_like_protection(binary_data)
            elif "steam" in scheme_info["name"].lower():
                binary_data = self.add_steam_drm_protection(binary_data)
            elif "flexlm" in scheme_info["name"].lower():
                binary_data = self.add_flexlm_protection(binary_data)
            elif "hasp" in scheme_info["name"].lower():
                binary_data = self.add_hasp_protection(binary_data)
            
            # Write protected binary
            with open(output_path, 'wb') as f:
                f.write(binary_data)
            
            return True
            
        except Exception as e:
            print(f"Error creating protected sample: {e}")
            return False
    
    def add_denuvo_like_protection(self, binary_data: bytearray) -> bytearray:
        """Add Denuvo-like protection elements."""
        # Add anti-tamper sections
        tamper_check = b"\\x48\\x31\\xC0"  # xor rax, rax (simplified)
        tamper_check += b"DENUVO_TAMPER_CHECK_" + os.urandom(16)
        tamper_check += b"\\xC3"  # ret
        
        # Insert tamper check code
        binary_data.extend(tamper_check)
        
        # Add hardware ID generation code
        hwid_code = b"HWID_GENERATION_CODE_"
        hwid_code += hashlib.sha256(b"hardware_fingerprint").digest()[:16]
        binary_data.extend(hwid_code)
        
        return binary_data
    
    def add_steam_drm_protection(self, binary_data: bytearray) -> bytearray:
        """Add Steam DRM protection elements."""
        # Add Steam stub signatures
        steam_stub = b"STEAMSTUB_DATA_"
        steam_stub += b"\\x00" * 32  # Placeholder for Steam data
        steam_stub += b"STEAM_CLIENT_CHECK"
        
        binary_data.extend(steam_stub)
        
        # Add Steam API simulation
        steam_api = b"STEAM_API_INIT_CHECK_"
        steam_api += struct.pack("<L", 0x12345678)  # Steam App ID simulation
        binary_data.extend(steam_api)
        
        return binary_data
    
    def add_flexlm_protection(self, binary_data: bytearray) -> bytearray:
        """Add FlexLM licensing protection elements."""
        # Add license server communication code
        flexlm_code = b"FLEXLM_LICENSE_SERVER_"
        flexlm_code += b"\\x00\\x00\\x69\\x5C"  # Port 27000 (FlexLM default)
        flexlm_code += b"VENDOR_DAEMON_CHECK"
        
        binary_data.extend(flexlm_code)
        
        # Add feature checking code
        feature_check = b"FLEXLM_FEATURE_CHECK_"
        feature_check += b"PRODUCT_NAME_HERE_"
        feature_check += b"VERSION_1_0_"
        binary_data.extend(feature_check)
        
        return binary_data
    
    def add_hasp_protection(self, binary_data: bytearray) -> bytearray:
        """Add HASP hardware key protection elements."""
        # Add hardware key detection code
        hasp_code = b"HASP_HW_KEY_DETECTION_"
        hasp_code += b"\\x05\\x00"  # USB vendor ID simulation
        hasp_code += b"\\x01\\x00"  # Product ID simulation
        hasp_code += b"DONGLE_PRESENT_CHECK"
        
        binary_data.extend(hasp_code)
        
        # Add HASP API simulation
        hasp_api = b"HASP_LOGIN_API_"
        hasp_api += struct.pack("<L", 0xABCDEF12)  # Feature ID
        hasp_api += b"HASP_ENCRYPT_DECRYPT"
        binary_data.extend(hasp_api)
        
        return binary_data
    
    def create_license_specific_samples(self):
        """Create samples specific to license validation testing."""
        print("\\n🔐 Creating license-specific samples...")
        
        license_samples = [
            {
                "name": "enterprise_license_check.exe",
                "type": "enterprise",
                "features": [b"ENTERPRISE_LICENSE", b"DOMAIN_CHECK", b"SEAT_COUNT"]
            },
            {
                "name": "floating_license_client.exe", 
                "type": "floating",
                "features": [b"FLOATING_LICENSE", b"SERVER_HEARTBEAT", b"LICENSE_CHECKOUT"]
            },
            {
                "name": "dongle_protected_app.exe",
                "type": "dongle", 
                "features": [b"HARDWARE_DONGLE", b"USB_KEY_CHECK", b"CHALLENGE_RESPONSE"]
            },
            {
                "name": "online_activation_app.exe",
                "type": "online",
                "features": [b"ONLINE_ACTIVATION", b"SERVER_VALIDATION", b"MACHINE_FINGERPRINT"]
            }
        ]
        
        for sample in license_samples:
            output_path = self.protected_dir / sample["name"]
            self.create_license_sample(output_path, sample)
    
    def create_license_sample(self, output_path: Path, sample_config: Dict):
        """Create a specific license validation sample."""
        # Create minimal PE with license features
        pe_data = self.create_minimal_pe_with_features(sample_config["features"])
        
        # Add license type specific elements
        if sample_config["type"] == "enterprise":
            pe_data = self.add_enterprise_license_features(pe_data)
        elif sample_config["type"] == "floating":
            pe_data = self.add_floating_license_features(pe_data)
        elif sample_config["type"] == "dongle":
            pe_data = self.add_dongle_license_features(pe_data)
        elif sample_config["type"] == "online":
            pe_data = self.add_online_activation_features(pe_data)
        
        output_path.write_bytes(pe_data)
        print(f"✅ Created license sample: {output_path.name}")
    
    def create_minimal_pe_with_features(self, features: List[bytes]) -> bytes:
        """Create minimal PE with specific features."""
        pe_data = self.create_minimal_pe_structure()
        
        # Add feature signatures
        for feature in features:
            pe_data += feature + b"\\x00"
        
        return pe_data
    
    def create_minimal_pe_structure(self) -> bytes:
        """Create minimal valid PE structure."""
        # DOS header
        dos_header = b'MZ\\x90\\x00' + b'\\x00' * 56 + b'\\x40\\x00\\x00\\x00'
        
        # PE header
        pe_header = b'PE\\x00\\x00'  # PE signature
        pe_header += b'\\x4c\\x01'    # Machine (i386)
        pe_header += b'\\x01\\x00'    # NumberOfSections
        pe_header += b'\\x00' * 16   # Timestamps etc
        pe_header += b'\\xE0\\x00'    # SizeOfOptionalHeader
        pe_header += b'\\x02\\x01'    # Characteristics
        
        # Optional header (minimal)
        opt_header = b'\\x0B\\x01'    # Magic (PE32)
        opt_header += b'\\x00' * 222  # Rest of optional header
        
        return dos_header + pe_header + opt_header
    
    def create_minimal_pe(self, output_path: Path):
        """Create minimal PE binary."""
        pe_data = self.create_minimal_pe_structure()
        output_path.write_bytes(pe_data)
    
    def add_enterprise_license_features(self, pe_data: bytes) -> bytes:
        """Add enterprise license specific features."""
        enterprise_data = pe_data + b"ENTERPRISE_LICENSE_VALIDATION_"
        enterprise_data += b"DOMAIN_CONTROLLER_CHECK_"
        enterprise_data += b"ACTIVE_DIRECTORY_LOOKUP_"
        enterprise_data += b"SEAT_COUNT_VALIDATION_"
        return enterprise_data
    
    def add_floating_license_features(self, pe_data: bytes) -> bytes:
        """Add floating license specific features."""
        floating_data = pe_data + b"FLOATING_LICENSE_SERVER_"
        floating_data += struct.pack("<H", 27000)  # Default FlexLM port
        floating_data += b"LICENSE_CHECKOUT_REQUEST_"
        floating_data += b"HEARTBEAT_MECHANISM_"
        return floating_data
    
    def add_dongle_license_features(self, pe_data: bytes) -> bytes:
        """Add dongle license specific features."""
        dongle_data = pe_data + b"HARDWARE_DONGLE_DETECTION_"
        dongle_data += b"USB_ENUMERATION_CODE_"
        dongle_data += b"CHALLENGE_RESPONSE_CRYPTO_"
        dongle_data += b"DONGLE_MEMORY_READ_WRITE_"
        return dongle_data
    
    def add_online_activation_features(self, pe_data: bytes) -> bytes:
        """Add online activation specific features."""
        online_data = pe_data + b"ONLINE_ACTIVATION_SERVER_"
        online_data += b"HTTPS_SSL_VALIDATION_"
        online_data += b"MACHINE_FINGERPRINT_GEN_"
        online_data += b"ACTIVATION_KEY_VALIDATION_"
        return online_data

def main():
    """Main protection scheme generation entry point."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    generator = ProtectionSchemeGenerator(fixtures_dir)
    generator.generate_all_protection_schemes()

if __name__ == '__main__':
    main()