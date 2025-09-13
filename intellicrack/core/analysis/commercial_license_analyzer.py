"""Commercial License Protocol Analyzer for FlexLM, HASP, and CodeMeter.

This module provides comprehensive analysis and bypass generation for
commercial license protection systems used in enterprise software.
"""

import struct
import time
from pathlib import Path
from typing import Any

from ...utils.logger import get_logger
from ..network.protocol_fingerprinter import ProtocolFingerprinter
from ..network.protocols.flexlm_parser import FlexLMProtocolParser
from ..protection_bypass.dongle_emulator import HardwareDongleEmulator

logger = get_logger(__name__)


class CommercialLicenseAnalyzer:
    """Comprehensive analyzer for commercial license protection systems."""

    def __init__(self, binary_path: str | None = None):
        """Initialize the commercial license analyzer.

        Args:
            binary_path: Path to the binary to analyze
        """
        self.binary_path = binary_path
        self.flexlm_parser = FlexLMProtocolParser()
        self.dongle_emulator = HardwareDongleEmulator()
        self.protocol_fingerprinter = ProtocolFingerprinter()

        # Detection results
        self.detected_systems = []
        self.license_servers = []
        self.protection_features = {}

        # Bypass strategies
        self.bypass_strategies = {}

    def analyze_binary(self, binary_path: str | None = None) -> dict[str, Any]:
        """Analyze binary for commercial license protections.

        Args:
            binary_path: Optional path to binary (uses self.binary_path if not provided)

        Returns:
            Analysis results including detected systems and bypass strategies
        """
        if binary_path:
            self.binary_path = binary_path

        results = {
            "detected_systems": [],
            "license_servers": [],
            "protection_features": {},
            "bypass_strategies": {},
            "confidence": 0.0,
        }

        if not self.binary_path or not Path(self.binary_path).exists():
            logger.warning(f"Binary path invalid: {self.binary_path}")
            return results

        # Detect FlexLM
        flexlm_detected = self._detect_flexlm()
        if flexlm_detected:
            results["detected_systems"].append("FlexLM")
            results["bypass_strategies"]["flexlm"] = self._generate_flexlm_bypass()

        # Detect HASP
        hasp_detected = self._detect_hasp()
        if hasp_detected:
            results["detected_systems"].append("HASP")
            results["bypass_strategies"]["hasp"] = self._generate_hasp_bypass()

        # Detect CodeMeter
        codemeter_detected = self._detect_codemeter()
        if codemeter_detected:
            results["detected_systems"].append("CodeMeter")
            results["bypass_strategies"]["codemeter"] = self._generate_codemeter_bypass()

        # Analyze network protocols
        protocol_analysis = self._analyze_network_protocols()
        results["license_servers"] = protocol_analysis.get("servers", [])
        results["protection_features"] = protocol_analysis.get("features", {})

        # Calculate confidence
        results["confidence"] = self._calculate_confidence(results)

        return results

    def analyze(self) -> dict[str, Any]:
        """Wrapper method for API compatibility with tests."""
        return self.analyze_binary(self.binary_path)

    def _detect_flexlm(self) -> bool:
        """Detect FlexLM license system in binary.

        Returns:
            True if FlexLM detected
        """
        flexlm_indicators = [
            b"FLEXlm",
            b"lmgrd",
            b"lmutil",
            b"lmstat",
            b"FLEXLM_DIAGNOSTICS",
            b"@(#)FLEXlm",
            b"license.dat",
            b"license.lic",
            b"VENDOR_LICENSE_FILE",
            b"LM_LICENSE_FILE",
        ]

        flexlm_apis = [
            b"lc_checkout",
            b"lc_checkin",
            b"lc_init",
            b"lc_set_attr",
            b"lc_get_attr",
            b"lc_cryptstr",
            b"lc_new_job",
            b"lc_free_job",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for FlexLM indicators
            for indicator in flexlm_indicators:
                if indicator in binary_data:
                    logger.info(f"FlexLM indicator found: {indicator}")
                    return True

            # Check for FlexLM API calls
            for api in flexlm_apis:
                if api in binary_data:
                    logger.info(f"FlexLM API found: {api}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting FlexLM: {e}")

        return False

    def _detect_hasp(self) -> bool:
        """Detect HASP dongle protection in binary.

        Returns:
            True if HASP detected
        """
        hasp_indicators = [
            b"hasp_login",
            b"hasp_logout",
            b"hasp_encrypt",
            b"hasp_decrypt",
            b"hasp_get_info",
            b"hasp_update",
            b"HASP",
            b"Sentinel",
            b"hasplms.exe",
            b"aksusbd.sys",
        ]

        hasp_dlls = [
            b"hasp_windows",
            b"hasp_net_windows",
            b"hasp_windows_x64",
            b"haspvlib",
            b"hasp_api",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for HASP indicators
            for indicator in hasp_indicators:
                if indicator in binary_data:
                    logger.info(f"HASP indicator found: {indicator}")
                    return True

            # Check for HASP DLLs
            for dll in hasp_dlls:
                if dll in binary_data:
                    logger.info(f"HASP DLL reference found: {dll}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting HASP: {e}")

        return False

    def _detect_codemeter(self) -> bool:
        """Detect CodeMeter protection in binary.

        Returns:
            True if CodeMeter detected
        """
        codemeter_indicators = [
            b"CodeMeter",
            b"CmDongle",
            b"CmStick",
            b"WibuKey",
            b"WIBU-SYSTEMS",
            b"CmContainer",
            b"CmActLicense",
            b"CodeMeterRuntime",
        ]

        codemeter_apis = [
            b"CmGetInfo",
            b"CmGetLicenseInfo",
            b"CmGetVersion",
            b"CmAccess",
            b"CmCrypt",
            b"CmDecrypt",
            b"CmEncrypt",
            b"CmRelease",
        ]

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for CodeMeter indicators
            for indicator in codemeter_indicators:
                if indicator in binary_data:
                    logger.info(f"CodeMeter indicator found: {indicator}")
                    return True

            # Check for CodeMeter APIs
            for api in codemeter_apis:
                if api in binary_data:
                    logger.info(f"CodeMeter API found: {api}")
                    return True

        except Exception as e:
            logger.error(f"Error detecting CodeMeter: {e}")

        return False

    def _analyze_network_protocols(self) -> dict[str, Any]:
        """Analyze network protocols for license communication.

        Returns:
            Network protocol analysis results
        """
        analysis = {"servers": [], "features": {}, "protocols": []}

        # Use protocol fingerprinter to detect license servers
        if self.binary_path:
            fingerprint = self.protocol_fingerprinter.fingerprint_packet(b"", {"binary_path": self.binary_path})

            if fingerprint and fingerprint.get("protocol_type") in [
                "FlexLM",
                "HASP Network",
                "CodeMeter Network",
            ]:
                analysis["protocols"].append(fingerprint.get("protocol_type"))

                # Extract server information
                if fingerprint.get("server_port"):
                    analysis["servers"].append(
                        {
                            "type": fingerprint.get("protocol_type"),
                            "port": fingerprint.get("server_port"),
                            "hostname": fingerprint.get("server_hostname", "localhost"),
                        }
                    )

                # Extract feature information
                analysis["features"] = fingerprint.get("features", {})

        return analysis

    def _generate_flexlm_bypass(self) -> dict[str, Any]:
        """Generate FlexLM bypass strategy.

        Returns:
            FlexLM bypass configuration
        """
        bypass = {
            "method": "flexlm_emulation",
            "server_port": 27000,  # Default FlexLM port
            "vendor_daemon": "vendor",
            "features": [],
            "patches": [],
            "hooks": [],
            "emulation_script": "",
        }

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "lc_checkout",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return success)
                "description": "Always return successful checkout",
            },
            {
                "api": "lc_init",
                "replacement": b"\xb8\x01\x00\x00\x00\xc3",  # mov eax,1; ret
                "description": "Always return initialized",
            },
            {
                "api": "lc_cryptstr",
                "replacement": b"\x48\x89\xf0\xc3",  # mov rax,rsi; ret (return input)
                "description": "Bypass encryption check",
            },
        ]

        # Generate binary patches
        bypass["patches"] = [
            {
                "pattern": b"\x74.\x8b\x45.\x85\xc0",  # Common license check pattern
                "replacement": b"\x90\x90" + b"\x8b\x45.\x85\xc0",  # NOP the conditional jump
                "description": "Remove license validation jump",
            }
        ]

        # Generate emulation script
        bypass["emulation_script"] = self._generate_flexlm_script()
        bypass["frida_script"] = self._generate_flexlm_script()

        return bypass

    def _generate_hasp_bypass(self) -> dict[str, Any]:
        """Generate HASP bypass strategy.

        Returns:
            HASP bypass configuration
        """
        bypass = {
            "method": "hasp_emulation",
            "dongle_type": "HASP HL",
            "vendor_id": 0x0529,
            "product_id": 0x0001,
            "features": [],
            "hooks": [],
            "virtual_device": {},
            "emulation_script": "",
        }

        # Get dongle configuration
        dongle_config = self.dongle_emulator.get_dongle_config("hasp")
        bypass["vendor_id"] = dongle_config["vendor_id"]
        bypass["product_id"] = dongle_config["product_id"]
        bypass["features"] = dongle_config["features"]

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "hasp_login",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return 0/success)
                "description": "Always return successful login",
            },
            {
                "api": "hasp_encrypt",
                "replacement": self._generate_hasp_encrypt_patch(),
                "description": "XOR encryption with dynamic key generation",
            },
            {
                "api": "hasp_get_info",
                "replacement": self._generate_hasp_info_response(),
                "description": "Return valid dongle info",
            },
        ]

        # Configure virtual device
        bypass["virtual_device"] = {
            "type": "USB",
            "vendor_id": bypass["vendor_id"],
            "product_id": bypass["product_id"],
            "serial": dongle_config["serial"],
            "memory_size": dongle_config["memory_size"],
        }

        # Generate emulation script
        bypass["emulation_script"] = self._generate_hasp_script()
        bypass["frida_script"] = self._generate_hasp_script()
        bypass["api_hooks"] = bypass["hooks"]  # Alias for compatibility

        return bypass

    def _generate_codemeter_bypass(self) -> dict[str, Any]:
        """Generate CodeMeter bypass strategy.

        Returns:
            CodeMeter bypass configuration
        """
        bypass = {
            "method": "codemeter_emulation",
            "container_type": "CmStick",
            "firm_code": 100000,
            "product_code": 1,
            "features": [],
            "hooks": [],
            "patches": [],
            "emulation_script": "",
        }

        # Get dongle configuration
        dongle_config = self.dongle_emulator.get_dongle_config("codemeter")
        bypass["features"] = dongle_config["features"]

        # Generate API hooks
        bypass["hooks"] = [
            {
                "api": "CmAccess",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret (return 0/success)
                "description": "Always return successful access",
            },
            {
                "api": "CmGetLicenseInfo",
                "replacement": self._generate_codemeter_license_info(),
                "description": "Return valid license info",
            },
            {
                "api": "CmCrypt",
                "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret
                "description": "Bypass encryption/decryption",
            },
        ]

        # Generate binary patches
        bypass["patches"] = [
            {
                "pattern": b"\xff\x15....\x85\xc0\x75",  # Call CmAccess and check result
                "replacement": b"\x31\xc0\x90\x90\x90\x90\x90\x90\x90",  # xor eax,eax + NOPs
                "description": "Bypass CmAccess check",
            }
        ]

        # Generate emulation script
        bypass["emulation_script"] = self._generate_codemeter_script()
        bypass["frida_script"] = self._generate_codemeter_script()

        return bypass

    def _generate_hasp_info_response(self) -> bytes:
        """Generate dynamic HASP info response bytes based on binary analysis.

        Returns:
            Binary response for hasp_get_info
        """
        import hashlib
        import time

        # Generate dynamic values based on binary analysis
        binary_hash = 0
        vendor_id = 0x529  # Default SafeNet vendor ID range
        product_id = 1

        if hasattr(self, "binary_path") and self.binary_path:
            # Generate values from binary characteristics
            try:
                with open(self.binary_path, "rb") as f:
                    # Read first 4KB for fingerprinting
                    data = f.read(4096)
                    hash_obj = hashlib.sha256(data)
                    hash_bytes = hash_obj.digest()

                    # Extract vendor ID from hash (keep in valid range)
                    vendor_id = (struct.unpack("<H", hash_bytes[0:2])[0] & 0x0FFF) | 0x0500

                    # Extract product ID
                    product_id = struct.unpack("<H", hash_bytes[2:4])[0] & 0x00FF
                    if product_id == 0:
                        product_id = 1

                    # Generate serial from binary
                    binary_hash = struct.unpack("<I", hash_bytes[4:8])[0]
            except (OSError, IOError, struct.error, ValueError):
                # Use fallback values if binary reading fails
                vendor_id = 0x0500 | (int(time.time()) & 0x0FFF)
                product_id = 1
                binary_hash = hash(self.binary_path) & 0xFFFFFFFF

        # Generate serial number based on system and binary
        import platform

        machine_id = hash(platform.node()) & 0xFFFFFFFF
        serial_number = (binary_hash ^ machine_id) & 0x7FFFFFFF
        if serial_number == 0:
            serial_number = 0x10000000 | (int(time.time()) & 0x0FFFFFFF)

        # Calculate memory size based on product type
        memory_sizes = {
            1: 0x100,  # 256 bytes - Basic
            2: 0x400,  # 1KB - Standard
            3: 0x1000,  # 4KB - Professional
            4: 0x4000,  # 16KB - Enterprise
        }
        memory_size = memory_sizes.get(product_id & 0x03, 0x100)

        # Real-time clock value (current timestamp)
        rtc_value = int(time.time()) & 0xFFFFFFFF

        # Generate features bitmap based on analysis
        features = 0

        # Analyze binary for feature requirements
        if hasattr(self, "protection_info") and self.protection_info:
            if self.protection_info.get("has_network", False):
                features |= 0x00000001  # Network feature
            if self.protection_info.get("has_crypto", False):
                features |= 0x00000002  # Crypto feature
            if self.protection_info.get("has_timer", False):
                features |= 0x00000004  # Timer feature
            if self.protection_info.get("has_counter", False):
                features |= 0x00000008  # Counter feature

        # Enable all features if none detected (full license)
        if features == 0:
            features = 0xFFFFFFFF

        # HASP info structure with dynamic values
        info = struct.pack(
            "<IIIIIIII",
            0x4D535048,  # Magic "HPSM"
            0x00000001,  # Version
            vendor_id,  # Dynamic vendor ID
            product_id,  # Dynamic product ID
            serial_number,  # Dynamic serial number
            memory_size,  # Dynamic memory size
            rtc_value,  # Current RTC
            features,  # Dynamic features bitmap
        )

        # Add extended info if needed
        if hasattr(self, "extended_info") and self.extended_info:
            # Add session info
            session_info = struct.pack(
                "<II",
                0x53455353,  # "SESS"
                machine_id,  # Session ID
            )
            info += session_info

        return info

    def _generate_codemeter_license_info(self) -> bytes:
        """Generate dynamic CodeMeter license info response based on binary analysis.

        Returns:
            Binary response for CmGetLicenseInfo
        """
        import hashlib
        import time

        # Generate dynamic values based on binary analysis
        firm_code = 100000  # Default Wibu-Systems range
        product_code = 1
        feature_map = 0

        if hasattr(self, "binary_path") and self.binary_path:
            # Generate values from binary characteristics
            try:
                with open(self.binary_path, "rb") as f:
                    # Read sections for analysis
                    data = f.read(8192)
                    hash_obj = hashlib.sha256(data)
                    hash_bytes = hash_obj.digest()

                    # Generate firm code (100000-999999 range for custom)
                    firm_code = 100000 + (struct.unpack("<I", hash_bytes[0:4])[0] % 900000)

                    # Generate product code (1-65535)
                    product_code = (struct.unpack("<H", hash_bytes[4:6])[0] % 65535) + 1

                    # Analyze binary for feature requirements
                    data_str = data.decode("latin-1", errors="ignore").lower()

                    # Check for specific CodeMeter API calls to determine features
                    if "cmaccess" in data_str:
                        feature_map |= 0x00000001  # Basic access
                    if "cmcrypt" in data_str:
                        feature_map |= 0x00000002  # Encryption
                    if "cmsign" in data_str:
                        feature_map |= 0x00000004  # Signing
                    if "cmtime" in data_str:
                        feature_map |= 0x00000008  # Time functions
                    if "cmcount" in data_str:
                        feature_map |= 0x00000010  # Counter functions
                    if "cmlist" in data_str:
                        feature_map |= 0x00000020  # List functions
                    if "cmserial" in data_str:
                        feature_map |= 0x00000040  # Serial functions

            except (OSError, IOError, struct.error, ValueError, UnicodeDecodeError):
                # Use fallback values if binary analysis fails
                firm_code = 100000 + (hash(self.binary_path) % 900000)
                product_code = 1
                feature_map = 0xFFFFFFFF  # Enable all features as fallback

        # Enable all features if none detected (full license)
        if feature_map == 0:
            feature_map = 0xFFFFFFFF

        # Generate options based on system
        options = 0

        # Check for network license
        if hasattr(self, "protection_info") and self.protection_info:
            if self.protection_info.get("has_network", False):
                options |= 0x00000001  # Network license
            if self.protection_info.get("has_usb", False):
                options |= 0x00000002  # USB dongle
            if self.protection_info.get("has_cloud", False):
                options |= 0x00000004  # Cloud license

        # Version information from binary
        major_version = 1
        minor_version = 0

        if hasattr(self, "version_info") and self.version_info:
            major_version = self.version_info.get("major", 1)
            minor_version = self.version_info.get("minor", 0)

        # License count (seats)
        count = 1  # Single user by default

        if options & 0x00000001:  # Network license
            count = 100  # Multi-user for network licenses

        # Generate box serial based on machine
        import platform

        machine_hash = hash(platform.node()) & 0xFFFFFFFF

        # CodeMeter license structure with dynamic values
        info = struct.pack(
            "<IIIIIHHBBBB",
            0x434D4C49,  # Magic "ILMC"
            firm_code,  # Dynamic firm code
            product_code,  # Dynamic product code
            feature_map,  # Dynamic feature map
            options,  # Dynamic options
            major_version,  # Version major
            minor_version,  # Version minor
            count,  # License count
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
        )

        # Add extended license data
        # Box information
        box_info = struct.pack(
            "<IIII",
            0x424F5821,  # Magic "!XOB"
            machine_hash,  # Box serial
            0x00010001,  # Box version
            int(time.time()) & 0xFFFFFFFF,  # Timestamp
        )
        info += box_info

        # Add usage data
        usage_data = struct.pack(
            "<IIHH",
            0x55534745,  # Magic "EGSU"
            count,  # Total licenses
            count,  # Available licenses
            0,  # Reserved
        )
        info += usage_data

        # Add expiration data if needed
        if hasattr(self, "expiration_info") and self.expiration_info:
            exp_time = self.expiration_info.get("expiry_time", 0)
            if exp_time == 0:
                exp_time = 0xFFFFFFFF  # Never expires

            exp_data = struct.pack(
                "<II",
                0x45585052,  # Magic "RPXE"
                exp_time,  # Expiration timestamp
            )
            info += exp_data

        return info

    def _generate_hasp_encrypt_patch(self) -> bytes:
        """Generate x86-64 assembly patch for HASP encryption.

        Returns:
            Binary patch bytes for XOR encryption with dynamic key
        """
        import hashlib
        import platform
        import struct

        # Generate dynamic encryption key based on system
        machine_id = hash(platform.node()) & 0xFFFFFFFF
        timestamp = int(time.time())

        # Create XOR key from system characteristics
        key_data = f"{machine_id}:{timestamp}".encode()
        key_hash = hashlib.sha256(key_data).digest()[:4]
        xor_key = struct.unpack("<I", key_hash)[0]

        # x86-64 assembly for XOR encryption
        # Function: hasp_encrypt(handle, buffer, length)
        # RDI = handle, RSI = buffer, RDX = length

        patch = bytearray()

        # Save registers
        patch += b"\x50"  # push rax
        patch += b"\x51"  # push rcx
        patch += b"\x52"  # push rdx
        patch += b"\x56"  # push rsi

        # Check if length > 0
        patch += b"\x48\x85\xd2"  # test rdx, rdx
        patch += b"\x74\x1f"  # jz end

        # Load XOR key
        patch += b"\x48\xb8"  # movabs rax, imm64
        patch += struct.pack("<Q", xor_key)  # XOR key value

        # Setup loop counter
        patch += b"\x48\x89\xd1"  # mov rcx, rdx (length)

        # Encryption loop
        # loop_start:
        patch += b"\x8a\x1e"  # mov bl, [rsi]
        patch += b"\x30\xc3"  # xor bl, al
        patch += b"\x88\x1e"  # mov [rsi], bl
        patch += b"\x48\xff\xc6"  # inc rsi
        patch += b"\x48\xc1\xc8\x08"  # ror rax, 8 (rotate key)
        patch += b"\xe2\xf3"  # loop loop_start

        # end:
        # Restore registers
        patch += b"\x5e"  # pop rsi
        patch += b"\x5a"  # pop rdx
        patch += b"\x59"  # pop rcx
        patch += b"\x58"  # pop rax

        # Return success (0)
        patch += b"\x31\xc0"  # xor eax, eax
        patch += b"\xc3"  # ret

        return bytes(patch)

    def _generate_flexlm_script(self) -> str:
        """Generate Frida script for FlexLM bypass.

        Returns:
            Frida script as string
        """
        import hashlib
        import platform
        import time

        # Generate dynamic license data based on system and binary
        machine_name = platform.node()
        timestamp = int(time.time())

        # Generate vendor daemon code
        vendor_code = hashlib.sha256(f"{machine_name}:{timestamp}".encode()).hexdigest()[:16]

        # Generate hostid based on system
        hostid = hashlib.sha256(machine_name.encode()).hexdigest()[:8]

        return f"""
// FlexLM Advanced License Bypass Script with Dynamic License Generation
// Generated at: {timestamp}

var flexlm_context = {{
    vendor_code: "{vendor_code}",
    hostid: "{hostid}",
    features: {{}},
    license_data: null,
    daemon_port: 27000 + (Process.id % 1000),
    server_name: "{machine_name}",
    license_version: "11.16.2",
    vendor_keys: {{}}
}};

// Generate dynamic license data
function generateLicenseData(feature, version) {{
    var date = new Date();
    var expiry = new Date(date.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

    var license_key = [];
    var seed = Process.id ^ date.getTime();

    // Generate 20-byte license key
    for (var i = 0; i < 20; i++) {{
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        license_key.push((seed >> 16) & 0xff);
    }}

    return {{
        feature: feature,
        version: version || "1.0",
        vendor: flexlm_context.vendor_code,
        expiry_date: expiry.toISOString().split('T')[0],
        issued_date: date.toISOString().split('T')[0],
        count: 9999,
        hostid: flexlm_context.hostid,
        server: flexlm_context.server_name,
        port: flexlm_context.daemon_port,
        key: license_key,
        signature: generateSignature(feature, version, license_key)
    }};
}}

// Generate cryptographic signature
function generateSignature(feature, version, key) {{
    var sig = [];
    var data = feature + version + flexlm_context.vendor_code;
    var hash = 0;

    for (var i = 0; i < data.length; i++) {{
        hash = ((hash << 5) - hash) + data.charCodeAt(i);
        hash = hash & 0xffffffff;
    }}

    // Mix with key
    for (var i = 0; i < key.length; i++) {{
        hash ^= key[i] << ((i % 4) * 8);
    }}

    // Generate 16-byte signature
    for (var i = 0; i < 16; i++) {{
        hash = (hash * 1103515245 + 12345) & 0x7fffffff;
        sig.push((hash >> (i % 3 * 8)) & 0xff);
    }}

    return sig;
}}

// Hook lc_checkout with dynamic license generation
Interceptor.attach(Module.findExportByName(null, "lc_checkout"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.feature = args[1].readCString();
        this.version = args[2].readCString();
        this.license_handle = args[5];

        console.log("[FlexLM] lc_checkout called");
        console.log("  Feature: " + this.feature);
        console.log("  Version: " + this.version);

        // Generate and store license for this feature
        if (!flexlm_context.features[this.feature]) {{
            flexlm_context.features[this.feature] = generateLicenseData(this.feature, this.version);
            console.log("[FlexLM] Generated license for " + this.feature);
        }}

        // Write license data to handle if provided
        if (!this.license_handle.isNull()) {{
            var lic = flexlm_context.features[this.feature];

            // Write license structure (simplified FLEXlm license format)
            this.license_handle.writeU32(0x4C494300); // "LIC\\0" magic
            this.license_handle.add(4).writeU32(lic.count);
            this.license_handle.add(8).writeU32(Date.parse(lic.expiry_date) / 1000);
            this.license_handle.add(12).writePointer(Memory.allocUtf8String(lic.vendor));
            this.license_handle.add(16).writePointer(Memory.allocUtf8String(lic.server));
            this.license_handle.add(20).writeU32(lic.port);

            // Write signature
            var sig_buf = Memory.alloc(16);
            for (var i = 0; i < 16; i++) {{
                sig_buf.add(i).writeU8(lic.signature[i]);
            }}
            this.license_handle.add(24).writePointer(sig_buf);
        }}
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] License checkout: returning success (0)");
        retval.replace(0);  // LM_NOERROR
    }}
}});

// Hook lc_init with proper job structure initialization
Interceptor.attach(Module.findExportByName(null, "lc_init"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.vendor_code = args[1];
        this.vendor_key = args[2];

        console.log("[FlexLM] lc_init called");

        // Initialize job structure
        if (!this.job.isNull()) {{
            this.job.writeU32(0x4A4F4200); // "JOB\\0" magic
            this.job.add(4).writeU32(Process.id); // job ID
            this.job.add(8).writeU32(1); // initialized flag
            this.job.add(12).writePointer(Memory.allocUtf8String(flexlm_context.vendor_code));
            this.job.add(16).writeU32(parseInt(flexlm_context.hostid, 16));
            this.job.add(20).writeU32(flexlm_context.daemon_port);

            // Initialize vendor daemon connection info
            this.job.add(24).writePointer(Memory.allocUtf8String(flexlm_context.server_name));
            this.job.add(28).writeU32(1); // connected flag
        }}

        // Store vendor key if provided
        if (!this.vendor_key.isNull()) {{
            var key_data = this.vendor_key.readByteArray(16);
            flexlm_context.vendor_keys[this.vendor_code.readCString()] = key_data;
        }}
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] Initialization: returning valid job handle");
        if (retval.toInt32() < 0) {{
            // Replace error with valid job pointer
            var job = Memory.alloc(32);
            job.writeU32(0x4A4F4200); // "JOB\\0" magic
            job.add(4).writeU32(Process.id);
            job.add(8).writeU32(1); // initialized
            retval.replace(job);
        }}
    }}
}});

// Hook lc_cryptstr for license string decryption
Interceptor.attach(Module.findExportByName(null, "lc_cryptstr"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.input = args[1];
        this.input_str = this.input.readCString();
        this.vendor_key = args[2];

        console.log("[FlexLM] lc_cryptstr called");
        console.log("  Input: " + this.input_str);
    }},
    onLeave: function(retval) {{
        // Decrypt or generate valid license string
        if (this.input_str.indexOf("FEATURE") === 0 || this.input_str.indexOf("INCREMENT") === 0) {{
            // Parse and generate valid license line
            var parts = this.input_str.split(" ");
            var feature = parts[1] || "default";
            var vendor = parts[2] || flexlm_context.vendor_code;

            var lic = flexlm_context.features[feature] || generateLicenseData(feature, "1.0");

            // Generate valid FlexLM license line format
            var license_line = "FEATURE " + feature + " " + vendor + " " +
                              lic.version + " permanent uncounted " +
                              lic.signature.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() +
                              " HOSTID=" + flexlm_context.hostid;

            var result = Memory.allocUtf8String(license_line);
            console.log("[FlexLM] Generated license line: " + license_line);
            retval.replace(result);
        }} else {{
            // For other strings, return decrypted (original) version
            console.log("[FlexLM] Returning decrypted string");
            retval.replace(this.input);
        }}
    }}
}});

// Hook lc_checkin for license release
Interceptor.attach(Module.findExportByName(null, "lc_checkin"), {{
    onEnter: function(args) {{
        var feature = args[1].readCString();
        console.log("[FlexLM] lc_checkin called for feature: " + feature);
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] License checkin: returning success");
        retval.replace(0);  // Always successful
    }}
}});

// Hook lc_hostid to return consistent hostid
Interceptor.attach(Module.findExportByName(null, "lc_hostid"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.hostid_type = args[1];
        this.hostid_buf = args[2];

        console.log("[FlexLM] lc_hostid called, type: " + this.hostid_type.toInt32());
    }},
    onLeave: function(retval) {{
        if (!this.hostid_buf.isNull()) {{
            // Write our generated hostid
            this.hostid_buf.writeUtf8String(flexlm_context.hostid);
            console.log("[FlexLM] Returning hostid: " + flexlm_context.hostid);
        }}
        retval.replace(0);  // Success
    }}
}});

// Hook lc_get_attr for license attributes
Interceptor.attach(Module.findExportByName(null, "lc_get_attr"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.attr_key = args[1].readCString();
        this.attr_buf = args[2];

        console.log("[FlexLM] lc_get_attr called for: " + this.attr_key);
    }},
    onLeave: function(retval) {{
        if (!this.attr_buf.isNull()) {{
            // Return appropriate attribute values
            if (this.attr_key === "LM_A_VENDOR_CODE") {{
                this.attr_buf.writeUtf8String(flexlm_context.vendor_code);
            }} else if (this.attr_key === "LM_A_HOST") {{
                this.attr_buf.writeUtf8String(flexlm_context.server_name);
            }} else if (this.attr_key === "LM_A_PORT") {{
                this.attr_buf.writeUtf8String(flexlm_context.daemon_port.toString());
            }} else if (this.attr_key === "LM_A_LICENSE_VERSION") {{
                this.attr_buf.writeUtf8String(flexlm_context.license_version);
            }} else {{
                this.attr_buf.writeUtf8String("1");  // Default value
            }}
        }}
        retval.replace(0);  // Success
    }}
}});

// Hook lc_status for license status checks
Interceptor.attach(Module.findExportByName(null, "lc_status"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.feature = args[1].readCString();

        console.log("[FlexLM] lc_status called for feature: " + this.feature);
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] Status check: returning licensed (0)");
        retval.replace(0);  // Feature is licensed
    }}
}});

// Hook l_sg for security/signature functions
Interceptor.attach(Module.findExportByName(null, "l_sg"), {{
    onEnter: function(args) {{
        console.log("[FlexLM] l_sg (signature) called");
        this.output = args[0];
    }},
    onLeave: function(retval) {{
        // Generate valid signature
        if (!this.output.isNull()) {{
            var sig = generateSignature("default", "1.0", [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]);
            for (var i = 0; i < 16; i++) {{
                this.output.add(i).writeU8(sig[i]);
            }}
        }}
        retval.replace(0);  // Success
    }}
}});

console.log("[FlexLM] Advanced bypass hooks installed");
console.log("[FlexLM] Vendor code: " + flexlm_context.vendor_code);
console.log("[FlexLM] HostID: " + flexlm_context.hostid);
console.log("[FlexLM] Server: " + flexlm_context.server_name + ":" + flexlm_context.daemon_port);
"""

    def _generate_hasp_script(self) -> str:
        """Generate Frida script for HASP bypass with dynamic handle generation.

        Returns:
            Frida script as string
        """
        return """
// HASP Dongle Emulation Script with Dynamic Handle
var hasp_handle = Memory.alloc(4);

// Generate dynamic handle based on process and timestamp
var process_id = Process.id;
var timestamp = Date.now();
var dynamic_handle = (process_id ^ timestamp) & 0x7FFFFFFF;
if (dynamic_handle === 0) {
    dynamic_handle = 0x10000000 | (Math.random() * 0x0FFFFFFF) | 0;
}
hasp_handle.writeU32(dynamic_handle);

console.log("[HASP] Generated dynamic handle: 0x" + dynamic_handle.toString(16));

// Track session data
var session_data = {
    handle: dynamic_handle,
    login_time: Date.now(),
    feature_id: 0,
    vendor_id: 0
};

Interceptor.attach(Module.findExportByName(null, "hasp_login"), {
    onEnter: function(args) {
        var feature_id = args[0].toInt32();
        var vendor_code = args[1];
        session_data.feature_id = feature_id;

        console.log("[HASP] hasp_login called");
        console.log("  Feature ID: " + feature_id);
        if (vendor_code) {
            console.log("  Vendor code present");
            // Extract vendor ID from vendor code if possible
            try {
                var vendor_bytes = vendor_code.readByteArray(16);
                var vendor_hash = 0;
                for (var i = 0; i < 16; i++) {
                    vendor_hash = (vendor_hash << 1) ^ vendor_bytes[i];
                }
                session_data.vendor_id = vendor_hash & 0xFFFF;
            } catch(e) {}
        }

        this.handle_ptr = args[4];  // Handle output pointer
    },
    onLeave: function(retval) {
        console.log("[HASP] Emulating successful login");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(hasp_handle);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_encrypt"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();

        console.log("[HASP] hasp_encrypt called");
        console.log("  Handle: 0x" + this.handle.toString(16));
        console.log("  Length: " + this.length);
    },
    onLeave: function(retval) {
        console.log("[HASP] Performing XOR encryption");
        // Simple XOR encryption with handle as key
        if (this.buffer && this.length > 0) {
            var data = this.buffer.readByteArray(this.length);
            var encrypted = new Uint8Array(this.length);
            var key = this.handle;

            for (var i = 0; i < this.length; i++) {
                encrypted[i] = data[i] ^ ((key >> ((i % 4) * 8)) & 0xFF);
            }

            this.buffer.writeByteArray(encrypted);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_decrypt"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();

        console.log("[HASP] hasp_decrypt called");
    },
    onLeave: function(retval) {
        console.log("[HASP] Performing XOR decryption");
        // Same XOR operation for decryption
        if (this.buffer && this.length > 0) {
            var data = this.buffer.readByteArray(this.length);
            var decrypted = new Uint8Array(this.length);
            var key = this.handle;

            for (var i = 0; i < this.length; i++) {
                decrypted[i] = data[i] ^ ((key >> ((i % 4) * 8)) & 0xFF);
            }

            this.buffer.writeByteArray(decrypted);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_get_info"), {
    onEnter: function(args) {
        this.scope = args[1].readCString();
        this.format = args[2].readCString();
        this.info_ptr = args[3];

        console.log("[HASP] hasp_get_info called");
        console.log("  Scope: " + this.scope);
        console.log("  Format: " + this.format);
    },
    onLeave: function(retval) {
        console.log("[HASP] Providing dynamic dongle info");
        if (this.info_ptr) {
            var info_xml = '<?xml version="1.0" encoding="UTF-8"?>';
            info_xml += '<hasp_info>';
            info_xml += '<dongle>';
            info_xml += '<id>' + session_data.handle.toString(16) + '</id>';
            info_xml += '<vendor_id>' + (session_data.vendor_id || 0x529).toString(16) + '</vendor_id>';
            info_xml += '<feature_id>' + session_data.feature_id + '</feature_id>';
            info_xml += '<session_time>' + (Date.now() - session_data.login_time) + '</session_time>';
            info_xml += '<memory_size>256</memory_size>';
            info_xml += '<type>HASP_HL_PRO</type>';
            info_xml += '</dongle>';
            info_xml += '</hasp_info>';

            this.info_ptr.writeUtf8String(info_xml);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_get_size"), {
    onEnter: function(args) {
        this.size_ptr = args[2];
    },
    onLeave: function(retval) {
        console.log("[HASP] Returning memory size");
        if (this.size_ptr) {
            this.size_ptr.writeU32(256);  // 256 bytes memory
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_read"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.file_id = args[1].toInt32();
        this.offset = args[2].toInt32();
        this.length = args[3].toInt32();
        this.buffer = args[4];

        console.log("[HASP] hasp_read called");
        console.log("  File ID: " + this.file_id);
        console.log("  Offset: " + this.offset);
        console.log("  Length: " + this.length);
    },
    onLeave: function(retval) {
        console.log("[HASP] Providing memory data");
        if (this.buffer && this.length > 0) {
            // Generate consistent data based on file_id and offset
            var data = new Uint8Array(this.length);
            for (var i = 0; i < this.length; i++) {
                data[i] = ((this.file_id + this.offset + i) * 0x37) & 0xFF;
            }
            this.buffer.writeByteArray(data);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

console.log("[HASP] Dongle emulation active with dynamic handle: 0x" + dynamic_handle.toString(16));
"""

    def _generate_codemeter_script(self) -> str:
        """Generate Frida script for CodeMeter bypass with dynamic handle generation.

        Returns:
            Frida script as string
        """
        return """
// CodeMeter License Bypass Script with Dynamic Handle
var cm_handle = Memory.alloc(8);

// Generate dynamic handle based on process, machine, and timestamp
var process_id = Process.id;
var process_name = Process.enumerateModules()[0].name;
var timestamp = Date.now();

// Create unique handle combining multiple factors
var name_hash = 0;
for (var i = 0; i < process_name.length; i++) {
    name_hash = ((name_hash << 5) - name_hash) + process_name.charCodeAt(i);
    name_hash = name_hash & 0xFFFFFFFF;
}

var dynamic_handle_low = (process_id ^ timestamp) & 0xFFFFFFFF;
var dynamic_handle_high = (name_hash ^ (timestamp >> 32)) & 0xFFFFFFFF;

// Ensure non-zero handle
if (dynamic_handle_low === 0) {
    dynamic_handle_low = 0x10000000 | (Math.random() * 0x0FFFFFFF) | 0;
}
if (dynamic_handle_high === 0) {
    dynamic_handle_high = 0x20000000 | (Math.random() * 0x0FFFFFFF) | 0;
}

// Write 64-bit handle
if (Process.arch === 'x64') {
    cm_handle.writeU64((BigInt(dynamic_handle_high) << 32n) | BigInt(dynamic_handle_low));
} else {
    cm_handle.writeU32(dynamic_handle_low);
}

console.log("[CodeMeter] Generated dynamic handle: 0x" + dynamic_handle_high.toString(16) + dynamic_handle_low.toString(16));

// Track session and license data
var session_data = {
    handle: {low: dynamic_handle_low, high: dynamic_handle_high},
    firm_code: 0,
    product_code: 0,
    feature_map: 0xFFFFFFFF,
    access_time: Date.now(),
    box_serial: 0,
    encryption_key: null
};

// Generate box serial from machine characteristics
try {
    var modules = Process.enumerateModules();
    var module_hash = 0;
    for (var i = 0; i < Math.min(5, modules.length); i++) {
        module_hash ^= modules[i].base.toInt32();
    }
    session_data.box_serial = module_hash & 0x7FFFFFFF;
} catch(e) {
    session_data.box_serial = (Math.random() * 0x7FFFFFFF) | 0;
}

Interceptor.attach(Module.findExportByName(null, "CmAccess"), {
    onEnter: function(args) {
        var firm_code = args[0].toInt32();
        var product_code = args[1].toInt32();
        var feature_code = args[2].toInt32();

        session_data.firm_code = firm_code;
        session_data.product_code = product_code;

        console.log("[CodeMeter] CmAccess called");
        console.log("  FirmCode: " + firm_code);
        console.log("  ProductCode: " + product_code);
        console.log("  FeatureCode: " + feature_code);

        this.handle_ptr = args[3];
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing access with dynamic handle");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(cm_handle);
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetLicenseInfo"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.info_ptr = args[1];
        this.info_size = args[2] ? args[2].toInt32() : 0;

        console.log("[CodeMeter] CmGetLicenseInfo called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing dynamic license info");
        if (this.info_ptr) {
            // Write dynamic license structure
            var offset = 0;

            // Magic header
            this.info_ptr.add(offset).writeU32(0x434D4C49);  // "ILMC"
            offset += 4;

            // Firm code (use session data or generate)
            this.info_ptr.add(offset).writeU32(session_data.firm_code || 100000);
            offset += 4;

            // Product code
            this.info_ptr.add(offset).writeU32(session_data.product_code || 1);
            offset += 4;

            // Feature map (all features enabled)
            this.info_ptr.add(offset).writeU32(session_data.feature_map);
            offset += 4;

            // Box serial
            this.info_ptr.add(offset).writeU32(session_data.box_serial);
            offset += 4;

            // License options
            this.info_ptr.add(offset).writeU32(0x00000001);  // Network capable
            offset += 4;

            // Version info
            this.info_ptr.add(offset).writeU16(1);  // Major
            this.info_ptr.add(offset + 2).writeU16(0);  // Minor
            offset += 4;

            // Usage counters
            this.info_ptr.add(offset).writeU32(100);  // Total licenses
            this.info_ptr.add(offset + 4).writeU32(99);  // Available
            offset += 8;

            // Timestamp
            this.info_ptr.add(offset).writeU32((Date.now() / 1000) | 0);
            offset += 4;
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetBoxInfo"), {
    onEnter: function(args) {
        this.info_ptr = args[1];
        this.info_size = args[2] ? args[2].toInt32() : 0;

        console.log("[CodeMeter] CmGetBoxInfo called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing dynamic box info");
        if (this.info_ptr && this.info_size >= 32) {
            // Box info structure
            this.info_ptr.writeU32(0x424F5821);  // "!XOB" magic
            this.info_ptr.add(4).writeU32(session_data.box_serial);
            this.info_ptr.add(8).writeU32(0x00010001);  // Version 1.1
            this.info_ptr.add(12).writeU32(0x00000003);  // Box type: CmStick
            this.info_ptr.add(16).writeU32(0xFFFFFFFF);  // Capabilities: All
            this.info_ptr.add(20).writeU32(1024 * 1024);  // Memory: 1MB
            this.info_ptr.add(24).writeU32((Date.now() / 1000) | 0);  // Timestamp
            this.info_ptr.add(28).writeU32(0);  // Reserved
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmCrypt"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.mode = args[1].toInt32();
        this.data = args[2];
        this.length = args[3].toInt32();

        console.log("[CodeMeter] CmCrypt called");
        console.log("  Mode: " + (this.mode === 1 ? "Encrypt" : "Decrypt"));
        console.log("  Length: " + this.length);

        // Generate encryption key if not exists
        if (!session_data.encryption_key) {
            session_data.encryption_key = new Uint8Array(32);
            for (var i = 0; i < 32; i++) {
                session_data.encryption_key[i] = ((session_data.box_serial >> (i % 4)) ^ i) & 0xFF;
            }
        }
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Performing XOR encryption/decryption");

        // Perform simple XOR encryption/decryption
        if (this.data && this.length > 0) {
            var buffer = this.data.readByteArray(this.length);
            var processed = new Uint8Array(this.length);

            for (var i = 0; i < this.length; i++) {
                processed[i] = buffer[i] ^ session_data.encryption_key[i % 32];
            }

            this.data.writeByteArray(processed);
        }

        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetStatus"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.status_ptr = args[1];

        console.log("[CodeMeter] CmGetStatus called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Returning healthy status");
        if (this.status_ptr) {
            // Status structure
            this.status_ptr.writeU32(0);  // Status: OK
            this.status_ptr.add(4).writeU32(session_data.box_serial);  // Box serial
            this.status_ptr.add(8).writeU32(100);  // Total licenses
            this.status_ptr.add(12).writeU32(99);  // Free licenses
            this.status_ptr.add(16).writeU32((Date.now() - session_data.access_time) / 1000 | 0);  // Uptime
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmRelease"), {
    onEnter: function(args) {
        console.log("[CodeMeter] CmRelease called - maintaining session");
    },
    onLeave: function(retval) {
        // Don't actually release, just return success
        retval.replace(0);  // CM_OK
    }
});

console.log("[CodeMeter] License bypass active with dynamic handle");
console.log("[CodeMeter] Box Serial: 0x" + session_data.box_serial.toString(16));
"""

    def _calculate_confidence(self, results: dict[str, Any]) -> float:
        """Calculate confidence score for analysis results.

        Args:
            results: Analysis results

        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.0

        # Add confidence for each detected system
        confidence += len(results["detected_systems"]) * 0.25

        # Add confidence for bypass strategies
        confidence += len(results["bypass_strategies"]) * 0.15

        # Add confidence for detected servers
        confidence += min(len(results["license_servers"]) * 0.1, 0.3)

        # Add confidence for protection features
        confidence += min(len(results["protection_features"]) * 0.05, 0.2)

        return min(confidence, 1.0)

    def generate_bypass_report(self, analysis: dict[str, Any]) -> str:
        """Generate detailed bypass report.

        Args:
            analysis: Analysis results

        Returns:
            Formatted report string
        """
        report = "=" * 60 + "\n"
        report += "COMMERCIAL LICENSE PROTECTION ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"

        report += f"Binary: {self.binary_path}\n"
        report += f"Analysis Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Confidence: {analysis['confidence']:.1%}\n\n"

        report += "DETECTED SYSTEMS:\n"
        report += "-" * 30 + "\n"
        for system in analysis["detected_systems"]:
            report += f"  • {system}\n"

        if analysis["license_servers"]:
            report += "\nLICENSE SERVERS:\n"
            report += "-" * 30 + "\n"
            for server in analysis["license_servers"]:
                report += f"  • Type: {server['type']}\n"
                report += f"    Port: {server['port']}\n"
                report += f"    Host: {server['hostname']}\n"

        if analysis["bypass_strategies"]:
            report += "\nBYPASS STRATEGIES:\n"
            report += "-" * 30 + "\n"
            for system, strategy in analysis["bypass_strategies"].items():
                report += f"\n{system.upper()}:\n"
                report += f"  Method: {strategy['method']}\n"
                report += f"  Hooks: {len(strategy.get('hooks', []))} API hooks\n"
                if "patches" in strategy:
                    report += f"  Patches: {len(strategy['patches'])} binary patches\n"
                if "emulation_script" in strategy:
                    report += "  Script: Frida script available\n"

        report += "\n" + "=" * 60 + "\n"

        return report


# Export main class
__all__ = ["CommercialLicenseAnalyzer"]
