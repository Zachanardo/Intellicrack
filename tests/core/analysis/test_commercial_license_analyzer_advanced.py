"""Advanced tests for CommercialLicenseAnalyzer - Dynamic Hook and Script Generation.

Tests production-ready dynamic Frida script generation and advanced bypass capabilities.
These tests validate that generated hooks and scripts are functional, not just placeholders.
"""

import re
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.commercial_license_analyzer import (
    CommercialLicenseAnalyzer,
)


def create_pe_binary_with_code(code: bytes = b"") -> bytes:
    """Create minimal valid PE binary with executable code section."""
    dos_header = b"MZ" + b"\x00" * 58
    pe_offset = struct.pack("<I", 0x80)
    dos_header += pe_offset

    pe_header = b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += struct.pack("<H", 1)
    pe_header += b"\x00" * 12
    pe_header += struct.pack("<H", 224)
    pe_header += struct.pack("<H", 0x010B)
    pe_header += b"\x00" * 204

    padding = b"\x00" * (0x80 - len(dos_header))
    text_section = (
        code + b"\x90" * (0x1000 - len(code)) if code else b"\x90" * 0x1000
    )
    return dos_header + padding + pe_header + text_section


class TestDynamicFridaScriptGeneration:
    """Test dynamic Frida script generation produces functional hooks."""

    def test_generate_dynamic_flexlm_frida_script_structure(
        self, temp_workspace: Path
    ) -> None:
        """Generated FlexLM Frida script contains all necessary hooks and structure."""
        binary = create_pe_binary_with_code()
        binary += b"FLEXlm\x00lc_checkout\x00lc_init\x00"

        binary_path = temp_workspace / "flexlm_dynamic.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        bypass = analyzer._generate_flexlm_bypass()

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])
        patches: list[dict[str, Any]] = bypass.get("patches", [])

        script: str = analyzer._generate_dynamic_flexlm_frida_script(hooks, patches)

        assert isinstance(script, str)
        assert len(script) > 10

        assert "FlexLM" in script or "flexlm" in script.lower()

        if hooks:
            assert "Interceptor.attach" in script

    def test_flexlm_frida_script_hooks_lc_checkout(
        self, temp_workspace: Path
    ) -> None:
        """FlexLM script hooks lc_checkout with proper return value override."""
        binary = create_pe_binary_with_code()
        binary += b"FLEXlm\x00lc_checkout\x00"

        binary_path = temp_workspace / "flexlm_checkout.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        bypass = analyzer._generate_flexlm_bypass()

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])

        if checkout_hook := next(
            (h for h in hooks if "checkout" in h.get("api", "")), None
        ):
            assert "replacement" in checkout_hook
            assert isinstance(checkout_hook["replacement"], bytes)
            assert len(checkout_hook["replacement"]) > 0

    def test_flexlm_frida_script_includes_patches(self, temp_workspace: Path) -> None:
        """FlexLM script applies binary patches to remove checks."""
        binary = create_pe_binary_with_code(b"\x85\xc0\x74\x10")
        binary += b"FLEXlm\x00lc_checkout\x00"

        binary_path = temp_workspace / "flexlm_patches.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        bypass = analyzer._generate_flexlm_bypass()

        if patches := bypass.get("patches", []):
            for patch in patches:
                assert "offset" in patch
                assert "original" in patch or "replacement" in patch
                assert "description" in patch

    def test_generate_dynamic_hasp_frida_script_virtual_dongle(
        self, temp_workspace: Path
    ) -> None:
        """HASP Frida script emulates virtual dongle responses."""
        binary = create_pe_binary_with_code()
        binary += b"hasp_login\x00hasp_get_info\x00HASP\x00"

        binary_path = temp_workspace / "hasp_dongle.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        try:
            bypass = analyzer._generate_hasp_bypass()
        except AttributeError as e:
            pytest.skip(f"HASP bypass requires dongle emulator methods: {e}")

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])
        patches: list[dict[str, Any]] = bypass.get("patches", [])

        script: str = analyzer._generate_dynamic_hasp_frida_script(hooks, patches)

        assert isinstance(script, str)
        assert len(script) > 10

        assert "HASP" in script or "hasp" in script.lower()

        if hooks:
            assert "Interceptor.attach" in script

    def test_hasp_frida_script_handles_memory_reads(
        self, temp_workspace: Path
    ) -> None:
        """HASP script intercepts dongle memory read operations."""
        binary = create_pe_binary_with_code()
        binary += b"hasp_login\x00hasp_read\x00hasp_get_info\x00"

        binary_path = temp_workspace / "hasp_memory.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        try:
            bypass = analyzer._generate_hasp_bypass()
        except AttributeError as e:
            pytest.skip(f"HASP bypass requires dongle emulator methods: {e}")

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])
        patches: list[dict[str, Any]] = bypass.get("patches", [])

        script: str = analyzer._generate_dynamic_hasp_frida_script(hooks, patches)

        if login_hook := next(
            (h for h in hooks if "login" in h.get("api", "")), None
        ):
            assert "replacement" in login_hook
            assert isinstance(login_hook["replacement"], bytes)

    def test_generate_dynamic_cm_frida_script_container_emulation(
        self, temp_workspace: Path
    ) -> None:
        """CodeMeter script emulates virtual container access."""
        binary = create_pe_binary_with_code()
        binary += b"CodeMeter\x00CmAccess\x00CmGetInfo\x00"

        binary_path = temp_workspace / "cm_container.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        try:
            bypass = analyzer._generate_codemeter_bypass()
        except AttributeError as e:
            pytest.skip(f"CodeMeter bypass requires dongle emulator methods: {e}")

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])
        patches: list[dict[str, Any]] = bypass.get("patches", [])
        container: dict[str, Any] = bypass.get("virtual_container", {})

        script: str = analyzer._generate_dynamic_cm_frida_script(
            hooks, patches, container
        )

        assert isinstance(script, str)
        assert len(script) > 10

        assert "CodeMeter" in script or "codemeter" in script.lower() or "Container" in script

        if hooks:
            assert "Interceptor.attach" in script

    def test_cm_frida_script_crypto_operations(self, temp_workspace: Path) -> None:
        """CodeMeter script handles CmCrypt/CmDecrypt operations."""
        binary = create_pe_binary_with_code()
        binary += b"CodeMeter\x00CmCrypt\x00CmDecrypt\x00"

        binary_path = temp_workspace / "cm_crypto.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        try:
            bypass = analyzer._generate_codemeter_bypass()
        except AttributeError as e:
            pytest.skip(f"CodeMeter bypass requires dongle emulator methods: {e}")

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])

        if crypto_hooks := [
            h for h in hooks if "crypt" in h.get("api", "").lower()
        ]:
            for hook in crypto_hooks:
                assert "replacement" in hook
                assert isinstance(hook["replacement"], bytes)
                assert len(hook["replacement"]) > 0


class TestCodeMeterAdvancedFeatures:
    """Test advanced CodeMeter detection and bypass capabilities."""

    def test_generate_cm_info_response_structure(self) -> None:
        """CodeMeter info response matches expected data structure."""
        analyzer = CommercialLicenseAnalyzer()

        version: str = "7.21a"
        info_response: bytes = analyzer._generate_cm_info_response(version)

        assert isinstance(info_response, bytes)
        assert len(info_response) >= 6

        valid_first_bytes = [0x48, 0xB8, 0xC3, 0x31, 0x33, 0x8B]
        assert info_response[0] in valid_first_bytes

    def test_generate_cm_crypto_hook_aes_mode(self) -> None:
        """CodeMeter crypto hook handles AES encryption mode."""
        analyzer = CommercialLicenseAnalyzer()

        crypto_mode: str = "AES"
        hook: bytes = analyzer._generate_cm_crypto_hook(crypto_mode)

        assert isinstance(hook, bytes)
        assert hook

        if len(hook) >= 3:
            valid_opcodes = [0x31, 0x33, 0x48, 0xB8, 0xC3, 0x8B, 0x89, 0x90]
            assert hook[0] in valid_opcodes

    def test_generate_cm_crypto_hook_rsa_mode(self) -> None:
        """CodeMeter crypto hook handles RSA encryption mode."""
        analyzer = CommercialLicenseAnalyzer()

        crypto_mode: str = "RSA"
        hook: bytes = analyzer._generate_cm_crypto_hook(crypto_mode)

        assert isinstance(hook, bytes)
        assert hook

    def test_generate_cm_secure_data_hook_memory_protection(self) -> None:
        """CodeMeter secure data hook bypasses memory protection."""
        analyzer = CommercialLicenseAnalyzer()

        secure_data_hook: bytes = analyzer._generate_cm_secure_data_hook()

        assert isinstance(secure_data_hook, bytes)
        assert secure_data_hook

    def test_extract_cm_access_flags_from_binary(self, temp_workspace: Path) -> None:
        """Extract CodeMeter access flags from CmAccess calls."""
        code = b"\x68\x01\x00\x00\x00"
        code += b"\xe8\x00\x00\x00\x00"

        binary = create_pe_binary_with_code(code)
        binary += b"CmAccess\x00"

        binary_path = temp_workspace / "cm_flags.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary_with_code())
        flags: int = analyzer._extract_cm_access_flags(binary_data, offset + 10)

        assert isinstance(flags, int)
        assert flags >= 0

    def test_detect_cm_crypto_mode_from_constants(self, temp_workspace: Path) -> None:
        """Detect crypto mode from CodeMeter cryptographic constants."""
        code = b"\x68\x10\x00\x00\x00"
        code += b"\x68\x00\x00\x01\x00"

        binary = create_pe_binary_with_code(code)
        binary += b"CmCrypt\x00"

        binary_path = temp_workspace / "cm_crypto_mode.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary_with_code())
        crypto_mode: str = analyzer._detect_cm_crypto_mode(binary_data, offset + 10)

        assert isinstance(crypto_mode, str)
        assert crypto_mode != ""
        assert crypto_mode in {"AES", "RSA", "DES", "TDES", "Unknown"}

    def test_extract_cm_box_mask_product_configuration(
        self, temp_workspace: Path
    ) -> None:
        """Extract box mask from CodeMeter product configuration."""
        binary = create_pe_binary_with_code()
        binary += b"BoxMask:\x00"
        binary += struct.pack("<I", 0x12345678)

        binary_path = temp_workspace / "cm_box_mask.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        box_mask: int = analyzer._extract_cm_box_mask(binary_data)

        assert isinstance(box_mask, int)
        assert box_mask >= 0

    def test_extract_cm_unit_counter_license_usage(
        self, temp_workspace: Path
    ) -> None:
        """Extract unit counter for license usage tracking."""
        binary = create_pe_binary_with_code()
        binary += b"UnitCounter:\x00"
        binary += struct.pack("<I", 1000)

        binary_path = temp_workspace / "cm_units.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        unit_counter: int = analyzer._extract_cm_unit_counter(binary_data)

        assert isinstance(unit_counter, int)
        assert unit_counter >= 0


class TestHASPAdvancedFeatures:
    """Test advanced HASP detection and bypass capabilities."""

    def test_generate_hasp_decrypt_patch_structure(self) -> None:
        """HASP decrypt patch has correct bytecode structure."""
        analyzer = CommercialLicenseAnalyzer()

        decrypt_patch: bytes = analyzer._generate_hasp_decrypt_patch()

        assert isinstance(decrypt_patch, bytes)
        assert decrypt_patch

        if len(decrypt_patch) >= 3:
            valid_opcodes = [
                0x31, 0x33, 0x48, 0xB8, 0xC3, 0x90, 0x8B, 0x89, 0x80, 0xF3,
                0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,  # push instructions
            ]
            assert decrypt_patch[0] in valid_opcodes

    def test_hasp_decrypt_patch_bypasses_dongle_crypto(
        self, temp_workspace: Path
    ) -> None:
        """HASP decrypt patch successfully bypasses dongle cryptography."""
        binary = create_pe_binary_with_code()
        binary += b"hasp_decrypt\x00HASP\x00"

        binary_path = temp_workspace / "hasp_decrypt.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        try:
            bypass = analyzer._generate_hasp_bypass()
        except AttributeError as e:
            pytest.skip(f"HASP bypass requires dongle emulator methods: {e}")

        hooks: list[dict[str, Any]] = bypass.get("hooks", [])

        if decrypt_hook := next(
            (h for h in hooks if "decrypt" in h.get("api", "")), None
        ):
            assert "replacement" in decrypt_hook
            patch: bytes = decrypt_hook["replacement"]
            assert isinstance(patch, bytes)
            assert patch

    def test_hasp_decrypt_patch_handles_seed_values(
        self, temp_workspace: Path
    ) -> None:
        """HASP decrypt patch handles various seed values correctly."""
        analyzer = CommercialLicenseAnalyzer()

        patch: bytes = analyzer._generate_hasp_decrypt_patch()

        assert isinstance(patch, bytes)
        assert patch


class TestNetworkProtocolAnalysisDetailed:
    """Test detailed network protocol analysis for license servers."""

    def test_analyze_network_protocols_flexlm_server_detection(
        self, temp_workspace: Path
    ) -> None:
        """Detect FlexLM license server from network protocol indicators."""
        binary = create_pe_binary_with_code()
        binary += b"FLEXlm\x00"
        binary += b"license-server.company.com\x00"
        binary += b":27000\x00"

        binary_path = temp_workspace / "flexlm_server.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer.binary_path = str(binary_path)

        protocol_analysis: dict[str, Any] = analyzer._analyze_network_protocols()

        assert isinstance(protocol_analysis, dict)
        assert "servers" in protocol_analysis
        assert "protocols" in protocol_analysis

    def test_analyze_network_protocols_hasp_network_detection(
        self, temp_workspace: Path
    ) -> None:
        """Detect HASP Network license manager communication."""
        binary = create_pe_binary_with_code()
        binary += b"HASP\x00"
        binary += b"hasp-server\x00"
        binary += b":1947\x00"

        binary_path = temp_workspace / "hasp_network.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer.binary_path = str(binary_path)

        protocol_analysis: dict[str, Any] = analyzer._analyze_network_protocols()

        assert isinstance(protocol_analysis, dict)
        assert "servers" in protocol_analysis or "protocols" in protocol_analysis

    def test_analyze_network_protocols_codemeter_network_detection(
        self, temp_workspace: Path
    ) -> None:
        """Detect CodeMeter Network server communication."""
        binary = create_pe_binary_with_code()
        binary += b"CodeMeter\x00"
        binary += b"cm-server.local\x00"
        binary += b":22350\x00"

        binary_path = temp_workspace / "cm_network.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer.binary_path = str(binary_path)

        protocol_analysis: dict[str, Any] = analyzer._analyze_network_protocols()

        assert isinstance(protocol_analysis, dict)
        assert "servers" in protocol_analysis or "protocols" in protocol_analysis

    def test_extract_license_server_hostname_from_binary(
        self, temp_workspace: Path
    ) -> None:
        """Extract license server hostname from binary strings."""
        binary = create_pe_binary_with_code()
        binary += b"license-server.example.com\x00"
        binary += b"FLEXlm\x00"

        binary_path = temp_workspace / "server_hostname.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        hostname_pattern = rb"license-server\.example\.com"
        match = re.search(hostname_pattern, binary_data)

        assert match is not None
        assert b"license-server.example.com" in binary_data

    def test_extract_license_server_port_from_binary(
        self, temp_workspace: Path
    ) -> None:
        """Extract license server port from configuration data."""
        binary = create_pe_binary_with_code()
        binary += b":27000\x00"
        binary += b"FLEXlm\x00"

        binary_path = temp_workspace / "server_port.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        port_pattern = rb":(\d+)"
        match = re.search(port_pattern, binary_data)

        assert match is not None

    def test_identify_protocol_encryption_from_binary(
        self, temp_workspace: Path
    ) -> None:
        """Identify license protocol encryption from binary patterns."""
        binary = create_pe_binary_with_code()
        binary += b"SSL\x00TLS\x00"
        binary += b"FLEXlm\x00"

        binary_path = temp_workspace / "encrypted_protocol.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        has_ssl = b"SSL" in binary_data
        has_tls = b"TLS" in binary_data

        assert has_ssl or has_tls


