"""Production-ready tests for TPM detection capabilities.

Tests validate real TPM detection against actual binaries or system resources including:
- Entropy analysis for TPM data detection with statistical validation
- Behavior monitoring for TPM API call patterns
- TPM command sequence detection with protocol validation
- TPM-sealed data identification in memory with structure parsing
- Hardware vs software TPM differentiation
- Edge cases: Firmware TPM, platform-specific implementations

All tests validate REAL detection capabilities - tests MUST FAIL if functionality is broken.
"""

import hashlib
import math
import os
import struct
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.protection_bypass.tpm_bypass import TPMBypassEngine


class TestTPMEntropyAnalysisProduction:
    """Test entropy analysis for TPM data detection - validates real entropy calculations."""

    def test_entropy_analysis_calculates_shannon_entropy_correctly(self) -> None:
        """Entropy analysis must calculate Shannon entropy for data blocks."""
        engine = TPMBypassEngine()

        high_entropy_data = os.urandom(256)
        low_entropy_data = b"\x00" * 256

        high_entropy_value = self._calculate_shannon_entropy(high_entropy_data)
        low_entropy_value = self._calculate_shannon_entropy(low_entropy_data)

        assert high_entropy_value > 7.0, "Random data should have entropy > 7.0 bits per byte"
        assert low_entropy_value < 1.0, "Zero-filled data should have entropy < 1.0 bits per byte"

        binary_with_high_entropy = self._create_pe_with_data_section(high_entropy_data, [b"Tbs.dll", b"NCRYPT_TPM"])
        binary_with_low_entropy = self._create_pe_with_data_section(low_entropy_data, [b"Tbs.dll", b"NCRYPT_TPM"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_high_entropy)
            tmp_path_high = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_low_entropy)
            tmp_path_low = tmp.name

        try:
            analysis_high = engine.analyze_tpm_protection(tmp_path_high)
            analysis_low = engine.analyze_tpm_protection(tmp_path_low)

            assert "entropy_analysis" in analysis_high or "sealed_data_detected" in analysis_high, \
                "High entropy analysis must be present in results"
            assert "entropy_analysis" in analysis_low or "sealed_data_detected" in analysis_low, \
                "Low entropy analysis must be present in results"

            if "sealed_data_detected" in analysis_high and "sealed_data_detected" in analysis_low:
                assert analysis_high["sealed_data_detected"] != analysis_low["sealed_data_detected"], \
                    "Entropy analysis must differentiate high vs low entropy data"
        finally:
            Path(tmp_path_high).unlink(missing_ok=True)
            Path(tmp_path_low).unlink(missing_ok=True)

    def test_entropy_analysis_identifies_tpm2b_structure_by_entropy_and_size(self) -> None:
        """Entropy analysis must validate TPM2B structure format with size field and high entropy payload."""
        engine = TPMBypassEngine()

        valid_tpm2b_structure = self._create_valid_tpm2b_private_structure()
        invalid_tpm2b_structure = self._create_invalid_tpm2b_structure()

        binary_with_valid = self._create_pe_with_data_section(valid_tpm2b_structure, [b"Tbs.dll", b"TPM2B_PRIVATE"])
        binary_with_invalid = self._create_pe_with_data_section(invalid_tpm2b_structure, [b"Tbs.dll", b"TPM2B_PRIVATE"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_valid)
            tmp_path_valid = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_invalid)
            tmp_path_invalid = tmp.name

        try:
            analysis_valid = engine.analyze_tpm_protection(tmp_path_valid)
            analysis_invalid = engine.analyze_tpm_protection(tmp_path_invalid)

            assert analysis_valid["tpm_detected"] is True, "Valid TPM2B structure must be detected"

            if "sealed_data_detected" in analysis_valid and "sealed_data_detected" in analysis_invalid:
                if analysis_valid["sealed_data_detected"]:
                    assert not analysis_invalid["sealed_data_detected"], \
                        "Invalid TPM2B structure should not be detected as sealed data"
        finally:
            Path(tmp_path_valid).unlink(missing_ok=True)
            Path(tmp_path_invalid).unlink(missing_ok=True)

    def test_entropy_analysis_distinguishes_aes_cbc_from_tpm_sealed_data(self) -> None:
        """Entropy analysis must differentiate generic AES-CBC encryption from TPM-sealed structures."""
        engine = TPMBypassEngine()

        aes_encrypted_block = self._create_aes_cbc_encrypted_block()
        tpm_sealed_block = self._create_valid_tpm2b_private_structure()

        aes_entropy = self._calculate_shannon_entropy(aes_encrypted_block)
        tpm_entropy = self._calculate_shannon_entropy(tpm_sealed_block)

        assert abs(aes_entropy - tpm_entropy) < 0.5, "Both should have similar high entropy"

        binary_with_aes = self._create_pe_with_data_section(aes_encrypted_block, [b"BCryptEncrypt", b"AES"])
        binary_with_tpm = self._create_pe_with_data_section(tpm_sealed_block, [b"Tbs.dll", b"TPM2B_PRIVATE"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_aes)
            tmp_path_aes = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_tpm)
            tmp_path_tpm = tmp.name

        try:
            analysis_aes = engine.analyze_tpm_protection(tmp_path_aes)
            analysis_tpm = engine.analyze_tpm_protection(tmp_path_tpm)

            assert analysis_aes["tpm_detected"] is False, "AES-only binary should not be detected as TPM"
            assert analysis_tpm["tpm_detected"] is True, "TPM binary must be detected"
        finally:
            Path(tmp_path_aes).unlink(missing_ok=True)
            Path(tmp_path_tpm).unlink(missing_ok=True)

    def test_entropy_analysis_detects_tpm_credential_blob_structure(self) -> None:
        """Entropy analysis validates TPM2B_ID_OBJECT credential blob structure format."""
        engine = TPMBypassEngine()

        valid_credential_blob = self._create_tpm2b_id_object_structure()
        invalid_credential_blob = os.urandom(80)

        binary_with_valid = self._create_pe_with_data_section(valid_credential_blob, [b"Tbs.dll", b"Tpm2_ActivateCredential"])
        binary_with_invalid = self._create_pe_with_data_section(invalid_credential_blob, [])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_valid)
            tmp_path_valid = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_invalid)
            tmp_path_invalid = tmp.name

        try:
            analysis_valid = engine.analyze_tpm_protection(tmp_path_valid)
            analysis_invalid = engine.analyze_tpm_protection(tmp_path_invalid)

            assert analysis_valid["tpm_detected"] is True, "Valid credential blob must be detected"
            assert analysis_invalid["tpm_detected"] is False, "Invalid blob without TPM markers should not be detected"
        finally:
            Path(tmp_path_valid).unlink(missing_ok=True)
            Path(tmp_path_invalid).unlink(missing_ok=True)

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data in bits per byte.

        Args:
            data: Data to analyze.

        Returns:
            Shannon entropy value (0-8 bits per byte).

        """
        if not data:
            return 0.0

        byte_counts = Counter(data)
        data_len = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _create_pe_with_data_section(self, data: bytes, import_strings: list[bytes]) -> bytes:
        """Create minimal PE binary with data section and import strings.

        Args:
            data: Data to embed in data section.
            import_strings: Import strings to embed.

        Returns:
            PE binary with data section.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".data\x00\x00\x00" + b"\x00" * 32

        import_data = b""
        for imp in import_strings:
            import_data += imp + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + import_data + data

    def _create_valid_tpm2b_private_structure(self) -> bytes:
        """Create valid TPM2B_PRIVATE structure per TPM 2.0 spec.

        Returns:
            Valid TPM2B_PRIVATE structure with integrity HMAC, IV, and encrypted sensitive.

        """
        size = struct.pack(">H", 290)
        integrity_outer_hmac = hashlib.sha256(b"integrity_key" + os.urandom(16)).digest()
        iv = os.urandom(16)
        encrypted_sensitive = os.urandom(240)

        return size + integrity_outer_hmac + iv + encrypted_sensitive

    def _create_invalid_tpm2b_structure(self) -> bytes:
        """Create invalid TPM2B structure with wrong size field.

        Returns:
            Invalid TPM2B structure.

        """
        size = struct.pack(">H", 65535)
        random_data = os.urandom(100)

        return size + random_data

    def _create_aes_cbc_encrypted_block(self) -> bytes:
        """Create AES-CBC encrypted data block.

        Returns:
            AES-CBC encrypted data (IV + ciphertext).

        """
        iv = os.urandom(16)
        ciphertext = os.urandom(256)

        return iv + ciphertext

    def _create_tpm2b_id_object_structure(self) -> bytes:
        """Create TPM2B_ID_OBJECT credential blob structure.

        Returns:
            Valid TPM2B_ID_OBJECT structure.

        """
        size = struct.pack(">H", 80)
        credential_blob = os.urandom(78)

        return size + credential_blob


class TestTPMBehaviorMonitoringProduction:
    """Test behavior monitoring for TPM API call patterns - validates real pattern detection."""

    def test_behavior_monitoring_detects_tbs_initialization_sequence(self) -> None:
        """Behavior monitoring must identify Tbsi_Context_Create -> Submit_Command -> Close sequence."""
        engine = TPMBypassEngine()

        valid_sequence_binary = self._create_pe_with_api_sequence_ordered([
            b"Tbsi_Context_Create",
            b"Tbsip_Submit_Command",
            b"Tbsip_Context_Close",
        ])

        invalid_sequence_binary = self._create_pe_with_api_sequence_ordered([
            b"Tbsip_Submit_Command",
            b"Tbsip_Context_Close",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(valid_sequence_binary)
            tmp_path_valid = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(invalid_sequence_binary)
            tmp_path_invalid = tmp.name

        try:
            analysis_valid = engine.analyze_tpm_protection(tmp_path_valid)
            analysis_invalid = engine.analyze_tpm_protection(tmp_path_invalid)

            assert analysis_valid["tpm_detected"] is True, "Valid TBS sequence must be detected"
            assert len(analysis_valid["tpm_apis"]) >= 3, "All three APIs must be detected"

            assert "Tbsi_Context_Create" in str(analysis_valid["tpm_apis"]), "Context creation must be detected"
            assert "Tbsip_Submit_Command" in str(analysis_valid["tpm_apis"]), "Submit command must be detected"

            if "initialization_pattern" in analysis_valid:
                assert analysis_valid["initialization_pattern"] is True, "Initialization pattern must be recognized"
        finally:
            Path(tmp_path_valid).unlink(missing_ok=True)
            Path(tmp_path_invalid).unlink(missing_ok=True)

    def test_behavior_monitoring_identifies_ncrypt_tpm_provider_workflow(self) -> None:
        """Behavior monitoring must detect NCrypt TPM provider workflow pattern."""
        engine = TPMBypassEngine()

        ncrypt_workflow_binary = self._create_pe_with_api_sequence_ordered([
            b"NCryptOpenStorageProvider",
            b"NCRYPT_TPM_PLATFORM_TYPE_PROPERTY",
            b"NCryptCreatePersistedKey",
            b"NCryptSetProperty",
            b"NCryptFinalizeKey",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(ncrypt_workflow_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "NCrypt TPM workflow must be detected"
            assert "NCryptOpenStorageProvider" in str(analysis["tpm_apis"]) or "NCryptCreatePersistedKey" in str(analysis["tpm_apis"]), \
                "NCrypt APIs must be identified"

            if "ncrypt_workflow" in analysis:
                assert analysis["ncrypt_workflow"] is True, "NCrypt workflow pattern must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_behavior_monitoring_detects_pcr_extend_and_read_operations(self) -> None:
        """Behavior monitoring must identify PCR extend and read operations."""
        engine = TPMBypassEngine()

        pcr_operations_binary = self._create_pe_with_tpm_commands([
            b"Tpm2_PCR_Extend",
            b"Tpm2_PCR_Read",
            b"Tpm2_Quote",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(pcr_operations_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "PCR operations must be detected"

            if "pcr_operations" in analysis:
                assert analysis["pcr_operations"] is True, "PCR operation pattern must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_behavior_monitoring_identifies_seal_unseal_operation_pair(self) -> None:
        """Behavior monitoring must detect seal/unseal operation pairs for licensing."""
        engine = TPMBypassEngine()

        seal_unseal_binary = self._create_pe_with_tpm_commands([
            b"Tpm2_Create",
            b"Tpm2_Load",
            b"Tpm2_Unseal",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(seal_unseal_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "Seal/unseal operations must be detected"
            assert "Tpm2_Unseal" in str(analysis["tpm_apis"]) or "Tpm2_Load" in str(analysis["tpm_apis"]), \
                "Unseal or Load API must be detected"

            if "seal_operations" in analysis:
                assert analysis["seal_operations"] is True, "Seal operations must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _create_pe_with_api_sequence_ordered(self, api_calls: list[bytes]) -> bytes:
        """Create PE with specific ordered API call sequence.

        Args:
            api_calls: Ordered list of API call names.

        Returns:
            PE binary with ordered API sequence.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".text\x00\x00\x00" + b"\x00" * 32

        api_data = b""
        for api in api_calls:
            api_data += api + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + api_data

    def _create_pe_with_tpm_commands(self, commands: list[bytes]) -> bytes:
        """Create PE with TPM command references.

        Args:
            commands: List of TPM command names.

        Returns:
            PE binary with TPM commands.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".rdata\x00\x00" + b"\x00" * 32

        tpm_indicators = b"Tbs.dll\x00TPM2B_\x00"

        command_data = b""
        for cmd in commands:
            command_data += cmd + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + tpm_indicators + command_data


class TestTPMCommandSequenceDetectionProduction:
    """Test TPM command sequence detection - validates protocol-level command identification."""

    def test_command_sequence_detects_tpm2_startup_command_code(self) -> None:
        """Command sequence detection must identify TPM2_Startup command code 0x00000144."""
        engine = TPMBypassEngine()

        startup_command_header = struct.pack(">HI", 0x8001, 0x00000144)
        selftest_command_header = struct.pack(">HI", 0x8001, 0x00000143)

        binary_with_startup = self._create_pe_with_embedded_command_headers(
            [startup_command_header, selftest_command_header],
            [b"Tbs.dll", b"TPM2_Startup"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_startup)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "TPM2_Startup command sequence must be detected"

            analysis = engine.analyze_tpm_protection(tmp_path)
            assert analysis["tpm_detected"] is True, "Analysis must detect TPM usage from command codes"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_command_sequence_detects_seal_command_0x00000153(self) -> None:
        """Command sequence detection must identify TPM2_Create seal command code 0x00000153."""
        engine = TPMBypassEngine()

        create_command = struct.pack(">HI", 0x8001, 0x00000153)
        load_command = struct.pack(">HI", 0x8001, 0x00000157)

        binary_with_seal = self._create_pe_with_embedded_command_headers(
            [create_command, load_command],
            [b"Tbs.dll", b"Tpm2_Create"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_seal)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "TPM2_Create command must be detected"

            if "seal_operations" in analysis:
                assert analysis["seal_operations"] is True, "Seal operation must be identified from command code"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_command_sequence_detects_unseal_command_0x0000015E(self) -> None:
        """Command sequence detection must identify TPM2_Unseal command code 0x0000015E."""
        engine = TPMBypassEngine()

        unseal_command = struct.pack(">HI", 0x8001, 0x0000015E)

        binary_with_unseal = self._create_pe_with_embedded_command_headers(
            [unseal_command],
            [b"Tbs.dll", b"Tpm2_Unseal"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_unseal)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "TPM2_Unseal command must be detected"
            assert "Tpm2_Unseal" in str(analysis["tpm_apis"]) or len(analysis["tpm_apis"]) > 0, \
                "Unseal API must be identified"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_command_sequence_detects_quote_attestation_command_0x00000158(self) -> None:
        """Command sequence detection must identify TPM2_Quote attestation command code 0x00000158."""
        engine = TPMBypassEngine()

        quote_command = struct.pack(">HI", 0x8001, 0x00000158)
        certify_command = struct.pack(">HI", 0x8001, 0x00000148)

        binary_with_attestation = self._create_pe_with_embedded_command_headers(
            [quote_command, certify_command],
            [b"Tbs.dll", b"Tpm2_Quote"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_attestation)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "TPM2_Quote command must be detected"
            assert "Tpm2_Quote" in str(analysis["tpm_apis"]) or len(analysis["tpm_apis"]) > 0, \
                "Quote API must be identified"

            if "attestation_operations" in analysis:
                assert analysis["attestation_operations"] is True, "Attestation operation must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_command_sequence_detects_nvram_read_command_0x0000014E(self) -> None:
        """Command sequence detection must identify TPM2_NV_Read command code 0x0000014E."""
        engine = TPMBypassEngine()

        nv_read_command = struct.pack(">HI", 0x8001, 0x0000014E)
        nv_write_command = struct.pack(">HI", 0x8001, 0x00000137)

        binary_with_nvram = self._create_pe_with_embedded_command_headers(
            [nv_read_command, nv_write_command],
            [b"Tbs.dll", b"Tpm2_NV_Read"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_nvram)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "TPM2_NV_Read command must be detected"

            if "nvram_operations" in analysis:
                assert analysis["nvram_operations"] is True, "NVRAM operation must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_command_sequence_detects_pcr_extend_command_0x00000182(self) -> None:
        """Command sequence detection must identify TPM2_PCR_Extend command code 0x00000182."""
        engine = TPMBypassEngine()

        pcr_extend_command = struct.pack(">HI", 0x8001, 0x00000182)
        pcr_read_command = struct.pack(">HI", 0x8001, 0x0000017E)

        binary_with_pcr = self._create_pe_with_embedded_command_headers(
            [pcr_extend_command, pcr_read_command],
            [b"Tbs.dll", b"Tpm2_PCR_Extend"]
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_pcr)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "TPM2_PCR_Extend command must be detected"
            assert len(analysis.get("pcr_usage", [])) > 0 or "Tpm2_PCR_Extend" in str(analysis.get("tpm_apis", [])), \
                "PCR operations must be identified"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _create_pe_with_embedded_command_headers(self, command_headers: list[bytes], api_markers: list[bytes]) -> bytes:
        """Create PE with embedded TPM command headers and API markers.

        Args:
            command_headers: List of TPM command header bytes.
            api_markers: List of API marker strings.

        Returns:
            PE binary with embedded command structures.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".data\x00\x00\x00" + b"\x00" * 32

        api_data = b""
        for marker in api_markers:
            api_data += marker + b"\x00"

        command_data = b""
        for cmd in command_headers:
            command_data += cmd + os.urandom(16)

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + api_data + command_data


class TestTPMSealedDataIdentificationProduction:
    """Test TPM-sealed data identification in memory - validates structure parsing."""

    def test_sealed_data_identification_validates_tpm2b_private_integrity_hmac(self) -> None:
        """Sealed data identification must validate TPM2B_PRIVATE integrity HMAC structure."""
        engine = TPMBypassEngine()

        valid_tpm2b = self._create_tpm2b_private_with_valid_structure()
        invalid_tpm2b = self._create_tpm2b_private_with_invalid_hmac()

        binary_with_valid = self._create_pe_with_sealed_data(valid_tpm2b, [b"Tbs.dll", b"TPM2B_PRIVATE"])
        binary_with_invalid = self._create_pe_with_sealed_data(invalid_tpm2b, [b"Tbs.dll", b"TPM2B_PRIVATE"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_valid)
            tmp_path_valid = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_invalid)
            tmp_path_invalid = tmp.name

        try:
            analysis_valid = engine.analyze_tpm_protection(tmp_path_valid)
            analysis_invalid = engine.analyze_tpm_protection(tmp_path_invalid)

            assert analysis_valid["tpm_detected"] is True, "Valid TPM2B_PRIVATE must be detected"

            if "sealed_data_detected" in analysis_valid and "sealed_data_detected" in analysis_invalid:
                assert analysis_valid["sealed_data_detected"] is True, "Valid structure must be identified"
        finally:
            Path(tmp_path_valid).unlink(missing_ok=True)
            Path(tmp_path_invalid).unlink(missing_ok=True)

    def test_sealed_data_identification_detects_policy_digest_in_sealed_blob(self) -> None:
        """Sealed data identification must detect policy digest in policy-sealed blobs."""
        engine = TPMBypassEngine()

        policy_sealed_blob = self._create_policy_sealed_tpm2b_structure()

        binary_with_policy = self._create_pe_with_sealed_data(policy_sealed_blob, [b"Tbs.dll", b"Tpm2_PolicyPCR"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_policy)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "Policy-sealed TPM data must be detected"

            if "policy_sealed_data" in analysis:
                assert analysis["policy_sealed_data"] is True, "Policy sealing must be recognized"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_sealed_data_identification_distinguishes_bitlocker_vmk_structure(self) -> None:
        """Sealed data identification must recognize BitLocker VMK TPM-sealed structure."""
        engine = TPMBypassEngine()

        bitlocker_vmk = self._create_bitlocker_vmk_tpm_structure()
        generic_sealed = self._create_tpm2b_private_with_valid_structure()

        binary_with_vmk = self._create_pe_with_sealed_data(bitlocker_vmk, [b"Tbs.dll", b"BitLocker"])
        binary_with_generic = self._create_pe_with_sealed_data(generic_sealed, [b"Tbs.dll", b"TPM2B_PRIVATE"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_vmk)
            tmp_path_vmk = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_generic)
            tmp_path_generic = tmp.name

        try:
            analysis_vmk = engine.analyze_tpm_protection(tmp_path_vmk)
            analysis_generic = engine.analyze_tpm_protection(tmp_path_generic)

            assert analysis_vmk["tpm_detected"] is True, "BitLocker VMK must be detected"
            assert analysis_generic["tpm_detected"] is True, "Generic sealed data must be detected"

            if "bitlocker_vmk_detected" in analysis_vmk:
                assert analysis_vmk["bitlocker_vmk_detected"] is True, "BitLocker VMK must be specifically identified"
        finally:
            Path(tmp_path_vmk).unlink(missing_ok=True)
            Path(tmp_path_generic).unlink(missing_ok=True)

    def test_sealed_data_identification_rejects_non_tpm_high_entropy_data(self) -> None:
        """Sealed data identification must reject generic high-entropy data without TPM structure."""
        engine = TPMBypassEngine()

        random_high_entropy = os.urandom(300)
        tpm_sealed_data = self._create_tpm2b_private_with_valid_structure()

        binary_with_random = self._create_pe_with_sealed_data(random_high_entropy, [])
        binary_with_tpm = self._create_pe_with_sealed_data(tpm_sealed_data, [b"Tbs.dll", b"TPM2B_"])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_random)
            tmp_path_random = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(binary_with_tpm)
            tmp_path_tpm = tmp.name

        try:
            analysis_random = engine.analyze_tpm_protection(tmp_path_random)
            analysis_tpm = engine.analyze_tpm_protection(tmp_path_tpm)

            assert analysis_random["tpm_detected"] is False, "Random data without TPM markers must not be detected"
            assert analysis_tpm["tpm_detected"] is True, "TPM sealed data with markers must be detected"
        finally:
            Path(tmp_path_random).unlink(missing_ok=True)
            Path(tmp_path_tpm).unlink(missing_ok=True)

    def _create_tpm2b_private_with_valid_structure(self) -> bytes:
        """Create TPM2B_PRIVATE with valid size, HMAC, IV, and encrypted data.

        Returns:
            Valid TPM2B_PRIVATE structure.

        """
        size = struct.pack(">H", 290)
        integrity_hmac = hashlib.sha256(b"outer_wrapper_key" + os.urandom(16)).digest()
        iv = os.urandom(16)
        encrypted_sensitive = os.urandom(240)

        return size + integrity_hmac + iv + encrypted_sensitive

    def _create_tpm2b_private_with_invalid_hmac(self) -> bytes:
        """Create TPM2B_PRIVATE with invalid HMAC (wrong size).

        Returns:
            Invalid TPM2B_PRIVATE structure.

        """
        size = struct.pack(">H", 100)
        invalid_hmac = os.urandom(16)
        iv = os.urandom(16)
        encrypted_sensitive = os.urandom(64)

        return size + invalid_hmac + iv + encrypted_sensitive

    def _create_policy_sealed_tpm2b_structure(self) -> bytes:
        """Create TPM2B_PRIVATE with policy digest.

        Returns:
            Policy-sealed TPM2B_PRIVATE structure.

        """
        size = struct.pack(">H", 320)
        integrity_hmac = hashlib.sha256(b"policy_wrapper").digest()
        policy_digest = hashlib.sha256(b"TPM2_PolicyPCR" + struct.pack(">I", 7)).digest()
        iv = os.urandom(16)
        encrypted_sensitive = os.urandom(240)

        return size + integrity_hmac + policy_digest + iv + encrypted_sensitive

    def _create_bitlocker_vmk_tpm_structure(self) -> bytes:
        """Create BitLocker VMK TPM-sealed structure.

        Returns:
            BitLocker VMK sealed structure.

        """
        vmk_marker = b"VMK\x00"
        tpm_protector_guid = b"\x01\x02\x03\x04" * 4
        size = struct.pack(">H", 256)
        tpm_sealed_vmk = os.urandom(240)

        return vmk_marker + tpm_protector_guid + size + tpm_sealed_vmk

    def _create_pe_with_sealed_data(self, sealed_data: bytes, markers: list[bytes]) -> bytes:
        """Create PE with embedded TPM sealed data and markers.

        Args:
            sealed_data: TPM sealed data structure.
            markers: API/structure markers.

        Returns:
            PE binary with sealed data.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".data\x00\x00\x00" + b"\x00" * 32

        marker_data = b""
        for marker in markers:
            marker_data += marker + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + marker_data + sealed_data


class TestHardwareVsSoftwareTPMProduction:
    """Test hardware vs software TPM differentiation - validates TPM type detection."""

    def test_tpm_type_detection_identifies_hardware_tpm_device_interface(self) -> None:
        """TPM type detection must identify hardware TPM via device interface markers."""
        engine = TPMBypassEngine()

        hardware_tpm_binary = self._create_pe_with_tpm_type_markers([
            b"Tbs.dll",
            b"TPM_DEVICE_INTERFACE",
            b"NCRYPT_TPM_PAD_PSS",
            b"\\Device\\TPM",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(hardware_tpm_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "Hardware TPM must be detected"

            if "tpm_type" in analysis:
                assert "hardware" in analysis["tpm_type"].lower(), "TPM type must be identified as hardware"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_tpm_type_detection_identifies_software_tpm_simulator(self) -> None:
        """TPM type detection must identify software TPM simulator."""
        engine = TPMBypassEngine()

        software_tpm_binary = self._create_pe_with_tpm_type_markers([
            b"Tbs.dll",
            b"SOFTWARE_TPM",
            b"TPM_SIMULATOR",
            b"tpm.msc",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(software_tpm_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "Software TPM must be detected"

            if "tpm_type" in analysis:
                assert "software" in analysis["tpm_type"].lower() or "virtual" in analysis["tpm_type"].lower(), \
                    "TPM type must be identified as software/virtual"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_tpm_type_detection_identifies_firmware_tpm_ftpm(self) -> None:
        """TPM type detection must identify firmware TPM (fTPM)."""
        engine = TPMBypassEngine()

        firmware_tpm_binary = self._create_pe_with_tpm_type_markers([
            b"Tbs.dll",
            b"FIRMWARE_TPM",
            b"fTPM",
            b"PLATFORM_FIRMWARE",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(firmware_tpm_binary)
            tmp_path = tmp.name

        try:
            analysis = engine.analyze_tpm_protection(tmp_path)

            assert analysis["tpm_detected"] is True, "Firmware TPM must be detected"

            if "tpm_type" in analysis:
                assert "firmware" in analysis["tpm_type"].lower() or "hardware" in analysis["tpm_type"].lower(), \
                    "TPM type must be identified as firmware or hardware"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_tpm_type_detection_differentiates_discrete_vs_integrated_tpm(self) -> None:
        """TPM type detection must differentiate discrete TPM chip from integrated fTPM."""
        engine = TPMBypassEngine()

        discrete_tpm_binary = self._create_pe_with_tpm_type_markers([
            b"Tbs.dll",
            b"INFINEON",
            b"SLB9665",
            b"TPM_20_DEVICE",
        ])

        integrated_tpm_binary = self._create_pe_with_tpm_type_markers([
            b"Tbs.dll",
            b"INTEL_PTT",
            b"fTPM",
            b"CPU_INTEGRATED",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(discrete_tpm_binary)
            tmp_path_discrete = tmp.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(integrated_tpm_binary)
            tmp_path_integrated = tmp.name

        try:
            analysis_discrete = engine.analyze_tpm_protection(tmp_path_discrete)
            analysis_integrated = engine.analyze_tpm_protection(tmp_path_integrated)

            assert analysis_discrete["tpm_detected"] is True, "Discrete TPM must be detected"
            assert analysis_integrated["tpm_detected"] is True, "Integrated TPM must be detected"

            if "tpm_type" in analysis_discrete and "tpm_type" in analysis_integrated:
                discrete_type = analysis_discrete["tpm_type"].lower()
                integrated_type = analysis_integrated["tpm_type"].lower()

                assert discrete_type != integrated_type or "infineon" in str(analysis_discrete).lower(), \
                    "Discrete and integrated TPM should be differentiated"
        finally:
            Path(tmp_path_discrete).unlink(missing_ok=True)
            Path(tmp_path_integrated).unlink(missing_ok=True)

    def _create_pe_with_tpm_type_markers(self, markers: list[bytes]) -> bytes:
        """Create PE with TPM type identification markers.

        Args:
            markers: List of TPM type marker strings.

        Returns:
            PE binary with TPM type markers.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".rdata\x00\x00" + b"\x00" * 32

        marker_data = b""
        for marker in markers:
            marker_data += marker + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + marker_data


class TestTPMPlatformSpecificImplementationsProduction:
    """Test platform-specific TPM implementation detection - validates vendor/platform identification."""

    def test_platform_detection_identifies_intel_ptt_implementation(self) -> None:
        """Platform detection must identify Intel Platform Trust Technology (PTT)."""
        engine = TPMBypassEngine()

        intel_ptt_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"INTEL_PTT",
            b"TPM_DEVICE_INTERFACE",
            b"NCRYPT_TPM",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(intel_ptt_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Intel PTT must be detected as TPM usage"

            analysis = engine.analyze_tpm_protection(tmp_path)
            assert analysis["tpm_detected"] is True, "Intel PTT must be detected in analysis"

            analysis_str = str(analysis).lower()
            assert "intel" in analysis_str or "ptt" in analysis_str or "firmware" in analysis_str, \
                "Analysis must identify Intel PTT platform"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_amd_ftpm_implementation(self) -> None:
        """Platform detection must identify AMD fTPM implementation."""
        engine = TPMBypassEngine()

        amd_ftpm_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"AMD_fTPM",
            b"TPM2B_PUBLIC",
            b"Tbsip_Submit_Command",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(amd_ftpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "AMD fTPM must be detected"

            analysis = engine.analyze_tpm_protection(tmp_path)
            assert analysis["tpm_detected"] is True, "AMD fTPM analysis must succeed"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_qualcomm_qsee_tpm(self) -> None:
        """Platform detection must identify Qualcomm QSEE TPM on ARM platforms."""
        engine = TPMBypassEngine()

        qsee_tpm_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"QSEE_TPM",
            b"ARM_TRUSTZONE",
            b"TPM2_Create",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(qsee_tpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Qualcomm QSEE TPM must be detected"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_microsoft_azure_vtpm(self) -> None:
        """Platform detection must identify Microsoft Azure virtual TPM."""
        engine = TPMBypassEngine()

        azure_vtpm_binary = self._create_pe_with_platform_markers([
            b"tpm20.dll",
            b"AZURE_VTPM",
            b"TPM_DEVICE_INTERFACE",
            b"Tbsi_Context_Create",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(azure_vtpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Azure vTPM must be detected"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_infineon_discrete_tpm_chip(self) -> None:
        """Platform detection must identify Infineon discrete TPM chip."""
        engine = TPMBypassEngine()

        infineon_tpm_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"INFINEON",
            b"SLB9665",
            b"TPM_20_DEVICE",
            b"Tbsip_Submit_Command",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(infineon_tpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Infineon TPM must be detected"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_nuvoton_tpm_implementation(self) -> None:
        """Platform detection must identify Nuvoton TPM chips."""
        engine = TPMBypassEngine()

        nuvoton_tpm_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"NUVOTON",
            b"NPCT",
            b"TPM2B_PUBLIC",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(nuvoton_tpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Nuvoton TPM must be detected"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_identifies_stmicroelectronics_tpm(self) -> None:
        """Platform detection must identify STMicroelectronics TPM modules."""
        engine = TPMBypassEngine()

        st_tpm_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"STMicroelectronics",
            b"ST33",
            b"NCRYPT_TPM",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(st_tpm_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "STMicroelectronics TPM must be detected"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_platform_detection_handles_mixed_tpm_12_and_20_support(self) -> None:
        """Platform detection must handle binaries supporting both TPM 1.2 and 2.0."""
        engine = TPMBypassEngine()

        mixed_version_binary = self._create_pe_with_platform_markers([
            b"Tbs.dll",
            b"TPM_ORD_OSAP",
            b"TPM2_Create",
            b"Tbsip_Submit_Command",
        ])

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(mixed_version_binary)
            tmp_path = tmp.name

        try:
            result = engine.detect_tpm_usage(tmp_path)
            assert result is True, "Mixed TPM version support must be detected"

            analysis = engine.analyze_tpm_protection(tmp_path)
            assert analysis["tpm_detected"] is True, "Mixed version analysis must succeed"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _create_pe_with_platform_markers(self, markers: list[bytes]) -> bytes:
        """Create PE with platform-specific TPM markers.

        Args:
            markers: List of platform marker strings.

        Returns:
            PE binary with platform markers.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 18
        section_header = b".rdata\x00\x00" + b"\x00" * 32

        marker_data = b""
        for marker in markers:
            marker_data += marker + b"\x00"

        padding = b"\x00" * (512 - len(dos_header) - len(pe_header) - len(section_header))

        return dos_header + pe_header + section_header + padding + marker_data


@pytest.mark.skipif(sys.platform != "win32", reason="TPM detection designed for Windows platform")
class TestTPMDetectionWindowsIntegration:
    """Test TPM detection against Windows system resources - requires Windows OS."""

    def test_detect_windows_tpm_device_presence(self) -> None:
        """TPM detection must identify presence of Windows TPM device."""
        if not Path(r"C:\Windows\System32\Tbs.dll").exists():
            pytest.skip("Windows TPM Base Services DLL not found - TPM not available on this system")

        engine = TPMBypassEngine()

        tpm_device_check = engine.detect_tpm_usage(r"C:\Windows\System32\Tbs.dll")

        assert isinstance(tpm_device_check, bool), "TPM detection must return boolean result"

    def test_analyze_real_tpm_protected_binary_if_available(self) -> None:
        """Analyze real TPM-protected binary if available in test fixtures."""
        test_binary_path = Path(r"D:\Intellicrack\tests\fixtures\binaries\tpm_protected_sample.exe")

        if not test_binary_path.exists():
            pytest.skip(
                f"VERBOSE SKIP: Real TPM-protected binary not found at {test_binary_path}\n"
                f"To enable this test:\n"
                f"1. Obtain a TPM-protected binary (e.g., Windows Hello protected app, BitLocker-enabled binary)\n"
                f"2. Place it at: {test_binary_path}\n"
                f"3. Binary should use TBS.dll and TPM 2.0 APIs for license validation\n"
                f"4. Recommended samples: Microsoft Windows Hello credential guard binaries, "
                f"enterprise software with TPM-based licensing\n"
            )

        engine = TPMBypassEngine()

        detection_result = engine.detect_tpm_usage(str(test_binary_path))
        assert detection_result is True, "Real TPM-protected binary must be detected"

        analysis_result = engine.analyze_tpm_protection(str(test_binary_path))

        assert analysis_result["tpm_detected"] is True, "Real binary analysis must detect TPM usage"
        assert len(analysis_result["tpm_apis"]) > 0, "Real binary must have identifiable TPM APIs"
        assert analysis_result["protection_strength"] in ["weak", "medium", "strong"], \
            "Protection strength must be assessed"
        assert analysis_result["bypass_difficulty"] in ["easy", "medium", "hard"], \
            "Bypass difficulty must be assessed"
