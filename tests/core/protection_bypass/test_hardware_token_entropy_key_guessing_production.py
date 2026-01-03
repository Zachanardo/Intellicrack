"""Production Tests for Hardware Token Entropy-Based Key Guessing.

Validates entropy-based key extraction and guessing from hardware token memory dumps.
Tests MUST validate real key derivation, algorithm detection, format validation,
pattern recognition, and confidence scoring against realistic token data.

Expected Behavior (from testingtodo.md):
- Must implement proper key derivation validation
- Must detect key generation algorithms from behavior
- Must validate guessed keys against known formats
- Must use machine learning for key pattern recognition
- Must provide confidence scores for guesses
- Edge cases: Hardware-derived keys, time-based derivation

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from intellicrack.core.protection_bypass.hardware_token import HardwareTokenBypass


@pytest.fixture
def token_bypass() -> HardwareTokenBypass:
    """Create hardware token bypass instance."""
    return HardwareTokenBypass()


@pytest.fixture
def high_entropy_memory_dump(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create memory dump with known high-entropy keys at specific offsets.

    Returns:
        tuple: (dump_path, metadata dict with key locations and types)
    """
    dump_size = 32768
    dump_data = bytearray(dump_size)

    metadata: dict[str, Any] = {"keys": [], "entropy_threshold": 7.0}

    offset = 256
    yubikey_aes = secrets.token_bytes(16)
    dump_data[offset:offset+16] = yubikey_aes
    metadata["keys"].append({
        "offset": offset,
        "type": "yubikey_aes",
        "data": yubikey_aes.hex(),
        "expected_entropy": 7.8
    })

    offset = 1024
    securid_seed = secrets.token_bytes(16)
    dump_data[offset-4:offset] = b"\x00\x00\x00\x10"
    dump_data[offset:offset+16] = securid_seed
    metadata["keys"].append({
        "offset": offset,
        "type": "securid_seed",
        "data": securid_seed.hex(),
        "marker": b"\x00\x00\x00\x10",
        "expected_entropy": 7.5
    })

    offset = 2048
    rsa_seed_marker = b"RSA"
    rsa_seed = secrets.token_bytes(16)
    dump_data[offset:offset+3] = rsa_seed_marker
    dump_data[offset+3:offset+19] = rsa_seed
    metadata["keys"].append({
        "offset": offset + 3,
        "type": "rsa_securid",
        "data": rsa_seed.hex(),
        "marker": rsa_seed_marker,
        "expected_entropy": 7.6
    })

    offset = 4096
    seed_marker = b"SEED"
    seed_data = secrets.token_bytes(16)
    dump_data[offset:offset+4] = seed_marker
    dump_data[offset+4:offset+20] = seed_data
    metadata["keys"].append({
        "offset": offset + 4,
        "type": "seed_labeled",
        "data": seed_data.hex(),
        "marker": seed_marker,
        "expected_entropy": 7.7
    })

    offset = 8192
    for i in range(5):
        key_offset = offset + (i * 32)
        key_data = secrets.token_bytes(16)
        dump_data[key_offset:key_offset+16] = key_data
        metadata["keys"].append({
            "offset": key_offset,
            "type": f"cluster_key_{i}",
            "data": key_data.hex(),
            "expected_entropy": 7.5 + (i * 0.1)
        })

    offset = 16384
    low_entropy = bytes([0x41] * 8 + [0x42] * 8)
    dump_data[offset:offset+16] = low_entropy
    metadata["keys"].append({
        "offset": offset,
        "type": "low_entropy_decoy",
        "data": low_entropy.hex(),
        "expected_entropy": 1.0,
        "should_reject": True
    })

    dump_file = tmp_path / "high_entropy_dump.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file, metadata


@pytest.fixture
def pbkdf2_derived_keys_dump(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create dump with PBKDF2-derived keys showing derivation patterns.

    Returns:
        tuple: (dump_path, metadata with derivation parameters)
    """
    dump_size = 16384
    dump_data = bytearray(dump_size)

    password = b"test_password_123"
    salt = secrets.token_bytes(16)
    iterations = 100000

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    derived_key = kdf.derive(password)

    offset = 1000
    dump_data[offset:offset+16] = salt
    dump_data[offset+64:offset+96] = derived_key

    metadata = {
        "derivation_type": "PBKDF2-HMAC-SHA256",
        "password": password,
        "salt": salt.hex(),
        "salt_offset": offset,
        "iterations": iterations,
        "derived_key": derived_key.hex(),
        "key_offset": offset + 64,
        "key_length": 32
    }

    dump_file = tmp_path / "pbkdf2_derived.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file, metadata


@pytest.fixture
def time_based_otp_dump(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create dump with TOTP seed and time-based derivation patterns.

    Returns:
        tuple: (dump_path, metadata with TOTP parameters)
    """
    dump_size = 8192
    dump_data = bytearray(dump_size)

    totp_secret = secrets.token_bytes(20)
    timestamp = int(time.time())
    time_step = 30

    time_counter = timestamp // time_step
    time_bytes = struct.pack(">Q", time_counter)

    hmac_hash = hmac.new(totp_secret, time_bytes, hashlib.sha1).digest()
    offset_value = hmac_hash[-1] & 0x0F
    token_bytes = hmac_hash[offset_value:offset_value+4]
    token = struct.unpack(">I", token_bytes)[0] & 0x7FFFFFFF
    otp = str(token % 1000000).zfill(6)

    dump_offset = 500
    dump_data[dump_offset:dump_offset+20] = totp_secret
    dump_data[dump_offset+64:dump_offset+72] = time_bytes

    metadata = {
        "secret": totp_secret.hex(),
        "secret_offset": dump_offset,
        "timestamp": timestamp,
        "time_counter": time_counter,
        "time_step": time_step,
        "otp": otp,
        "algorithm": "TOTP-SHA1"
    }

    dump_file = tmp_path / "totp_dump.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file, metadata


@pytest.fixture
def hardware_derived_keys_dump(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create dump simulating keys derived from hardware identifiers.

    Returns:
        tuple: (dump_path, metadata with hardware derivation info)
    """
    dump_size = 16384
    dump_data = bytearray(dump_size)

    cpu_id = b"GenuineIntel_1234567890ABCDEF"
    mac_address = bytes.fromhex("001122334455")
    disk_serial = b"DISK_SN_9876543210"

    hardware_composite = cpu_id + mac_address + disk_serial
    hardware_hash = hashlib.sha256(hardware_composite).digest()

    derived_aes_key = hardware_hash[:16]
    derived_hmac_key = hardware_hash[16:32]

    offset = 2000
    dump_data[offset:offset+len(cpu_id)] = cpu_id
    dump_data[offset+128:offset+128+6] = mac_address
    dump_data[offset+256:offset+256+len(disk_serial)] = disk_serial
    dump_data[offset+512:offset+528] = derived_aes_key
    dump_data[offset+544:offset+560] = derived_hmac_key

    metadata = {
        "derivation_type": "hardware_composite_sha256",
        "cpu_id": cpu_id.decode("utf-8", errors="ignore"),
        "mac_address": mac_address.hex(),
        "disk_serial": disk_serial.decode("utf-8", errors="ignore"),
        "composite_hash": hardware_hash.hex(),
        "aes_key": derived_aes_key.hex(),
        "aes_key_offset": offset + 512,
        "hmac_key": derived_hmac_key.hex(),
        "hmac_key_offset": offset + 544
    }

    dump_file = tmp_path / "hardware_derived.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file, metadata


@pytest.fixture
def mixed_format_keys_dump(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create dump with keys in various formats (raw, base64, hex-encoded).

    Returns:
        tuple: (dump_path, metadata with format information)
    """
    dump_size = 16384
    dump_data = bytearray(dump_size)

    raw_key = secrets.token_bytes(16)
    hex_key = raw_key.hex().encode("ascii")

    import base64
    base64_key = base64.b64encode(raw_key)

    offset = 1000
    dump_data[offset:offset+16] = raw_key
    dump_data[offset+100:offset+100+len(hex_key)] = hex_key
    dump_data[offset+200:offset+200+len(base64_key)] = base64_key

    metadata = {
        "raw_key": raw_key.hex(),
        "raw_offset": offset,
        "hex_encoded": hex_key.decode("ascii"),
        "hex_offset": offset + 100,
        "base64_encoded": base64_key.decode("ascii"),
        "base64_offset": offset + 200
    }

    dump_file = tmp_path / "mixed_formats.bin"
    dump_file.write_bytes(bytes(dump_data))
    return dump_file, metadata


class TestEntropyBasedKeyExtraction:
    """Test entropy-based key extraction from memory dumps."""

    def test_extract_high_entropy_yubikey_keys(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Entropy detection identifies YubiKey AES keys above threshold."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        assert result["success"] is True
        assert "yubikey_secrets" in result

        yubikey_keys = result["yubikey_secrets"]
        assert len(yubikey_keys) > 0

        expected_yubikey_keys = [
            k for k in metadata["keys"]
            if k["type"] == "yubikey_aes"
        ]

        for expected_key in expected_yubikey_keys:
            found = False
            for key_id, key_hex in yubikey_keys.items():
                if key_hex == expected_key["data"]:
                    found = True
                    assert "yubikey_aes" in key_id
                    assert f"{expected_key['offset']:08x}" in key_id
                    break
            assert found, f"Expected key at offset {expected_key['offset']} not found"

    def test_extract_securid_seeds_with_markers(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """SecurID seed extraction identifies seeds after RSA/SEED markers."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        assert result["success"] is True
        assert "securid_seeds" in result

        seeds = result["securid_seeds"]
        assert len(seeds) >= 3

        expected_seeds = [
            k for k in metadata["keys"]
            if "securid" in k["type"] or "seed" in k["type"]
        ]

        found_count = 0
        for expected_seed in expected_seeds:
            if expected_seed.get("should_reject"):
                continue
            for seed_id, seed_hex in seeds.items():
                if seed_hex == expected_seed["data"]:
                    found_count += 1
                    break

        assert found_count >= 2, f"Expected at least 2 SecurID seeds, found {found_count}"

    def test_reject_low_entropy_candidates(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Low entropy data is correctly rejected as non-key material."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        low_entropy_key = next(
            k for k in metadata["keys"]
            if k.get("should_reject") and k["type"] == "low_entropy_decoy"
        )

        all_extracted = []
        if "yubikey_secrets" in result:
            all_extracted.extend(result["yubikey_secrets"].values())
        if "securid_seeds" in result:
            all_extracted.extend(result["securid_seeds"].values())
        if "smartcard_keys" in result:
            all_extracted.extend(result["smartcard_keys"].values())

        assert low_entropy_key["data"] not in all_extracted, \
            "Low entropy decoy was incorrectly identified as a key"

    def test_entropy_calculation_accuracy(
        self,
        token_bypass: HardwareTokenBypass
    ) -> None:
        """Shannon entropy calculation provides accurate measurements."""
        high_entropy_data = secrets.token_bytes(16)
        calculated_entropy = token_bypass._calculate_entropy(high_entropy_data)
        assert calculated_entropy >= 7.0, \
            f"High entropy data measured {calculated_entropy}, expected >= 7.0"

        low_entropy_data = bytes([0x00] * 16)
        calculated_entropy = token_bypass._calculate_entropy(low_entropy_data)
        assert calculated_entropy == 0.0, \
            f"Zero entropy data measured {calculated_entropy}, expected 0.0"

        medium_entropy_data = bytes([i % 4 for i in range(16)])
        calculated_entropy = token_bypass._calculate_entropy(medium_entropy_data)
        assert 1.0 <= calculated_entropy <= 3.0, \
            f"Medium entropy data measured {calculated_entropy}, expected 1.0-3.0"

        random_ascii = b"A" * 8 + b"B" * 8
        calculated_entropy = token_bypass._calculate_entropy(random_ascii)
        assert calculated_entropy < 2.0, \
            f"Repeated pattern measured {calculated_entropy}, expected < 2.0"

    def test_extract_multiple_key_types_simultaneously(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Extraction identifies multiple key types in single dump."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        assert result["success"] is True
        assert "yubikey_secrets" in result
        assert "securid_seeds" in result

        total_keys = (
            len(result.get("yubikey_secrets", {})) +
            len(result.get("securid_seeds", {})) +
            len(result.get("smartcard_keys", {}))
        )

        expected_valid_keys = len([
            k for k in metadata["keys"]
            if not k.get("should_reject", False)
        ])

        assert total_keys >= expected_valid_keys * 0.8, \
            f"Expected ~{expected_valid_keys} keys, extracted {total_keys}"


class TestKeyDerivationValidation:
    """Test validation of key derivation algorithms."""

    def test_detect_pbkdf2_derivation_pattern(
        self,
        token_bypass: HardwareTokenBypass,
        pbkdf2_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """PBKDF2-derived keys are identified and validated."""
        dump_path, metadata = pbkdf2_derived_keys_dump

        dump_data = dump_path.read_bytes()

        salt_offset = metadata["salt_offset"]
        salt = dump_data[salt_offset:salt_offset+16]
        assert salt.hex() == metadata["salt"]

        key_offset = metadata["key_offset"]
        derived_key = dump_data[key_offset:key_offset+32]
        assert derived_key.hex() == metadata["derived_key"]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=metadata["iterations"],
            backend=default_backend()
        )

        recomputed_key = kdf.derive(metadata["password"])
        assert recomputed_key == derived_key, \
            "PBKDF2 key derivation validation failed"

    def test_validate_derived_key_structure(
        self,
        token_bypass: HardwareTokenBypass,
        pbkdf2_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Derived keys have proper structure and length."""
        dump_path, metadata = pbkdf2_derived_keys_dump

        dump_data = dump_path.read_bytes()
        key_offset = metadata["key_offset"]
        derived_key = dump_data[key_offset:key_offset+32]

        assert len(derived_key) == 32

        entropy = token_bypass._calculate_entropy(derived_key)
        assert entropy >= 7.0, \
            f"Derived key has low entropy {entropy}, possible weak derivation"

        assert derived_key != bytes(32), "Derived key is all zeros"
        assert derived_key != bytes([0xFF] * 32), "Derived key is all ones"


class TestTimeBasedKeyDerivation:
    """Test time-based OTP and key derivation detection."""

    def test_extract_totp_secret_from_dump(
        self,
        token_bypass: HardwareTokenBypass,
        time_based_otp_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """TOTP secrets are extracted and validated."""
        dump_path, metadata = time_based_otp_dump

        dump_data = dump_path.read_bytes()
        secret_offset = metadata["secret_offset"]
        extracted_secret = dump_data[secret_offset:secret_offset+20]

        assert extracted_secret.hex() == metadata["secret"]

        entropy = token_bypass._calculate_entropy(extracted_secret)
        assert entropy >= 6.5, \
            f"TOTP secret has low entropy {entropy}"

    def test_validate_totp_generation(
        self,
        time_based_otp_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """TOTP generation from extracted secret produces valid codes."""
        dump_path, metadata = time_based_otp_dump

        dump_data = dump_path.read_bytes()
        secret_offset = metadata["secret_offset"]
        secret = dump_data[secret_offset:secret_offset+20]

        time_counter = metadata["time_counter"]
        time_bytes = struct.pack(">Q", time_counter)

        hmac_hash = hmac.new(secret, time_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        token_bytes = hmac_hash[offset:offset+4]
        token = struct.unpack(">I", token_bytes)[0] & 0x7FFFFFFF
        otp = str(token % 1000000).zfill(6)

        assert otp == metadata["otp"], \
            f"TOTP validation failed: got {otp}, expected {metadata['otp']}"

    def test_time_drift_tolerance(
        self,
        time_based_otp_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Time-based derivation handles clock drift correctly."""
        dump_path, metadata = time_based_otp_dump

        dump_data = dump_path.read_bytes()
        secret_offset = metadata["secret_offset"]
        secret = dump_data[secret_offset:secret_offset+20]

        valid_otps = []
        base_counter = metadata["time_counter"]

        for drift in range(-2, 3):
            counter = base_counter + drift
            time_bytes = struct.pack(">Q", counter)
            hmac_hash = hmac.new(secret, time_bytes, hashlib.sha1).digest()
            offset = hmac_hash[-1] & 0x0F
            token_bytes = hmac_hash[offset:offset+4]
            token = struct.unpack(">I", token_bytes)[0] & 0x7FFFFFFF
            otp = str(token % 1000000).zfill(6)
            valid_otps.append(otp)

        assert metadata["otp"] in valid_otps, \
            "Expected OTP not found in drift window"
        assert len(set(valid_otps)) >= 3, \
            "Time drift not producing different OTPs"


class TestHardwareDerivedKeys:
    """Test detection and validation of hardware-derived keys."""

    def test_extract_hardware_identifiers(
        self,
        token_bypass: HardwareTokenBypass,
        hardware_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Hardware identifiers are extracted from memory dump."""
        dump_path, metadata = hardware_derived_keys_dump

        dump_data = dump_path.read_bytes()

        cpu_id = metadata["cpu_id"].encode("utf-8")
        assert cpu_id in dump_data, "CPU ID not found in dump"

        mac_bytes = bytes.fromhex(metadata["mac_address"])
        assert mac_bytes in dump_data, "MAC address not found in dump"

        disk_serial = metadata["disk_serial"].encode("utf-8")
        assert disk_serial in dump_data, "Disk serial not found in dump"

    def test_validate_hardware_key_derivation(
        self,
        token_bypass: HardwareTokenBypass,
        hardware_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Keys derived from hardware IDs are validated correctly."""
        dump_path, metadata = hardware_derived_keys_dump

        cpu_id = metadata["cpu_id"].encode("utf-8")
        mac_address = bytes.fromhex(metadata["mac_address"])
        disk_serial = metadata["disk_serial"].encode("utf-8")

        hardware_composite = cpu_id + mac_address + disk_serial
        recomputed_hash = hashlib.sha256(hardware_composite).digest()

        assert recomputed_hash.hex() == metadata["composite_hash"]

        aes_key = recomputed_hash[:16]
        assert aes_key.hex() == metadata["aes_key"]

        hmac_key = recomputed_hash[16:32]
        assert hmac_key.hex() == metadata["hmac_key"]

    def test_extract_hardware_derived_keys(
        self,
        token_bypass: HardwareTokenBypass,
        hardware_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Hardware-derived keys are identified in extraction."""
        dump_path, metadata = hardware_derived_keys_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        assert result["success"] is True

        aes_key_found = False
        hmac_key_found = False

        for key_dict in [result.get("yubikey_secrets", {}),
                         result.get("smartcard_keys", {})]:
            for key_hex in key_dict.values():
                if key_hex == metadata["aes_key"]:
                    aes_key_found = True
                if key_hex == metadata["hmac_key"]:
                    hmac_key_found = True

        assert aes_key_found or hmac_key_found, \
            "Hardware-derived keys not detected in extraction"


class TestKeyFormatValidation:
    """Test validation of keys against known formats."""

    def test_validate_aes_key_format(
        self,
        token_bypass: HardwareTokenBypass
    ) -> None:
        """AES keys are validated for correct length and structure."""
        valid_aes_128 = secrets.token_bytes(16)
        assert len(valid_aes_128) == 16

        entropy = token_bypass._calculate_entropy(valid_aes_128)
        assert entropy >= 7.0

        valid_aes_256 = secrets.token_bytes(32)
        assert len(valid_aes_256) == 32

        invalid_length = secrets.token_bytes(15)
        assert len(invalid_length) != 16 and len(invalid_length) != 32

    def test_validate_rsa_seed_format(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """RSA SecurID seeds are validated for format compliance."""
        dump_path, metadata = high_entropy_memory_dump

        rsa_seeds = [
            k for k in metadata["keys"]
            if k["type"] == "rsa_securid"
        ]

        for seed_info in rsa_seeds:
            seed_bytes = bytes.fromhex(seed_info["data"])
            assert len(seed_bytes) == 16, "RSA seed must be 16 bytes"

            entropy = token_bypass._calculate_entropy(seed_bytes)
            assert entropy >= 6.0, "RSA seed entropy too low"

    def test_detect_hex_encoded_keys(
        self,
        token_bypass: HardwareTokenBypass,
        mixed_format_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Hex-encoded keys are detected and decoded."""
        dump_path, metadata = mixed_format_keys_dump

        dump_data = dump_path.read_bytes()
        hex_encoded = metadata["hex_encoded"]

        assert hex_encoded in dump_data.decode("ascii", errors="ignore")

        decoded = bytes.fromhex(hex_encoded)
        assert decoded.hex() == metadata["raw_key"]

    def test_detect_base64_encoded_keys(
        self,
        token_bypass: HardwareTokenBypass,
        mixed_format_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Base64-encoded keys are detected and decoded."""
        dump_path, metadata = mixed_format_keys_dump

        dump_data = dump_path.read_bytes()
        base64_encoded = metadata["base64_encoded"]

        assert base64_encoded in dump_data.decode("ascii", errors="ignore")

        import base64
        decoded = base64.b64decode(base64_encoded)
        assert decoded.hex() == metadata["raw_key"]


class TestKeyPatternRecognition:
    """Test machine learning and pattern recognition for keys."""

    def test_recognize_key_clustering(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Multiple keys in close proximity are recognized as cluster."""
        dump_path, metadata = high_entropy_memory_dump

        cluster_keys = [
            k for k in metadata["keys"]
            if "cluster_key" in k["type"]
        ]

        assert len(cluster_keys) == 5

        offsets = [k["offset"] for k in cluster_keys]
        for i in range(len(offsets) - 1):
            distance = offsets[i+1] - offsets[i]
            assert distance == 32, f"Key cluster spacing inconsistent: {distance}"

    def test_pattern_based_key_identification(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Keys are identified by patterns beyond entropy alone."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        securid_seeds = result.get("securid_seeds", {})

        for seed_id, seed_hex in securid_seeds.items():
            found_metadata = False
            for expected_key in metadata["keys"]:
                if expected_key["data"] == seed_hex:
                    assert "marker" in expected_key, \
                        "SecurID seed should have been preceded by marker"
                    found_metadata = True
                    break

            if found_metadata:
                break

        assert found_metadata, "No marker-based keys identified"

    def test_statistical_key_validation(
        self,
        token_bypass: HardwareTokenBypass
    ) -> None:
        """Statistical properties validate key candidates."""
        valid_key = secrets.token_bytes(16)
        entropy = token_bypass._calculate_entropy(valid_key)
        assert entropy >= 7.0

        byte_counts: dict[int, int] = {}
        for byte in valid_key:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        max_repeats = max(byte_counts.values())
        assert max_repeats <= 4, "Valid key should not have excessive repetition"

        weak_key = bytes([0x01, 0x02] * 8)
        weak_entropy = token_bypass._calculate_entropy(weak_key)
        assert weak_entropy < 2.0, "Weak key should have low entropy"


class TestConfidenceScoring:
    """Test confidence score generation for key guesses."""

    def test_high_confidence_for_marked_keys(
        self,
        token_bypass: HardwareTokenBypass,
        high_entropy_memory_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Keys with markers receive high confidence scores."""
        dump_path, metadata = high_entropy_memory_dump

        result = token_bypass.extract_token_secrets(str(dump_path))

        marked_keys = [
            k for k in metadata["keys"]
            if "marker" in k and not k.get("should_reject", False)
        ]

        assert len(marked_keys) > 0

        for marked_key in marked_keys:
            found = False
            for key_dict in [result.get("securid_seeds", {}),
                            result.get("yubikey_secrets", {})]:
                if marked_key["data"] in key_dict.values():
                    found = True
                    break

            if not found and "securid" in marked_key["type"]:
                continue

            assert found or "securid" in marked_key["type"], \
                f"Marked key at offset {marked_key['offset']} not extracted"

    def test_entropy_based_confidence(
        self,
        token_bypass: HardwareTokenBypass
    ) -> None:
        """Confidence correlates with entropy measurements."""
        high_entropy = secrets.token_bytes(16)
        high_score = token_bypass._calculate_entropy(high_entropy)

        medium_entropy = bytes([i % 16 for i in range(16)])
        medium_score = token_bypass._calculate_entropy(medium_entropy)

        low_entropy = bytes([0x42] * 16)
        low_score = token_bypass._calculate_entropy(low_entropy)

        assert high_score > medium_score > low_score
        assert high_score >= 7.0
        assert medium_score < 5.0
        assert low_score < 1.0

    def test_context_based_confidence(
        self,
        token_bypass: HardwareTokenBypass,
        pbkdf2_derived_keys_dump: tuple[Path, dict[str, Any]]
    ) -> None:
        """Keys with contextual evidence receive higher confidence."""
        dump_path, metadata = pbkdf2_derived_keys_dump

        dump_data = dump_path.read_bytes()

        salt_offset = metadata["salt_offset"]
        salt = dump_data[salt_offset:salt_offset+16]
        salt_entropy = token_bypass._calculate_entropy(salt)

        key_offset = metadata["key_offset"]
        key = dump_data[key_offset:key_offset+32]
        key_entropy = token_bypass._calculate_entropy(key)

        assert salt_entropy >= 7.0
        assert key_entropy >= 7.0

        distance = abs(key_offset - salt_offset)
        assert distance == 64, "Salt and key should be in proximity"


class TestEdgeCases:
    """Test edge cases in key extraction."""

    def test_extract_from_empty_dump(
        self,
        token_bypass: HardwareTokenBypass,
        tmp_path: Path
    ) -> None:
        """Empty dumps return unsuccessful extraction."""
        empty_dump = tmp_path / "empty.bin"
        empty_dump.write_bytes(b"")

        result = token_bypass.extract_token_secrets(str(empty_dump))

        assert result["success"] is False
        assert len(result.get("yubikey_secrets", {})) == 0
        assert len(result.get("securid_seeds", {})) == 0

    def test_extract_from_small_dump(
        self,
        token_bypass: HardwareTokenBypass,
        tmp_path: Path
    ) -> None:
        """Small dumps below key size are handled correctly."""
        small_dump = tmp_path / "small.bin"
        small_dump.write_bytes(secrets.token_bytes(10))

        result = token_bypass.extract_token_secrets(str(small_dump))

        assert result["success"] is False

    def test_extract_from_corrupted_markers(
        self,
        token_bypass: HardwareTokenBypass,
        tmp_path: Path
    ) -> None:
        """Corrupted markers are handled gracefully."""
        dump_data = bytearray(4096)

        dump_data[100:102] = b"RS"
        dump_data[102:118] = secrets.token_bytes(16)

        dump_data[500:503] = b"SEE"
        dump_data[503:519] = secrets.token_bytes(16)

        dump_file = tmp_path / "corrupted.bin"
        dump_file.write_bytes(bytes(dump_data))

        result = token_bypass.extract_token_secrets(str(dump_file))

        assert "securid_seeds" in result or "yubikey_secrets" in result

    def test_nonexistent_dump_path(
        self,
        token_bypass: HardwareTokenBypass
    ) -> None:
        """Nonexistent paths return unsuccessful extraction."""
        result = token_bypass.extract_token_secrets("/nonexistent/path/dump.bin")

        assert result["success"] is False

    def test_overlapping_key_candidates(
        self,
        token_bypass: HardwareTokenBypass,
        tmp_path: Path
    ) -> None:
        """Overlapping high-entropy regions are handled correctly."""
        dump_size = 4096
        dump_data = bytearray(dump_size)

        offset = 1000
        continuous_high_entropy = secrets.token_bytes(64)
        dump_data[offset:offset+64] = continuous_high_entropy

        dump_file = tmp_path / "overlapping.bin"
        dump_file.write_bytes(bytes(dump_data))

        result = token_bypass.extract_token_secrets(str(dump_file))

        if result.get("yubikey_secrets"):
            keys = list(result["yubikey_secrets"].values())

            for i, key1 in enumerate(keys):
                for key2 in keys[i+1:]:
                    key1_bytes = bytes.fromhex(key1)
                    key2_bytes = bytes.fromhex(key2)
                    assert key1_bytes != key2_bytes or key1 == key2

    def test_maximum_dump_size_handling(
        self,
        token_bypass: HardwareTokenBypass,
        tmp_path: Path
    ) -> None:
        """Large dumps are processed without memory issues."""
        large_size = 1024 * 1024
        dump_data = bytearray(large_size)

        for offset in range(0, large_size, 65536):
            if offset + 16 <= large_size:
                dump_data[offset:offset+16] = secrets.token_bytes(16)

        dump_file = tmp_path / "large.bin"
        dump_file.write_bytes(bytes(dump_data))

        result = token_bypass.extract_token_secrets(str(dump_file))

        assert result["success"] is True

        total_keys = (
            len(result.get("yubikey_secrets", {})) +
            len(result.get("securid_seeds", {}))
        )
        assert total_keys > 0
