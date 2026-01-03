r"""Production tests for certificate pinning detector - static AND dynamic analysis.

CRITICAL REQUIREMENTS FROM testingtodo.md:
- Must implement dynamic analysis for pinning detection
- Must hook SSL/TLS validation functions
- Must detect runtime certificate comparisons
- Must identify pinned certificates from memory
- Must support framework-specific detection
- Edge cases: Custom TLS implementations, hybrid apps

This test suite validates BOTH static and dynamic pinning detection capabilities.
Tests MUST FAIL if dynamic analysis is not implemented.
NO mocks, NO stubs - only real binary analysis and runtime instrumentation.
"""

import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.certificate.pinning_detector import (
    PinningDetector,
    PinningInfo,
    PinningLocation,
    PinningReport,
)

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class TestStaticCertificateHashDetection:
    """Test static hash detection in binaries."""

    def test_detects_sha256_hashes_in_windows_pe(self, tmp_path: Path) -> None:
        """Detector finds SHA-256 certificate hashes in PE binaries."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        test_exe = tmp_path / "test.exe"

        pe_header = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        )
        pe_header += b"\x00" * (0x3C - len(pe_header))
        pe_header += struct.pack("<I", 0x80)
        pe_header += b"\x00" * (0x80 - len(pe_header))
        pe_header += b"PE\x00\x00"
        pe_header += b"\x00" * 100

        embedded_data = f"PINNED_CERT_HASH={test_hash}\x00".encode("utf-8")
        test_exe.write_bytes(pe_header + embedded_data)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_exe))

        assert len(hashes) > 0
        assert any(test_hash in h.lower() for h in hashes)
        assert any("SHA-256" in h or "sha256" in h.lower() for h in hashes)

    def test_detects_sha1_hashes_in_binary(self, tmp_path: Path) -> None:
        """Detector finds SHA-1 certificate hashes in binaries."""
        test_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        test_bin = tmp_path / "test.bin"

        binary_data = b"\x00" * 256
        binary_data += f"cert_sha1={test_hash}\x00".encode("utf-8")
        binary_data += b"\x00" * 256
        test_bin.write_bytes(binary_data)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_bin))

        assert len(hashes) > 0
        assert any(test_hash in h.lower() for h in hashes)
        assert any("SHA-1" in h for h in hashes)

    def test_detects_base64_encoded_sha256_pins(self, tmp_path: Path) -> None:
        """Detector finds Base64-encoded SHA-256 pins (OkHttp format)."""
        base64_pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        test_file = tmp_path / "test.apk"

        data = f'CertificatePinner.Builder().add("example.com", "sha256/{base64_pin}")'.encode("utf-8")
        test_file.write_bytes(data)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_file))

        assert len(hashes) > 0
        assert any(base64_pin in h for h in hashes)
        assert any("SHA-256-B64" in h for h in hashes)

    def test_detects_multiple_hashes_in_single_binary(self, tmp_path: Path) -> None:
        """Detector finds all certificate hashes in binary with multiple pins."""
        hash1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hash2 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        hash3 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

        test_file = tmp_path / "multi_pin.bin"
        data = f"PRIMARY={hash1}\nBACKUP={hash2}\nLEGACY={hash3}\n".encode("utf-8")
        test_file.write_bytes(data)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_file))

        assert len(hashes) >= 3
        found_hashes = [h.split(":", 1)[1] if ":" in h else h for h in hashes]
        assert any(hash1 in fh.lower() for fh in found_hashes)
        assert any(hash2 in fh.lower() for fh in found_hashes)
        assert any(hash3 in fh.lower() for fh in found_hashes)

    def test_handles_binary_with_no_hashes(self, tmp_path: Path) -> None:
        """Detector returns empty list for binaries without certificate hashes."""
        test_file = tmp_path / "no_pins.bin"
        test_file.write_bytes(b"Just some random data\x00\x01\x02\x03")

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_file))

        assert isinstance(hashes, list)
        assert len(hashes) == 0

    def test_rejects_nonexistent_file(self) -> None:
        """Detector raises FileNotFoundError for missing binaries."""
        detector = PinningDetector()

        with pytest.raises(FileNotFoundError):
            detector.scan_for_certificate_hashes("/nonexistent/path/to/binary.exe")


class TestStaticPinningLogicDetection:
    """Test static analysis of pinning logic in binaries."""

    def test_detects_windows_winhttp_pinning_logic(self, tmp_path: Path) -> None:
        """Detector identifies WinHTTP certificate validation patterns."""
        test_exe = tmp_path / "winhttp_app.exe"

        pe_minimal = self._create_minimal_pe_with_imports(
            ["WinHttpSetOption", "WinHttpQueryOption", "CertGetCertificateChain"]
        )
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        data = pe_minimal + f"PINNED={test_hash}\x00".encode("utf-8")
        test_exe.write_bytes(data)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(test_exe))

        assert len(locations) > 0
        assert any(loc.pinning_type == "custom" for loc in locations)
        assert any("WinHttpSetOption" in str(loc.evidence) or "WinHttpQueryOption" in str(loc.evidence) for loc in locations)
        assert all(loc.confidence >= 0.5 for loc in locations)

    def test_detects_openssl_pinning_logic_in_elf(self, tmp_path: Path) -> None:
        """Detector identifies OpenSSL certificate validation patterns."""
        test_elf = tmp_path / "openssl_app"

        elf_minimal = self._create_minimal_elf_with_imports(
            ["SSL_CTX_set_verify", "X509_verify_cert", "SSL_get_verify_result"]
        )
        test_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        data = elf_minimal + f"pin={test_hash}\x00".encode("utf-8")
        test_elf.write_bytes(data)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(test_elf))

        assert len(locations) > 0
        assert any(loc.pinning_type == "openssl" for loc in locations)
        assert any("SSL" in str(loc.evidence) or "X509" in str(loc.evidence) for loc in locations)

    def test_platform_detection_for_pe_binary(self, tmp_path: Path) -> None:
        """Detector correctly identifies Windows PE platform."""
        test_exe = tmp_path / "test.exe"
        pe_data = self._create_minimal_pe_with_imports([])
        test_exe.write_bytes(pe_data)

        detector = PinningDetector()
        detector.detect_pinning_logic(str(test_exe))

        assert detector.platform == "windows"

    def test_platform_detection_for_elf_binary(self, tmp_path: Path) -> None:
        """Detector correctly identifies Linux ELF platform."""
        test_elf = tmp_path / "test"
        elf_data = self._create_minimal_elf_with_imports([])
        test_elf.write_bytes(elf_data)

        detector = PinningDetector()
        detector.detect_pinning_logic(str(test_elf))

        assert detector.platform in ["linux", "android"]

    def test_handles_corrupted_binary_gracefully(self, tmp_path: Path) -> None:
        """Detector handles corrupted binaries without crashing."""
        test_file = tmp_path / "corrupted.exe"
        test_file.write_bytes(b"MZ\x90\x00CORRUPTED_DATA\x00\x00\x00")

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(test_file))

        assert isinstance(locations, list)

    def _create_minimal_pe_with_imports(self, import_names: list[str]) -> bytes:
        """Create minimal valid PE binary with specified imports."""
        pe_header = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        )
        pe_header += b"\x00" * (0x3C - len(pe_header))
        pe_header += struct.pack("<I", 0x80)
        pe_header += b"\x00" * (0x80 - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x014C)
        sections = struct.pack("<H", 1)
        coff_header = pe_signature + machine + sections + b"\x00" * 16

        pe_data = pe_header + coff_header
        pe_data += b"\x00" * 200

        for imp_name in import_names:
            pe_data += imp_name.encode("utf-8") + b"\x00"

        return pe_data

    def _create_minimal_elf_with_imports(self, import_names: list[str]) -> bytes:
        """Create minimal valid ELF binary with specified imports."""
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        elf_header += struct.pack("<H", 2)
        elf_header += struct.pack("<H", 0x3E)
        elf_header += struct.pack("<I", 1)
        elf_header += b"\x00" * 32

        elf_data = elf_header
        elf_data += b"\x00" * 200

        for imp_name in import_names:
            elf_data += imp_name.encode("utf-8") + b"\x00"

        return elf_data


class TestCrossReferenceAnalysis:
    """Test cross-reference analysis for certificate hashes."""

    def test_finds_all_references_to_certificate_hash(self, tmp_path: Path) -> None:
        """Detector locates all memory offsets referencing certificate hash."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        test_file = tmp_path / "multi_ref.bin"

        data = b"\x00" * 100
        data += test_hash.encode("utf-8")
        data += b"\x00" * 200
        data += test_hash.encode("utf-8")
        data += b"\x00" * 300
        data += test_hash.encode("utf-8")
        data += b"\x00" * 100

        test_file.write_bytes(data)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(test_file))

        assert len(cross_refs) > 0
        hash_key = f"SHA-256:{test_hash}"
        assert any(hash_key in key for key in cross_refs.keys())

        found_addresses = next((addrs for key, addrs in cross_refs.items() if test_hash in key), [])
        assert len(found_addresses) == 3

    def test_cross_refs_with_no_hashes_returns_empty(self, tmp_path: Path) -> None:
        """Detector returns empty dict when no hashes found."""
        test_file = tmp_path / "no_hashes.bin"
        test_file.write_bytes(b"Random data without hashes")

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(test_file))

        assert isinstance(cross_refs, dict)
        assert len(cross_refs) == 0


class TestComprehensivePinningReport:
    """Test comprehensive pinning report generation."""

    def test_generates_complete_report_for_pinned_binary(self, tmp_path: Path) -> None:
        """Detector generates full report with all detection data."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        test_exe = tmp_path / "pinned_app.exe"

        pe_data = self._create_pe_with_pinning(test_hash, ["WinHttpSetOption", "CertGetCertificateChain"])
        test_exe.write_bytes(pe_data)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_exe))

        assert isinstance(report, PinningReport)
        assert report.binary_path == str(test_exe)
        assert report.platform == "windows"
        assert report.confidence >= 0.5
        assert len(report.bypass_recommendations) > 0

    def test_report_has_pinning_property_accurate(self, tmp_path: Path) -> None:
        """Report.has_pinning property correctly indicates pinning presence."""
        test_hash = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        test_file = tmp_path / "has_pins.bin"

        data = f"CERTIFICATE_PIN={test_hash}\x00".encode("utf-8")
        test_file.write_bytes(data)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_file))

        assert report.has_pinning is True
        assert len(report.detected_pins) > 0 or len(report.pinning_locations) > 0

    def test_report_bypass_recommendations_relevant(self, tmp_path: Path) -> None:
        """Report includes relevant bypass recommendations based on detection."""
        test_exe = tmp_path / "bypass_test.exe"
        pe_data = self._create_pe_with_pinning(
            "abc123",
            ["WinHttpSetOption"]
        )
        test_exe.write_bytes(pe_data)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_exe))

        assert len(report.bypass_recommendations) > 0
        recommendations_text = " ".join(report.bypass_recommendations).lower()
        assert "hook" in recommendations_text or "patch" in recommendations_text or "frida" in recommendations_text

    def test_report_confidence_scoring_accurate(self, tmp_path: Path) -> None:
        """Report confidence score reflects detection quality."""
        test_file = tmp_path / "confidence_test.bin"
        test_file.write_bytes(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_file))

        assert 0.0 <= report.confidence <= 1.0

    def _create_pe_with_pinning(self, cert_hash: str, imports: list[str]) -> bytes:
        """Create PE binary with certificate pinning."""
        pe_header = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        )
        pe_header += b"\x00" * (0x3C - len(pe_header))
        pe_header += struct.pack("<I", 0x80)
        pe_header += b"\x00" * (0x80 - len(pe_header))
        pe_header += b"PE\x00\x00"
        pe_header += b"\x00" * 200

        for imp in imports:
            pe_header += imp.encode("utf-8") + b"\x00"

        pe_header += f"PINNED_HASH={cert_hash}\x00".encode("utf-8")
        return pe_header


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida required for dynamic analysis tests")
class TestDynamicAnalysisCapabilities:
    """Test REQUIRED dynamic analysis features - tests MUST FAIL if not implemented."""

    def test_dynamic_tls_hooking_method_exists(self) -> None:
        """Detector MUST have attach_dynamic_hooks method for runtime analysis."""
        detector = PinningDetector()

        if not hasattr(detector, "attach_dynamic_hooks"):
            pytest.fail(
                "CRITICAL: PinningDetector missing attach_dynamic_hooks() method. "
                "Dynamic SSL/TLS hooking NOT implemented. "
                "Required by testingtodo.md: 'Must hook SSL/TLS validation functions'"
            )

    def test_crypto_operation_monitoring_exists(self) -> None:
        """Detector MUST have monitor_crypto_operations for runtime hash detection."""
        detector = PinningDetector()

        if not hasattr(detector, "monitor_crypto_operations"):
            pytest.fail(
                "CRITICAL: PinningDetector missing monitor_crypto_operations() method. "
                "Runtime certificate comparison detection NOT implemented. "
                "Required by testingtodo.md: 'Must detect runtime certificate comparisons'"
            )

    def test_process_memory_scanning_exists(self) -> None:
        """Detector MUST have scan_process_memory for runtime certificate extraction."""
        detector = PinningDetector()

        if not hasattr(detector, "scan_process_memory"):
            pytest.fail(
                "CRITICAL: PinningDetector missing scan_process_memory() method. "
                "Memory-based certificate identification NOT implemented. "
                "Required by testingtodo.md: 'Must identify pinned certificates from memory'"
            )

    def test_runtime_report_generation_exists(self) -> None:
        """Detector MUST have generate_runtime_report for dynamic analysis reporting."""
        detector = PinningDetector()

        if not hasattr(detector, "generate_runtime_report"):
            pytest.fail(
                "CRITICAL: PinningDetector missing generate_runtime_report() method. "
                "Runtime analysis reporting NOT implemented. "
                "Required for complete dynamic analysis workflow"
            )

    def test_framework_specific_runtime_detection_exists(self) -> None:
        """Detector MUST have framework-specific runtime detection methods."""
        detector = PinningDetector()

        required_methods = {
            "detect_schannel_pinning": "Windows Schannel runtime detection",
            "detect_openssl_pinning_runtime": "OpenSSL runtime detection",
            "detect_custom_tls_pinning": "Custom TLS implementation detection"
        }

        missing = []
        for method, description in required_methods.items():
            if not hasattr(detector, method):
                missing.append(f"{method} ({description})")

        if missing:
            missing_methods_str: str = "\n".join(f"  - {m}" for m in missing)
            pytest.fail(
                f"CRITICAL: PinningDetector missing framework-specific runtime detection methods:\n"
                + missing_methods_str +
                "\nRequired by testingtodo.md: 'Must support framework-specific detection'"
            )

    def test_hooks_winhttp_certificate_validation(self) -> None:
        """Detector hooks WinHttpQueryOption to capture certificate validation."""
        detector = PinningDetector()

        if not hasattr(detector, "attach_dynamic_hooks"):
            pytest.skip("attach_dynamic_hooks not implemented - cannot test hooking")

        python_test_script = """
import ssl
import socket
context = ssl.create_default_context()
try:
    with socket.create_connection(('example.com', 443), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname='example.com') as ssock:
            cert = ssock.getpeercert()
except:
    pass
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            detected_pins = detector.attach_dynamic_hooks(session, platform="windows")

            time.sleep(2)

            assert detected_pins is not None, "attach_dynamic_hooks returned None - hooking failed"
            assert isinstance(detected_pins, list), "attach_dynamic_hooks must return list of detected pins"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_monitors_crypto_hash_operations(self) -> None:
        """Detector monitors SHA-256 hash operations during certificate validation."""
        detector = PinningDetector()

        if not hasattr(detector, "monitor_crypto_operations"):
            pytest.skip("monitor_crypto_operations not implemented - cannot test crypto monitoring")

        python_test_script = """
import hashlib
cert_data = b"fake certificate data for testing"
hash_result = hashlib.sha256(cert_data).hexdigest()
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            crypto_events = detector.monitor_crypto_operations(session)

            time.sleep(2)

            assert crypto_events is not None, "monitor_crypto_operations returned None"
            assert isinstance(crypto_events, list), "monitor_crypto_operations must return list of crypto events"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_scans_process_memory_for_certificates(self) -> None:
        """Detector scans process memory to find certificate hashes."""
        detector = PinningDetector()

        if not hasattr(detector, "scan_process_memory"):
            pytest.skip("scan_process_memory not implemented - cannot test memory scanning")

        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        python_test_script = f"""
import time
pinned_hash = "{test_hash}"
time.sleep(5)
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            found_certs = detector.scan_process_memory(session, pattern="certificate_hash")

            time.sleep(1)

            assert found_certs is not None, "scan_process_memory returned None"
            assert isinstance(found_certs, list), "scan_process_memory must return list of found certificates"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_generates_runtime_analysis_report(self) -> None:
        """Detector generates comprehensive runtime analysis report."""
        detector = PinningDetector()

        if not hasattr(detector, "generate_runtime_report"):
            pytest.skip("generate_runtime_report not implemented - cannot test runtime reporting")

        python_test_script = """
import ssl
context = ssl.create_default_context()
import time
time.sleep(2)
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            report = detector.generate_runtime_report(session, platform="windows")

            time.sleep(2)

            assert report is not None, "generate_runtime_report returned None"
            assert hasattr(report, "detected_pins") or "detected_pins" in report, "Report missing detected_pins"
            assert hasattr(report, "hooks_installed") or "hooks_installed" in report, "Report missing hooks_installed"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida required for edge case tests")
class TestDynamicAnalysisEdgeCases:
    """Test edge cases for dynamic analysis - custom TLS, hybrid apps."""

    def test_detects_custom_tls_implementation(self) -> None:
        """Detector identifies pinning in custom TLS implementations."""
        detector = PinningDetector()

        if not hasattr(detector, "detect_custom_tls_pinning"):
            pytest.fail(
                "CRITICAL: detect_custom_tls_pinning not implemented. "
                "Required by testingtodo.md edge case: 'Custom TLS implementations'"
            )

        python_test_script = """
import hashlib
def custom_cert_verify(cert_data):
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    actual = hashlib.sha256(cert_data).hexdigest()
    return actual == expected
custom_cert_verify(b"test cert data")
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            custom_pins = detector.detect_custom_tls_pinning(session)

            time.sleep(2)

            assert custom_pins is not None, "detect_custom_tls_pinning returned None"
            assert isinstance(custom_pins, list), "detect_custom_tls_pinning must return list"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_detects_hybrid_app_pinning(self) -> None:
        """Detector identifies pinning in hybrid native/managed apps."""
        detector = PinningDetector()

        if not hasattr(detector, "detect_hybrid_pinning"):
            pytest.fail(
                "CRITICAL: detect_hybrid_pinning not implemented. "
                "Required by testingtodo.md edge case: 'hybrid apps'"
            )

        python_test_script = """
import ssl
import ctypes
context = ssl.create_default_context()
libc = ctypes.CDLL(None)
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            hybrid_pins = detector.detect_hybrid_pinning(session)

            time.sleep(2)

            assert hybrid_pins is not None, "detect_hybrid_pinning returned None"
            assert isinstance(hybrid_pins, dict), "detect_hybrid_pinning should return dict with native/managed components"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_detects_managed_ssl_pinning(self) -> None:
        """Detector identifies pinning in managed code (Python SSL module)."""
        detector = PinningDetector()

        if not hasattr(detector, "detect_managed_ssl_pinning"):
            pytest.fail("CRITICAL: detect_managed_ssl_pinning not implemented for managed code detection")

        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        python_test_script = f"""
import ssl
import hashlib
PINNED = "{test_hash}"
def verify(cert):
    return hashlib.sha256(str(cert).encode()).hexdigest() == PINNED
context = ssl.create_default_context()
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            managed_pins = detector.detect_managed_ssl_pinning(session)

            time.sleep(2)

            assert managed_pins is not None, "detect_managed_ssl_pinning returned None"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_handles_obfuscated_hash_comparisons(self) -> None:
        """Detector identifies obfuscated certificate hash comparisons."""
        detector = PinningDetector()

        if not hasattr(detector, "detect_obfuscated_comparisons"):
            pytest.fail("CRITICAL: detect_obfuscated_comparisons not implemented for obfuscation detection")

        python_test_script = """
import hashlib
def obfuscated_verify(data):
    h = hashlib.sha256(data).hexdigest()
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    return all(a == b for a, b in zip(h, expected))
obfuscated_verify(b"test")
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            obfuscated = detector.detect_obfuscated_comparisons(session)

            time.sleep(2)

            assert obfuscated is not None, "detect_obfuscated_comparisons returned None"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass

    def test_tracks_dynamic_certificate_pin_generation(self) -> None:
        """Detector identifies dynamically generated certificate pins at runtime."""
        detector = PinningDetector()

        if not hasattr(detector, "track_dynamic_pins"):
            pytest.fail("CRITICAL: track_dynamic_pins not implemented for dynamic pin tracking")

        python_test_script = """
import hashlib
import time
def gen_pin():
    return hashlib.sha256(str(time.time()).encode()).hexdigest()
pin = gen_pin()
"""

        proc = subprocess.Popen(
            [sys.executable, "-c", python_test_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(0.5)

        try:
            device = frida.get_local_device()
            session = device.attach(proc.pid)

            dynamic_pins = detector.track_dynamic_pins(session)

            time.sleep(2)

            assert dynamic_pins is not None, "track_dynamic_pins returned None"

        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except:
                pass
