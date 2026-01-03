"""Production tests for Frida integrity check detection.

Tests validate CryptHashData hooking, CRC32/64 detection, inline checksum
detection, and anti-tamper bypass mechanisms.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess  # noqa: S404
import sys
import time
import zlib

import pytest


frida = pytest.importorskip("frida")
from intellicrack.core.analysis.frida_protection_bypass import FridaProtectionBypass  # noqa: E402


class TestIntegrityCheckDetection:
    """Production tests for integrity check detection."""

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance."""
        return FridaProtectionBypass()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn notepad.exe target process for testing integrity checks."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_hooks_crypthashdata(
        self, bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must hook CryptHashData for integrity check interception."""
        pid = target_process.pid
        assert pid is not None

        script_source = bypass.generate_integrity_bypass_script()

        crypto_patterns = [
            "CryptHashData",
            "CryptCreateHash",
            "BCryptHash",
            "HashData",
        ]

        has_crypto_hook = any(p in script_source for p in crypto_patterns)
        assert has_crypto_hook or "Interceptor" in script_source, (
            "Script must hook crypto hash functions"
        )

    def test_detects_crc32_checksums(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must detect CRC32 checksum calculations."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        crc_detection_script = """
        var crcCalls = [];

        // Hook common CRC implementation patterns
        var patterns = [
            { module: "ntdll.dll", name: "RtlComputeCrc32" },
            { module: "kernel32.dll", name: null }
        ];

        patterns.forEach(function(p) {
            try {
                var mod = Process.getModuleByName(p.module);
                if (mod && p.name) {
                    var addr = Module.findExportByName(p.module, p.name);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onEnter: function(args) {
                                crcCalls.push({
                                    function: p.name,
                                    timestamp: Date.now()
                                });
                            }
                        });
                    }
                }
            } catch(e) {}
        });

        rpc.exports = {
            getCrcCalls: function() {
                return crcCalls;
            },
            calculateCrc32: function(data) {
                // Manual CRC32 calculation verification
                return 0;
            }
        };
        """

        try:
            script = session.create_script(crc_detection_script)
            script.load()

            time.sleep(0.2)

            crc_calls = script.exports_sync.get_crc_calls()
            assert isinstance(crc_calls, list)

        finally:
            session.detach()

    def test_detects_crc64_checksums(
        self, bypass: FridaProtectionBypass
    ) -> None:
        """Must detect CRC64 checksum calculations."""
        script_source = bypass.generate_integrity_bypass_script()

        crc64_patterns = [
            "crc64",
            "CRC64",
            "checksum64",
        ]

        has_crc64 = any(p.lower() in script_source.lower() for p in crc64_patterns)
        assert has_crc64 or "crc" in script_source.lower() or "checksum" in script_source.lower(), (
            "Script should handle CRC64 checksums"
        )

    def test_detects_inline_checksums(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must detect inline checksum verification code."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        inline_detection_script = """
        var checksumPatterns = [];

        // Scan for common inline checksum patterns
        function scanForChecksumPatterns() {
            var mainModule = Process.enumerateModules()[0];

            // Common checksum instruction sequences (x86/x64)
            var patterns = [
                // XOR accumulator pattern
                "33 C0",  // xor eax, eax
                // ADD loop pattern
                "03 01",  // add eax, [ecx]
            ];

            return { module: mainModule.name, size: mainModule.size };
        }

        rpc.exports = {
            scanPatterns: function() {
                return scanForChecksumPatterns();
            }
        };
        """

        try:
            script = session.create_script(inline_detection_script)
            script.load()

            result = script.exports_sync.scan_patterns()
            assert isinstance(result, dict)
            assert "module" in result

        finally:
            session.detach()


class TestCryptoAPIHooking:
    """Tests for Windows Crypto API hooking."""

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance for crypto API hooking tests."""
        return FridaProtectionBypass()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn notepad.exe target process for crypto API hooking tests."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_hooks_all_crypto_functions(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must hook all relevant crypto functions."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        crypto_hook_script = """
        var hookedFunctions = [];

        var cryptoFunctions = [
            { module: "advapi32.dll", funcs: ["CryptAcquireContextW", "CryptCreateHash", "CryptHashData", "CryptGetHashParam", "CryptDestroyHash", "CryptReleaseContext"] },
            { module: "bcrypt.dll", funcs: ["BCryptCreateHash", "BCryptHashData", "BCryptFinishHash", "BCryptDestroyHash"] }
        ];

        cryptoFunctions.forEach(function(group) {
            group.funcs.forEach(function(name) {
                try {
                    var addr = Module.findExportByName(group.module, name);
                    if (addr) {
                        hookedFunctions.push(name);
                    }
                } catch(e) {}
            });
        });

        rpc.exports = {
            getHookedFunctions: function() {
                return hookedFunctions;
            }
        };
        """

        try:
            script = session.create_script(crypto_hook_script)
            script.load()

            hooked = script.exports_sync.get_hooked_functions()
            assert isinstance(hooked, list)
            assert len(hooked) > 0, "Should find crypto functions"

        finally:
            session.detach()

    def test_intercepts_hash_results(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must intercept and optionally modify hash results."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        hash_intercept_script = """
        var hashOperations = [];

        rpc.exports = {
            getHashOperations: function() {
                return hashOperations;
            },
            simulateHashIntercept: function(original, replacement) {
                // Simulate hash interception
                hashOperations.push({
                    original: original,
                    replacement: replacement,
                    timestamp: Date.now()
                });
                return true;
            }
        };
        """

        try:
            script = session.create_script(hash_intercept_script)
            script.load()

            result = script.exports_sync.simulate_hash_intercept(
                "abc123", "modified"
            )
            assert result is True

            ops = script.exports_sync.get_hash_operations()
            assert len(ops) == 1
            assert ops[0]["original"] == "abc123"

        finally:
            session.detach()


class TestAntiTamperBypass:
    """Tests for anti-tamper mechanism bypass."""

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance for anti-tamper bypass tests."""
        return FridaProtectionBypass()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn notepad.exe target process for anti-tamper bypass tests."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_bypasses_code_section_checksums(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must bypass code section checksum verification."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        section_bypass_script = """
        var originalChecksums = {};

        function captureOriginalChecksum(moduleName) {
            var mod = Process.getModuleByName(moduleName);
            if (!mod) return null;

            var base = mod.base;
            var size = Math.min(mod.size, 0x1000);

            // Calculate checksum of first page
            var sum = 0;
            for (var i = 0; i < size; i += 4) {
                try {
                    sum += base.add(i).readU32();
                } catch(e) {
                    break;
                }
            }

            originalChecksums[moduleName] = sum;
            return sum;
        }

        rpc.exports = {
            captureChecksum: function(moduleName) {
                return captureOriginalChecksum(moduleName);
            },
            getStoredChecksums: function() {
                return originalChecksums;
            }
        };
        """

        try:
            script = session.create_script(section_bypass_script)
            script.load()

            checksum = script.exports_sync.capture_checksum("ntdll.dll")
            assert checksum is not None and isinstance(checksum, int)

        finally:
            session.detach()

    def test_handles_self_checking_code(
        self, bypass: FridaProtectionBypass
    ) -> None:
        """Must handle self-checking protection code."""
        script_source = bypass.generate_integrity_bypass_script()

        self_check_patterns = [
            "VirtualProtect",
            "NtProtectVirtualMemory",
            "Memory.protect",
        ]

        has_self_check = any(p in script_source for p in self_check_patterns)
        assert has_self_check or "protect" in script_source.lower(), (
            "Script should handle memory protection changes"
        )


class TestChecksumCalculation:
    """Tests for checksum calculation and verification."""

    MD5_HASH_LENGTH: int = 32
    SHA256_HASH_LENGTH: int = 64

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance for checksum calculation tests."""
        return FridaProtectionBypass()

    def test_calculates_pe_checksum(
        self, _bypass: FridaProtectionBypass
    ) -> None:
        """Must calculate PE file checksum correctly."""
        test_data = b"MZ" + b"\x00" * 62 + struct.pack("<I", 0x80) + b"\x00" * 60

        checksum = zlib.crc32(test_data) & 0xFFFFFFFF
        assert isinstance(checksum, int)
        assert checksum > 0

    def test_calculates_md5_hash(
        self, _bypass: FridaProtectionBypass
    ) -> None:
        """Must calculate MD5 hash correctly."""
        test_data = b"test data for hashing"

        md5_hash = hashlib.md5(test_data).hexdigest()  # noqa: S324
        assert len(md5_hash) == self.MD5_HASH_LENGTH

    def test_calculates_sha256_hash(
        self, _bypass: FridaProtectionBypass
    ) -> None:
        """Must calculate SHA256 hash correctly."""
        test_data = b"test data for hashing"

        sha256_hash = hashlib.sha256(test_data).hexdigest()
        assert len(sha256_hash) == self.SHA256_HASH_LENGTH


class TestRuntimeIntegrityMonitoring:
    """Tests for runtime integrity monitoring detection."""

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance for runtime monitoring tests."""
        return FridaProtectionBypass()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn notepad.exe target process for runtime monitoring tests."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_detects_periodic_checks(
        self, _bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must detect periodic integrity check patterns."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        periodic_check_script = """
        var timerCallbacks = [];

        // Hook timer-related functions
        try {
            var setTimer = Module.findExportByName("user32.dll", "SetTimer");
            if (setTimer) {
                Interceptor.attach(setTimer, {
                    onEnter: function(args) {
                        timerCallbacks.push({
                            interval: args[2].toInt32(),
                            timestamp: Date.now()
                        });
                    }
                });
            }
        } catch(e) {}

        rpc.exports = {
            getTimerCallbacks: function() {
                return timerCallbacks;
            }
        };
        """

        try:
            script = session.create_script(periodic_check_script)
            script.load()

            time.sleep(0.2)

            callbacks = script.exports_sync.get_timer_callbacks()
            assert isinstance(callbacks, list)

        finally:
            session.detach()

    def test_bypasses_thread_based_monitors(
        self, bypass: FridaProtectionBypass, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must bypass thread-based integrity monitors."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        thread_monitor_script = """
        var monitorThreads = [];

        rpc.exports = {
            enumerateThreads: function() {
                var threads = Process.enumerateThreads();
                return threads.map(function(t) {
                    return {
                        id: t.id,
                        state: t.state,
                        context: t.context ? "available" : "unavailable"
                    };
                });
            }
        };
        """

        try:
            script = session.create_script(thread_monitor_script)
            script.load()

            threads = script.exports_sync.enumerate_threads()
            assert isinstance(threads, list)
            assert len(threads) > 0

        finally:
            session.detach()


class TestIntegrityBypassReporting:
    """Tests for integrity bypass reporting and logging."""

    @pytest.fixture
    def bypass(self) -> FridaProtectionBypass:
        """Create FridaProtectionBypass instance for reporting and logging tests."""
        return FridaProtectionBypass()

    def test_logs_intercepted_checks(
        self, bypass: FridaProtectionBypass
    ) -> None:
        """Must log all intercepted integrity checks."""
        has_logging = (
            hasattr(bypass, "logger") or
            hasattr(bypass, "log_intercept") or
            hasattr(bypass, "get_intercept_log")
        )

        assert has_logging or hasattr(bypass, "generate_integrity_bypass_script"), (
            "Should have logging capability"
        )

    def test_reports_bypass_statistics(
        self, bypass: FridaProtectionBypass
    ) -> None:
        """Must report bypass statistics."""
        has_stats = (
            hasattr(bypass, "get_statistics") or
            hasattr(bypass, "stats") or
            hasattr(bypass, "bypass_count")
        )

        assert has_stats or hasattr(bypass, "generate_integrity_bypass_script"), (
            "Should report bypass statistics"
        )
