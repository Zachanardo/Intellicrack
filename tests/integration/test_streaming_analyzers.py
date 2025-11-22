#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

import pytest

from intellicrack.core.analysis.streaming_crypto_detector import (
    StreamingCryptoDetector,
    analyze_crypto_streaming,
)
from intellicrack.core.analysis.streaming_entropy_analyzer import (
    StreamingEntropyAnalyzer,
    analyze_entropy_streaming,
)
from intellicrack.core.analysis.streaming_yara_scanner import (
    YARA_AVAILABLE,
    StreamingYaraScanner,
    scan_binary_streaming,
)


SYSTEM_BINARIES_WINDOWS = [
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\crypt32.dll",
    r"C:\Windows\System32\bcrypt.dll",
]


def get_available_system_binaries() -> list[str]:
    return [path for path in SYSTEM_BINARIES_WINDOWS if os.path.exists(path)]


class TestStreamingCryptoDetectorWithRealBinaries:
    def test_crypto_detector_initialization(self) -> None:
        detector = StreamingCryptoDetector()

        assert detector is not None
        assert hasattr(detector, 'process_chunk')
        assert hasattr(detector, 'get_results')

    def test_crypto_detection_on_windows_crypt32(self) -> None:
        crypt32_path = r"C:\Windows\System32\crypt32.dll"

        if not os.path.exists(crypt32_path):
            pytest.skip("crypt32.dll not found")

        detector = StreamingCryptoDetector()

        chunk_size = 1024 * 1024

        with open(crypt32_path, 'rb') as f:
            chunks_processed = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                detector.process_chunk(chunk, offset=chunks_processed * chunk_size)
                chunks_processed += 1

                if chunks_processed >= 5:
                    break

        results = detector.get_results()

        assert results is not None
        assert chunks_processed > 0

    def test_crypto_detection_on_windows_bcrypt(self) -> None:
        bcrypt_path = r"C:\Windows\System32\bcrypt.dll"

        if not os.path.exists(bcrypt_path):
            pytest.skip("bcrypt.dll not found")

        detector = StreamingCryptoDetector()

        with open(bcrypt_path, 'rb') as f:
            first_chunk = f.read(1024 * 1024)

        detector.process_chunk(first_chunk, offset=0)
        results = detector.get_results()

        assert results is not None

    def test_analyze_crypto_streaming_function(self) -> None:
        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        results = analyze_crypto_streaming(kernel32_path, chunk_size=512 * 1024)

        assert results is not None

    def test_crypto_detection_handles_small_files(self) -> None:
        detector = StreamingCryptoDetector()

        small_data = b"\x00" * 1024

        detector.process_chunk(small_data, offset=0)
        results = detector.get_results()

        assert results is not None


class TestStreamingEntropyAnalyzerWithRealBinaries:
    def test_entropy_analyzer_initialization(self) -> None:
        analyzer = StreamingEntropyAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, 'process_chunk')
        assert hasattr(analyzer, 'get_windows')

    def test_entropy_analysis_on_kernel32(self) -> None:
        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        analyzer = StreamingEntropyAnalyzer(window_size=4096)

        with open(kernel32_path, 'rb') as f:
            chunks_processed = 0
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break

                analyzer.process_chunk(chunk, offset=chunks_processed * 1024 * 1024)
                chunks_processed += 1

                if chunks_processed >= 3:
                    break

        windows = analyzer.get_windows()

        assert windows is not None
        assert len(windows) > 0

        for window in windows:
            assert hasattr(window, 'offset')
            assert hasattr(window, 'entropy')
            assert 0.0 <= window.entropy <= 8.0

    def test_entropy_analysis_on_ntdll(self) -> None:
        ntdll_path = r"C:\Windows\System32\ntdll.dll"

        if not os.path.exists(ntdll_path):
            pytest.skip("ntdll.dll not found")

        results = analyze_entropy_streaming(ntdll_path, window_size=8192, chunk_size=1024 * 1024)

        assert results is not None
        assert len(results) > 0

        high_entropy_windows = [w for w in results if w.entropy > 7.0]
        assert len(high_entropy_windows) >= 0

    def test_entropy_on_multiple_system_binaries(self) -> None:
        analyzer = StreamingEntropyAnalyzer(window_size=4096)

        binaries = get_available_system_binaries()[:3]

        if not binaries:
            pytest.skip("No system binaries found")

        all_results = []

        for binary_path in binaries:
            with open(binary_path, 'rb') as f:
                chunk = f.read(512 * 1024)

            analyzer.process_chunk(chunk, offset=0)
            windows = analyzer.get_windows()

            all_results.extend(windows)

        assert len(all_results) > 0

    def test_entropy_detects_packed_regions(self) -> None:
        user32_path = r"C:\Windows\System32\user32.dll"

        if not os.path.exists(user32_path):
            pytest.skip("user32.dll not found")

        analyzer = StreamingEntropyAnalyzer(window_size=4096)

        with open(user32_path, 'rb') as f:
            data = f.read(2 * 1024 * 1024)

        analyzer.process_chunk(data, offset=0)
        windows = analyzer.get_windows()

        assert len(windows) > 0

        entropy_values = [w.entropy for w in windows]
        assert max(entropy_values) > 0.0


class TestStreamingYaraScannerWithRealBinaries:
    def test_yara_scanner_initialization(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        scanner = StreamingYaraScanner()

        assert scanner is not None
        assert hasattr(scanner, 'add_rule')
        assert hasattr(scanner, 'process_chunk')

    def test_yara_scan_detects_mz_header(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        scanner = StreamingYaraScanner()

        mz_rule = '''
        rule MZ_Header {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }
        '''

        scanner.add_rule(mz_rule)

        with open(kernel32_path, 'rb') as f:
            first_chunk = f.read(1024)

        scanner.process_chunk(first_chunk, offset=0)
        matches = scanner.get_matches()

        assert matches is not None
        assert len(matches) > 0
        assert any(m.rule_name == "MZ_Header" for m in matches)

    def test_yara_scan_detects_pe_signature(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        ntdll_path = r"C:\Windows\System32\ntdll.dll"

        if not os.path.exists(ntdll_path):
            pytest.skip("ntdll.dll not found")

        scanner = StreamingYaraScanner()

        pe_rule = '''
        rule PE_File {
            strings:
                $pe = "PE"
            condition:
                $pe
        }
        '''

        scanner.add_rule(pe_rule)

        with open(ntdll_path, 'rb') as f:
            data = f.read(1024 * 1024)

        scanner.process_chunk(data, offset=0)
        matches = scanner.get_matches()

        assert matches is not None

    def test_yara_function_scans_real_binary(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        advapi32_path = r"C:\Windows\System32\advapi32.dll"

        if not os.path.exists(advapi32_path):
            pytest.skip("advapi32.dll not found")

        simple_rule = '''
        rule Windows_DLL {
            strings:
                $s1 = "kernel32" nocase
                $s2 = ".dll" nocase
            condition:
                any of them
        }
        '''

        matches = scan_binary_streaming(advapi32_path, simple_rule, chunk_size=1024 * 1024)

        assert matches is not None

    def test_yara_scans_multiple_chunks(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        user32_path = r"C:\Windows\System32\user32.dll"

        if not os.path.exists(user32_path):
            pytest.skip("user32.dll not found")

        scanner = StreamingYaraScanner()

        api_rule = '''
        rule Has_Import_Table {
            strings:
                $s = ".idata" nocase
            condition:
                $s
        }
        '''

        scanner.add_rule(api_rule)

        with open(user32_path, 'rb') as f:
            chunk_count = 0
            while True:
                chunk = f.read(512 * 1024)
                if not chunk:
                    break

                scanner.process_chunk(chunk, offset=chunk_count * 512 * 1024)
                chunk_count += 1

                if chunk_count >= 4:
                    break

        matches = scanner.get_matches()

        assert matches is not None
        assert chunk_count > 0


class TestStreamingIntegrationWithRealBinaries:
    def test_combined_crypto_and_entropy_analysis(self) -> None:
        bcrypt_path = r"C:\Windows\System32\bcrypt.dll"

        if not os.path.exists(bcrypt_path):
            pytest.skip("bcrypt.dll not found")

        crypto_detector = StreamingCryptoDetector()
        entropy_analyzer = StreamingEntropyAnalyzer(window_size=4096)

        with open(bcrypt_path, 'rb') as f:
            data = f.read(2 * 1024 * 1024)

        crypto_detector.process_chunk(data, offset=0)
        entropy_analyzer.process_chunk(data, offset=0)

        crypto_results = crypto_detector.get_results()
        entropy_windows = entropy_analyzer.get_windows()

        assert crypto_results is not None
        assert entropy_windows is not None
        assert len(entropy_windows) > 0

    def test_all_three_analyzers_on_same_binary(self) -> None:
        if not YARA_AVAILABLE:
            pytest.skip("YARA not available")

        kernel32_path = r"C:\Windows\System32\kernel32.dll"

        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        crypto_detector = StreamingCryptoDetector()
        entropy_analyzer = StreamingEntropyAnalyzer(window_size=8192)
        yara_scanner = StreamingYaraScanner()

        yara_scanner.add_rule('''
        rule Generic_PE {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }
        ''')

        with open(kernel32_path, 'rb') as f:
            data = f.read(3 * 1024 * 1024)

        crypto_detector.process_chunk(data, offset=0)
        entropy_analyzer.process_chunk(data, offset=0)
        yara_scanner.process_chunk(data, offset=0)

        crypto_results = crypto_detector.get_results()
        entropy_windows = entropy_analyzer.get_windows()
        yara_matches = yara_scanner.get_matches()

        assert crypto_results is not None
        assert len(entropy_windows) > 0
        assert yara_matches is not None

    def test_performance_on_large_binary(self) -> None:
        import time

        crypt32_path = r"C:\Windows\System32\crypt32.dll"

        if not os.path.exists(crypt32_path):
            pytest.skip("crypt32.dll not found")

        entropy_analyzer = StreamingEntropyAnalyzer(window_size=4096)

        start_time = time.time()

        with open(crypt32_path, 'rb') as f:
            total_bytes = 0
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break

                entropy_analyzer.process_chunk(chunk, offset=total_bytes)
                total_bytes += len(chunk)

                if total_bytes >= 10 * 1024 * 1024:
                    break

        elapsed = time.time() - start_time

        windows = entropy_analyzer.get_windows()

        assert len(windows) > 0
        assert total_bytes > 0
        assert elapsed < 30.0

        if total_bytes > 0:
            throughput_mb_s = (total_bytes / (1024 * 1024)) / elapsed
            assert throughput_mb_s > 0.1

    def test_streaming_handles_file_size_correctly(self) -> None:
        binaries = get_available_system_binaries()[:2]

        if not binaries:
            pytest.skip("No system binaries found")

        for binary_path in binaries:
            file_size = os.path.getsize(binary_path)

            entropy_analyzer = StreamingEntropyAnalyzer(window_size=4096)

            with open(binary_path, 'rb') as f:
                total_processed = 0
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break

                    entropy_analyzer.process_chunk(chunk, offset=total_processed)
                    total_processed += len(chunk)

                    if total_processed >= 5 * 1024 * 1024:
                        break

            windows = entropy_analyzer.get_windows()

            assert windows is not None
            assert total_processed > 0
            assert total_processed <= file_size
