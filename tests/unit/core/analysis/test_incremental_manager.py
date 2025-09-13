"""
Comprehensive test suite for incremental_manager.py module.

This test suite validates the production-ready functionality of the IncrementalAnalysisManager
and secure pickle functions through specification-driven, black-box testing methodology.
Tests are designed to validate genuine binary analysis capabilities and fail for placeholder implementations.
"""

import unittest
import tempfile
import shutil
import os
import hashlib
import pickle
import time
import threading
import gzip
from pathlib import Path

from intellicrack.core.analysis.incremental_manager import (
    IncrementalAnalysisManager,
    secure_pickle_dump,
    secure_pickle_load,
    RestrictedUnpickler,
    run_analysis_manager,
    PICKLE_SECURITY_KEY
)


class TestSecurePickleFunctions(unittest.TestCase):
    """Test secure pickle serialization functions with production-ready security validation."""

    def setUp(self):
        """Set up test fixtures with real data structures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test_pickle.pkl")

        # Real analysis data structures that should be serializable
        self.test_analysis_data = {
            "file_hash": "sha256:abc123def456",
            "timestamp": time.time(),
            "analysis_results": {
                "basic_info": {
                    "file_size": 12345,
                    "entry_point": "0x401000",
                    "architecture": "x86_64",
                    "sections": [".text", ".data", ".rdata"]
                },
                "entropy_analysis": {
                    "overall_entropy": 7.2,
                    "section_entropy": {".text": 6.8, ".data": 2.1, ".rdata": 5.5}
                },
                "strings": ["This program cannot be run", "kernel32.dll", "GetProcAddress"],
                "headers": {
                    "pe_characteristics": 0x0102,
                    "image_base": 0x400000,
                    "section_alignment": 0x1000
                }
            },
            "cache_metadata": {
                "version": "1.0",
                "analysis_type": "comprehensive",
                "created_by": "IncrementalAnalysisManager"
            }
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_secure_pickle_dump_creates_valid_encrypted_file(self):
        """Test that secure_pickle_dump creates properly encrypted files with integrity checks."""
        # Test with complex analysis data
        secure_pickle_dump(self.test_analysis_data, self.test_file)

        # Verify file was created and has content
        self.assertTrue(os.path.exists(self.test_file))
        self.assertGreater(os.path.getsize(self.test_file), 0)

        # Verify file content is not readable as plain pickle (security requirement)
        with self.assertRaises((pickle.UnpicklingError, UnicodeDecodeError, ValueError)):
            with open(self.test_file, 'rb') as f:
                pickle.load(f)

    def test_secure_pickle_load_decrypts_and_validates_data(self):
        """Test that secure_pickle_load properly decrypts and validates serialized data."""
        # Store data securely
        secure_pickle_dump(self.test_analysis_data, self.test_file)

        # Load and verify data integrity
        loaded_data = secure_pickle_load(self.test_file)

        # Validate complete data structure
        self.assertEqual(loaded_data["file_hash"], self.test_analysis_data["file_hash"])
        self.assertEqual(loaded_data["analysis_results"]["basic_info"]["file_size"], 12345)
        self.assertEqual(loaded_data["analysis_results"]["entropy_analysis"]["overall_entropy"], 7.2)
        self.assertListEqual(loaded_data["analysis_results"]["strings"],
                           ["This program cannot be run", "kernel32.dll", "GetProcAddress"])

    def test_secure_pickle_prevents_code_injection_attacks(self):
        """Test that secure pickle functions prevent malicious code execution."""
        # Create malicious payload that would execute code if not properly restricted
        class MaliciousClass:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'SECURITY_BREACH' > malicious_output.txt",))

        malicious_data = {"payload": MaliciousClass()}

        # Secure dump should handle this safely
        secure_pickle_dump(malicious_data, self.test_file)

        # Loading should either fail safely or strip malicious content
        try:
            loaded_data = secure_pickle_load(self.test_file)
            # If it loads, verify no code execution occurred
            self.assertFalse(os.path.exists("malicious_output.txt"))
        except (pickle.PicklingError, AttributeError, ImportError):
            # Expected behavior for security-restricted unpickling
            pass

    def test_restricted_unpickler_blocks_dangerous_modules(self):
        """Test that RestrictedUnpickler prevents loading of dangerous modules."""
        unpickler = RestrictedUnpickler(None)

        # Should block system modules that could be exploited
        dangerous_modules = ['os', 'subprocess', 'sys', '__builtin__', 'builtins']

        for module in dangerous_modules:
            with self.assertRaises((pickle.UnpicklingError, ImportError, AttributeError)):
                unpickler.find_class(module, 'system')

    def test_secure_pickle_handles_large_analysis_datasets(self):
        """Test that secure pickle functions handle large analysis datasets efficiently."""
        # Create large analysis dataset simulating real binary analysis
        large_dataset = {
            "strings": ["string_{}".format(i) for i in range(10000)],
            "disassembly": [
                {"address": hex(0x401000 + i*4), "instruction": f"mov eax, {i}"}
                for i in range(5000)
            ],
            "control_flow": {
                f"block_{i}": {
                    "start": hex(0x401000 + i*100),
                    "end": hex(0x401000 + i*100 + 50),
                    "successors": [f"block_{i+1}", f"block_{i+2}"] if i < 4998 else []
                }
                for i in range(5000)
            }
        }

        # Should handle large datasets without errors
        secure_pickle_dump(large_dataset, self.test_file)
        loaded_dataset = secure_pickle_load(self.test_file)

        # Verify data integrity on large dataset
        self.assertEqual(len(loaded_dataset["strings"]), 10000)
        self.assertEqual(len(loaded_dataset["disassembly"]), 5000)
        self.assertEqual(len(loaded_dataset["control_flow"]), 5000)
        self.assertEqual(loaded_dataset["strings"][9999], "string_9999")


class TestIncrementalAnalysisManager(unittest.TestCase):
    """
    Comprehensive test suite for IncrementalAnalysisManager class.

    These tests validate production-ready incremental binary analysis capabilities
    including sophisticated caching, hash validation, and performance optimization.
    """

    def setUp(self):
        """Set up test fixtures with real binary samples and cache directories."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, "analysis_cache")

        # Create test binary files with realistic content
        self.create_test_binary_samples()

        # Initialize manager with production configuration
        self.config = {
            'analysis': {
                'cache_dir': self.cache_dir,
                'chunk_size': 8192,
                'max_cache_size': 100 * 1024 * 1024,  # 100MB
                'enable_compression': True,
                'cache_expiry_days': 30
            }
        }

        self.manager = IncrementalAnalysisManager(self.config)

    def create_test_binary_samples(self):
        """Create realistic test binary samples for analysis testing."""
        # Simple PE-like binary structure
        self.test_binary1 = os.path.join(self.temp_dir, "test_binary1.exe")
        pe_header = b"MZ\x90\x00" + b"\x00" * 56 + b"PE\x00\x00"
        pe_content = pe_header + b"\x4C\x01" + b"\x00" * 1000 + b"This program cannot be run in DOS mode.\r\n\r\n$"
        pe_content += b"\x00" * (4096 - len(pe_content))
        pe_content += b"\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64"  # "Hello World"

        with open(self.test_binary1, 'wb') as f:
            f.write(pe_content)

        # ELF-like binary structure
        self.test_binary2 = os.path.join(self.temp_dir, "test_binary2.elf")
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        elf_content = elf_header + b"\x02\x00\x3E\x00" + b"\x00" * 2000
        elf_content += b"kernel32.dll\x00GetProcAddress\x00LoadLibraryA\x00"

        with open(self.test_binary2, 'wb') as f:
            f.write(elf_content)

        # Packed binary with high entropy
        self.test_binary_packed = os.path.join(self.temp_dir, "packed_binary.exe")
        packed_content = pe_header + bytes([i % 256 for i in range(8192)])  # High entropy content

        with open(self.test_binary_packed, 'wb') as f:
            f.write(packed_content)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manager_initialization_creates_cache_infrastructure(self):
        """Test that manager initialization creates proper cache infrastructure."""
        # Verify cache directory creation
        self.assertTrue(os.path.exists(self.cache_dir))

        # Verify configuration is properly loaded
        self.assertEqual(self.manager.cache_dir, self.cache_dir)
        self.assertEqual(self.manager.chunk_size, 8192)
        self.assertEqual(self.manager.max_cache_size, 100 * 1024 * 1024)
        self.assertTrue(self.manager.enable_compression)

        # Verify internal data structures are initialized
        self.assertIsInstance(self.manager.analysis_cache, dict)
        self.assertIsInstance(self.manager.file_hashes, dict)
        self.assertEqual(self.manager.cache_hits, 0)
        self.assertEqual(self.manager.cache_misses, 0)

    def test_set_binary_calculates_secure_hash_and_validates_file(self):
        """Test that set_binary properly calculates file hashes and validates binary files."""
        # Set binary file
        result = self.manager.set_binary(self.test_binary1)
        self.assertTrue(result)

        # Verify current binary is set
        self.assertEqual(self.manager.current_binary, self.test_binary1)
        self.assertIsNotNone(self.manager.current_binary_hash)

        # Verify hash is cryptographically secure (SHA-256)
        self.assertEqual(len(self.manager.current_binary_hash), 64)  # SHA-256 hex length

        # Verify hash consistency on re-calculation
        hash1 = self.manager.current_binary_hash
        self.manager.set_binary(self.test_binary1)
        hash2 = self.manager.current_binary_hash
        self.assertEqual(hash1, hash2)

        # Verify different files produce different hashes
        self.manager.set_binary(self.test_binary2)
        hash3 = self.manager.current_binary_hash
        self.assertNotEqual(hash1, hash3)

    def test_set_binary_rejects_invalid_files(self):
        """Test that set_binary properly rejects non-existent or invalid files."""
        # Test non-existent file
        result = self.manager.set_binary("non_existent_file.exe")
        self.assertFalse(result)
        self.assertIsNone(self.manager.current_binary)

        # Test directory instead of file
        result = self.manager.set_binary(self.temp_dir)
        self.assertFalse(result)

        # Test empty file
        empty_file = os.path.join(self.temp_dir, "empty.exe")
        with open(empty_file, 'wb') as f:
            pass
        result = self.manager.set_binary(empty_file)
        self.assertFalse(result)

    def test_cache_analysis_stores_and_retrieves_complex_results(self):
        """Test that cache_analysis stores complete analysis results with metadata."""
        self.manager.set_binary(self.test_binary1)

        # Create comprehensive analysis results
        analysis_results = {
            "basic_analysis": {
                "file_format": "PE",
                "architecture": "x86_64",
                "entry_point": "0x401000",
                "file_size": os.path.getsize(self.test_binary1),
                "sections": [
                    {"name": ".text", "virtual_address": "0x401000", "size": 4096, "characteristics": 0x60000020},
                    {"name": ".data", "virtual_address": "0x402000", "size": 1024, "characteristics": 0xC0000040}
                ]
            },
            "entropy_analysis": {
                "overall_entropy": 6.8,
                "section_entropy": {".text": 7.2, ".data": 2.1},
                "packed_probability": 0.15
            },
            "strings_analysis": {
                "ascii_strings": ["This program cannot be run", "Hello World"],
                "unicode_strings": [],
                "interesting_strings": ["GetProcAddress", "LoadLibrary"]
            },
            "headers_analysis": {
                "pe_header": {
                    "machine_type": 0x8664,
                    "number_of_sections": 2,
                    "time_date_stamp": int(time.time()),
                    "characteristics": 0x0102
                }
            }
        }

        # Cache the analysis
        cache_success = self.manager.cache_analysis("comprehensive", analysis_results)
        self.assertTrue(cache_success)

        # Retrieve and verify cached analysis
        cached_results = self.manager.get_cached_analysis("comprehensive")
        self.assertIsNotNone(cached_results)

        # Verify complete data structure integrity
        self.assertEqual(cached_results["basic_analysis"]["file_format"], "PE")
        self.assertEqual(cached_results["basic_analysis"]["architecture"], "x86_64")
        self.assertEqual(len(cached_results["basic_analysis"]["sections"]), 2)
        self.assertEqual(cached_results["entropy_analysis"]["overall_entropy"], 6.8)
        self.assertIn("This program cannot be run", cached_results["strings_analysis"]["ascii_strings"])
        self.assertEqual(cached_results["headers_analysis"]["pe_header"]["machine_type"], 0x8664)

    def test_cache_invalidation_on_file_changes(self):
        """Test that cache is properly invalidated when binary files change."""
        self.manager.set_binary(self.test_binary1)

        # Cache initial analysis
        initial_results = {"analysis": "initial_data", "timestamp": time.time()}
        self.manager.cache_analysis("basic", initial_results)

        # Verify cache hit
        cached = self.manager.get_cached_analysis("basic")
        self.assertEqual(cached["analysis"], "initial_data")

        # Modify the binary file
        with open(self.test_binary1, 'ab') as f:
            f.write(b"MODIFIED_CONTENT")

        # Reset binary (recalculate hash)
        self.manager.set_binary(self.test_binary1)

        # Cache should be invalidated for modified file
        cached_after_modification = self.manager.get_cached_analysis("basic")
        self.assertIsNone(cached_after_modification)

    def test_analyze_incremental_performs_comprehensive_analysis(self):
        """Test that analyze_incremental performs sophisticated binary analysis with caching."""
        self.manager.set_binary(self.test_binary1)

        # First analysis should be comprehensive
        results = self.manager.analyze_incremental(["basic", "entropy", "strings", "headers"])

        # Verify comprehensive analysis results
        self.assertIsNotNone(results)
        self.assertIn("basic_analysis", results)
        self.assertIn("entropy_analysis", results)
        self.assertIn("strings_analysis", results)
        self.assertIn("headers_analysis", results)

        # Verify basic analysis detects file format
        basic = results["basic_analysis"]
        self.assertIsNotNone(basic.get("file_format"))
        self.assertIsNotNone(basic.get("file_size"))

        # Verify entropy analysis calculates meaningful values
        entropy = results["entropy_analysis"]
        self.assertIsInstance(entropy.get("overall_entropy"), (int, float))
        self.assertGreater(entropy["overall_entropy"], 0)
        self.assertLess(entropy["overall_entropy"], 8)

        # Verify strings extraction finds real content
        strings = results["strings_analysis"]
        self.assertIsInstance(strings.get("strings"), list)
        self.assertGreater(len(strings["strings"]), 0)

        # Verify headers analysis extracts format-specific data
        headers = results["headers_analysis"]
        self.assertIsNotNone(headers)

    def test_analyze_incremental_utilizes_cache_for_performance(self):
        """Test that incremental analysis demonstrates performance improvement through caching."""
        self.manager.set_binary(self.test_binary1)

        # First analysis (cache miss)
        start_time = time.time()
        results1 = self.manager.analyze_incremental(["basic", "entropy"])
        first_duration = time.time() - start_time

        # Second analysis of same file (should use cache)
        start_time = time.time()
        results2 = self.manager.analyze_incremental(["basic", "entropy"])
        second_duration = time.time() - start_time

        # Verify results are identical
        self.assertEqual(results1, results2)

        # Verify cache statistics show hits
        stats = self.manager.get_cache_stats()
        self.assertGreater(stats["cache_hits"], 0)

        # Cache should provide measurable performance improvement
        self.assertLess(second_duration, first_duration * 0.8)  # At least 20% improvement

    def test_entropy_analysis_detects_packing_accurately(self):
        """Test that entropy analysis accurately detects packed/encrypted binaries."""
        # Test normal binary
        self.manager.set_binary(self.test_binary1)
        results_normal = self.manager.analyze_incremental(["entropy"])
        entropy_normal = results_normal["entropy_analysis"]["overall_entropy"]

        # Test packed binary (high entropy)
        self.manager.set_binary(self.test_binary_packed)
        results_packed = self.manager.analyze_incremental(["entropy"])
        entropy_packed = results_packed["entropy_analysis"]["overall_entropy"]

        # Packed binary should have significantly higher entropy
        self.assertGreater(entropy_packed, entropy_normal)
        self.assertGreater(entropy_packed, 7.0)  # Packed binaries typically > 7.0 entropy

        # Verify packing probability calculation
        packed_prob = results_packed["entropy_analysis"].get("packed_probability", 0)
        self.assertGreater(packed_prob, 0.7)  # High probability for packed binary

    def test_cache_cleanup_removes_expired_entries(self):
        """Test that cache cleanup removes expired and oversized entries."""
        self.manager.set_binary(self.test_binary1)

        # Create multiple cached analyses
        for i in range(5):
            analysis_type = f"test_analysis_{i}"
            results = {"data": f"analysis_{i}", "size": 1024 * 1024}  # 1MB each
            self.manager.cache_analysis(analysis_type, results)

        # Verify entries are cached
        stats_before = self.manager.get_cache_stats()
        self.assertGreaterEqual(stats_before["total_entries"], 5)

        # Perform cleanup
        cleaned_entries = self.manager.cleanup_old_cache(max_age_days=0)  # Immediate cleanup
        self.assertGreater(cleaned_entries, 0)

        # Verify cleanup effectiveness
        stats_after = self.manager.get_cache_stats()
        self.assertLess(stats_after["total_entries"], stats_before["total_entries"])

    def test_cache_stats_provide_comprehensive_metrics(self):
        """Test that get_cache_stats provides detailed cache performance metrics."""
        self.manager.set_binary(self.test_binary1)

        # Generate some cache activity
        self.manager.analyze_incremental(["basic"])  # Cache miss
        self.manager.analyze_incremental(["basic"])  # Cache hit

        stats = self.manager.get_cache_stats()

        # Verify comprehensive statistics
        required_stats = ["cache_hits", "cache_misses", "hit_ratio", "total_entries", "cache_size_mb"]
        for stat in required_stats:
            self.assertIn(stat, stats)

        # Verify meaningful values
        self.assertGreaterEqual(stats["cache_hits"], 1)
        self.assertGreaterEqual(stats["cache_misses"], 1)
        self.assertIsInstance(stats["hit_ratio"], float)
        self.assertGreaterEqual(stats["hit_ratio"], 0.0)
        self.assertLessEqual(stats["hit_ratio"], 1.0)

    def test_concurrent_cache_access_thread_safety(self):
        """Test that cache operations are thread-safe under concurrent access."""
        self.manager.set_binary(self.test_binary1)

        results = []
        errors = []

        def concurrent_analysis(thread_id):
            try:
                result = self.manager.analyze_incremental(["basic"])
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))

        # Run concurrent analysis threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=concurrent_analysis, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")

        # Verify all threads got consistent results
        self.assertEqual(len(results), 10)
        first_result = results[0][1]
        for thread_id, result in results:
            self.assertEqual(result, first_result)

    def test_large_binary_chunked_processing(self):
        """Test that large binaries are processed efficiently through chunking."""
        # Create large binary file
        large_binary = os.path.join(self.temp_dir, "large_binary.exe")
        large_size = 50 * 1024 * 1024  # 50MB

        with open(large_binary, 'wb') as f:
            # Write data in chunks to simulate large binary
            chunk_data = b"A" * self.manager.chunk_size
            for i in range(large_size // self.manager.chunk_size):
                f.write(chunk_data)

        # Analyze large binary
        self.manager.set_binary(large_binary)

        start_time = time.time()
        results = self.manager.analyze_incremental(["basic"])
        processing_time = time.time() - start_time

        # Verify analysis completed successfully
        self.assertIsNotNone(results)
        self.assertIn("basic_analysis", results)

        # Verify efficient processing (should complete within reasonable time)
        self.assertLess(processing_time, 30.0)  # Should complete within 30 seconds

    def test_error_handling_for_corrupted_cache(self):
        """Test that corrupted cache files are handled gracefully."""
        self.manager.set_binary(self.test_binary1)

        # Create analysis and cache it
        results = {"test": "data"}
        self.manager.cache_analysis("test_type", results)

        # Corrupt the cache file
        cache_files = [f for f in os.listdir(self.cache_dir) if f.endswith('.cache')]
        if cache_files:
            cache_file_path = os.path.join(self.cache_dir, cache_files[0])
            with open(cache_file_path, 'wb') as f:
                f.write(b"CORRUPTED_DATA_INVALID_PICKLE")

        # Attempting to load corrupted cache should handle gracefully
        try:
            cached_results = self.manager.get_cached_analysis("test_type")
            # Should either return None or handle corruption gracefully
            self.assertIsNone(cached_results)
        except Exception as e:
            self.fail(f"Corrupted cache caused unhandled exception: {e}")

    def test_cross_platform_path_handling(self):
        """Test that cache management works correctly across different path formats."""
        # Test with different path separators and formats
        test_paths = [
            self.test_binary1,
            self.test_binary1.replace('\\', '/'),  # Unix-style paths
            os.path.abspath(self.test_binary1),     # Absolute paths
        ]

        for test_path in test_paths:
            if os.path.exists(test_path):
                success = self.manager.set_binary(test_path)
                self.assertTrue(success, f"Failed to set binary with path: {test_path}")

                # Verify hash calculation is consistent regardless of path format
                hash_value = self.manager.current_binary_hash
                self.assertIsNotNone(hash_value)
                self.assertEqual(len(hash_value), 64)


class TestIncrementalAnalysisIntegration(unittest.TestCase):
    """
    Integration tests that validate the complete incremental analysis workflow
    with real binary samples and complex analysis scenarios.
    """

    def setUp(self):
        """Set up integration test environment with realistic binary samples."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, "integration_cache")

        # Create realistic PE binary sample
        self.create_realistic_pe_sample()

        self.config = {
            'analysis': {
                'cache_dir': self.cache_dir,
                'chunk_size': 4096,
                'max_cache_size': 50 * 1024 * 1024,
                'enable_compression': True,
                'cache_expiry_days': 7
            }
        }

        self.manager = IncrementalAnalysisManager(self.config)

    def create_realistic_pe_sample(self):
        """Create a realistic PE binary sample for integration testing."""
        self.pe_sample = os.path.join(self.temp_dir, "realistic_sample.exe")

        # DOS header
        dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        dos_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        dos_header += b"\x00" * 32 + b"\x80\x00\x00\x00"  # e_lfanew = 0x80

        # DOS stub
        dos_stub = b"This program cannot be run in DOS mode.\r\n\r\n$" + b"\x00" * 7

        # Align to PE header position
        pe_offset = 0x80
        padding = b"\x00" * (pe_offset - len(dos_header) - len(dos_stub))

        # PE header
        pe_header = b"PE\x00\x00"  # PE signature
        pe_header += b"\x4c\x01"    # Machine (i386)
        pe_header += b"\x03\x00"    # NumberOfSections
        pe_header += b"\x00" * 16   # Other fields
        pe_header += b"\xe0\x00"    # SizeOfOptionalHeader
        pe_header += b"\x02\x01"    # Characteristics

        # Optional header
        opt_header = b"\x0b\x01"    # Magic (PE32)
        opt_header += b"\x00" * 220 # Simplified optional header

        # Section headers
        text_section = b".text\x00\x00\x00"  # Name
        text_section += b"\x00\x10\x00\x00"  # VirtualSize
        text_section += b"\x00\x10\x00\x00"  # VirtualAddress
        text_section += b"\x00\x10\x00\x00"  # SizeOfRawData
        text_section += b"\x00\x04\x00\x00"  # PointerToRawData
        text_section += b"\x00" * 12         # Other fields
        text_section += b"\x20\x00\x00\x60"  # Characteristics

        data_section = b".data\x00\x00\x00"  # Name
        data_section += b"\x00\x10\x00\x00"  # VirtualSize
        data_section += b"\x00\x20\x00\x00"  # VirtualAddress
        data_section += b"\x00\x10\x00\x00"  # SizeOfRawData
        data_section += b"\x00\x14\x00\x00"  # PointerToRawData
        data_section += b"\x00" * 12         # Other fields
        data_section += b"\x40\x00\x00\xC0"  # Characteristics

        rdata_section = b".rdata\x00\x00"    # Name
        rdata_section += b"\x00\x10\x00\x00" # VirtualSize
        rdata_section += b"\x00\x30\x00\x00" # VirtualAddress
        rdata_section += b"\x00\x10\x00\x00" # SizeOfRawData
        rdata_section += b"\x00\x24\x00\x00" # PointerToRawData
        rdata_section += b"\x00" * 12        # Other fields
        rdata_section += b"\x40\x00\x00\x40" # Characteristics

        # Construct header
        header = dos_header + dos_stub + padding + pe_header + opt_header
        header += text_section + data_section + rdata_section

        # Pad to first section
        header += b"\x00" * (0x400 - len(header))

        # .text section content (some realistic x86 code)
        text_content = b"\x55\x8b\xec"  # push ebp; mov ebp, esp
        text_content += b"\x83\xec\x40"  # sub esp, 0x40
        text_content += b"\x68\x00\x30\x40\x00"  # push offset "Hello World"
        text_content += b"\xff\x15\x00\x20\x40\x00"  # call [printf]
        text_content += b"\x33\xc0"  # xor eax, eax
        text_content += b"\xc9\xc3"  # leave; ret
        text_content += b"\x00" * (0x1000 - len(text_content))

        # .data section content
        data_content = b"Hello World!\x00" + b"\x00" * (0x1000 - 13)

        # .rdata section content (import table-like data)
        rdata_content = b"kernel32.dll\x00GetStdHandle\x00WriteFile\x00"
        rdata_content += b"\x00" * (0x1000 - len(rdata_content))

        # Write complete PE file
        with open(self.pe_sample, 'wb') as f:
            f.write(header + text_content + data_content + rdata_content)

    def tearDown(self):
        """Clean up integration test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_analysis_workflow_with_caching(self):
        """Test complete analysis workflow from binary loading to cached retrieval."""
        # Set binary and perform comprehensive analysis
        self.assertTrue(self.manager.set_binary(self.pe_sample))

        # First comprehensive analysis
        analysis_types = ["basic", "entropy", "strings", "headers"]
        results = self.manager.analyze_incremental(analysis_types)

        # Verify comprehensive results structure
        self.assertIsNotNone(results)
        for analysis_type in analysis_types:
            self.assertIn(f"{analysis_type}_analysis", results)

        # Verify basic analysis detected PE format correctly
        basic = results["basic_analysis"]
        self.assertIn("file_format", basic)
        self.assertTrue(basic["file_size"] > 0)

        # Verify entropy analysis calculated reasonable values
        entropy = results["entropy_analysis"]
        self.assertIsInstance(entropy["overall_entropy"], (int, float))
        self.assertGreater(entropy["overall_entropy"], 1.0)
        self.assertLess(entropy["overall_entropy"], 8.0)

        # Verify strings extraction found embedded strings
        strings = results["strings_analysis"]
        self.assertIsInstance(strings["strings"], list)
        found_strings = [s.lower() for s in strings["strings"]]
        expected_strings = ["hello world", "kernel32.dll", "getstdhandle"]
        for expected in expected_strings:
            self.assertTrue(any(expected in s for s in found_strings),
                          f"Expected string '{expected}' not found in {found_strings}")

        # Verify headers analysis extracted PE-specific data
        headers = results["headers_analysis"]
        self.assertIsNotNone(headers)

        # Test cache performance on subsequent analysis
        start_time = time.time()
        cached_results = self.manager.analyze_incremental(analysis_types)
        cache_time = time.time() - start_time

        # Cached results should be identical and faster
        self.assertEqual(results, cached_results)
        self.assertLess(cache_time, 0.1)  # Should be very fast from cache

        # Verify cache statistics
        stats = self.manager.get_cache_stats()
        self.assertGreater(stats["cache_hits"], 0)
        self.assertGreater(stats["hit_ratio"], 0.5)

    def test_progressive_analysis_with_selective_caching(self):
        """Test progressive analysis where different analysis types are cached independently."""
        self.manager.set_binary(self.pe_sample)

        # Perform analyses progressively
        basic_results = self.manager.analyze_incremental(["basic"])
        entropy_results = self.manager.analyze_incremental(["entropy"])
        strings_results = self.manager.analyze_incremental(["strings"])

        # Each analysis should be cached independently
        combined_results = self.manager.analyze_incremental(["basic", "entropy", "strings"])

        # Verify combined results include all components
        self.assertIn("basic_analysis", combined_results)
        self.assertIn("entropy_analysis", combined_results)
        self.assertIn("strings_analysis", combined_results)

        # Verify individual results match combined results
        self.assertEqual(basic_results["basic_analysis"], combined_results["basic_analysis"])
        self.assertEqual(entropy_results["entropy_analysis"], combined_results["entropy_analysis"])
        self.assertEqual(strings_results["strings_analysis"], combined_results["strings_analysis"])

        # Cache should show multiple hits
        stats = self.manager.get_cache_stats()
        self.assertGreaterEqual(stats["cache_hits"], 3)


class TestRunAnalysisManager(unittest.TestCase):
    """
    Test suite for run_analysis_manager orchestration function.

    Validates the high-level analysis orchestration functionality that coordinates
    incremental analysis workflows for production security research scenarios.
    """

    def setUp(self):
        """Set up test fixtures for analysis manager orchestration testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, "orchestration_cache")

        # Create comprehensive test binary
        self.test_binary = os.path.join(self.temp_dir, "orchestration_test.exe")
        self.create_comprehensive_test_binary()

        # Production-ready configuration
        self.config = {
            'analysis': {
                'cache_dir': self.cache_dir,
                'chunk_size': 4096,
                'max_cache_size': 100 * 1024 * 1024,
                'enable_compression': True,
                'cache_expiry_days': 14,
                'enable_gui': False,
                'concurrent_analysis': True,
                'analysis_timeout': 300
            }
        }

        # Analysis parameters for comprehensive security research
        self.analysis_params = {
            'binary_path': self.test_binary,
            'analysis_types': ['basic', 'entropy', 'strings', 'headers', 'advanced'],
            'output_format': 'detailed',
            'enable_caching': True,
            'force_refresh': False,
            'security_analysis': True,
            'performance_profiling': True
        }

    def create_comprehensive_test_binary(self):
        """Create a comprehensive test binary for orchestration testing."""
        # Multi-section PE with realistic security research scenarios
        dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        dos_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        dos_header += b"\x00" * 32 + b"\x80\x00\x00\x00"

        # Realistic DOS stub
        dos_stub = b"This program cannot be run in DOS mode.\r\n\r\n$" + b"\x00" * 7

        # PE header with security-relevant characteristics
        pe_header = b"PE\x00\x00\x4c\x01\x04\x00"  # PE32, i386, 4 sections
        pe_header += int(time.time()).to_bytes(4, 'little')  # Current timestamp
        pe_header += b"\x00" * 12  # Symbol table info
        pe_header += b"\xe0\x00"   # Size of optional header
        pe_header += b"\x02\x01"   # Characteristics: executable, no relocations

        # Optional header with security implications
        opt_header = b"\x0b\x01\x01\x00"  # PE32 magic + linker version
        opt_header += b"\x00\x20\x00\x00"  # Size of code
        opt_header += b"\x00\x10\x00\x00"  # Size of initialized data
        opt_header += b"\x00\x00\x00\x00"  # Size of uninitialized data
        opt_header += b"\x00\x10\x40\x00"  # Entry point (0x401000)
        opt_header += b"\x00\x10\x40\x00"  # Base of code
        opt_header += b"\x00\x20\x40\x00"  # Base of data
        opt_header += b"\x00\x00\x40\x00"  # Image base
        opt_header += b"\x00\x10\x00\x00"  # Section alignment
        opt_header += b"\x00\x02\x00\x00"  # File alignment
        opt_header += b"\x04\x00\x04\x00"  # OS/Subsystem version
        opt_header += b"\x00\x00\x00\x00"  # Image version
        opt_header += b"\x04\x00"          # Subsystem version
        opt_header += b"\x00\x00"          # Reserved
        opt_header += b"\x00\x60\x40\x00"  # Size of image
        opt_header += b"\x00\x04\x00\x00"  # Size of headers
        opt_header += b"\x00\x00\x00\x00"  # Checksum
        opt_header += b"\x02\x00"          # Subsystem (GUI)
        opt_header += b"\x00\x00"          # DLL characteristics
        opt_header += (b"\x00\x10\x00\x00" * 4)  # Stack/heap sizes
        opt_header += b"\x00\x00\x00\x00"  # Loader flags
        opt_header += b"\x10\x00\x00\x00"  # Number of directories
        opt_header += b"\x00" * 128        # Data directories

        # Section headers for comprehensive analysis
        sections = []

        # .text section (executable code)
        text_header = b".text\x00\x00\x00"
        text_header += b"\x00\x20\x00\x00"  # Virtual size
        text_header += b"\x00\x10\x40\x00"  # Virtual address
        text_header += b"\x00\x20\x00\x00"  # Size of raw data
        text_header += b"\x00\x04\x00\x00"  # File pointer to raw data
        text_header += b"\x00" * 12         # Relocations/line numbers
        text_header += b"\x20\x00\x00\x60"  # Characteristics (CODE|EXECUTE|READ)
        sections.append(text_header)

        # .data section (initialized data)
        data_header = b".data\x00\x00\x00"
        data_header += b"\x00\x10\x00\x00"  # Virtual size
        data_header += b"\x00\x30\x40\x00"  # Virtual address
        data_header += b"\x00\x10\x00\x00"  # Size of raw data
        data_header += b"\x00\x24\x00\x00"  # File pointer to raw data
        data_header += b"\x00" * 12         # Relocations/line numbers
        data_header += b"\x40\x00\x00\xC0"  # Characteristics (INITIALIZED_DATA|READ|WRITE)
        sections.append(data_header)

        # .rdata section (read-only data, imports)
        rdata_header = b".rdata\x00\x00"
        rdata_header += b"\x00\x10\x00\x00"  # Virtual size
        rdata_header += b"\x00\x40\x40\x00"  # Virtual address
        rdata_header += b"\x00\x10\x00\x00"  # Size of raw data
        rdata_header += b"\x00\x34\x00\x00"  # File pointer to raw data
        rdata_header += b"\x00" * 12         # Relocations/line numbers
        rdata_header += b"\x40\x00\x00\x40"  # Characteristics (INITIALIZED_DATA|READ)
        sections.append(rdata_header)

        # .rsrc section (resources)
        rsrc_header = b".rsrc\x00\x00\x00"
        rsrc_header += b"\x00\x10\x00\x00"  # Virtual size
        rsrc_header += b"\x00\x50\x40\x00"  # Virtual address
        rsrc_header += b"\x00\x10\x00\x00"  # Size of raw data
        rsrc_header += b"\x00\x44\x00\x00"  # File pointer to raw data
        rsrc_header += b"\x00" * 12         # Relocations/line numbers
        rsrc_header += b"\x40\x00\x00\x40"  # Characteristics (INITIALIZED_DATA|READ)
        sections.append(rsrc_header)

        # Construct header
        header = dos_header + dos_stub
        header += b"\x00" * (0x80 - len(header))  # Pad to PE header
        header += pe_header + opt_header
        for section in sections:
            header += section
        header += b"\x00" * (0x400 - len(header))  # Pad to first section

        # .text section content (realistic x86 assembly for security analysis)
        text_content = b""
        # Standard function prologue
        text_content += b"\x55\x8B\xEC"                    # push ebp; mov ebp, esp
        text_content += b"\x83\xEC\x40"                    # sub esp, 0x40
        # API calls (common in malware analysis scenarios)
        text_content += b"\x68\x00\x40\x40\x00"            # push offset aKernel32Dll
        text_content += b"\xFF\x15\x10\x40\x40\x00"        # call ds:LoadLibraryA
        text_content += b"\x68\x10\x40\x40\x00"            # push offset aGetprocaddres
        text_content += b"\x50"                            # push eax
        text_content += b"\xFF\x15\x14\x40\x40\x00"        # call ds:GetProcAddress
        # String manipulation (encryption/obfuscation detection)
        text_content += b"\x8B\x45\x08"                    # mov eax, [ebp+arg_0]
        text_content += b"\x80\x30\x42"                    # xor byte ptr [eax], 42h
        text_content += b"\x40"                            # inc eax
        text_content += b"\x80\x38\x00"                    # cmp byte ptr [eax], 0
        text_content += b"\x75\xF7"                        # jnz short loop
        # Function epilogue
        text_content += b"\x33\xC0"                        # xor eax, eax
        text_content += b"\xC9\xC3"                        # leave; ret
        # Pad section
        text_content += b"\x00" * (0x2000 - len(text_content))

        # .data section (initialized data with security research indicators)
        data_content = b""
        # Configuration data
        data_content += b"\x01\x00\x00\x00"                # Version
        data_content += b"\x42\x42\x42\x42"                # XOR key
        data_content += b"CONFIGURATION_DATA\x00"
        # Encrypted strings (common in protected software)
        encrypted_string = b"Uijt!jt!bo!fodszqufe!tusjoh"  # "This is an encrypted string" with +1 cipher
        data_content += encrypted_string + b"\x00"
        # Pad section
        data_content += b"\x00" * (0x1000 - len(data_content))

        # .rdata section (imports and read-only data)
        rdata_content = b""
        # Import names (realistic API calls for security analysis)
        rdata_content += b"kernel32.dll\x00"
        rdata_content += b"LoadLibraryA\x00"
        rdata_content += b"GetProcAddress\x00"
        rdata_content += b"VirtualAlloc\x00"
        rdata_content += b"VirtualProtect\x00"
        rdata_content += b"CreateProcessA\x00"
        rdata_content += b"WriteProcessMemory\x00"
        rdata_content += b"ntdll.dll\x00"
        rdata_content += b"NtQueryInformationProcess\x00"
        rdata_content += b"NtSetInformationThread\x00"
        # Interesting strings for analysis
        rdata_content += b"This program is protected by advanced security\x00"
        rdata_content += b"License verification failed\x00"
        rdata_content += b"Debug detected - terminating\x00"
        # Pad section
        rdata_content += b"\x00" * (0x1000 - len(rdata_content))

        # .rsrc section (resources)
        rsrc_content = b""
        # Version resource header
        rsrc_content += b"\x00\x00\x00\x00\x20\x00\x00\x00"  # Resource directory
        rsrc_content += b"\xFF\xFF\x10\x00"                   # Version resource type
        rsrc_content += b"\x00\x00\x00\x00"                   # Time/date stamp
        rsrc_content += b"\x04\x00\x00\x00"                   # Major/minor version
        rsrc_content += b"\x01\x00\x00\x00"                   # Number of entries
        # Version info
        rsrc_content += b"ProductVersion\x00\x00\x001.0.0.0\x00\x00\x00"
        rsrc_content += b"FileDescription\x00\x00\x00Security Research Tool\x00\x00"
        rsrc_content += b"CompanyName\x00\x00\x00Intellicrack Research\x00\x00"
        # Pad section
        rsrc_content += b"\x00" * (0x1000 - len(rsrc_content))

        # Write complete binary
        with open(self.test_binary, 'wb') as f:
            f.write(header + text_content + data_content + rdata_content + rsrc_content)

    def tearDown(self):
        """Clean up orchestration test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_run_analysis_manager_performs_comprehensive_orchestrated_analysis(self):
        """Test that run_analysis_manager orchestrates complete analysis workflows."""
        # Execute comprehensive analysis orchestration
        results = run_analysis_manager(self.config, **self.analysis_params)

        # Verify orchestration returned comprehensive results
        self.assertIsNotNone(results)
        self.assertIsInstance(results, dict)

        # Verify all requested analysis types were completed
        expected_analysis_types = ['basic', 'entropy', 'strings', 'headers']
        for analysis_type in expected_analysis_types:
            analysis_key = f"{analysis_type}_analysis"
            self.assertIn(analysis_key, results,
                         f"Missing {analysis_key} in orchestrated results")

        # Verify comprehensive analysis metadata
        self.assertIn('analysis_metadata', results)
        metadata = results['analysis_metadata']
        self.assertIn('start_time', metadata)
        self.assertIn('end_time', metadata)
        self.assertIn('total_duration', metadata)
        self.assertIn('cache_utilization', metadata)

        # Verify security-focused analysis results
        basic_results = results.get('basic_analysis', {})
        self.assertIn('security_indicators', basic_results)
        self.assertIn('protection_analysis', basic_results)

        # Verify performance profiling if enabled
        if self.analysis_params.get('performance_profiling'):
            self.assertIn('performance_metrics', results)

    def test_run_analysis_manager_handles_caching_orchestration(self):
        """Test that run_analysis_manager properly orchestrates caching workflows."""
        # First analysis (should create cache)
        results1 = run_analysis_manager(self.config, **self.analysis_params)

        # Second analysis (should utilize cache)
        start_time = time.time()
        results2 = run_analysis_manager(self.config, **self.analysis_params)
        cached_duration = time.time() - start_time

        # Verify cache utilization improved performance
        self.assertLess(cached_duration, 5.0)  # Should be fast from cache

        # Verify results consistency
        self.assertEqual(results1['basic_analysis'], results2['basic_analysis'])
        self.assertEqual(results1['entropy_analysis'], results2['entropy_analysis'])

        # Verify cache metadata indicates utilization
        cache_metadata = results2['analysis_metadata']['cache_utilization']
        self.assertGreater(cache_metadata['cache_hits'], 0)
        self.assertGreater(cache_metadata['hit_ratio'], 0.7)  # High cache hit ratio

    def test_run_analysis_manager_handles_force_refresh_workflows(self):
        """Test that run_analysis_manager handles force refresh scenarios correctly."""
        # Initial analysis
        results1 = run_analysis_manager(self.config, **self.analysis_params)

        # Force refresh analysis
        refresh_params = self.analysis_params.copy()
        refresh_params['force_refresh'] = True
        results2 = run_analysis_manager(self.config, **refresh_params)

        # Verify forced refresh bypassed cache
        cache_metadata2 = results2['analysis_metadata']['cache_utilization']
        self.assertEqual(cache_metadata2['cache_hits'], 0)  # No cache hits on forced refresh

        # Verify results are still consistent
        self.assertEqual(results1['basic_analysis'], results2['basic_analysis'])

    def test_run_analysis_manager_handles_concurrent_analysis_coordination(self):
        """Test that run_analysis_manager coordinates concurrent analysis properly."""
        if not self.config['analysis'].get('concurrent_analysis'):
            self.skipTest("Concurrent analysis not enabled in configuration")

        # Test concurrent analysis coordination
        concurrent_params = self.analysis_params.copy()
        concurrent_params['analysis_types'] = ['basic', 'entropy', 'strings', 'headers']

        results = run_analysis_manager(self.config, **concurrent_params)

        # Verify all analysis types completed successfully
        self.assertIn('basic_analysis', results)
        self.assertIn('entropy_analysis', results)
        self.assertIn('strings_analysis', results)
        self.assertIn('headers_analysis', results)

        # Verify concurrency metadata
        metadata = results['analysis_metadata']
        if 'concurrency_info' in metadata:
            self.assertIn('parallel_tasks', metadata['concurrency_info'])
            self.assertIn('coordination_overhead', metadata['concurrency_info'])

    def test_run_analysis_manager_error_handling_and_recovery(self):
        """Test that run_analysis_manager handles errors gracefully with recovery mechanisms."""
        # Test with invalid binary path
        invalid_params = self.analysis_params.copy()
        invalid_params['binary_path'] = '/nonexistent/path/invalid.exe'

        results = run_analysis_manager(self.config, **invalid_params)

        # Should handle error gracefully
        self.assertIsNotNone(results)
        self.assertIn('error_info', results)
        self.assertIn('error_type', results['error_info'])
        self.assertEqual(results['error_info']['error_type'], 'file_not_found')

        # Test with invalid analysis types
        invalid_analysis_params = self.analysis_params.copy()
        invalid_analysis_params['analysis_types'] = ['invalid_analysis_type']

        results2 = run_analysis_manager(self.config, **invalid_analysis_params)

        # Should handle invalid analysis types gracefully
        self.assertIsNotNone(results2)
        if 'error_info' in results2:
            self.assertIn('unsupported_analysis_types', results2['error_info'])

    def test_run_analysis_manager_timeout_handling(self):
        """Test that run_analysis_manager respects analysis timeout configurations."""
        # Create configuration with very short timeout
        timeout_config = self.config.copy()
        timeout_config['analysis']['analysis_timeout'] = 1  # 1 second timeout

        # Test with large binary that should timeout
        large_binary = os.path.join(self.temp_dir, "large_timeout_test.exe")
        with open(large_binary, 'wb') as f:
            f.write(b"PE\x00\x00" + b"A" * (10 * 1024 * 1024))  # 10MB binary

        timeout_params = self.analysis_params.copy()
        timeout_params['binary_path'] = large_binary
        timeout_params['analysis_types'] = ['basic', 'entropy', 'strings']

        start_time = time.time()
        results = run_analysis_manager(timeout_config, **timeout_params)
        execution_time = time.time() - start_time

        # Should respect timeout
        self.assertLess(execution_time, 10.0)  # Should not take much longer than timeout

        # Should indicate timeout occurred
        if 'error_info' in results:
            self.assertIn('timeout', results['error_info'].get('error_type', '').lower())

    def test_run_analysis_manager_output_format_handling(self):
        """Test that run_analysis_manager handles different output formats correctly."""
        # Test detailed format
        detailed_params = self.analysis_params.copy()
        detailed_params['output_format'] = 'detailed'

        detailed_results = run_analysis_manager(self.config, **detailed_params)

        # Verify detailed format includes comprehensive information
        self.assertIn('analysis_metadata', detailed_results)
        self.assertIn('performance_metrics', detailed_results.get('analysis_metadata', {}))

        # Test summary format
        summary_params = self.analysis_params.copy()
        summary_params['output_format'] = 'summary'

        summary_results = run_analysis_manager(self.config, **summary_params)

        # Verify summary format is more concise
        self.assertIsNotNone(summary_results)
        # Summary should have core analysis but less detailed metadata
        expected_keys = ['basic_analysis', 'entropy_analysis', 'strings_analysis']
        for key in expected_keys:
            if key.replace('_analysis', '') in self.analysis_params['analysis_types']:
                self.assertIn(key, summary_results)

    def test_run_analysis_manager_security_analysis_integration(self):
        """Test that run_analysis_manager integrates security-focused analysis correctly."""
        security_params = self.analysis_params.copy()
        security_params['security_analysis'] = True
        security_params['analysis_types'] = ['basic', 'entropy', 'strings', 'headers']

        results = run_analysis_manager(self.config, **security_params)

        # Verify security analysis integration
        self.assertIn('security_summary', results)
        security_summary = results['security_summary']

        # Verify security-relevant metrics
        expected_security_metrics = [
            'packing_probability',
            'encryption_indicators',
            'suspicious_api_calls',
            'protection_mechanisms',
            'threat_level_assessment'
        ]

        for metric in expected_security_metrics:
            self.assertIn(metric, security_summary,
                         f"Missing security metric: {metric}")

        # Verify threat assessment is meaningful
        threat_level = security_summary.get('threat_level_assessment', {})
        self.assertIn('overall_score', threat_level)
        self.assertIsInstance(threat_level['overall_score'], (int, float))
        self.assertGreaterEqual(threat_level['overall_score'], 0)
        self.assertLessEqual(threat_level['overall_score'], 10)


if __name__ == '__main__':
    # Configure test runner for comprehensive reporting
    unittest.main(verbosity=2, buffer=True)
