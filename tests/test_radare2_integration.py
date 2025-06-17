"""
Comprehensive Test Suite for Radare2 Integration

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellirack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellirack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import unittest
import tempfile
import os
import json
import time
import threading
import struct
import shutil
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Import modules to test
try:
    from intellicrack.utils.tools.radare2_utils import R2Session, R2Exception
    from intellicrack.core.analysis.radare2_decompiler import R2Decompiler
    from intellicrack.core.analysis.radare2_esil import R2ESILEngine
    from intellicrack.core.analysis.radare2_strings import R2StringAnalyzer
    from intellicrack.core.analysis.radare2_signatures import R2SignatureAnalyzer
    from intellicrack.core.analysis.radare2_imports import R2ImportAnalyzer
    from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine
    from intellicrack.core.analysis.radare2_ai_integration import R2AIIntegration
    from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator
    from intellicrack.core.analysis.radare2_binary_diff import R2BinaryDiff
    from intellicrack.core.analysis.radare2_scripting import R2ScriptEngine
    from intellicrack.core.analysis.radare2_json_standardizer import R2JSONStandardizer, standardize_r2_result
    from intellicrack.core.analysis.radare2_error_handler import R2ErrorHandler, ErrorSeverity, RecoveryStrategy
    from intellicrack.core.analysis.radare2_performance_optimizer import R2PerformanceOptimizer, OptimizationStrategy
    from intellicrack.core.analysis.radare2_realtime_analyzer import R2RealtimeAnalyzer, UpdateMode, AnalysisEvent
    from intellicrack.core.analysis.radare2_enhanced_integration import EnhancedR2Integration
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available for testing: {e}")
    MODULES_AVAILABLE = False


class TestBinaryGenerator:
    """Helper class to generate test binaries"""
    
    @staticmethod
    def create_simple_elf(path: str, with_strings: bool = True, with_functions: bool = True):
        """Create a simple ELF binary for testing"""
        # ELF header for x86-64
        elf_header = bytearray([
            0x7F, 0x45, 0x4C, 0x46,  # Magic
            0x02,  # 64-bit
            0x01,  # Little endian
            0x01,  # ELF version
            0x00,  # System V ABI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Padding
            0x02, 0x00,  # Executable file
            0x3E, 0x00,  # x86-64
            0x01, 0x00, 0x00, 0x00,  # Version
            0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # Entry point
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Section header offset
            0x00, 0x00, 0x00, 0x00,  # Flags
            0x40, 0x00,  # ELF header size
            0x38, 0x00,  # Program header size
            0x01, 0x00,  # Program header count
            0x00, 0x00,  # Section header size
            0x00, 0x00,  # Section header count
            0x00, 0x00   # Section header string index
        ])
        
        # Program header
        program_header = bytearray([
            0x01, 0x00, 0x00, 0x00,  # PT_LOAD
            0x05, 0x00, 0x00, 0x00,  # Flags (R+X)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Offset
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # Virtual address
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # Physical address
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # File size
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Memory size
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   # Alignment
        ])
        
        # Simple x86-64 code
        code = bytearray([
            0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1 (sys_exit)
            0xBF, 0x00, 0x00, 0x00, 0x00,  # mov edi, 0 (exit code)
            0x0F, 0x05                      # syscall
        ])
        
        # Pad to align
        code.extend([0x90] * (0x78 - len(elf_header) - len(program_header)))  # NOP padding
        
        # Add strings if requested
        strings_data = b""
        if with_strings:
            strings_data = b"\x00LICENSE_KEY=DEMO-1234-5678\x00"
            strings_data += b"Copyright (c) 2025 Test Software\x00"
            strings_data += b"strcpy\x00sprintf\x00vulnerable_function\x00"
        
        # Combine all parts
        binary_data = elf_header + program_header + code + strings_data
        
        # Pad to reasonable size
        binary_data.extend([0x00] * (512 - len(binary_data)))
        
        with open(path, 'wb') as f:
            f.write(binary_data)
    
    @staticmethod
    def create_simple_pe(path: str, with_imports: bool = True):
        """Create a simple PE binary for testing"""
        # Simplified PE structure
        dos_header = bytearray([
            0x4D, 0x5A,  # MZ signature
            0x90, 0x00,  # Bytes on last page
            0x03, 0x00,  # Pages in file
            0x00, 0x00,  # Relocations
            0x04, 0x00,  # Size of header in paragraphs
            0x00, 0x00,  # Minimum extra paragraphs
            0xFF, 0xFF,  # Maximum extra paragraphs
            0x00, 0x00,  # Initial SS
            0xB8, 0x00,  # Initial SP
            0x00, 0x00,  # Checksum
            0x00, 0x00,  # Initial IP
            0x00, 0x00,  # Initial CS
            0x40, 0x00,  # File address of relocation table
            0x00, 0x00,  # Overlay number
        ])
        dos_header.extend([0x00] * 36)  # Reserved
        dos_header.extend([0x80, 0x00, 0x00, 0x00])  # PE header offset
        
        # DOS stub
        dos_stub = bytearray([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
                            0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21])
        dos_stub.extend(b'This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00')
        
        # Pad to PE header
        padding = bytearray([0x00] * (0x80 - len(dos_header) - len(dos_stub)))
        
        # PE signature
        pe_signature = bytearray([0x50, 0x45, 0x00, 0x00])  # PE\0\0
        
        # COFF header
        coff_header = bytearray([
            0x64, 0x86,  # Machine (x64)
            0x01, 0x00,  # Number of sections
            0x00, 0x00, 0x00, 0x00,  # TimeDateStamp
            0x00, 0x00, 0x00, 0x00,  # PointerToSymbolTable
            0x00, 0x00, 0x00, 0x00,  # NumberOfSymbols
            0xF0, 0x00,  # SizeOfOptionalHeader
            0x22, 0x00   # Characteristics
        ])
        
        # Combine binary
        binary_data = dos_header + dos_stub + padding + pe_signature + coff_header
        
        # Add more data to make it look like a real PE
        binary_data.extend([0x00] * (1024 - len(binary_data)))
        
        with open(path, 'wb') as f:
            f.write(binary_data)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2Utils(unittest.TestCase):
    """Test core radare2 utilities"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        TestBinaryGenerator.create_simple_elf(self.test_binary)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_r2_session_connect(self, mock_r2pipe):
        """Test R2Session connection"""
        mock_r2 = MagicMock()
        mock_r2pipe.return_value = mock_r2
        
        session = R2Session(self.test_binary)
        result = session.connect()
        
        self.assertTrue(result)
        self.assertTrue(session.is_connected)
        mock_r2pipe.assert_called_once()
        mock_r2.cmd.assert_called_with('aaa')
    
    @patch('r2pipe.open')
    def test_r2_session_context_manager(self, mock_r2pipe):
        """Test R2Session as context manager"""
        mock_r2 = MagicMock()
        mock_r2pipe.return_value = mock_r2
        
        with R2Session(self.test_binary) as session:
            self.assertTrue(session.is_connected)
        
        mock_r2.quit.assert_called_once()
    
    @patch('r2pipe.open')
    def test_r2_session_command_execution(self, mock_r2pipe):
        """Test command execution"""
        mock_r2 = MagicMock()
        mock_r2.cmd.return_value = "test output"
        mock_r2.cmdj.return_value = {"test": "json"}
        mock_r2pipe.return_value = mock_r2
        
        session = R2Session(self.test_binary)
        session.connect()
        
        # Test regular command
        result = session._execute_command("i")
        self.assertEqual(result, "test output")
        
        # Test JSON command
        result = session._execute_command("ij", expect_json=True)
        self.assertEqual(result, {"test": "json"})
    
    def test_r2_session_no_binary(self):
        """Test R2Session with non-existent binary"""
        session = R2Session("/non/existent/file")
        
        with self.assertRaises(R2Exception):
            session.connect()


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2Decompiler(unittest.TestCase):
    """Test radare2 decompiler"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        TestBinaryGenerator.create_simple_elf(self.test_binary)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_decompiler_initialization(self, mock_r2pipe):
        """Test decompiler initialization"""
        mock_r2 = MagicMock()
        mock_r2pipe.return_value = mock_r2
        
        decompiler = R2Decompiler(self.test_binary)
        self.assertEqual(decompiler.binary_path, self.test_binary)
        self.assertIsNotNone(decompiler.logger)
    
    @patch('r2pipe.open')
    def test_analyze_license_functions(self, mock_r2pipe):
        """Test license function analysis"""
        mock_r2 = MagicMock()
        mock_r2.cmdj.side_effect = [
            # Function list
            [
                {"name": "check_license", "offset": 0x1000, "size": 100},
                {"name": "validate_key", "offset": 0x2000, "size": 200}
            ],
            # Decompiled code for first function
            "int check_license() { return strcmp(key, \"LICENSE\"); }",
            # Decompiled code for second function  
            "int validate_key() { return 1; }"
        ]
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        decompiler = R2Decompiler(self.test_binary)
        result = decompiler.analyze_license_functions()
        
        self.assertIn('license_functions', result)
        self.assertIn('decompiled_functions', result)
        self.assertEqual(len(result['license_functions']), 2)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available") 
class TestRadare2StringAnalyzer(unittest.TestCase):
    """Test radare2 string analyzer"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        TestBinaryGenerator.create_simple_elf(self.test_binary, with_strings=True)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_string_analysis(self, mock_r2pipe):
        """Test string analysis"""
        mock_r2 = MagicMock()
        mock_r2.cmdj.side_effect = [
            # All strings
            [
                {"string": "LICENSE_KEY=DEMO-1234-5678", "vaddr": 0x1000, "size": 26},
                {"string": "Copyright (c) 2025", "vaddr": 0x2000, "size": 18},
                {"string": "strcpy", "vaddr": 0x3000, "size": 6}
            ],
            # Data section strings
            [{"string": "LICENSE_KEY=DEMO-1234-5678", "vaddr": 0x1000, "size": 26}],
            # Wide strings
            []
        ]
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        analyzer = R2StringAnalyzer(self.test_binary)
        result = analyzer.analyze_strings()
        
        self.assertIn('license_strings', result)
        self.assertIn('crypto_strings', result)
        self.assertIn('debug_strings', result)
        self.assertEqual(len(result['license_strings']), 1)
        self.assertTrue(any('LICENSE' in s['string'] for s in result['license_strings']))


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2ErrorHandler(unittest.TestCase):
    """Test error handling and recovery"""
    
    def setUp(self):
        """Set up test environment"""
        self.error_handler = R2ErrorHandler()
    
    def test_error_classification(self):
        """Test error severity classification"""
        # Test critical errors
        memory_error = MemoryError("Out of memory")
        severity = self.error_handler._classify_error_severity(memory_error, "test_operation")
        self.assertEqual(severity, ErrorSeverity.CRITICAL)
        
        # Test high severity errors
        file_error = FileNotFoundError("radare2 not found")
        severity = self.error_handler._classify_error_severity(file_error, "r2_operation")
        self.assertEqual(severity, ErrorSeverity.HIGH)
        
        # Test medium severity errors
        timeout_error = TimeoutError("Operation timed out")
        severity = self.error_handler._classify_error_severity(timeout_error, "test_operation")
        self.assertEqual(severity, ErrorSeverity.MEDIUM)
        
        # Test low severity errors
        json_error = ValueError("Invalid JSON")
        severity = self.error_handler._classify_error_severity(json_error, "test_operation")
        self.assertEqual(severity, ErrorSeverity.LOW)
    
    def test_recovery_strategy_determination(self):
        """Test recovery strategy determination"""
        # Create test error events
        critical_event = self.error_handler._create_error_event(
            MemoryError("Out of memory"),
            "test_operation",
            {}
        )
        strategy = self.error_handler._determine_recovery_strategy(critical_event)
        self.assertEqual(strategy, RecoveryStrategy.USER_INTERVENTION)
        
        # Test r2pipe error
        r2_event = self.error_handler._create_error_event(
            Exception("r2pipe connection failed"),
            "r2_connect",
            {}
        )
        strategy = self.error_handler._determine_recovery_strategy(r2_event)
        self.assertEqual(strategy, RecoveryStrategy.RETRY)
    
    def test_circuit_breaker(self):
        """Test circuit breaker functionality"""
        operation = "test_operation"
        
        # Initially circuit should be closed
        self.assertFalse(self.error_handler._is_circuit_broken(operation))
        
        # Simulate failures
        for _ in range(6):  # Threshold is 5
            self.error_handler._update_circuit_breaker(operation, success=False)
        
        # Circuit should now be open
        self.assertTrue(self.error_handler._is_circuit_broken(operation))
        
        # Reset circuit
        self.error_handler.reset_circuit_breaker(operation)
        self.assertFalse(self.error_handler._is_circuit_broken(operation))
    
    def test_error_statistics(self):
        """Test error statistics tracking"""
        # Create some test errors
        test_error = ValueError("Test error")
        self.error_handler.handle_error(test_error, "test_operation", {})
        
        stats = self.error_handler.get_error_statistics()
        
        self.assertIn('session_stats', stats)
        self.assertIn('error_count_by_type', stats)
        self.assertIn('error_count_by_severity', stats)
        self.assertEqual(stats['session_stats']['total_errors'], 1)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2PerformanceOptimizer(unittest.TestCase):
    """Test performance optimization"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.small_binary = os.path.join(self.test_dir, "small_binary")
        self.large_binary = os.path.join(self.test_dir, "large_binary")
        
        # Create small binary (1KB)
        with open(self.small_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        # Create large binary (50MB)
        with open(self.large_binary, 'wb') as f:
            f.write(b'\x00' * (50 * 1024 * 1024))
        
        self.optimizer = R2PerformanceOptimizer()
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_profile_selection(self):
        """Test performance profile selection"""
        # Test small file profile
        small_config = self.optimizer.optimize_for_binary(self.small_binary)
        self.assertEqual(small_config['profile_name'], "Small Files (<10MB)")
        self.assertEqual(small_config['analysis_level'], 'aaaa')
        
        # Test large file profile
        large_config = self.optimizer.optimize_for_binary(self.large_binary)
        self.assertEqual(large_config['profile_name'], "Large Files (100MB-1GB)")
        self.assertEqual(large_config['analysis_level'], 'aa')
    
    def test_strategy_optimizations(self):
        """Test different optimization strategies"""
        # Test memory conservative strategy
        mem_optimizer = R2PerformanceOptimizer(OptimizationStrategy.MEMORY_CONSERVATIVE)
        config = mem_optimizer.optimize_for_binary(self.small_binary)
        self.assertEqual(config['parallel_workers'], 1)
        self.assertFalse(config['cache_enabled'])
        
        # Test speed optimized strategy
        speed_optimizer = R2PerformanceOptimizer(OptimizationStrategy.SPEED_OPTIMIZED)
        config = speed_optimizer.optimize_for_binary(self.small_binary)
        self.assertTrue(config['cache_enabled'])
        self.assertGreater(config['parallel_workers'], 1)
    
    def test_system_resource_adaptation(self):
        """Test adaptation based on system resources"""
        # Mock system info with low memory
        with patch.object(self.optimizer, '_get_system_info') as mock_sys_info:
            mock_sys_info.return_value = {
                'cpu_count': 4,
                'memory_total': 4 * 1024 * 1024 * 1024,  # 4GB
                'memory_available': 500 * 1024 * 1024,   # 500MB available
                'memory_percent': 87.5,
                'cpu_percent': 20,
                'disk_usage': 50
            }
            
            config = self.optimizer.optimize_for_binary(self.small_binary)
            
            # Should adapt to low memory
            self.assertLess(config['memory_limit'], 500)
            self.assertIn('aa', config['analysis_level'])  # Reduced analysis


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2RealtimeAnalyzer(unittest.TestCase):
    """Test real-time analysis capabilities"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        TestBinaryGenerator.create_simple_elf(self.test_binary)
        
        self.analyzer = R2RealtimeAnalyzer(
            update_mode=UpdateMode.INTERVAL,
            update_interval=1.0,  # 1 second for testing
            max_concurrent_analyses=2
        )
    
    def tearDown(self):
        """Clean up test environment"""
        self.analyzer.cleanup()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_add_remove_binary(self):
        """Test adding and removing binaries"""
        # Add binary
        result = self.analyzer.add_binary(self.test_binary)
        self.assertTrue(result)
        self.assertIn(self.test_binary, self.analyzer.watched_binaries)
        
        # Remove binary
        result = self.analyzer.remove_binary(self.test_binary)
        self.assertTrue(result)
        self.assertNotIn(self.test_binary, self.analyzer.watched_binaries)
    
    def test_event_callbacks(self):
        """Test event callback system"""
        events_received = []
        
        def test_callback(update):
            events_received.append(update)
        
        # Register callback
        self.analyzer.register_event_callback(AnalysisEvent.ANALYSIS_STARTED, test_callback)
        
        # Emit test event
        from intellicrack.core.analysis.radare2_realtime_analyzer import AnalysisUpdate
        test_update = AnalysisUpdate(
            timestamp=time.time(),
            event_type=AnalysisEvent.ANALYSIS_STARTED,
            binary_path=self.test_binary,
            data={'test': True}
        )
        self.analyzer._emit_event(test_update)
        
        # Check callback was called
        self.assertEqual(len(events_received), 1)
        self.assertEqual(events_received[0].binary_path, self.test_binary)
    
    @patch('r2pipe.open')
    def test_incremental_analysis(self, mock_r2pipe):
        """Test incremental analysis functionality"""
        mock_r2 = MagicMock()
        mock_r2.cmd.return_value = None
        mock_r2.cmdj.return_value = [
            {"string": "test_string", "vaddr": 0x1000}
        ]
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        # Add binary and perform analysis
        self.analyzer.add_binary(self.test_binary)
        self.analyzer._perform_incremental_analysis(
            self.test_binary,
            AnalysisEvent.ANALYSIS_STARTED
        )
        
        # Check results were stored
        results = self.analyzer.get_latest_results(self.test_binary)
        self.assertIsNotNone(results)
        self.assertIn('strings', results)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2JSONStandardizer(unittest.TestCase):
    """Test JSON standardization"""
    
    def setUp(self):
        """Set up test environment"""
        self.standardizer = R2JSONStandardizer()
    
    def test_base_structure_creation(self):
        """Test creation of base standardized structure"""
        base = self.standardizer._create_base_structure(
            'vulnerability',
            '/test/binary',
            {'custom': 'metadata'}
        )
        
        # Check required fields
        self.assertIn('schema_version', base)
        self.assertIn('analysis_metadata', base)
        self.assertIn('binary_metadata', base)
        self.assertIn('analysis_results', base)
        self.assertIn('summary_statistics', base)
        self.assertIn('ml_features', base)
        self.assertIn('status', base)
        
        # Check metadata
        self.assertEqual(base['analysis_metadata']['analysis_type'], 'vulnerability')
        self.assertEqual(base['binary_metadata']['file_path'], '/test/binary')
        self.assertEqual(base['additional_metadata']['custom'], 'metadata')
    
    def test_vulnerability_standardization(self):
        """Test vulnerability result standardization"""
        raw_result = {
            'buffer_overflows': [
                {
                    'function': 'strcpy_wrapper',
                    'address': 0x1000,
                    'severity': 'high',
                    'description': 'Unsafe strcpy usage'
                }
            ],
            'format_string_bugs': []
        }
        
        result = self.standardizer.standardize_analysis_result(
            'vulnerability',
            raw_result,
            '/test/binary'
        )
        
        # Check standardized structure
        self.assertEqual(result['schema_version'], '2.0.0')
        self.assertIn('vulnerabilities', result['analysis_results'])
        self.assertEqual(result['summary_statistics']['total_vulnerabilities'], 1)
        self.assertEqual(result['summary_statistics']['high_vulnerabilities'], 1)
    
    def test_comprehensive_standardization(self):
        """Test comprehensive analysis standardization"""
        raw_result = {
            'components': {
                'strings': {
                    'license_strings': ['LICENSE_KEY=DEMO'],
                    'total_strings': 100
                },
                'vulnerability': {
                    'buffer_overflows': [],
                    'format_string_bugs': []
                }
            },
            'binary_path': '/test/binary'
        }
        
        result = self.standardizer.standardize_analysis_result(
            'comprehensive',
            raw_result,
            '/test/binary'
        )
        
        # Check comprehensive structure
        self.assertIn('components', result['analysis_results'])
        self.assertIn('cross_component_analysis', result['analysis_results'])
        self.assertIn('unified_findings', result['analysis_results'])
        self.assertEqual(result['summary_statistics']['components_analyzed'], 2)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestEnhancedR2Integration(unittest.TestCase):
    """Test enhanced integration with all components"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        TestBinaryGenerator.create_simple_elf(self.test_binary)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_component_initialization(self, mock_r2pipe):
        """Test initialization of all components"""
        mock_r2 = MagicMock()
        mock_r2pipe.return_value = mock_r2
        
        integration = EnhancedR2Integration(self.test_binary)
        
        # Check all components were initialized
        expected_components = [
            'decompiler', 'esil', 'strings', 'signatures',
            'imports', 'vulnerability', 'ai', 'bypass',
            'diff', 'scripting'
        ]
        
        for component in expected_components:
            self.assertIn(component, integration.components)
    
    def test_performance_monitoring(self):
        """Test performance monitoring and statistics"""
        integration = EnhancedR2Integration(self.test_binary)
        
        # Record some fake performance data
        integration._record_analysis_time('test_component', 1.5, success=True)
        integration._record_analysis_time('test_component', 2.0, success=True)
        integration._record_analysis_time('test_component', 3.0, success=False)
        
        stats = integration.get_performance_stats()
        
        # Check statistics
        self.assertIn('analysis_times', stats)
        self.assertIn('test_component', stats['analysis_times'])
        
        component_stats = stats['analysis_times']['test_component']
        self.assertEqual(component_stats['successes'], 2)
        self.assertEqual(component_stats['failures'], 1)
        self.assertEqual(component_stats['avg_time'], 2.166666666666667)  # (1.5+2.0+3.0)/3
    
    def test_cache_functionality(self):
        """Test caching system"""
        integration = EnhancedR2Integration(self.test_binary, {'cache_ttl': 1})  # 1 second TTL
        
        # Cache a result
        test_result = {'test': 'data'}
        integration._cache_result('test_key', test_result)
        
        # Retrieve from cache
        cached = integration._get_cached_result('test_key')
        self.assertEqual(cached, test_result)
        
        # Wait for TTL to expire
        time.sleep(1.1)
        
        # Should return None after expiry
        cached = integration._get_cached_result('test_key')
        self.assertIsNone(cached)
    
    def test_health_status(self):
        """Test health status reporting"""
        integration = EnhancedR2Integration(self.test_binary)
        
        health = integration.get_health_status()
        
        # Check health structure
        self.assertIn('overall_health', health)
        self.assertIn('components_available', health)
        self.assertIn('cache_health', health)
        self.assertIn('error_health', health)
        
        # Initially should be healthy
        self.assertEqual(health['overall_health'], 'healthy')


class TestSuite:
    """Main test suite runner"""
    
    @staticmethod
    def run_all_tests():
        """Run all radare2 integration tests"""
        # Create test suite
        suite = unittest.TestSuite()
        
        # Add all test classes
        test_classes = [
            TestRadare2Utils,
            TestRadare2Decompiler,
            TestRadare2StringAnalyzer,
            TestRadare2ErrorHandler,
            TestRadare2PerformanceOptimizer,
            TestRadare2RealtimeAnalyzer,
            TestRadare2JSONStandardizer,
            TestEnhancedR2Integration
        ]
        
        for test_class in test_classes:
            tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result.wasSuccessful()


if __name__ == '__main__':
    # Run all tests
    success = TestSuite.run_all_tests()
    exit(0 if success else 1)