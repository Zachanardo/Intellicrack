"""
Advanced Integration Tests for Radare2 Components

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
import shutil
from unittest.mock import Mock, patch, MagicMock, call
from typing import Dict, List, Any

# Import modules to test
try:
    from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine
    from intellicrack.core.analysis.radare2_ai_integration import R2AIIntegration
    from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator, BypassStrategy
    from intellicrack.core.analysis.radare2_binary_diff import R2BinaryDiff
    from intellicrack.core.analysis.radare2_scripting import R2ScriptEngine
    from intellicrack.core.analysis.cfg_explorer import CFGExplorer
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available for testing: {e}")
    MODULES_AVAILABLE = False


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2VulnerabilityEngine(unittest.TestCase):
    """Test vulnerability detection engine"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        
        # Create test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_buffer_overflow_detection(self, mock_r2pipe):
        """Test buffer overflow detection"""
        mock_r2 = MagicMock()
        
        # Mock function analysis
        mock_r2.cmdj.side_effect = [
            # Function list
            [
                {"name": "vulnerable_func", "offset": 0x1000, "size": 100},
                {"name": "safe_func", "offset": 0x2000, "size": 50}
            ],
            # Instructions for vulnerable_func (contains strcpy)
            [
                {"opcode": "call strcpy", "offset": 0x1010, "type": "call"},
                {"opcode": "mov rax, rbx", "offset": 0x1015, "type": "mov"}
            ],
            # Instructions for safe_func
            [
                {"opcode": "mov rax, rbx", "offset": 0x2000, "type": "mov"}
            ]
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        engine = R2VulnerabilityEngine(self.test_binary)
        result = engine._detect_buffer_overflows()
        
        self.assertIn('buffer_overflows', result)
        self.assertEqual(len(result['buffer_overflows']), 1)
        self.assertEqual(result['buffer_overflows'][0]['function'], 'vulnerable_func')
    
    @patch('r2pipe.open')
    def test_format_string_detection(self, mock_r2pipe):
        """Test format string vulnerability detection"""
        mock_r2 = MagicMock()
        
        # Mock analysis
        mock_r2.cmdj.side_effect = [
            # Function list
            [{"name": "print_func", "offset": 0x1000, "size": 100}],
            # Instructions containing printf without format
            [
                {"opcode": "push rdi", "offset": 0x1000, "type": "push"},
                {"opcode": "call printf", "offset": 0x1005, "type": "call"}
            ]
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        engine = R2VulnerabilityEngine(self.test_binary)
        result = engine._detect_format_string_bugs()
        
        self.assertIn('format_string_bugs', result)
        self.assertEqual(len(result['format_string_bugs']), 1)
    
    @patch('r2pipe.open')
    def test_comprehensive_scan(self, mock_r2pipe):
        """Test comprehensive vulnerability scan"""
        mock_r2 = MagicMock()
        
        # Mock comprehensive analysis
        mock_r2.cmdj.side_effect = [
            # Function list (called multiple times)
            [{"name": "test_func", "offset": 0x1000, "size": 100}],
            # Instructions (called for each detection type)
            [{"opcode": "call strcpy", "offset": 0x1010, "type": "call"}],
            [{"name": "test_func", "offset": 0x1000, "size": 100}],
            [{"opcode": "call printf", "offset": 0x1020, "type": "call"}],
            # Continue for other detection types...
            [], [], [], [], [], [], [], [], [], [], [], [], [], []
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        engine = R2VulnerabilityEngine(self.test_binary)
        result = engine.comprehensive_vulnerability_scan()
        
        # Check result structure
        self.assertIn('summary', result)
        self.assertIn('total_vulnerabilities', result['summary'])
        self.assertIn('severity_breakdown', result['summary'])
        self.assertIn('buffer_overflows', result)
        self.assertIn('format_string_bugs', result)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2AIIntegration(unittest.TestCase):
    """Test AI/ML integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        
        # Create test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_feature_extraction(self, mock_r2pipe):
        """Test ML feature extraction"""
        mock_r2 = MagicMock()
        
        # Mock binary info and analysis
        mock_r2.cmdj.side_effect = [
            # Binary info
            {
                "bin": {"arch": "x86", "bits": 64, "endian": "little"},
                "core": {"file": self.test_binary, "size": 1024}
            },
            # Functions
            [{"name": "main", "offset": 0x1000, "size": 100}],
            # Imports
            [{"name": "strcpy", "type": "FUNC"}],
            # Strings
            [{"string": "LICENSE_KEY", "vaddr": 0x2000}],
            # Sections
            [{"name": ".text", "size": 512, "perm": "r-x"}]
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        ai_integration = R2AIIntegration(self.test_binary)
        features = ai_integration._extract_ml_features()
        
        # Check feature structure
        self.assertIn('file_size', features)
        self.assertIn('architecture', features)
        self.assertIn('function_count', features)
        self.assertIn('import_count', features)
        self.assertIn('string_count', features)
        self.assertIn('section_count', features)
        self.assertEqual(features['file_size'], 1024)
        self.assertEqual(features['function_count'], 1)
    
    def test_model_training(self):
        """Test ML model training"""
        ai_integration = R2AIIntegration(self.test_binary)
        
        # Create synthetic training data
        features = [
            [1000, 50, 10, 5, 100, 3, 0.5, 0.2, 0.8, 0.1] + [0] * 240,
            [2000, 100, 20, 10, 200, 5, 0.6, 0.3, 0.7, 0.2] + [0] * 240,
            [500, 25, 5, 2, 50, 2, 0.4, 0.1, 0.9, 0.05] + [0] * 240
        ]
        labels = [1, 1, 0]  # License detection labels
        
        # Train model
        ai_integration._train_license_model(features, labels)
        
        # Check model exists
        self.assertIsNotNone(ai_integration.models['license_detection'])
        
        # Test prediction
        test_features = [[1500, 75, 15, 7, 150, 4, 0.55, 0.25, 0.75, 0.15] + [0] * 240]
        prediction = ai_integration.models['license_detection'].predict(test_features)
        self.assertEqual(len(prediction), 1)
    
    @patch('r2pipe.open')
    def test_anomaly_detection(self, mock_r2pipe):
        """Test anomaly detection"""
        mock_r2 = MagicMock()
        
        # Mock function analysis
        mock_r2.cmdj.side_effect = [
            # Functions with varying complexity
            [
                {"name": "func1", "offset": 0x1000, "size": 100, "cc": 5},
                {"name": "func2", "offset": 0x2000, "size": 200, "cc": 10},
                {"name": "anomaly_func", "offset": 0x3000, "size": 1000, "cc": 50}
            ]
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        ai_integration = R2AIIntegration(self.test_binary)
        result = ai_integration._detect_anomalies()
        
        self.assertIn('function_anomalies', result)
        self.assertIn('anomaly_score', result)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2BypassGenerator(unittest.TestCase):
    """Test bypass generation"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        
        # Create test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_patch_generation(self, mock_r2pipe):
        """Test patch-based bypass generation"""
        mock_r2 = MagicMock()
        
        # Mock license check function
        mock_r2.cmdj.side_effect = [
            # License functions
            [{"name": "check_license", "offset": 0x1000, "size": 50}],
            # Function instructions
            [
                {"offset": 0x1000, "opcode": "push rbp", "size": 1},
                {"offset": 0x1001, "opcode": "mov rbp, rsp", "size": 3},
                {"offset": 0x1004, "opcode": "test eax, eax", "size": 2},
                {"offset": 0x1006, "opcode": "jz 0x1020", "size": 2},
                {"offset": 0x1008, "opcode": "mov eax, 0", "size": 5},
                {"offset": 0x100d, "opcode": "ret", "size": 1}
            ]
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        generator = R2BypassGenerator(self.test_binary)
        result = generator._generate_patch_bypass([{"name": "check_license", "offset": 0x1000}])
        
        self.assertIn('patches', result)
        self.assertGreater(len(result['patches']), 0)
        
        # Check patch structure
        patch = result['patches'][0]
        self.assertIn('offset', patch)
        self.assertIn('original', patch)
        self.assertIn('patched', patch)
        self.assertIn('description', patch)
    
    def test_keygen_generation(self):
        """Test keygen generation"""
        generator = R2BypassGenerator(self.test_binary)
        
        # Test simple checksum keygen
        result = generator._generate_keygen_bypass(
            validation_funcs=[{"name": "validate_key", "type": "checksum"}],
            key_format="XXXX-XXXX-XXXX-XXXX"
        )
        
        self.assertIn('keygen_algorithm', result)
        self.assertIn('example_keys', result)
        self.assertGreater(len(result['example_keys']), 0)
        
        # Check key format
        for key in result['example_keys']:
            self.assertRegex(key, r'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')
    
    @patch('r2pipe.open')
    def test_comprehensive_bypass_generation(self, mock_r2pipe):
        """Test comprehensive bypass strategy generation"""
        mock_r2 = MagicMock()
        
        # Mock comprehensive analysis
        mock_r2.cmdj.side_effect = [
            # Functions
            [
                {"name": "check_license", "offset": 0x1000, "size": 100},
                {"name": "validate_serial", "offset": 0x2000, "size": 150}
            ],
            # Strings
            [
                {"string": "Invalid license", "vaddr": 0x3000},
                {"string": "LICENSE_KEY=", "vaddr": 0x3100}
            ],
            # Additional mocks for each function analysis
            [], [], [], []
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        generator = R2BypassGenerator(self.test_binary)
        result = generator.generate_bypass_strategies()
        
        # Check comprehensive result
        self.assertIn('license_functions', result)
        self.assertIn('bypass_strategies', result)
        self.assertIn('recommended_approach', result)
        self.assertIn('confidence_score', result)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2BinaryDiff(unittest.TestCase):
    """Test binary diffing capabilities"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.binary1 = os.path.join(self.test_dir, "binary1")
        self.binary2 = os.path.join(self.test_dir, "binary2")
        
        # Create test binaries with slight differences
        with open(self.binary1, 'wb') as f:
            f.write(b'\x00' * 512 + b'VERSION_1.0' + b'\x00' * 501)
        
        with open(self.binary2, 'wb') as f:
            f.write(b'\x00' * 512 + b'VERSION_2.0' + b'\x00' * 501)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_function_diff(self, mock_r2pipe):
        """Test function-level diffing"""
        # Create two mock r2 instances
        mock_r2_1 = MagicMock()
        mock_r2_2 = MagicMock()
        
        # Mock function lists
        mock_r2_1.cmdj.return_value = [
            {"name": "main", "offset": 0x1000, "size": 100},
            {"name": "check_license", "offset": 0x2000, "size": 150}
        ]
        
        mock_r2_2.cmdj.return_value = [
            {"name": "main", "offset": 0x1000, "size": 120},  # Size changed
            {"name": "check_license_v2", "offset": 0x2100, "size": 200}  # Name and offset changed
        ]
        
        # Mock r2pipe.open to return different instances
        mock_r2pipe.side_effect = [mock_r2_1, mock_r2_2]
        
        diff_engine = R2BinaryDiff(self.binary1, self.binary2)
        result = diff_engine.diff_functions()
        
        self.assertIn('added_functions', result)
        self.assertIn('removed_functions', result)
        self.assertIn('modified_functions', result)
        self.assertIn('identical_functions', result)
    
    @patch('r2pipe.open')
    def test_string_diff(self, mock_r2pipe):
        """Test string-level diffing"""
        mock_r2_1 = MagicMock()
        mock_r2_2 = MagicMock()
        
        # Mock string lists
        mock_r2_1.cmdj.return_value = [
            {"string": "VERSION_1.0", "vaddr": 0x200},
            {"string": "Copyright 2024", "vaddr": 0x300}
        ]
        
        mock_r2_2.cmdj.return_value = [
            {"string": "VERSION_2.0", "vaddr": 0x200},
            {"string": "Copyright 2025", "vaddr": 0x300},
            {"string": "New Feature", "vaddr": 0x400}
        ]
        
        mock_r2pipe.side_effect = [mock_r2_1, mock_r2_2]
        
        diff_engine = R2BinaryDiff(self.binary1, self.binary2)
        result = diff_engine.diff_strings()
        
        self.assertIn('added_strings', result)
        self.assertIn('removed_strings', result)
        self.assertIn('modified_strings', result)
        self.assertEqual(len(result['added_strings']), 1)
        self.assertEqual(result['added_strings'][0]['string'], "New Feature")


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestRadare2Scripting(unittest.TestCase):
    """Test radare2 scripting capabilities"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        
        # Create test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_script_generation(self):
        """Test R2 script generation"""
        script_engine = R2ScriptEngine(self.test_binary)
        
        # Generate analysis script
        script = script_engine.generate_analysis_script(
            analysis_types=['functions', 'strings', 'imports'],
            output_format='json'
        )
        
        self.assertIn('# Radare2 Analysis Script', script)
        self.assertIn('aaa', script)  # Analysis command
        self.assertIn('aflj', script)  # Functions JSON
        self.assertIn('izzj', script)  # Strings JSON
        self.assertIn('iij', script)   # Imports JSON
    
    def test_custom_script_generation(self):
        """Test custom script generation"""
        script_engine = R2ScriptEngine(self.test_binary)
        
        # Create custom analysis workflow
        custom_analysis = {
            'name': 'License Analysis',
            'steps': [
                {'command': 'aaa', 'description': 'Analyze all'},
                {'command': 'afl~license', 'description': 'Find license functions'},
                {'command': 'pdf @@ fcn.license*', 'description': 'Disassemble license functions'}
            ]
        }
        
        script = script_engine._generate_custom_script(custom_analysis)
        
        self.assertIn('License Analysis', script)
        self.assertIn('afl~license', script)
        self.assertIn('pdf @@ fcn.license*', script)
    
    @patch('r2pipe.open')
    def test_script_execution(self, mock_r2pipe):
        """Test script execution"""
        mock_r2 = MagicMock()
        
        # Mock command execution
        mock_r2.cmd.side_effect = [
            None,  # aaa
            '[{"name": "main", "offset": 4096}]',  # aflj
            '[{"string": "test", "vaddr": 8192}]'  # izzj
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        script_engine = R2ScriptEngine(self.test_binary)
        
        # Execute simple script
        script_content = "aaa\naflj\nizzj"
        result = script_engine.execute_script(script_content, capture_output=True)
        
        self.assertIn('execution_time', result)
        self.assertIn('outputs', result)
        self.assertEqual(len(result['outputs']), 3)


@unittest.skipUnless(MODULES_AVAILABLE, "Radare2 modules not available")
class TestCFGExplorerEnhanced(unittest.TestCase):
    """Test enhanced CFG explorer"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_binary = os.path.join(self.test_dir, "test_binary")
        
        # Create test binary
        with open(self.test_binary, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('r2pipe.open')
    def test_enhanced_cfg_analysis(self, mock_r2pipe):
        """Test enhanced CFG analysis with ML integration"""
        mock_r2 = MagicMock()
        
        # Mock CFG data
        mock_r2.cmdj.side_effect = [
            # Function list
            [{"name": "main", "offset": 0x1000}],
            # Function CFG
            [
                {
                    "offset": 0x1000,
                    "size": 10,
                    "jump": 0x1010,
                    "fail": 0x1020,
                    "ops": [
                        {"type": "cmp", "opcode": "cmp eax, 0"},
                        {"type": "cjmp", "opcode": "je 0x1020"}
                    ]
                },
                {
                    "offset": 0x1010,
                    "size": 5,
                    "jump": 0x1030,
                    "ops": [{"type": "mov", "opcode": "mov eax, 1"}]
                },
                {
                    "offset": 0x1020,
                    "size": 5,
                    "jump": 0x1030,
                    "ops": [{"type": "mov", "opcode": "mov eax, 0"}]
                }
            ],
            # Additional analysis data
            [], []  # Empty responses for other queries
        ]
        
        mock_r2pipe.return_value.__enter__ = lambda self: mock_r2
        mock_r2pipe.return_value.__exit__ = lambda self, *args: None
        
        explorer = CFGExplorer()
        result = explorer.analyze_binary(self.test_binary)
        
        self.assertIn('functions_analyzed', result)
        self.assertIn('license_patterns', result)
        self.assertIn('complexity_metrics', result)


class IntegrationTestSuite:
    """Advanced integration test suite"""
    
    @staticmethod
    def run_all_tests():
        """Run all advanced integration tests"""
        # Create test suite
        suite = unittest.TestSuite()
        
        # Add all test classes
        test_classes = [
            TestRadare2VulnerabilityEngine,
            TestRadare2AIIntegration,
            TestRadare2BypassGenerator,
            TestRadare2BinaryDiff,
            TestRadare2Scripting,
            TestCFGExplorerEnhanced
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
    success = IntegrationTestSuite.run_all_tests()
    exit(0 if success else 1)