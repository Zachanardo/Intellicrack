"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Comprehensive Test Suite for Frida Integration

Tests all aspects of the Frida management system including:
- Core functionality
- Protection detection
- Performance optimization
- Bypass strategies
- GUI components
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Import Frida components
try:
    from intellicrack.core.frida_bypass_wizard import BypassStrategy, FridaBypassWizard, WizardState
    from intellicrack.core.frida_manager import (
        FridaManager,
        FridaOperationLogger,
        FridaPerformanceOptimizer,
        HookBatcher,
        HookCategory,
        ProtectionDetector,
        ProtectionType,
    )
    from intellicrack.core.frida_presets import (
        FRIDA_PRESETS,
        get_preset_by_software,
        get_scripts_for_protection,
    )
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class TestFridaOperationLogger(unittest.TestCase):
    """Test the Frida operation logging system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.temp_dir = tempfile.mkdtemp()
        self.logger = FridaOperationLogger(self.temp_dir)

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_initialization(self):
        """Test logger initialization"""
        self.assertTrue(self.logger.log_dir.exists())
        self.assertTrue(self.logger.operation_log.exists())
        self.assertTrue(self.logger.hook_log.exists())
        self.assertTrue(self.logger.performance_log.exists())
        self.assertTrue(self.logger.bypass_log.exists())

    def test_operation_logging(self):
        """Test operation logging"""
        # Log successful operation
        self.logger.log_operation(
            "test_operation",
            {"pid": 1234, "process_name": "test.exe"},
            success=True
        )

        # Log failed operation
        self.logger.log_operation(
            "failed_operation",
            {"pid": 5678},
            success=False,
            error="Test error"
        )

        # Check statistics
        stats = self.logger.get_statistics()
        self.assertEqual(stats['total_operations'], 2)

    def test_hook_logging(self):
        """Test hook logging"""
        # Log hook execution
        self.logger.log_hook(
            "CreateFileW",
            "kernel32.dll",
            ["C:\\test.txt", 0x80000000],
            return_value=0x12345678,
            modified=True
        )

        # Check statistics
        stats = self.logger.get_statistics()
        self.assertEqual(stats['successful_hooks'], 1)

    def test_performance_logging(self):
        """Test performance metric logging"""
        # Log performance metrics
        self.logger.log_performance("cpu_time", 45.5, "ms")
        self.logger.log_performance("memory_used", 512, "MB")

        # Check metrics
        stats = self.logger.get_statistics()
        self.assertIn('avg_cpu_time', stats)
        self.assertIn('max_memory_used', stats)

    def test_bypass_logging(self):
        """Test bypass attempt logging"""
        # Log successful bypass
        self.logger.log_bypass_attempt(
            ProtectionType.LICENSE,
            "api_hooking",
            success=True,
            details={"script": "license_bypass"}
        )

        # Log failed bypass
        self.logger.log_bypass_attempt(
            ProtectionType.ANTI_DEBUG,
            "patch_check",
            success=False
        )

        # Check statistics
        stats = self.logger.get_statistics()
        self.assertEqual(stats['bypasses_attempted'], 2)
        self.assertEqual(stats['bypasses_successful'], 1)
        self.assertEqual(stats['bypass_success_rate'], 50.0)

    def test_log_export(self):
        """Test log export functionality"""
        # Add some logs
        self.logger.log_operation("test", {"data": "test"}, True)

        # Export logs
        export_dir = self.logger.export_logs()
        self.assertTrue(Path(export_dir).exists())

        # Check exported files
        stats_file = Path(export_dir) / "statistics.json"
        self.assertTrue(stats_file.exists())

        with open(stats_file) as f:
            stats = json.load(f)
            self.assertIn('total_operations', stats)


class TestProtectionDetector(unittest.TestCase):
    """Test the protection detection system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.detector = ProtectionDetector()

    def test_api_detection(self):
        """Test API-based protection detection"""
        # Test anti-debug detection
        detected = self.detector.analyze_api_call(
            "kernel32.dll",
            "IsDebuggerPresent",
            []
        )
        self.assertIn(ProtectionType.ANTI_DEBUG, detected)

        # Test license detection
        detected = self.detector.analyze_api_call(
            "advapi32.dll",
            "RegQueryValueEx",
            ["HKLM\\Software\\License", "Key"]
        )
        self.assertIn(ProtectionType.LICENSE, detected)

    def test_string_detection(self):
        """Test string-based protection detection"""
        # Test license string
        detected = self.detector.analyze_string(
            "This is a trial version. License required."
        )
        self.assertIn(ProtectionType.LICENSE, detected)
        self.assertIn(ProtectionType.TIME, detected)

        # Test VM detection string
        detected = self.detector.analyze_string(
            "Running in VMware virtual machine"
        )
        self.assertIn(ProtectionType.ANTI_VM, detected)

    def test_adaptation_callbacks(self):
        """Test protection adaptation callbacks"""
        callback_called = False
        detected_type = None

        def test_callback(prot_type, details):
            nonlocal callback_called, detected_type
            callback_called = True
            detected_type = prot_type

        # Register callback
        self.detector.register_adaptation_callback(test_callback)

        # Trigger detection
        self.detector.notify_protection_detected(
            ProtectionType.LICENSE,
            {"test": "data"}
        )

        self.assertTrue(callback_called)
        self.assertEqual(detected_type, ProtectionType.LICENSE)

    def test_get_detected_protections(self):
        """Test retrieving detected protections"""
        # Detect some protections
        self.detector.analyze_api_call("kernel32.dll", "IsDebuggerPresent", [])
        self.detector.analyze_string("license.dat")

        # Get detections
        protections = self.detector.get_detected_protections()
        self.assertIn("Anti-Debugging", protections)
        self.assertIn("License Verification", protections)


class TestHookBatcher(unittest.TestCase):
    """Test the hook batching system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.batcher = HookBatcher(max_batch_size=5, batch_timeout_ms=50)

    def test_hook_batching(self):
        """Test hook batching functionality"""
        # Add hooks
        for i in range(10):
            self.batcher.add_hook(
                HookCategory.MEDIUM,
                {
                    'module': f'module{i}.dll',
                    'function': f'func{i}',
                    'priority': i
                }
            )

        # Check queue
        stats = self.batcher.get_batch_stats()
        self.assertEqual(stats['pending_hooks'], 10)

    def test_batch_categorization(self):
        """Test hook categorization"""
        # Add hooks with different categories
        self.batcher.add_hook(HookCategory.CRITICAL, {'module': 'critical.dll'})
        self.batcher.add_hook(HookCategory.HIGH, {'module': 'high.dll'})
        self.batcher.add_hook(HookCategory.LOW, {'module': 'low.dll'})

        # Check categorization
        stats = self.batcher.get_batch_stats()
        self.assertEqual(stats['categories']['CRITICAL'], 1)
        self.assertEqual(stats['categories']['HIGH'], 1)
        self.assertEqual(stats['categories']['LOW'], 1)


class TestFridaPerformanceOptimizer(unittest.TestCase):
    """Test the performance optimization system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.optimizer = FridaPerformanceOptimizer()

    def test_baseline_measurement(self):
        """Test baseline measurement"""
        self.optimizer.measure_baseline()
        self.assertGreater(self.optimizer.baseline_memory, 0)
        self.assertGreaterEqual(self.optimizer.baseline_cpu, 0)

    def test_hook_filtering(self):
        """Test selective hook filtering"""
        # Should always hook critical functions
        should_hook = self.optimizer.should_hook_function(
            "kernel32.dll",
            "VirtualProtect",
            HookCategory.CRITICAL
        )
        self.assertTrue(should_hook)

        # Test with high resource usage simulation
        with patch.object(self.optimizer, 'get_current_usage') as mock_usage:
            mock_usage.return_value = {
                'memory_mb': 600,
                'cpu_percent': 90,
                'threads': 50,
                'handles': 100
            }

            # Should not hook low priority with high usage
            should_hook = self.optimizer.should_hook_function(
                "user32.dll",
                "GetWindowText",
                HookCategory.LOW
            )
            self.assertFalse(should_hook)

    def test_script_optimization(self):
        """Test script optimization"""
        original_script = "Interceptor.attach(ptr('0x12345'), {});"
        optimized = self.optimizer.optimize_script(original_script)

        # Should add caching and batching code
        self.assertIn("_cache", optimized)
        self.assertIn("batchedSend", optimized)
        self.assertIn(original_script, optimized)

    def test_optimization_recommendations(self):
        """Test optimization recommendations"""
        # Simulate high resource usage
        with patch.object(self.optimizer, 'get_current_usage') as mock_usage:
            mock_usage.return_value = {
                'memory_mb': 1500,
                'cpu_percent': 85,
                'threads': 100,
                'handles': 500
            }

            recommendations = self.optimizer.get_optimization_recommendations()
            self.assertTrue(len(recommendations) > 0)
            self.assertTrue(any("memory" in r.lower() for r in recommendations))
            self.assertTrue(any("cpu" in r.lower() for r in recommendations))


class TestFridaManager(unittest.TestCase):
    """Test the main Frida manager"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.temp_dir = tempfile.mkdtemp()
        self.manager = FridaManager(self.temp_dir)

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        if hasattr(self, 'manager'):
            self.manager.cleanup()

    @patch('frida.get_local_device')
    def test_process_attachment(self, mock_device):
        """Test process attachment"""
        # Mock Frida device and session
        mock_session = MagicMock()
        mock_session.pid = 1234
        mock_session.get_process_name.return_value = "test.exe"

        mock_device.return_value.attach.return_value = mock_session

        # Test attachment
        success = self.manager.attach_to_process(1234)
        self.assertTrue(success)
        self.assertIn("test.exe_1234", self.manager.sessions)

    def test_script_loading(self):
        """Test script loading"""
        # Create test script
        test_script = Path(self.manager.script_dir) / "test_script.js"
        test_script.parent.mkdir(parents=True, exist_ok=True)
        test_script.write_text("console.log('test');")

        # Mock session
        mock_session = MagicMock()
        mock_script = MagicMock()
        mock_session.create_script.return_value = mock_script

        self.manager.sessions["test_session"] = mock_session

        # Load script
        success = self.manager.load_script("test_session", "test_script")
        self.assertTrue(success)
        mock_script.load.assert_called_once()

    def test_selective_instrumentation(self):
        """Test selective instrumentation generation"""
        script = self.manager.create_selective_instrumentation(
            target_apis=['kernel32.dll!CreateFileW', 'ntdll.dll!NtOpenFile'],
            analysis_requirements={
                'trace_api_calls': True,
                'monitor_memory': True,
                'detect_protections': True
            }
        )

        # Check generated script
        self.assertIn("CreateFileW", script)
        self.assertIn("NtOpenFile", script)
        self.assertIn("Memory Monitoring", script)
        self.assertIn("Protection Detection", script)

    def test_statistics_generation(self):
        """Test statistics generation"""
        stats = self.manager.get_statistics()

        # Check structure
        self.assertIn('logger', stats)
        self.assertIn('detector', stats)
        self.assertIn('batcher', stats)
        self.assertIn('optimizer', stats)
        self.assertIn('sessions', stats)
        self.assertIn('scripts', stats)


class TestFridaBypassWizard(unittest.TestCase):
    """Test the automated bypass wizard"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.manager = FridaManager()
        self.wizard = FridaBypassWizard(self.manager)

    def test_wizard_modes(self):
        """Test wizard mode settings"""
        # Test mode setting
        self.wizard.set_mode("aggressive")
        self.assertEqual(self.wizard.mode, "aggressive")
        self.assertEqual(self.wizard.config['name'], "Aggressive Mode")

        # Test invalid mode
        self.wizard.set_mode("invalid")
        self.assertEqual(self.wizard.mode, "balanced")  # Should default

    def test_bypass_strategy(self):
        """Test bypass strategy creation"""
        strategy = BypassStrategy(
            ProtectionType.LICENSE,
            ["license_bypass", "registry_monitor"],
            priority=80,
            dependencies=[ProtectionType.ANTI_DEBUG]
        )

        # Test properties
        self.assertEqual(strategy.protection_type, ProtectionType.LICENSE)
        self.assertEqual(len(strategy.scripts), 2)
        self.assertEqual(strategy.priority, 80)

        # Test dependency checking
        can_apply = strategy.can_apply({ProtectionType.ANTI_DEBUG})
        self.assertTrue(can_apply)

        can_apply = strategy.can_apply(set())
        self.assertFalse(can_apply)
        
    def test_wizard_state(self):
        """Test wizard state management"""
        # Test initial state
        initial_state = WizardState()
        self.assertEqual(initial_state.phase, "idle")
        self.assertFalse(initial_state.is_running)
        self.assertEqual(initial_state.progress, 0)
        self.assertIsNone(initial_state.current_protection)
        self.assertEqual(len(initial_state.completed_protections), 0)
        self.assertEqual(len(initial_state.errors), 0)
        
        # Test state transitions
        initial_state.phase = "analyzing"
        initial_state.is_running = True
        initial_state.progress = 25
        self.assertEqual(initial_state.phase, "analyzing")
        self.assertTrue(initial_state.is_running)
        self.assertEqual(initial_state.progress, 25)
        
        # Test protection tracking
        initial_state.current_protection = ProtectionType.LICENSE
        initial_state.completed_protections.append(ProtectionType.ANTI_DEBUG)
        self.assertEqual(initial_state.current_protection, ProtectionType.LICENSE)
        self.assertIn(ProtectionType.ANTI_DEBUG, initial_state.completed_protections)
        
        # Test error tracking
        initial_state.errors.append({"type": "hook_failed", "message": "Failed to hook function"})
        self.assertEqual(len(initial_state.errors), 1)
        self.assertEqual(initial_state.errors[0]["type"], "hook_failed")

    @patch.object(FridaBypassWizard, '_analyze_process')
    @patch.object(FridaBypassWizard, '_detect_protections')
    async def test_wizard_execution(self, mock_detect, mock_analyze):
        """Test wizard execution flow"""
        # Set up mocks
        mock_analyze.return_value = None
        mock_detect.return_value = None

        # Set detected protections
        self.wizard.detected_protections = {
            ProtectionType.LICENSE: True,
            ProtectionType.TIME: True
        }

        # Test planning
        await self.wizard._plan_strategy()

        # Check strategies
        self.assertTrue(len(self.wizard.strategies) > 0)
        self.assertTrue(any(
            s.protection_type == ProtectionType.LICENSE
            for s in self.wizard.strategies
        ))

    def test_protection_detection_by_imports(self):
        """Test protection detection from imports"""
        # Set test imports
        self.wizard.analysis_results['imports'] = [
            {'name': 'IsDebuggerPresent', 'module': 'kernel32.dll'},
            {'name': 'GetTickCount', 'module': 'kernel32.dll'},
            {'name': 'RegQueryValueEx', 'module': 'advapi32.dll'}
        ]

        # Analyze imports
        self.wizard._analyze_imports_for_protections()

        # Check detections
        self.assertIn(ProtectionType.ANTI_DEBUG, self.wizard.detected_protections)
        self.assertIn(ProtectionType.TIME, self.wizard.detected_protections)
        self.assertIn(ProtectionType.LICENSE, self.wizard.detected_protections)


class TestFridaPresets(unittest.TestCase):
    """Test preset configurations"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

    def test_preset_structure(self):
        """Test preset configuration structure"""
        # Check Adobe preset
        adobe_preset = FRIDA_PRESETS.get("Adobe Creative Cloud")
        self.assertIsNotNone(adobe_preset)
        self.assertIn('description', adobe_preset)
        self.assertIn('scripts', adobe_preset)
        self.assertIn('protections', adobe_preset)
        self.assertIn('options', adobe_preset)

        # Check scripts list
        self.assertIsInstance(adobe_preset['scripts'], list)
        self.assertGreater(len(adobe_preset['scripts']), 0)

    def test_preset_lookup(self):
        """Test preset lookup by software name"""
        # Test exact match
        preset = get_preset_by_software("Adobe")
        self.assertIsNotNone(preset)
        self.assertIn("Adobe", preset.get('target', ''))

        # Test fuzzy match
        preset = get_preset_by_software("photoshop")
        self.assertIsNotNone(preset)

        # Test no match
        preset = get_preset_by_software("Unknown Software XYZ")
        self.assertEqual(preset['scripts'], ["registry_monitor"])  # Minimal preset

    def test_protection_script_mapping(self):
        """Test protection to script mapping"""
        # Test license scripts
        scripts = get_scripts_for_protection("LICENSE")
        self.assertIn("cloud_licensing_bypass", scripts)
        self.assertIn("registry_monitor", scripts)

        # Test anti-debug scripts
        scripts = get_scripts_for_protection("ANTI_DEBUG")
        self.assertIn("anti_debugger", scripts)

        # Test unknown protection
        scripts = get_scripts_for_protection("UNKNOWN")
        self.assertEqual(scripts, [])


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""

    def setUp(self):
        """Set up test environment"""
        if not FRIDA_AVAILABLE:
            self.skipTest("Frida modules not available")

        self.temp_dir = tempfile.mkdtemp()
        self.manager = FridaManager(self.temp_dir)
        self.wizard = FridaBypassWizard(self.manager)

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        if hasattr(self, 'manager'):
            self.manager.cleanup()

    def test_full_workflow(self):
        """Test complete workflow from detection to bypass"""
        # Simulate API detection
        self.manager.detector.analyze_api_call(
            "kernel32.dll",
            "IsDebuggerPresent",
            []
        )

        # Check detection
        protections = self.manager.detector.get_detected_protections()
        self.assertIn("Anti-Debugging", protections)

        # Get statistics
        stats = self.manager.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('detector', stats)

    def test_export_functionality(self):
        """Test analysis export"""
        # Add some data
        self.manager.logger.log_operation("test", {"data": "test"}, True)
        self.manager.detector.analyze_api_call("kernel32.dll", "IsDebuggerPresent", [])

        # Export analysis
        export_dir = self.manager.export_analysis()
        self.assertTrue(Path(export_dir).exists())

        # Check summary file
        summary_file = Path(export_dir) / "analysis_summary.json"
        self.assertTrue(summary_file.exists())

        with open(summary_file) as f:
            summary = json.load(f)
            self.assertIn('statistics', summary)
            self.assertIn('detected_protections', summary)


def run_tests():
    """Run all tests"""
    unittest.main()


if __name__ == '__main__':
    run_tests()
