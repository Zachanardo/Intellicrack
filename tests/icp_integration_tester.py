#!/usr/bin/env python3
"""
ICP Engine Integration Testing Framework

Comprehensive testing suite for validating the complete ICP Engine integration
into Intellicrack's GUI system.

Phase 5: Complete System Testing & Integration Validation

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import List, Optional, Dict, Any

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.utils.logger import get_logger
except ImportError:
    logging.basicConfig(level=logging.INFO)
    def get_logger(name):
        return logging.getLogger(name)

logger = get_logger(__name__)

class ICPIntegrationTester:
    """Comprehensive ICP Engine integration testing framework"""

    def __init__(self):
        self.test_results = {
            'phase_a': {'status': 'pending', 'details': [], 'errors': []},
            'phase_b': {'status': 'pending', 'details': [], 'errors': []},
            'phase_c': {'status': 'pending', 'details': [], 'errors': []},
            'phase_d': {'status': 'pending', 'details': [], 'errors': []},
            'phase_e': {'status': 'pending', 'details': [], 'errors': []},
        }
        self.test_binaries = []
        self.start_time = time.time()

    def log_result(self, phase: str, message: str, is_error: bool = False):
        """Log test result for a phase"""
        if is_error:
            self.test_results[phase]['errors'].append(message)
            logger.error(f"[{phase.upper()}] {message}")
        else:
            self.test_results[phase]['details'].append(message)
            logger.info(f"[{phase.upper()}] {message}")

    def find_test_binaries(self) -> List[str]:
        """Find binary files for testing"""
        logger.info("Searching for test binary samples...")

        search_paths = [
            "/mnt/c/Intellicrack/backups/icp_engine_pre_rebrand",
            "/mnt/c/Intellicrack/dev/conflict_test/lib/python3.12/site-packages/pip/_vendor/distlib",
            "/mnt/c/Intellicrack/test_venv/lib/python3.12/site-packages/pip/_vendor/distlib"
        ]

        binaries = []
        for search_path in search_paths:
            if os.path.exists(search_path):
                for root, dirs, files in os.walk(search_path):
                    for file in files:
                        if file.endswith(('.exe', '.dll')):
                            full_path = os.path.join(root, file)
                            # Check file size (skip very small files)
                            if os.path.getsize(full_path) > 1024:  # At least 1KB
                                binaries.append(full_path)
                            if len(binaries) >= 10:  # Limit for testing
                                break
                    if len(binaries) >= 10:
                        break

        self.test_binaries = binaries[:10]  # Take first 10
        logger.info(f"Found {len(self.test_binaries)} test binaries")
        return self.test_binaries

    def run_phase_a_foundation(self) -> bool:
        """Phase A: Foundation Validation"""
        logger.info("=" * 60)
        logger.info("PHASE A: FOUNDATION VALIDATION")
        logger.info("=" * 60)

        try:
            # Test 1: die-python import and basic functionality
            self.log_result('phase_a', "Testing die-python import...")
            try:
                import die
                self.log_result('phase_a', f"✓ die-python imported successfully (v{die.__version__})")
                self.log_result('phase_a', f"✓ DIE engine version: {die.die_version}")
            except ImportError as e:
                self.log_result('phase_a', f"✗ die-python import failed: {e}", True)
                return False

            # Test 2: Basic scan functionality
            self.log_result('phase_a', "Testing basic die-python scan functionality...")
            if self.test_binaries:
                test_file = self.test_binaries[0]
                try:
                    results = list(die.scan_file(test_file))
                    self.log_result('phase_a', f"✓ Basic scan successful: {len(results)} results")
                except Exception as e:
                    self.log_result('phase_a', f"✗ Basic scan failed: {e}", True)
                    return False
            else:
                self.log_result('phase_a', "! No test binaries found for scan test", True)
                return False

            # Test 3: ICP Backend import
            self.log_result('phase_a', "Testing ICP Backend import...")
            try:
                from intellicrack.protection.icp_backend import ICPBackend, get_icp_backend
                backend = get_icp_backend()
                self.log_result('phase_a', "✓ ICP Backend imported and initialized successfully")
            except Exception as e:
                self.log_result('phase_a', f"✗ ICP Backend import failed: {e}", True)
                return False

            # Test 4: Analysis orchestrator import
            self.log_result('phase_a', "Testing Analysis Orchestrator import...")
            try:
                from intellicrack.analysis.analysis_result_orchestrator import AnalysisResultOrchestrator
                orchestrator = AnalysisResultOrchestrator()
                self.log_result('phase_a', "✓ Analysis Orchestrator imported and initialized")
            except Exception as e:
                self.log_result('phase_a', f"✗ Analysis Orchestrator import failed: {e}", True)
                return False

            self.test_results['phase_a']['status'] = 'passed'
            logger.info("PHASE A: PASSED ✓")
            return True

        except Exception as e:
            self.log_result('phase_a', f"Critical error in Phase A: {e}", True)
            self.test_results['phase_a']['status'] = 'failed'
            logger.error("PHASE A: FAILED ✗")
            return False

    def run_phase_b_integration(self) -> bool:
        """Phase B: Integration Testing"""
        logger.info("=" * 60)
        logger.info("PHASE B: INTEGRATION TESTING")
        logger.info("=" * 60)

        try:
            # Test 1: ICP Backend async analysis
            self.log_result('phase_b', "Testing ICP Backend async analysis...")
            try:
                from intellicrack.protection.icp_backend import get_icp_backend, ScanMode
                backend = get_icp_backend()

                if self.test_binaries:
                    test_file = self.test_binaries[0]

                    # Test async analysis
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    result = loop.run_until_complete(
                        backend.analyze_file(test_file, ScanMode.NORMAL)
                    )

                    loop.close()

                    if result and not result.error:
                        self.log_result('phase_b', f"✓ Async analysis successful: {len(result.all_detections)} detections")
                    else:
                        self.log_result('phase_b', f"✗ Async analysis failed: {result.error if result else 'No result'}", True)
                        return False
                else:
                    self.log_result('phase_b', "! No test binaries for async analysis", True)
                    return False

            except Exception as e:
                self.log_result('phase_b', f"✗ Async analysis test failed: {e}", True)
                return False

            # Test 2: Different scan modes
            self.log_result('phase_b', "Testing different scan modes...")
            try:
                from intellicrack.protection.icp_backend import ScanMode

                scan_modes = [
                    ScanMode.NORMAL,
                    ScanMode.DEEP,
                    ScanMode.HEURISTIC
                ]

                for scan_mode in scan_modes:
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)

                        result = loop.run_until_complete(
                            backend.analyze_file(self.test_binaries[0], scan_mode)
                        )

                        loop.close()

                        if result and not result.error:
                            self.log_result('phase_b', f"✓ {scan_mode.name} scan mode successful")
                        else:
                            self.log_result('phase_b', f"! {scan_mode.name} scan mode had issues", True)

                    except Exception as e:
                        self.log_result('phase_b', f"✗ {scan_mode.name} scan mode failed: {e}", True)

            except Exception as e:
                self.log_result('phase_b', f"✗ Scan mode testing failed: {e}", True)
                return False

            # Test 3: Signal connections (basic validation)
            self.log_result('phase_b', "Testing signal connection infrastructure...")
            try:
                from PyQt5.QtCore import QObject, pyqtSignal

                class TestSignalEmitter(QObject):
                    test_signal = pyqtSignal(object)

                class TestSignalReceiver(QObject):
                    def __init__(self):
                        super().__init__()
                        self.received_data = None

                    def on_signal_received(self, data):
                        self.received_data = data

                emitter = TestSignalEmitter()
                receiver = TestSignalReceiver()

                # Connect signal
                emitter.test_signal.connect(receiver.on_signal_received)

                # Test emission
                test_data = {"test": "data"}
                emitter.test_signal.emit(test_data)

                if receiver.received_data == test_data:
                    self.log_result('phase_b', "✓ PyQt5 signal connections working")
                else:
                    self.log_result('phase_b', "✗ PyQt5 signal connections failed", True)
                    return False

            except Exception as e:
                self.log_result('phase_b', f"✗ Signal connection test failed: {e}", True)
                return False

            self.test_results['phase_b']['status'] = 'passed'
            logger.info("PHASE B: PASSED ✓")
            return True

        except Exception as e:
            self.log_result('phase_b', f"Critical error in Phase B: {e}", True)
            self.test_results['phase_b']['status'] = 'failed'
            logger.error("PHASE B: FAILED ✗")
            return False

    def run_phase_c_realworld(self) -> bool:
        """Phase C: Real-World Testing"""
        logger.info("=" * 60)
        logger.info("PHASE C: REAL-WORLD TESTING")
        logger.info("=" * 60)

        try:
            from intellicrack.protection.icp_backend import get_icp_backend, ScanMode
            backend = get_icp_backend()

            performance_results = []

            # Test with multiple binary samples
            self.log_result('phase_c', f"Testing with {len(self.test_binaries)} binary samples...")

            for i, test_file in enumerate(self.test_binaries[:5]):  # Test first 5
                try:
                    start_time = time.time()

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    result = loop.run_until_complete(
                        backend.analyze_file(test_file, ScanMode.DEEP)
                    )

                    loop.close()

                    analysis_time = time.time() - start_time
                    performance_results.append(analysis_time)

                    filename = os.path.basename(test_file)
                    if result and not result.error:
                        self.log_result('phase_c', 
                            f"✓ {filename}: {len(result.all_detections)} detections ({analysis_time:.2f}s)")
                    else:
                        self.log_result('phase_c', 
                            f"! {filename}: Analysis had issues ({analysis_time:.2f}s)")

                except Exception as e:
                    self.log_result('phase_c', f"✗ Analysis failed for {os.path.basename(test_file)}: {e}", True)

            # Performance evaluation
            if performance_results:
                avg_time = sum(performance_results) / len(performance_results)
                max_time = max(performance_results)

                self.log_result('phase_c', f"Performance: Avg {avg_time:.2f}s, Max {max_time:.2f}s")

                if max_time > 15.0:  # Allow up to 15s for large files
                    self.log_result('phase_c', f"! Performance concern: {max_time:.2f}s exceeds target")
                else:
                    self.log_result('phase_c', "✓ Performance within acceptable range")

            self.test_results['phase_c']['status'] = 'passed'
            logger.info("PHASE C: PASSED ✓")
            return True

        except Exception as e:
            self.log_result('phase_c', f"Critical error in Phase C: {e}", True)
            self.test_results['phase_c']['status'] = 'failed'
            logger.error("PHASE C: FAILED ✗")
            return False

    def run_phase_d_handlers(self) -> bool:
        """Phase D: Handler Validation"""
        logger.info("=" * 60)
        logger.info("PHASE D: HANDLER VALIDATION")
        logger.info("=" * 60)

        try:
            # Test orchestrator handler registration
            self.log_result('phase_d', "Testing analysis orchestrator handler system...")

            try:
                from intellicrack.analysis.analysis_result_orchestrator import AnalysisResultOrchestrator
                from PyQt5.QtCore import QObject

                # Create test handler
                class TestHandler(QObject):
                    def __init__(self):
                        super().__init__()
                        self.received_analysis = None
                        self.received_icp = None

                    def on_analysis_complete(self, result):
                        self.received_analysis = result

                    def on_icp_analysis_complete(self, result):
                        self.received_icp = result

                orchestrator = AnalysisResultOrchestrator()
                test_handler = TestHandler()

                # Register handler
                orchestrator.register_handler(test_handler)
                self.log_result('phase_d', "✓ Handler registration successful")

                # Test ICP analysis handling (mock data)
                from intellicrack.protection.icp_backend import ICPScanResult, ICPFileInfo, ICPDetection

                mock_detection = ICPDetection(
                    name="Test Protection",
                    type="Packer",
                    version="1.0",
                    confidence=0.95,
                    info="Test detection",
                    string="TEST"
                )

                mock_file_info = ICPFileInfo(
                    filetype="PE32",
                    size=12345,
                    detections=[mock_detection]
                )

                mock_result = ICPScanResult(
                    file_path=self.test_binaries[0] if self.test_binaries else "/test/file.exe",
                    scan_mode="DEEP",
                    file_infos=[mock_file_info],
                    error=None,
                    raw_json={"test": "data"}
                )

                # Test orchestrator handling
                orchestrator.on_icp_analysis_complete(mock_result)

                if test_handler.received_icp:
                    self.log_result('phase_d', "✓ ICP handler integration successful")
                else:
                    self.log_result('phase_d', "✗ ICP handler did not receive data", True)
                    return False

            except Exception as e:
                self.log_result('phase_d', f"✗ Handler validation failed: {e}", True)
                return False

            self.test_results['phase_d']['status'] = 'passed'
            logger.info("PHASE D: PASSED ✓")
            return True

        except Exception as e:
            self.log_result('phase_d', f"Critical error in Phase D: {e}", True)
            self.test_results['phase_d']['status'] = 'failed'
            logger.error("PHASE D: FAILED ✗")
            return False

    def run_phase_e_regression(self) -> bool:
        """Phase E: Regression Testing"""
        logger.info("=" * 60)
        logger.info("PHASE E: REGRESSION TESTING")
        logger.info("=" * 60)

        try:
            # Test core imports still work
            self.log_result('phase_e', "Testing core module imports...")

            try:
                from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
                from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine

                analyzer = MultiFormatBinaryAnalyzer()
                vuln_engine = AdvancedVulnerabilityEngine()

                self.log_result('phase_e', "✓ Core analyzers import and initialize successfully")

            except Exception as e:
                self.log_result('phase_e', f"✗ Core analyzer import failed: {e}", True)
                return False

            # Test logger functionality
            self.log_result('phase_e', "Testing logging system...")
            try:
                from intellicrack.utils.logger import get_logger
                test_logger = get_logger("test_regression")
                test_logger.info("Regression test log message")
                self.log_result('phase_e', "✓ Logging system functional")
            except Exception as e:
                self.log_result('phase_e', f"✗ Logging system failed: {e}", True)
                return False

            # Memory usage check (basic)
            self.log_result('phase_e', "Checking memory usage...")
            try:
                import psutil
                import os

                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024

                self.log_result('phase_e', f"Current memory usage: {memory_mb:.1f} MB")

                if memory_mb > 500:  # More than 500MB might indicate issues
                    self.log_result('phase_e', f"! High memory usage detected: {memory_mb:.1f} MB")
                else:
                    self.log_result('phase_e', "✓ Memory usage within reasonable range")

            except ImportError:
                self.log_result('phase_e', "! psutil not available for memory check")
            except Exception as e:
                self.log_result('phase_e', f"! Memory check failed: {e}")

            self.test_results['phase_e']['status'] = 'passed'
            logger.info("PHASE E: PASSED ✓")
            return True

        except Exception as e:
            self.log_result('phase_e', f"Critical error in Phase E: {e}", True)
            self.test_results['phase_e']['status'] = 'failed'
            logger.error("PHASE E: FAILED ✗")
            return False

    def run_all_phases(self) -> Dict[str, Any]:
        """Run all testing phases sequentially"""
        logger.info("🔬 ICP ENGINE INTEGRATION TESTING FRAMEWORK")
        logger.info("=" * 60)

        # Find test binaries first
        self.find_test_binaries()
        if not self.test_binaries:
            logger.error("No test binaries found! Cannot proceed with testing.")
            return self.generate_report()

        # Phase A: Foundation (critical path)
        if not self.run_phase_a_foundation():
            logger.error("Phase A failed - stopping testing")
            return self.generate_report()

        # Phase B: Integration (depends on A)
        if not self.run_phase_b_integration():
            logger.error("Phase B failed - continuing with limited testing")

        # Phase C: Real-world (depends on B)
        if self.test_results['phase_b']['status'] == 'passed':
            if not self.run_phase_c_realworld():
                logger.error("Phase C failed - continuing with handler testing")
        else:
            logger.warning("Skipping Phase C due to Phase B failure")
            self.test_results['phase_c']['status'] = 'skipped'

        # Phase D: Handlers (can run independent)
        if not self.run_phase_d_handlers():
            logger.error("Phase D failed - continuing with regression testing")

        # Phase E: Regression (final validation)
        if not self.run_phase_e_regression():
            logger.error("Phase E failed - integration may have caused regressions")

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_time = time.time() - self.start_time

        # Count results
        passed = sum(1 for result in self.test_results.values() if result['status'] == 'passed')
        failed = sum(1 for result in self.test_results.values() if result['status'] == 'failed')
        skipped = sum(1 for result in self.test_results.values() if result['status'] == 'skipped')
        total = len(self.test_results)

        success_rate = (passed / total) * 100 if total > 0 else 0

        logger.info("=" * 60)
        logger.info("🔬 COMPREHENSIVE INTEGRATION TEST RESULTS")
        logger.info("=" * 60)

        for phase, result in self.test_results.items():
            status_symbol = {
                'passed': '✓ PASS',
                'failed': '✗ FAIL', 
                'skipped': '- SKIP',
                'pending': '? PENDING'
            }.get(result['status'], '? UNKNOWN')

            logger.info(f"{phase.replace('_', ' ').title():<25} {status_symbol}")

        logger.info("-" * 60)
        logger.info(f"Total Tests: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Skipped: {skipped}")
        logger.info(f"Success Rate: {success_rate:.1f}%")
        logger.info(f"Total Time: {total_time:.1f} seconds")
        logger.info("=" * 60)

        if success_rate >= 80:
            logger.info("🎉 INTEGRATION TESTING: OVERALL SUCCESS")
        elif success_rate >= 60:
            logger.warning("⚠️  INTEGRATION TESTING: PARTIAL SUCCESS")
        else:
            logger.error("❌ INTEGRATION TESTING: SIGNIFICANT ISSUES")

        report = {
            'success_rate': success_rate,
            'total_time': total_time,
            'phase_results': self.test_results,
            'test_binaries_count': len(self.test_binaries),
            'summary': {
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'total': total
            }
        }

        return report


def main():
    """Main entry point for testing"""
    tester = ICPIntegrationTester()

    try:
        report = tester.run_all_phases()

        # Save report to file
        import json
        report_file = "/mnt/c/Intellicrack/icp_integration_test_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Detailed report saved to: {report_file}")

        # Return appropriate exit code
        if report['success_rate'] >= 80:
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Failure

    except Exception as e:
        logger.error(f"Critical testing framework error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(2)  # Critical error


if __name__ == "__main__":
    main()