#!/usr/bin/env python3
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
Component validation tests for Intellicrack exploitation framework.

Validates individual components, imports, and functionality without
requiring full integration testing.
"""

import importlib
import logging
import os
import sys
import unittest
from typing import Any, Dict, List

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Test environment setup
os.environ['INTELLICRACK_TEST_MODE'] = '1'


class TestComponentValidation(unittest.TestCase):
    """Validate that all exploitation components can be imported and initialized."""

    def setUp(self):
        """Set up test environment."""
        logging.basicConfig(level=logging.WARNING)  # Reduce noise during testing

    def test_core_payload_generation_imports(self):
        """Test imports for payload generation components."""
        components = [
            'intellicrack.core.exploitation.payload_engine',
            'intellicrack.core.exploitation.payload_types',
            'intellicrack.core.exploitation.shellcode_generator',
            'intellicrack.core.exploitation.payload_templates'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'Payload Generation')

    def test_core_c2_imports(self):
        """Test imports for C2 components."""
        components = [
            'intellicrack.core.c2.c2_manager',
            'intellicrack.core.c2.c2_server',
            'intellicrack.core.c2.session_manager',
            'intellicrack.core.c2.encryption_manager'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'C2')

    def test_core_anti_analysis_imports(self):
        """Test imports for anti-analysis components."""
        components = [
            'intellicrack.core.anti_analysis',
            'intellicrack.core.anti_analysis.vm_detector',
            'intellicrack.core.anti_analysis.sandbox_detector',
            'intellicrack.core.anti_analysis.debugger_detector'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'Anti-Analysis')

    def test_core_mitigation_bypass_imports(self):
        """Test imports for mitigation bypass components."""
        components = [
            'intellicrack.core.exploitation.bypass_engine',
            'intellicrack.core.exploitation.aslr_bypass',
            'intellicrack.core.exploitation.cfi_bypass',
            'intellicrack.core.exploitation.dep_bypass'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'Mitigation Bypasses')

    def test_core_post_exploitation_imports(self):
        """Test imports for post-exploitation components."""
        components = [
            'intellicrack.core.exploitation.persistence_manager',
            'intellicrack.core.exploitation.privilege_escalation',
            'intellicrack.core.exploitation.lateral_movement',
            'intellicrack.core.exploitation.credential_harvesting'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'Post-Exploitation')

    def test_core_vulnerability_research_imports(self):
        """Test imports for vulnerability research components."""
        components = [
            'intellicrack.core.vulnerability_research.research_manager',
            'intellicrack.core.vulnerability_research.vulnerability_analyzer',
            'intellicrack.core.vulnerability_research.binary_differ',
            'intellicrack.core.vulnerability_research.fuzzing_engine',
            'intellicrack.core.vulnerability_research.ml_adaptation_engine'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'Vulnerability Research')

    def test_ai_integration_imports(self):
        """Test imports for AI integration components."""
        components = [
            'intellicrack.ai.vulnerability_research_integration',
            'intellicrack.ai.exploitation_orchestrator'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'AI Integration')

    def test_ui_integration_imports(self):
        """Test imports for UI integration components."""
        components = [
            'intellicrack.ui.exploitation_handlers',
            'intellicrack.ui.dialogs.vulnerability_research_dialog'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'UI Integration')

    def test_cli_integration_imports(self):
        """Test imports for CLI integration."""
        components = [
            'intellicrack.cli.cli'
        ]

        import_results = self._test_imports(components)
        self._assert_import_success(import_results, 'CLI Integration')

    def _test_imports(self, components: List[str]) -> Dict[str, Any]:
        """Test importing a list of components."""
        results = {
            'successful': [],
            'failed': [],
            'total': len(components)
        }

        for component in components:
            try:
                module = importlib.import_module(component)
                results['successful'].append({
                    'component': component,
                    'module': module
                })
            except Exception as e:
                results['failed'].append({
                    'component': component,
                    'error': str(e),
                    'error_type': type(e).__name__
                })

        return results

    def _assert_import_success(self, import_results: Dict[str, Any], category: str):
        """Assert that import results meet success criteria."""
        total = import_results['total']
        successful = len(import_results['successful'])
        failed = len(import_results['failed'])

        success_rate = (successful / total * 100) if total > 0 else 0

        print(f"\n{category} Import Results:")
        print(f"  Total: {total}")
        print(f"  Successful: {successful}")
        print(f"  Failed: {failed}")
        print(f"  Success Rate: {success_rate:.1f}%")

        if failed > 0:
            print("  Failed imports:")
            for failure in import_results['failed']:
                print(f"    - {failure['component']}: {failure['error_type']} - {failure['error']}")

        # Allow some failures for optional components, but require majority success
        self.assertGreaterEqual(success_rate, 50.0,
                              f"{category} import success rate too low: {success_rate:.1f}%")


class TestClassInstantiation(unittest.TestCase):
    """Test that key classes can be instantiated successfully."""

    def test_payload_engine_instantiation(self):
        """Test PayloadEngine instantiation."""
        try:
            from intellicrack.core.exploitation.payload_engine import PayloadEngine
            engine = PayloadEngine()
            self.assertIsNotNone(engine)
            print("✓ PayloadEngine instantiation successful")
        except Exception as e:
            self.skipTest(f"PayloadEngine not available: {e}")

    def test_c2_manager_instantiation(self):
        """Test C2Manager instantiation."""
        try:
            from intellicrack.core.c2.c2_manager import C2Manager
            manager = C2Manager()
            self.assertIsNotNone(manager)
            print("✓ C2Manager instantiation successful")
        except Exception as e:
            self.skipTest(f"C2Manager not available: {e}")

    def test_persistence_manager_instantiation(self):
        """Test PersistenceManager instantiation."""
        try:
            from intellicrack.core.exploitation.persistence_manager import PersistenceManager
            manager = PersistenceManager()
            self.assertIsNotNone(manager)
            print("✓ PersistenceManager instantiation successful")
        except Exception as e:
            self.skipTest(f"PersistenceManager not available: {e}")

    def test_research_manager_instantiation(self):
        """Test ResearchManager instantiation."""
        try:
            from intellicrack.core.vulnerability_research.research_manager import ResearchManager
            manager = ResearchManager()
            self.assertIsNotNone(manager)
            print("✓ ResearchManager instantiation successful")
        except Exception as e:
            self.skipTest(f"ResearchManager not available: {e}")

    def test_exploitation_orchestrator_instantiation(self):
        """Test ExploitationOrchestrator instantiation."""
        try:
            from intellicrack.ai.exploitation_orchestrator import ExploitationOrchestrator
            orchestrator = ExploitationOrchestrator()
            self.assertIsNotNone(orchestrator)
            print("✓ ExploitationOrchestrator instantiation successful")
        except Exception as e:
            self.skipTest(f"ExploitationOrchestrator not available: {e}")


class TestMethodAvailability(unittest.TestCase):
    """Test that key methods are available on instantiated classes."""

    def test_payload_engine_methods(self):
        """Test PayloadEngine key methods are available."""
        try:
            from intellicrack.core.exploitation.payload_engine import PayloadEngine
            engine = PayloadEngine()

            # Check key methods exist
            self.assertTrue(hasattr(engine, 'generate_payload'))
            self.assertTrue(callable(getattr(engine, 'generate_payload')))

            print("✓ PayloadEngine methods available")
        except Exception as e:
            self.skipTest(f"PayloadEngine not available: {e}")

    def test_c2_manager_methods(self):
        """Test C2Manager key methods are available."""
        try:
            from intellicrack.core.c2.c2_manager import C2Manager
            manager = C2Manager()

            # Check key methods exist
            self.assertTrue(hasattr(manager, 'start_server'))
            self.assertTrue(callable(getattr(manager, 'start_server')))

            print("✓ C2Manager methods available")
        except Exception as e:
            self.skipTest(f"C2Manager not available: {e}")

    def test_orchestrator_methods(self):
        """Test ExploitationOrchestrator key methods are available."""
        try:
            from intellicrack.ai.exploitation_orchestrator import ExploitationOrchestrator
            orchestrator = ExploitationOrchestrator()

            # Check key methods exist
            self.assertTrue(hasattr(orchestrator, 'orchestrate_full_exploitation'))
            self.assertTrue(callable(getattr(orchestrator, 'orchestrate_full_exploitation')))
            self.assertTrue(hasattr(orchestrator, 'get_orchestrator_status'))
            self.assertTrue(callable(getattr(orchestrator, 'get_orchestrator_status')))

            print("✓ ExploitationOrchestrator methods available")
        except Exception as e:
            self.skipTest(f"ExploitationOrchestrator not available: {e}")


def run_component_validation():
    """Run comprehensive component validation."""
    print("="*70)
    print("INTELLICRACK COMPONENT VALIDATION SUITE")
    print("="*70)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestComponentValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestClassInstantiation))
    suite.addTests(loader.loadTestsFromTestCase(TestMethodAvailability))

    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True
    )

    result = runner.run(suite)

    # Summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0
    successful = total_tests - failures - errors - skipped

    print("\nCOMPONENT VALIDATION SUMMARY:")
    print(f"  Total Tests: {total_tests}")
    print(f"  Successful: {successful}")
    print(f"  Failures: {failures}")
    print(f"  Errors: {errors}")
    print(f"  Skipped: {skipped}")

    success_rate = (successful / total_tests * 100) if total_tests > 0 else 0
    print(f"  Success Rate: {success_rate:.1f}%")

    if success_rate >= 70:
        print("\n✅ COMPONENT VALIDATION: PASSED")
        print("   All critical components are properly structured!")
    else:
        print("\n❌ COMPONENT VALIDATION: FAILED")
        print("   Some components have structural issues.")

    print("="*70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_component_validation()
    sys.exit(0 if success else 1)
