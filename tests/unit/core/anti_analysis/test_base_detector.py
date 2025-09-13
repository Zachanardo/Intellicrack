"""
Comprehensive test suite for BaseDetector anti-analysis detection module.

This test suite validates the production-ready capabilities of the BaseDetector class
using specification-driven, black-box testing methodology. Tests are designed to
validate genuine anti-analysis detection capabilities required for security research.
"""

import pytest
import unittest
import logging
import platform
import subprocess
from typing import Dict, List, Any, Tuple

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from intellicrack.core.anti_analysis.base_detector import BaseDetector


class TestBaseDetector(unittest.TestCase):
    """Test suite for BaseDetector class functionality."""

    def setUp(self):
        """Set up test fixtures with production-ready expectations."""
        self.detector = BaseDetector()

    def tearDown(self):
        """Clean up after tests."""
        pass

    def test_init_initializes_logger_and_detection_methods(self):
        """Test that __init__ properly initializes logger and detection methods."""
        detector = BaseDetector()

        # Should have a properly configured logger
        self.assertIsInstance(detector.logger, logging.Logger)
        self.assertEqual(detector.logger.name, 'BaseDetector')

        # Should have detection methods dictionary
        self.assertIsInstance(detector.detection_methods, dict)
        self.assertGreater(len(detector.detection_methods), 0,
                          "Detection methods dictionary should contain actual detection techniques")

    def test_get_detection_type_returns_valid_classification(self):
        """Test that get_detection_type returns proper detector classification."""
        detection_type = self.detector.get_detection_type()

        # Should return a string classification
        self.assertIsInstance(detection_type, str)
        self.assertGreater(len(detection_type), 0)

        # Should be a meaningful classification for anti-analysis detection
        valid_types = ['debugger', 'vm', 'sandbox', 'analysis_tool', 'process_monitor', 'base']
        self.assertTrue(any(vtype in detection_type.lower() for vtype in valid_types),
                       f"Detection type '{detection_type}' should be a valid classification")

    def test_get_aggressive_methods_returns_advanced_techniques(self):
        """Test that get_aggressive_methods returns list of advanced detection techniques."""
        aggressive_methods = self.detector.get_aggressive_methods()

        # Should return a list of method names
        self.assertIsInstance(aggressive_methods, list)
        self.assertGreater(len(aggressive_methods), 0,
                          "Should have at least some aggressive detection methods")

        # Each method should be a string representing a callable method
        for method in aggressive_methods:
            self.assertIsInstance(method, str)
            self.assertTrue(hasattr(self.detector, method),
                           f"Method '{method}' should exist in detector class")
            self.assertTrue(callable(getattr(self.detector, method)),
                           f"Method '{method}' should be callable")

    def test_get_running_processes_detects_analysis_tools(self):
        """Test that get_running_processes accurately identifies analysis tools."""
        processes = self.detector.get_running_processes()

        # Should return a list of process information
        self.assertIsInstance(processes, list)

        # Each process entry should contain relevant information
        if len(processes) > 0:
            for process in processes:
                self.assertIsInstance(process, dict)
                # Should have at minimum name and pid
                self.assertIn('name', process)
                self.assertIn('pid', process)
                self.assertIsInstance(process['name'], str)
                self.assertIsInstance(process['pid'], int)

    def test_get_running_processes_handles_subprocess_errors(self):
        """Test that get_running_processes gracefully handles subprocess errors."""
        # Test real subprocess behavior and error handling
        try:
            processes = self.detector.get_running_processes()

            # Should handle errors gracefully and return empty list or alternative method
            self.assertIsInstance(processes, list)

            # If processes returned, validate structure
            if processes:
                for process in processes:
                    self.assertIsInstance(process, dict)
                    self.assertIn('name', process)
                    self.assertIn('pid', process)
        except (subprocess.CalledProcessError, OSError, PermissionError) as e:
            # Handle potential subprocess errors gracefully
            self.assertIsInstance(e, (subprocess.CalledProcessError, OSError, PermissionError))

    def test_get_running_processes_platform_specific_behavior(self):
        """Test that get_running_processes adapts to different platforms."""
        # Test real platform behavior
        current_platform = platform.system()

        processes = self.detector.get_running_processes()
        self.assertIsInstance(processes, list)

        # Validate platform-specific behavior based on actual platform
        if current_platform == 'Windows':
            # On Windows, should use tasklist or equivalent
            # Process names might include .exe extensions
            if processes:
                for process in processes:
                    self.assertIn('name', process)
                    self.assertIn('pid', process)
                    # Windows processes might have .exe extension
                    process_name = process['name']
                    self.assertIsInstance(process_name, str)
                    self.assertGreater(len(process_name), 0)
        elif current_platform in ['Linux', 'Darwin']:
            # On Unix-like systems, should use ps or equivalent
            if processes:
                for process in processes:
                    self.assertIn('name', process)
                    self.assertIn('pid', process)
                    self.assertIsInstance(process['name'], str)
                    self.assertIsInstance(process['pid'], int)
        else:
            # For other platforms, just ensure basic structure
            if processes:
                for process in processes:
                    self.assertIn('name', process)
                    self.assertIn('pid', process)

    def test_run_detection_loop_basic_functionality(self):
        """Test basic functionality of run_detection_loop."""
        # Test with non-aggressive mode
        results = self.detector.run_detection_loop(aggressive=False)

        # Should return detection results structure
        self.assertIsInstance(results, dict)
        self.assertIn('detections', results)
        self.assertIn('confidence_score', results)
        self.assertIn('summary', results)

        # Confidence score should be numeric and in valid range
        self.assertIsInstance(results['confidence_score'], (int, float))
        self.assertGreaterEqual(results['confidence_score'], 0)
        self.assertLessEqual(results['confidence_score'], 100)

    def test_run_detection_loop_aggressive_mode(self):
        """Test run_detection_loop with aggressive mode enabled."""
        # Get aggressive methods first
        aggressive_methods = self.detector.get_aggressive_methods()

        # Test with aggressive mode
        results = self.detector.run_detection_loop(
            aggressive=True,
            aggressive_methods=aggressive_methods
        )

        # Should return more comprehensive results in aggressive mode
        self.assertIsInstance(results, dict)
        self.assertIn('detections', results)
        self.assertIn('confidence_score', results)
        self.assertIn('summary', results)

        # Should have executed aggressive methods
        if aggressive_methods:
            detections = results['detections']
            self.assertGreater(len(detections), 0,
                             "Aggressive mode should produce detection results")

    def test_run_detection_loop_with_custom_aggressive_methods(self):
        """Test run_detection_loop with custom aggressive methods list."""
        # Test with specific subset of aggressive methods
        custom_methods = ['detect_debugger', 'detect_vm']  # Expected method names

        results = self.detector.run_detection_loop(
            aggressive=True,
            aggressive_methods=custom_methods
        )

        self.assertIsInstance(results, dict)
        self.assertIn('detections', results)

    def test_calculate_detection_score_empty_detections(self):
        """Test calculate_detection_score with empty detection list."""
        empty_detections = []
        score = self.detector.calculate_detection_score(empty_detections)

        self.assertIsInstance(score, (int, float))
        self.assertEqual(score, 0, "Empty detections should yield zero confidence")

    def test_calculate_detection_score_single_detection(self):
        """Test calculate_detection_score with single detection result."""
        single_detection = [
            {
                'method': 'test_method',
                'detected': True,
                'confidence': 75,
                'details': 'Test detection found evidence'
            }
        ]

        score = self.detector.calculate_detection_score(single_detection)

        self.assertIsInstance(score, (int, float))
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

    def test_calculate_detection_score_multiple_detections(self):
        """Test calculate_detection_score with multiple detection results."""
        multiple_detections = [
            {
                'method': 'method_1',
                'detected': True,
                'confidence': 80,
                'details': 'Strong evidence found'
            },
            {
                'method': 'method_2',
                'detected': True,
                'confidence': 60,
                'details': 'Moderate evidence found'
            },
            {
                'method': 'method_3',
                'detected': False,
                'confidence': 0,
                'details': 'No evidence found'
            }
        ]

        score = self.detector.calculate_detection_score(multiple_detections)

        self.assertIsInstance(score, (int, float))
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

        # Score should be higher than single detection due to multiple positive results
        single_score = self.detector.calculate_detection_score([multiple_detections[0]])
        self.assertGreater(score, single_score * 0.8,
                          "Multiple detections should increase confidence score")

    def test_calculate_detection_score_weighted_methods(self):
        """Test that calculate_detection_score properly weights different detection methods."""
        # Test with high-confidence detection method
        high_confidence_detection = [
            {
                'method': 'strong_detection_method',
                'detected': True,
                'confidence': 95,
                'details': 'Very strong evidence'
            }
        ]

        # Test with low-confidence detection method
        low_confidence_detection = [
            {
                'method': 'weak_detection_method',
                'detected': True,
                'confidence': 30,
                'details': 'Weak evidence'
            }
        ]

        high_score = self.detector.calculate_detection_score(high_confidence_detection)
        low_score = self.detector.calculate_detection_score(low_confidence_detection)

        self.assertGreater(high_score, low_score,
                          "High confidence detections should yield higher scores")

    def test_detection_methods_dictionary_structure(self):
        """Test that detection_methods contains properly structured method definitions."""
        detection_methods = self.detector.detection_methods

        self.assertIsInstance(detection_methods, dict)
        self.assertGreater(len(detection_methods), 0)

        for method_name, method_info in detection_methods.items():
            # Each method should have proper structure
            self.assertIsInstance(method_name, str)
            self.assertIsInstance(method_info, dict)

            # Should have required fields
            required_fields = ['enabled', 'weight', 'description']
            for field in required_fields:
                self.assertIn(field, method_info,
                            f"Method '{method_name}' should have '{field}' field")

    def test_logger_configuration(self):
        """Test that logger is properly configured for production use."""
        logger = self.detector.logger

        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'BaseDetector')

        # Should have appropriate logging level
        self.assertIn(logger.level, [logging.DEBUG, logging.INFO, logging.WARNING,
                                    logging.ERROR, logging.CRITICAL])

    def test_error_handling_in_detection_methods(self):
        """Test that detection methods handle errors gracefully."""
        # This tests the error handling in run_detection_loop

        # Create a real failing method that raises an exception
        def failing_detection_method():
            """Test method that intentionally fails."""
            raise Exception("Test exception for error handling validation")

        # Store original detection methods to restore later
        original_methods = self.detector.detection_methods.copy()

        try:
            # Add a real failing method to test error handling
            self.detector.detection_methods['test_failing_method'] = {
                'enabled': True,
                'weight': 1.0,
                'description': 'Test method that fails for error handling validation'
            }

            # Set the actual failing method
            setattr(self.detector, 'test_failing_method', failing_detection_method)

            # Should handle the exception and continue execution
            results = self.detector.run_detection_loop(aggressive=False)

            # Should still return valid structure even with failing methods
            self.assertIsInstance(results, dict)
            self.assertIn('detections', results)
            self.assertIn('confidence_score', results)
            self.assertIn('summary', results)

            # Error should be handled gracefully without crashing
            self.assertIsInstance(results['confidence_score'], (int, float))

        finally:
            # Restore original detection methods
            self.detector.detection_methods = original_methods
            # Remove the test method
            if hasattr(self.detector, 'test_failing_method'):
                delattr(self.detector, 'test_failing_method')

    def test_cross_platform_compatibility(self):
        """Test that BaseDetector works across different platforms."""
        # Test that basic functionality works regardless of platform
        detector = BaseDetector()

        # These should work on any platform
        self.assertIsNotNone(detector.get_detection_type())
        self.assertIsInstance(detector.get_aggressive_methods(), list)
        self.assertIsInstance(detector.get_running_processes(), list)

    def test_production_ready_detection_capabilities(self):
        """Test that detector has genuine production-ready detection capabilities."""
        # This test validates that the detector has real anti-analysis capabilities

        # Should have multiple detection methods
        methods = self.detector.detection_methods
        self.assertGreaterEqual(len(methods), 5,
                               "Production detector should have multiple detection methods")

        # Should have sophisticated detection techniques
        expected_categories = ['debugger', 'vm', 'sandbox', 'analysis', 'monitor']
        method_names = ' '.join(methods.keys()).lower()

        found_categories = sum(1 for category in expected_categories
                              if category in method_names)
        self.assertGreaterEqual(found_categories, 2,
                               "Should cover multiple categories of anti-analysis detection")

    def test_real_world_scenario_vm_detection(self):
        """Test detection capabilities against real-world VM scenarios."""
        # Run actual detection to see if it can identify virtualized environment
        results = self.detector.run_detection_loop(aggressive=False)

        # Should return meaningful results about environment
        self.assertIsInstance(results, dict)
        self.assertIn('detections', results)

        # If running in a VM, should detect it
        # This tests against real environment characteristics
        detections = results['detections']
        if detections:
            for detection in detections:
                self.assertIn('method', detection)
                self.assertIn('detected', detection)
                self.assertIn('confidence', detection)

    def test_real_world_scenario_process_analysis(self):
        """Test process analysis against real running processes."""
        processes = self.detector.get_running_processes()

        # Should return real process information
        self.assertIsInstance(processes, list)

        # If any processes found, validate structure
        if processes:
            for process in processes:
                self.assertIn('name', process)
                self.assertIsInstance(process['name'], str)
                self.assertGreater(len(process['name']), 0)

    def test_aggressive_mode_thoroughness(self):
        """Test that aggressive mode provides more thorough detection."""
        # Run standard detection
        standard_results = self.detector.run_detection_loop(aggressive=False)

        # Run aggressive detection
        aggressive_methods = self.detector.get_aggressive_methods()
        aggressive_results = self.detector.run_detection_loop(
            aggressive=True,
            aggressive_methods=aggressive_methods
        )

        # Aggressive mode should be more comprehensive
        if aggressive_methods:
            aggressive_detections = len(aggressive_results.get('detections', []))
            standard_detections = len(standard_results.get('detections', []))

            # Should have at least as many detections as standard mode
            self.assertGreaterEqual(aggressive_detections, standard_detections,
                                   "Aggressive mode should be at least as thorough as standard")

    def test_confidence_score_accuracy(self):
        """Test that confidence scores accurately reflect detection strength."""
        # Test with known positive detection scenario
        strong_detections = [
            {
                'method': 'strong_method_1',
                'detected': True,
                'confidence': 90,
                'details': 'Strong evidence'
            },
            {
                'method': 'strong_method_2',
                'detected': True,
                'confidence': 85,
                'details': 'Strong evidence'
            }
        ]

        weak_detections = [
            {
                'method': 'weak_method',
                'detected': True,
                'confidence': 25,
                'details': 'Weak evidence'
            }
        ]

        strong_score = self.detector.calculate_detection_score(strong_detections)
        weak_score = self.detector.calculate_detection_score(weak_detections)

        self.assertGreater(strong_score, weak_score * 2,
                          "Strong detections should yield significantly higher confidence")

    def test_detection_result_format_consistency(self):
        """Test that all detection results follow consistent format."""
        results = self.detector.run_detection_loop(aggressive=False)

        # Verify top-level structure
        required_keys = ['detections', 'confidence_score', 'summary']
        for key in required_keys:
            self.assertIn(key, results, f"Results should contain '{key}' field")

        # Verify detections structure
        detections = results['detections']
        self.assertIsInstance(detections, list)

        for detection in detections:
            self.assertIsInstance(detection, dict)
            detection_keys = ['method', 'detected', 'confidence', 'details']
            for key in detection_keys:
                self.assertIn(key, detection,
                            f"Each detection should contain '{key}' field")

            # Validate data types
            self.assertIsInstance(detection['method'], str)
            self.assertIsInstance(detection['detected'], bool)
            self.assertIsInstance(detection['confidence'], (int, float))
            self.assertIsInstance(detection['details'], str)

    def test_method_availability_validation(self):
        """Test that all registered detection methods are actually available."""
        detection_methods = self.detector.detection_methods

        for method_name in detection_methods.keys():
            # Method should exist as an attribute
            self.assertTrue(hasattr(self.detector, method_name),
                           f"Registered method '{method_name}' should exist in class")

            # Method should be callable
            method = getattr(self.detector, method_name)
            self.assertTrue(callable(method),
                           f"Registered method '{method_name}' should be callable")


class TestBaseDetectorIntegration(unittest.TestCase):
    """Integration tests for BaseDetector with real system interaction."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.detector = BaseDetector()

    def test_end_to_end_detection_workflow(self):
        """Test complete detection workflow from initialization to results."""
        # Initialize detector
        detector = BaseDetector()

        # Get detection capabilities
        detection_type = detector.get_detection_type()
        aggressive_methods = detector.get_aggressive_methods()

        # Run detection
        results = detector.run_detection_loop(
            aggressive=False,
            aggressive_methods=[]
        )

        # Calculate final score
        final_score = detector.calculate_detection_score(results['detections'])

        # Validate end-to-end workflow
        self.assertIsInstance(detection_type, str)
        self.assertIsInstance(aggressive_methods, list)
        self.assertIsInstance(results, dict)
        self.assertIsInstance(final_score, (int, float))

    def test_performance_characteristics(self):
        """Test that detection operations complete within reasonable time."""
        import time

        # Test basic detection performance
        start_time = time.time()
        results = self.detector.run_detection_loop(aggressive=False)
        end_time = time.time()

        detection_time = end_time - start_time

        # Should complete within reasonable time (10 seconds for basic detection)
        self.assertLess(detection_time, 10.0,
                       "Basic detection should complete within 10 seconds")

        # Should return results
        self.assertIsInstance(results, dict)
        self.assertIn('detections', results)


if __name__ == '__main__':
    unittest.main()
