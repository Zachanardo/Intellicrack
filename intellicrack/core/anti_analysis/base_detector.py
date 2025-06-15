"""
Base Detector for Anti-Analysis Modules

Shared functionality for detection implementations to eliminate code duplication.
"""

import logging
import platform
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple


class BaseDetector(ABC):
    """
    Abstract base class for anti-analysis detectors.
    Provides common detection loop functionality.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.AntiAnalysis")
        self.detection_methods = {}

    def run_detection_loop(self,
                          aggressive: bool = False,
                          aggressive_methods: List[str] = None) -> Dict[str, Any]:
        """
        Run the detection loop for all configured methods.
        
        Args:
            aggressive: Whether to run aggressive detection methods
            aggressive_methods: List of method names considered aggressive
            
        Returns:
            Detection results dictionary
        """
        if aggressive_methods is None:
            aggressive_methods = []

        results = {
            'detections': {},
            'detection_count': 0,
            'total_confidence': 0,
            'average_confidence': 0
        }

        detection_count = 0
        total_confidence = 0

        for method_name, method_func in self.detection_methods.items():
            # Skip aggressive methods if not requested
            if not aggressive and method_name in aggressive_methods:
                continue

            try:
                detected, confidence, details = method_func()
                results['detections'][method_name] = {
                    'detected': detected,
                    'confidence': confidence,
                    'details': details
                }

                if detected:
                    detection_count += 1
                    total_confidence += confidence

            except Exception as e:
                self.logger.debug(f"Detection method {method_name} failed: {e}")

        # Calculate overall results
        results['detection_count'] = detection_count
        results['total_confidence'] = total_confidence

        if detection_count > 0:
            results['average_confidence'] = total_confidence / detection_count
        else:
            results['average_confidence'] = 0

        return results

    @abstractmethod
    def get_aggressive_methods(self) -> List[str]:
        """Get list of method names that are considered aggressive."""
        pass

    @abstractmethod
    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        pass
    
    def get_running_processes(self) -> Tuple[str, List[str]]:
        """
        Get list of running processes based on platform.
        
        Returns:
            Tuple of (raw_output, process_list)
        """
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
                processes = result.stdout.lower()
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                processes = result.stdout.lower()
            
            # Also get individual process names
            process_list = []
            if platform.system() == 'Windows':
                # Parse tasklist output
                lines = result.stdout.strip().split('\n')[3:]  # Skip header
                for line in lines:
                    if line.strip():
                        process_name = line.split()[0].lower()
                        process_list.append(process_name)
            else:
                # Parse ps output
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            process_name = parts[10].lower()
                            process_list.append(process_name)
            
            return processes, process_list
            
        except Exception as e:
            self.logger.debug(f"Error getting process list: {e}")
            return "", []
    
    def calculate_detection_score(self, detections: Dict[str, Any], 
                                strong_methods: List[str], 
                                medium_methods: List[str] = None) -> int:
        """
        Calculate detection score based on method difficulty.
        
        Args:
            detections: Dictionary of detection results
            strong_methods: Methods that score 3 points
            medium_methods: Methods that score 2 points (optional)
            
        Returns:
            Score capped at 10
        """
        if medium_methods is None:
            medium_methods = []
        
        score = 0
        for method, result in detections.items():
            if isinstance(result, dict) and result.get('detected'):
                if method in strong_methods:
                    score += 3
                elif method in medium_methods:
                    score += 2
                else:
                    score += 1
        
        return min(10, score)
