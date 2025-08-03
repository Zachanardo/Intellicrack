"""
Structured Logging Integration for DIE Analysis

Provides comprehensive logging of DIE analysis operations with structured data,
performance metrics, and detailed error reporting.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import logging
import time
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .die_json_wrapper import DIEAnalysisResult, DIEDetection
from ..logging.audit_logger import get_audit_logger


class DIEStructuredLogger:
    """
    Structured logger for DIE analysis operations
    
    Provides comprehensive logging with performance metrics,
    error tracking, and analysis statistics.
    """

    def __init__(self, logger_name: str = "die_analysis"):
        """Initialize structured logger"""
        self.logger = logging.getLogger(logger_name)
        self.audit_logger = get_audit_logger()
        self.analysis_stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'total_detections': 0,
            'total_analysis_time': 0.0,
            'detection_types': {},
            'file_types': {},
            'architectures': {}
        }

    def log_analysis_start(self, file_path: str, scan_mode: str, timeout: int) -> str:
        """
        Log the start of DIE analysis
        
        Args:
            file_path: Path to file being analyzed
            scan_mode: Analysis scan mode
            timeout: Analysis timeout
            
        Returns:
            Analysis session ID for tracking
        """
        session_id = f"die_analysis_{int(time.time() * 1000)}"
        
        log_data = {
            'event': 'die_analysis_start',
            'session_id': session_id,
            'file_path': file_path,
            'scan_mode': scan_mode,
            'timeout': timeout,
            'timestamp': time.time()
        }
        
        self.logger.info(f"Starting DIE analysis: {file_path} (mode: {scan_mode})", 
                        extra={'structured_data': log_data})
        
        # Audit log
        self.audit_logger.log_operation(
            operation='die_analysis_start',
            resource=file_path,
            details={
                'session_id': session_id,
                'scan_mode': scan_mode,
                'timeout': timeout
            }
        )
        
        return session_id

    def log_analysis_complete(self, session_id: str, result: DIEAnalysisResult):
        """
        Log successful completion of DIE analysis
        
        Args:
            session_id: Analysis session ID
            result: DIE analysis result
        """
        # Update statistics
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['successful_analyses'] += 1
        self.analysis_stats['total_detections'] += len(result.detections)
        self.analysis_stats['total_analysis_time'] += result.analysis_time
        
        # Track file types and architectures
        self.analysis_stats['file_types'][result.file_type] = \
            self.analysis_stats['file_types'].get(result.file_type, 0) + 1
        self.analysis_stats['architectures'][result.architecture] = \
            self.analysis_stats['architectures'].get(result.architecture, 0) + 1
        
        # Track detection types
        for detection in result.detections:
            self.analysis_stats['detection_types'][detection.type] = \
                self.analysis_stats['detection_types'].get(detection.type, 0) + 1

        # Create structured log data
        log_data = {
            'event': 'die_analysis_complete',
            'session_id': session_id,
            'file_path': result.file_path,
            'file_type': result.file_type,
            'architecture': result.architecture,
            'file_size': result.file_size,
            'detection_count': len(result.detections),
            'analysis_time': result.analysis_time,
            'scan_mode': result.scan_mode,
            'entropy': result.entropy,
            'overlay_detected': result.overlay_detected,
            'sections_count': len(result.sections),
            'imports_count': len(result.imports),
            'exports_count': len(result.exports),
            'strings_count': len(result.strings),
            'warnings_count': len(result.warnings),
            'timestamp': time.time()
        }
        
        # Add detection summary
        detection_summary = {}
        for detection in result.detections:
            detection_summary[detection.type] = detection_summary.get(detection.type, 0) + 1
        log_data['detection_summary'] = detection_summary

        self.logger.info(
            f"DIE analysis completed: {result.file_path} "
            f"({len(result.detections)} detections, {result.analysis_time:.2f}s)",
            extra={'structured_data': log_data}
        )
        
        # Audit log with detailed results
        self.audit_logger.log_operation(
            operation='die_analysis_complete',
            resource=result.file_path,
            details={
                'session_id': session_id,
                'detection_count': len(result.detections),
                'analysis_time': result.analysis_time,
                'file_type': result.file_type,
                'architecture': result.architecture,
                'detections': [
                    {
                        'name': d.name,
                        'type': d.type,
                        'confidence': d.confidence
                    }
                    for d in result.detections[:10]  # Limit for log size
                ]
            }
        )

    def log_analysis_error(self, session_id: str, file_path: str, error: Exception, 
                          scan_mode: str = "unknown", analysis_time: float = 0.0):
        """
        Log DIE analysis error
        
        Args:
            session_id: Analysis session ID
            file_path: Path to file being analyzed
            error: Exception that occurred
            scan_mode: Analysis scan mode
            analysis_time: Time spent before error
        """
        # Update statistics
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['failed_analyses'] += 1
        self.analysis_stats['total_analysis_time'] += analysis_time

        log_data = {
            'event': 'die_analysis_error',
            'session_id': session_id,
            'file_path': file_path,
            'scan_mode': scan_mode,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'analysis_time': analysis_time,
            'timestamp': time.time()
        }

        self.logger.error(
            f"DIE analysis failed: {file_path} - {error}",
            extra={'structured_data': log_data},
            exc_info=True
        )
        
        # Audit log
        self.audit_logger.log_operation(
            operation='die_analysis_error',
            resource=file_path,
            details={
                'session_id': session_id,
                'error_type': type(error).__name__,
                'error_message': str(error),
                'analysis_time': analysis_time
            }
        )

    def log_detection_details(self, session_id: str, detections: List[DIEDetection]):
        """
        Log detailed information about detections
        
        Args:
            session_id: Analysis session ID
            detections: List of detections to log
        """
        if not detections:
            return

        for i, detection in enumerate(detections):
            log_data = {
                'event': 'die_detection_detail',
                'session_id': session_id,
                'detection_index': i,
                'detection_name': detection.name,
                'detection_type': detection.type,
                'detection_version': detection.version,
                'confidence': detection.confidence,
                'offset': detection.offset,
                'size': detection.size,
                'entropy': detection.entropy,
                'additional_info_keys': list(detection.additional_info.keys()),
                'timestamp': time.time()
            }

            self.logger.debug(
                f"Detection {i+1}: {detection.type} - {detection.name}",
                extra={'structured_data': log_data}
            )

    def log_performance_metrics(self, session_id: str, metrics: Dict[str, Any]):
        """
        Log performance metrics for DIE analysis
        
        Args:
            session_id: Analysis session ID
            metrics: Performance metrics dictionary
        """
        log_data = {
            'event': 'die_performance_metrics',
            'session_id': session_id,
            'metrics': metrics,
            'timestamp': time.time()
        }

        self.logger.info(
            f"DIE analysis performance metrics: {session_id}",
            extra={'structured_data': log_data}
        )

    def log_validation_result(self, session_id: str, file_path: str, 
                             is_valid: bool, validation_errors: List[str] = None):
        """
        Log JSON schema validation results
        
        Args:
            session_id: Analysis session ID
            file_path: Path to analyzed file
            is_valid: Whether result passed validation
            validation_errors: List of validation errors if any
        """
        log_data = {
            'event': 'die_validation_result',
            'session_id': session_id,
            'file_path': file_path,
            'is_valid': is_valid,
            'validation_errors': validation_errors or [],
            'timestamp': time.time()
        }

        if is_valid:
            self.logger.debug(
                f"DIE result validation passed: {file_path}",
                extra={'structured_data': log_data}
            )
        else:
            self.logger.warning(
                f"DIE result validation failed: {file_path} - {validation_errors}",
                extra={'structured_data': log_data}
            )

    @contextmanager
    def analysis_session(self, file_path: str, scan_mode: str, timeout: int):
        """
        Context manager for DIE analysis session logging
        
        Args:
            file_path: Path to file being analyzed
            scan_mode: Analysis scan mode
            timeout: Analysis timeout
            
        Yields:
            session_id: Analysis session ID
        """
        session_id = self.log_analysis_start(file_path, scan_mode, timeout)
        start_time = time.time()
        
        try:
            yield session_id
        except Exception as e:
            analysis_time = time.time() - start_time
            self.log_analysis_error(session_id, file_path, e, scan_mode, analysis_time)
            raise
        else:
            # Success case is handled by explicit log_analysis_complete call
            pass

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics"""
        stats = self.analysis_stats.copy()
        
        # Calculate derived statistics
        if stats['total_analyses'] > 0:
            stats['success_rate'] = stats['successful_analyses'] / stats['total_analyses']
            stats['average_analysis_time'] = stats['total_analysis_time'] / stats['total_analyses']
            stats['average_detections_per_file'] = stats['total_detections'] / stats['successful_analyses'] if stats['successful_analyses'] > 0 else 0
        else:
            stats['success_rate'] = 0.0
            stats['average_analysis_time'] = 0.0
            stats['average_detections_per_file'] = 0.0

        return stats

    def export_statistics_json(self) -> str:
        """Export statistics as JSON string"""
        stats = self.get_analysis_statistics()
        return json.dumps(stats, indent=2)

    def reset_statistics(self):
        """Reset analysis statistics"""
        self.analysis_stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'total_detections': 0,
            'total_analysis_time': 0.0,
            'detection_types': {},
            'file_types': {},
            'architectures': {}
        }
        
        self.logger.info("DIE analysis statistics reset")

    def log_cache_operation(self, operation: str, file_path: str, 
                           cache_hit: bool = False, cache_size: int = 0):
        """
        Log cache operations
        
        Args:
            operation: Cache operation type
            file_path: File path involved
            cache_hit: Whether this was a cache hit
            cache_size: Current cache size
        """
        log_data = {
            'event': 'die_cache_operation',
            'operation': operation,
            'file_path': file_path,
            'cache_hit': cache_hit,
            'cache_size': cache_size,
            'timestamp': time.time()
        }

        self.logger.debug(
            f"DIE cache {operation}: {file_path} (hit: {cache_hit})",
            extra={'structured_data': log_data}
        )


# Global structured logger instance
_global_die_logger: Optional[DIEStructuredLogger] = None

def get_die_structured_logger() -> DIEStructuredLogger:
    """Get or create global DIE structured logger"""
    global _global_die_logger
    
    if _global_die_logger is None:
        _global_die_logger = DIEStructuredLogger()
    
    return _global_die_logger


def log_die_analysis_session(file_path: str, scan_mode: str, timeout: int):
    """
    Decorator/context manager for logging DIE analysis sessions
    
    Usage:
        with log_die_analysis_session(file_path, scan_mode, timeout) as session_id:
            # Perform analysis
            result = analyze_file(...)
            # Log completion
            logger = get_die_structured_logger()
            logger.log_analysis_complete(session_id, result)
    """
    logger = get_die_structured_logger()
    return logger.analysis_session(file_path, scan_mode, timeout)


# Example usage
if __name__ == "__main__":
    import sys
    
    # Test structured logging
    logger = DIEStructuredLogger("test_die_logger")
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        with logger.analysis_session(file_path, "test", 60) as session_id:
            print(f"Analysis session: {session_id}")
            
            # Simulate analysis completion
            from .die_json_wrapper import DIEAnalysisResult, DIEDetection
            
            test_result = DIEAnalysisResult(
                file_path=file_path,
                file_type="PE32",
                architecture="x86",
                file_size=1024,
                detections=[
                    DIEDetection(name="Test", type="Packer", confidence=0.9)
                ],
                analysis_time=1.5
            )
            
            logger.log_analysis_complete(session_id, test_result)
    
    # Print statistics
    print("=== Analysis Statistics ===")
    print(logger.export_statistics_json())