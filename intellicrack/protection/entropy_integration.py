"""
Entropy Packer Detection Integration Module

Provides integration utilities, performance monitoring, and convenience functions
for the sophisticated entropy-based packer detection system. This module serves
as the primary interface for integrating entropy analysis into existing workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from ..utils.logger import get_logger
from .entropy_packer_detector import (
    SophisticatedEntropyPackerDetector, EntropyDetectionResult, EntropyAnalysisMode,
    PackerFamily, create_fast_detector, create_deep_detector, create_realtime_detector
)
from .intellicrack_protection_core import DetectionResult, ProtectionType

logger = get_logger(__name__)


class EntropyPerformanceMonitor:
    """Performance monitoring and optimization for entropy analysis"""
    
    def __init__(self):
        self.analysis_history = []
        self.performance_thresholds = {
            'analysis_time_warning': 30.0,  # seconds
            'memory_usage_warning': 500 * 1024 * 1024,  # 500MB
            'false_positive_rate_warning': 0.15  # 15%
        }
        
    def record_analysis(self, result: EntropyDetectionResult):
        """Record analysis result for performance monitoring"""
        self.analysis_history.append({
            'timestamp': time.time(),
            'file_path': result.file_path,
            'analysis_time': result.analysis_time,
            'memory_usage': result.memory_usage,
            'confidence_score': result.confidence_score,
            'false_positive_probability': result.false_positive_probability,
            'packer_family': result.packer_family.value,
            'is_packed': result.is_packed
        })
        
        # Keep only last 1000 analyses
        if len(self.analysis_history) > 1000:
            self.analysis_history = self.analysis_history[-1000:]
            
        self._check_performance_warnings(result)
    
    def _check_performance_warnings(self, result: EntropyDetectionResult):
        """Check for performance issues and log warnings"""
        if result.analysis_time > self.performance_thresholds['analysis_time_warning']:
            logger.warning(f"Slow entropy analysis: {result.analysis_time:.2f}s for {os.path.basename(result.file_path)}")
            
        if result.memory_usage > self.performance_thresholds['memory_usage_warning']:
            logger.warning(f"High memory usage: {result.memory_usage / 1024 / 1024:.1f}MB for {os.path.basename(result.file_path)}")
            
        if result.false_positive_probability > self.performance_thresholds['false_positive_rate_warning']:
            logger.warning(f"High false positive risk: {result.false_positive_probability:.2f} for {os.path.basename(result.file_path)}")
    
    def get_performance_summary(self) -> Dict[str, any]:
        """Get comprehensive performance summary"""
        if not self.analysis_history:
            return {"status": "no_data"}
            
        recent_analyses = self.analysis_history[-100:]  # Last 100 analyses
        
        # Calculate statistics
        analysis_times = [a['analysis_time'] for a in recent_analyses]
        memory_usages = [a['memory_usage'] for a in recent_analyses]
        confidence_scores = [a['confidence_score'] for a in recent_analyses]
        false_positive_probs = [a['false_positive_probability'] for a in recent_analyses]
        
        # Count packer families
        packer_counts = {}
        for analysis in recent_analyses:
            family = analysis['packer_family']
            packer_counts[family] = packer_counts.get(family, 0) + 1
        
        # Calculate detection rate
        packed_count = sum(1 for a in recent_analyses if a['is_packed'])
        detection_rate = packed_count / len(recent_analyses) if recent_analyses else 0.0
        
        return {
            "total_analyses": len(self.analysis_history),
            "recent_analyses": len(recent_analyses),
            "performance_metrics": {
                "avg_analysis_time": sum(analysis_times) / len(analysis_times),
                "max_analysis_time": max(analysis_times),
                "min_analysis_time": min(analysis_times),
                "avg_memory_usage_mb": sum(memory_usages) / len(memory_usages) / 1024 / 1024,
                "max_memory_usage_mb": max(memory_usages) / 1024 / 1024,
                "avg_confidence": sum(confidence_scores) / len(confidence_scores),
                "avg_false_positive_prob": sum(false_positive_probs) / len(false_positive_probs)
            },
            "detection_statistics": {
                "detection_rate": detection_rate,
                "packer_family_distribution": packer_counts
            },
            "performance_warnings": {
                "slow_analyses": len([t for t in analysis_times if t > self.performance_thresholds['analysis_time_warning']]),
                "high_memory_analyses": len([m for m in memory_usages if m > self.performance_thresholds['memory_usage_warning']]),
                "high_false_positive_risk": len([fp for fp in false_positive_probs if fp > self.performance_thresholds['false_positive_rate_warning']])
            }
        }


class EntropyBatchProcessor:
    """Batch processing utilities for entropy analysis"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(os.cpu_count() or 1, 8)
        self.performance_monitor = EntropyPerformanceMonitor()
        
    def process_directory(self, directory: str, 
                         analysis_mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD,
                         recursive: bool = True,
                         file_extensions: List[str] = None,
                         enable_ml: bool = True) -> List[EntropyDetectionResult]:
        """Process all files in a directory with parallel execution"""
        
        if file_extensions is None:
            file_extensions = ['.exe', '.dll', '.sys', '.ocx', '.scr', '.com']
            
        # Collect files to analyze
        files_to_process = []
        
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in file_extensions):
                        files_to_process.append(os.path.join(root, file))
        else:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        files_to_process.append(file_path)
        
        logger.info(f"Processing {len(files_to_process)} files in {directory} with {self.max_workers} workers")
        
        results = []
        start_time = time.time()
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create detector instances for each worker
            future_to_file = {}
            
            for file_path in files_to_process:
                detector = SophisticatedEntropyPackerDetector(analysis_mode)
                future = executor.submit(detector.analyze_file, file_path, enable_ml)
                future_to_file[future] = file_path
            
            # Collect results
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.performance_monitor.record_analysis(result)
                except Exception as e:
                    logger.error(f"Failed to analyze {file_path}: {e}")
        
        total_time = time.time() - start_time
        logger.info(f"Batch processing completed in {total_time:.2f}s - analyzed {len(results)} files")
        
        return results
    
    def process_file_list(self, file_paths: List[str],
                         analysis_mode: EntropyAnalysisMode = EntropyAnalysisMode.STANDARD,
                         enable_ml: bool = True) -> List[EntropyDetectionResult]:
        """Process a specific list of files"""
        
        logger.info(f"Processing {len(file_paths)} files with {self.max_workers} workers")
        
        results = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {}
            
            for file_path in file_paths:
                if os.path.isfile(file_path):
                    detector = SophisticatedEntropyPackerDetector(analysis_mode)
                    future = executor.submit(detector.analyze_file, file_path, enable_ml)
                    future_to_file[future] = file_path
                else:
                    logger.warning(f"File not found: {file_path}")
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.performance_monitor.record_analysis(result)
                except Exception as e:
                    logger.error(f"Failed to analyze {file_path}: {e}")
        
        total_time = time.time() - start_time
        logger.info(f"File list processing completed in {total_time:.2f}s")
        
        return results
    
    def get_performance_summary(self) -> Dict[str, any]:
        """Get performance summary for batch processing"""
        return self.performance_monitor.get_performance_summary()


class EntropyReportGenerator:
    """Generate comprehensive reports from entropy analysis results"""
    
    def __init__(self):
        self.report_templates = {
            'summary': self._generate_summary_report,
            'detailed': self._generate_detailed_report,
            'comparative': self._generate_comparative_report,
            'json': self._generate_json_report
        }
    
    def generate_report(self, results: List[EntropyDetectionResult],
                       report_type: str = 'summary',
                       output_file: Optional[str] = None) -> str:
        """Generate a comprehensive analysis report"""
        
        if report_type not in self.report_templates:
            raise ValueError(f"Unknown report type: {report_type}. Available: {list(self.report_templates.keys())}")
        
        report_content = self.report_templates[report_type](results)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            logger.info(f"Report saved to {output_file}")
        
        return report_content
    
    def _generate_summary_report(self, results: List[EntropyDetectionResult]) -> str:
        """Generate summary report"""
        lines = []
        lines.append("=== Entropy-Based Packer Detection Summary ===")
        lines.append(f"Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Files Analyzed: {len(results)}")
        lines.append("")
        
        # Overall statistics
        packed_files = [r for r in results if r.is_packed]
        lines.append(f"Packed Files Detected: {len(packed_files)} ({len(packed_files)/len(results)*100:.1f}%)")
        
        # Packer family distribution
        packer_counts = {}
        for result in packed_files:
            family = result.packer_family.value
            packer_counts[family] = packer_counts.get(family, 0) + 1
        
        if packer_counts:
            lines.append("\nPacker Family Distribution:")
            for family, count in sorted(packer_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {family.title()}: {count} files")
        
        # Confidence statistics
        if packed_files:
            confidences = [r.confidence_score for r in packed_files]
            lines.append(f"\nConfidence Statistics:")
            lines.append(f"  Average Confidence: {sum(confidences)/len(confidences):.2f}")
            lines.append(f"  Highest Confidence: {max(confidences):.2f}")
            lines.append(f"  Lowest Confidence: {min(confidences):.2f}")
        
        # Performance statistics
        analysis_times = [r.analysis_time for r in results]
        memory_usages = [r.memory_usage for r in results if r.memory_usage > 0]
        
        lines.append(f"\nPerformance Statistics:")
        lines.append(f"  Average Analysis Time: {sum(analysis_times)/len(analysis_times):.2f}s")
        lines.append(f"  Total Analysis Time: {sum(analysis_times):.2f}s")
        if memory_usages:
            lines.append(f"  Average Memory Usage: {sum(memory_usages)/len(memory_usages)/1024/1024:.1f}MB")
        
        return "\n".join(lines)
    
    def _generate_detailed_report(self, results: List[EntropyDetectionResult]) -> str:
        """Generate detailed report with individual file analysis"""
        lines = []
        lines.append("=== Detailed Entropy Analysis Report ===")
        lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        for i, result in enumerate(results, 1):
            lines.append(f"--- File {i}: {os.path.basename(result.file_path)} ---")
            lines.append(f"Full Path: {result.file_path}")
            lines.append(f"Analysis Mode: {result.analysis_mode.value}")
            lines.append(f"Is Packed: {result.is_packed}")
            
            if result.is_packed:
                lines.append(f"Packer Family: {result.packer_family.value}")
                lines.append(f"Confidence Score: {result.confidence_score:.3f}")
                lines.append(f"False Positive Probability: {result.false_positive_probability:.3f}")
                
                # Entropy metrics
                lines.append("\nEntropy Metrics:")
                lines.append(f"  Shannon Entropy: {result.metrics.shannon_entropy:.3f}")
                lines.append(f"  Compression Ratio: {result.metrics.compression_ratio:.3f}")
                lines.append(f"  Entropy Variance: {result.metrics.entropy_variance:.3f}")
                lines.append(f"  High Entropy Sections: {len(result.metrics.high_entropy_sections)}")
                
                # Recommendations
                if result.unpacking_recommendations:
                    lines.append("\nUnpacking Recommendations:")
                    for rec in result.unpacking_recommendations[:3]:  # Top 3 recommendations
                        lines.append(f"  - {rec}")
            
            lines.append(f"Analysis Time: {result.analysis_time:.2f}s")
            lines.append(f"Memory Usage: {result.memory_usage/1024/1024:.1f}MB")
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_comparative_report(self, results: List[EntropyDetectionResult]) -> str:
        """Generate comparative analysis report"""
        lines = []
        lines.append("=== Comparative Entropy Analysis Report ===")
        lines.append("")
        
        # Group results by packer family
        family_groups = {}
        for result in results:
            if result.is_packed:
                family = result.packer_family.value
                if family not in family_groups:
                    family_groups[family] = []
                family_groups[family].append(result)
        
        for family, family_results in family_groups.items():
            lines.append(f"--- {family.title()} Analysis ({len(family_results)} files) ---")
            
            # Calculate family statistics
            confidences = [r.confidence_score for r in family_results]
            entropies = [r.metrics.shannon_entropy for r in family_results]
            compression_ratios = [r.metrics.compression_ratio for r in family_results]
            
            lines.append(f"Confidence Range: {min(confidences):.2f} - {max(confidences):.2f}")
            lines.append(f"Average Confidence: {sum(confidences)/len(confidences):.2f}")
            lines.append(f"Entropy Range: {min(entropies):.3f} - {max(entropies):.3f}")
            lines.append(f"Average Entropy: {sum(entropies)/len(entropies):.3f}")
            lines.append(f"Compression Range: {min(compression_ratios):.3f} - {max(compression_ratios):.3f}")
            lines.append("")
            
            # List files
            lines.append("Files:")
            for result in family_results[:10]:  # Limit to first 10 files
                lines.append(f"  {os.path.basename(result.file_path)} (conf: {result.confidence_score:.2f})")
            if len(family_results) > 10:
                lines.append(f"  ... and {len(family_results) - 10} more files")
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_json_report(self, results: List[EntropyDetectionResult]) -> str:
        """Generate JSON report for programmatic processing"""
        report_data = {
            "metadata": {
                "generation_time": time.time(),
                "generation_date": time.strftime('%Y-%m-%d %H:%M:%S'),
                "total_files": len(results),
                "packed_files": len([r for r in results if r.is_packed])
            },
            "results": []
        }
        
        for result in results:
            result_data = {
                "file_path": result.file_path,
                "file_name": os.path.basename(result.file_path),
                "analysis_mode": result.analysis_mode.value,
                "is_packed": result.is_packed,
                "packer_family": result.packer_family.value,
                "confidence_score": result.confidence_score,
                "false_positive_probability": result.false_positive_probability,
                "entropy_metrics": {
                    "shannon_entropy": result.metrics.shannon_entropy,
                    "compression_ratio": result.metrics.compression_ratio,
                    "entropy_variance": result.metrics.entropy_variance,
                    "high_entropy_sections": result.metrics.high_entropy_sections,
                    "entropy_transitions": len(result.metrics.entropy_transitions),
                    "anomalous_regions": len(result.anomalous_regions)
                },
                "performance": {
                    "analysis_time": result.analysis_time,
                    "memory_usage_mb": result.memory_usage / 1024 / 1024
                },
                "recommendations": result.unpacking_recommendations,
                "bypass_strategies": result.bypass_strategies,
                "confidence_breakdown": result.confidence_breakdown
            }
            
            report_data["results"].append(result_data)
        
        return json.dumps(report_data, indent=2, default=str)


class EntropyConfigurationManager:
    """Manage entropy detection configurations and presets"""
    
    def __init__(self):
        self.presets = {
            'fast_scan': {
                'analysis_mode': EntropyAnalysisMode.FAST,
                'enable_ml': False,
                'description': 'Quick entropy analysis for large-scale scanning'
            },
            'standard_analysis': {
                'analysis_mode': EntropyAnalysisMode.STANDARD,
                'enable_ml': True,
                'description': 'Balanced analysis with ML enhancement'
            },
            'deep_investigation': {
                'analysis_mode': EntropyAnalysisMode.DEEP,
                'enable_ml': True,
                'description': 'Comprehensive analysis for detailed investigation'
            },
            'realtime_monitoring': {
                'analysis_mode': EntropyAnalysisMode.REALTIME,
                'enable_ml': False,
                'description': 'Optimized for real-time file monitoring'
            }
        }
    
    def get_preset(self, preset_name: str) -> Dict[str, any]:
        """Get configuration preset"""
        if preset_name not in self.presets:
            raise ValueError(f"Unknown preset: {preset_name}. Available: {list(self.presets.keys())}")
        return self.presets[preset_name].copy()
    
    def list_presets(self) -> Dict[str, str]:
        """List available presets with descriptions"""
        return {name: config['description'] for name, config in self.presets.items()}
    
    def create_detector_from_preset(self, preset_name: str) -> SophisticatedEntropyPackerDetector:
        """Create detector instance from preset configuration"""
        preset = self.get_preset(preset_name)
        return SophisticatedEntropyPackerDetector(preset['analysis_mode'])


# Convenience functions for common use cases
def quick_entropy_scan(file_path: str) -> bool:
    """Quick entropy-based packing check"""
    detector = create_fast_detector()
    result = detector.analyze_file(file_path, enable_ml=False)
    return result.is_packed

def detailed_entropy_analysis(file_path: str) -> EntropyDetectionResult:
    """Comprehensive entropy analysis with all features"""
    detector = create_deep_detector()
    return detector.analyze_file(file_path, enable_ml=True)

def batch_entropy_scan(directory: str, output_report: Optional[str] = None) -> List[EntropyDetectionResult]:
    """Batch entropy scanning with optional report generation"""
    processor = EntropyBatchProcessor()
    results = processor.process_directory(directory, analysis_mode=EntropyAnalysisMode.STANDARD)
    
    if output_report:
        report_generator = EntropyReportGenerator()
        report_generator.generate_report(results, 'summary', output_report)
    
    return results

def entropy_performance_benchmark(test_files: List[str]) -> Dict[str, any]:
    """Benchmark entropy analysis performance across different modes"""
    modes = [EntropyAnalysisMode.FAST, EntropyAnalysisMode.STANDARD, EntropyAnalysisMode.DEEP]
    benchmark_results = {}
    
    for mode in modes:
        detector = SophisticatedEntropyPackerDetector(mode)
        mode_results = []
        
        start_time = time.time()
        for file_path in test_files:
            if os.path.isfile(file_path):
                try:
                    result = detector.analyze_file(file_path)
                    mode_results.append(result.analysis_time)
                except Exception as e:
                    logger.error(f"Benchmark failed for {file_path}: {e}")
        
        total_time = time.time() - start_time
        
        benchmark_results[mode.value] = {
            'total_time': total_time,
            'average_time_per_file': sum(mode_results) / len(mode_results) if mode_results else 0,
            'files_processed': len(mode_results),
            'files_failed': len(test_files) - len(mode_results)
        }
    
    return benchmark_results


# Export key classes and functions
__all__ = [
    'EntropyPerformanceMonitor',
    'EntropyBatchProcessor', 
    'EntropyReportGenerator',
    'EntropyConfigurationManager',
    'quick_entropy_scan',
    'detailed_entropy_analysis',
    'batch_entropy_scan',
    'entropy_performance_benchmark'
]