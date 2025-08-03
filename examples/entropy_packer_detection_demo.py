"""
Comprehensive Demonstration of Sophisticated Entropy-Based Packer Detection

This example demonstrates the advanced entropy analysis capabilities for detecting
packed and compressed executables with high accuracy and low false positive rates.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sys
import time
from pathlib import Path

# Add intellicrack to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.protection.entropy_packer_detector import (
    SophisticatedEntropyPackerDetector, EntropyAnalysisMode, PackerFamily,
    create_fast_detector, create_deep_detector, create_realtime_detector
)
from intellicrack.protection.entropy_integration import (
    EntropyBatchProcessor, EntropyReportGenerator, EntropyConfigurationManager,
    quick_entropy_scan, detailed_entropy_analysis, batch_entropy_scan,
    entropy_performance_benchmark
)
from intellicrack.protection.advanced_detection_engine import create_advanced_detection_engine
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


def demonstrate_basic_entropy_analysis():
    """Demonstrate basic entropy analysis capabilities"""
    print("=== Basic Entropy Analysis Demo ===")
    
    # Find some executable files to analyze
    test_files = []
    
    # Look for Windows system files (safe to analyze)
    system_paths = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe", 
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\winver.exe"
    ]
    
    for path in system_paths:
        if os.path.exists(path):
            test_files.append(path)
            if len(test_files) >= 2:  # Limit for demo
                break
    
    if not test_files:
        print("No test files found. Please specify files to analyze.")
        return
    
    for file_path in test_files:
        print(f"\nAnalyzing: {os.path.basename(file_path)}")
        
        # Quick scan
        is_packed = quick_entropy_scan(file_path)
        print(f"Quick scan result: {'PACKED' if is_packed else 'NOT PACKED'}")
        
        # Detailed analysis
        result = detailed_entropy_analysis(file_path)
        
        print(f"Shannon Entropy: {result.metrics.shannon_entropy:.3f}")
        print(f"Compression Ratio: {result.metrics.compression_ratio:.3f}")
        print(f"Confidence Score: {result.confidence_score:.3f}")
        print(f"Packer Family: {result.packer_family.value}")
        print(f"Analysis Time: {result.analysis_time:.2f}s")
        
        if result.unpacking_recommendations:
            print("Recommendations:")
            for rec in result.unpacking_recommendations[:3]:
                print(f"  - {rec}")


def demonstrate_analysis_modes():
    """Demonstrate different analysis modes"""
    print("\n=== Analysis Modes Comparison ===")
    
    test_file = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(test_file):
        print("Test file not found, skipping analysis modes demo")
        return
    
    modes = [
        (EntropyAnalysisMode.FAST, "Fast Mode"),
        (EntropyAnalysisMode.STANDARD, "Standard Mode"),
        (EntropyAnalysisMode.DEEP, "Deep Mode"),
        (EntropyAnalysisMode.REALTIME, "Real-time Mode")
    ]
    
    print(f"Analyzing {os.path.basename(test_file)} with different modes:")
    
    for mode, mode_name in modes:
        detector = SophisticatedEntropyPackerDetector(mode)
        start_time = time.time()
        result = detector.analyze_file(test_file, enable_ml=False)
        analysis_time = time.time() - start_time
        
        print(f"\n{mode_name}:")
        print(f"  Analysis Time: {analysis_time:.3f}s")
        print(f"  Shannon Entropy: {result.metrics.shannon_entropy:.3f}")
        print(f"  Entropy Variance: {result.metrics.entropy_variance:.3f}")
        print(f"  Window Entropies: {len(result.metrics.window_entropies)} samples")
        print(f"  Memory Usage: {result.memory_usage / 1024 / 1024:.1f}MB")


def demonstrate_batch_processing():
    """Demonstrate batch processing capabilities"""
    print("\n=== Batch Processing Demo ===")
    
    # Use Windows System32 for demo (read-only analysis)
    system_dir = r"C:\Windows\System32"
    if not os.path.exists(system_dir):
        print("System directory not found, skipping batch demo")
        return
    
    print(f"Performing batch analysis on {system_dir}")
    print("(Limiting to first 5 executable files for demo)")
    
    # Create batch processor
    processor = EntropyBatchProcessor(max_workers=2)
    
    # Find executable files
    exe_files = []
    for file in os.listdir(system_dir):
        if file.lower().endswith(('.exe', '.dll')) and len(exe_files) < 5:
            file_path = os.path.join(system_dir, file)
            if os.path.isfile(file_path):
                exe_files.append(file_path)
    
    if not exe_files:
        print("No executable files found for batch processing")
        return
    
    # Process files
    start_time = time.time()
    results = processor.process_file_list(
        exe_files, 
        analysis_mode=EntropyAnalysisMode.FAST,
        enable_ml=False
    )
    batch_time = time.time() - start_time
    
    print(f"\nBatch processing completed in {batch_time:.2f}s")
    print(f"Files processed: {len(results)}")
    
    # Show summary
    packed_count = sum(1 for r in results if r.is_packed)
    avg_entropy = sum(r.metrics.shannon_entropy for r in results) / len(results)
    avg_compression = sum(r.metrics.compression_ratio for r in results) / len(results)
    
    print(f"Packed files detected: {packed_count}")
    print(f"Average entropy: {avg_entropy:.3f}")
    print(f"Average compression ratio: {avg_compression:.3f}")
    
    # Get performance summary
    perf_summary = processor.get_performance_summary()
    if perf_summary.get('status') != 'no_data':
        metrics = perf_summary['performance_metrics']
        print(f"Average analysis time: {metrics['avg_analysis_time']:.3f}s")


def demonstrate_report_generation():
    """Demonstrate report generation"""
    print("\n=== Report Generation Demo ===")
    
    # Create some mock results for demonstration
    from intellicrack.protection.entropy_packer_detector import (
        EntropyDetectionResult, MultiScaleEntropyMetrics, MLFeatureVector
    )
    from unittest.mock import Mock
    
    # Create mock results
    mock_results = []
    
    for i in range(3):
        # Create mock metrics
        mock_metrics = MultiScaleEntropyMetrics(
            shannon_entropy=7.0 + i * 0.5,
            renyi_entropy=6.8 + i * 0.4,
            kolmogorov_complexity_estimate=0.3 + i * 0.1,
            byte_level_entropy=7.0 + i * 0.5,
            word_level_entropy=6.9 + i * 0.4,
            dword_level_entropy=6.8 + i * 0.3,
            block_level_entropy=[7.0 + i * 0.5] * 10,
            window_entropies=[7.0 + i * 0.5] * 20,
            entropy_variance=0.2 + i * 0.1,
            entropy_skewness=0.1,
            entropy_kurtosis=-0.2,
            section_entropies={f'section_{j}': 7.0 + j * 0.2 for j in range(3)},
            high_entropy_sections=[f'section_{j}' for j in range(2)],
            entropy_distribution={'high': 0.7, 'medium': 0.2, 'low': 0.1},
            compression_ratio=0.3 + i * 0.1,
            compression_efficiency=0.7 - i * 0.1,
            decompression_complexity=50.0,
            repetitive_patterns=5,
            entropy_transitions=[(1, 0.5)],
            anomalous_regions=[],
            entropy_mean=7.0 + i * 0.5,
            entropy_std=0.1,
            entropy_range=0.2,
            autocorrelation=0.1
        )
        
        # Create mock ML features
        mock_features = Mock(spec=MLFeatureVector)
        
        # Create mock result
        mock_result = EntropyDetectionResult(
            file_path=f"/demo/test_file_{i}.exe",
            analysis_mode=EntropyAnalysisMode.STANDARD,
            metrics=mock_metrics,
            ml_features=mock_features,
            is_packed=i < 2,  # First two are packed
            packer_family=PackerFamily.UPX if i == 0 else PackerFamily.ASPACK if i == 1 else PackerFamily.UNKNOWN,
            confidence_score=0.85 if i < 2 else 0.15,
            false_positive_probability=0.1,
            entropy_visualizations={},
            anomalous_regions=[],
            unpacking_recommendations=[f"Recommendation {i+1}"],
            analysis_time=1.5 + i * 0.5,
            memory_usage=100 * 1024 * 1024,
            cache_hits=0,
            bypass_strategies=[f"Strategy {i+1}"],
            tool_recommendations=[f"Tool {i+1}"],
            confidence_breakdown={'signature_based': 0.8}
        )
        
        mock_results.append(mock_result)
    
    # Generate different types of reports
    generator = EntropyReportGenerator()
    
    print("Generating summary report...")
    summary_report = generator.generate_report(mock_results, 'summary')
    print(summary_report[:500] + "..." if len(summary_report) > 500 else summary_report)
    
    print("\n" + "="*50)
    print("Generating detailed report preview...")
    detailed_report = generator.generate_report(mock_results, 'detailed')
    print(detailed_report[:300] + "..." if len(detailed_report) > 300 else detailed_report)


def demonstrate_configuration_management():
    """Demonstrate configuration management"""
    print("\n=== Configuration Management Demo ===")
    
    config_manager = EntropyConfigurationManager()
    
    # List available presets
    print("Available configuration presets:")
    presets = config_manager.list_presets()
    for name, description in presets.items():
        print(f"  {name}: {description}")
    
    # Demonstrate preset usage
    print("\nCreating detectors from presets:")
    
    for preset_name in ['fast_scan', 'standard_analysis']:
        try:
            detector = config_manager.create_detector_from_preset(preset_name)
            preset_config = config_manager.get_preset(preset_name)
            
            print(f"\n{preset_name}:")
            print(f"  Analysis Mode: {preset_config['analysis_mode'].value}")
            print(f"  ML Enabled: {preset_config['enable_ml']}")
            print(f"  Description: {preset_config['description']}")
            
        except Exception as e:
            print(f"Failed to create detector for {preset_name}: {e}")


def demonstrate_advanced_detection_integration():
    """Demonstrate integration with advanced detection engine"""
    print("\n=== Advanced Detection Engine Integration ===")
    
    test_file = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(test_file):
        print("Test file not found, skipping integration demo")
        return
    
    # Create different detection engines
    engines = [
        (create_advanced_detection_engine(EntropyAnalysisMode.FAST), "Fast Engine"),
        (create_advanced_detection_engine(EntropyAnalysisMode.STANDARD), "Standard Engine"),
    ]
    
    print(f"Analyzing {os.path.basename(test_file)} with integrated detection engines:")
    
    for engine, engine_name in engines:
        try:
            start_time = time.time()
            result = engine.analyze(test_file, deep_analysis=False)
            analysis_time = time.time() - start_time
            
            print(f"\n{engine_name}:")
            print(f"  Analysis Time: {analysis_time:.2f}s")
            print(f"  Total Detections: {len(result.detections)}")
            print(f"  Overall Confidence: {result.overall_confidence:.1f}%")
            print(f"  Protection Layers: {result.protection_layers}")
            print(f"  Evasion Sophistication: {result.evasion_sophistication}")
            
            # Show entropy-specific detections
            entropy_detections = [d for d in result.detections if 'entropy' in d.name.lower()]
            if entropy_detections:
                print(f"  Entropy-based Detections: {len(entropy_detections)}")
                for detection in entropy_detections:
                    print(f"    - {detection.name} ({detection.confidence:.1f}%)")
            
        except Exception as e:
            print(f"Error with {engine_name}: {e}")


def demonstrate_performance_benchmark():
    """Demonstrate performance benchmarking"""
    print("\n=== Performance Benchmark Demo ===")
    
    # Find test files for benchmarking
    benchmark_files = []
    system_paths = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe"
    ]
    
    for path in system_paths:
        if os.path.exists(path):
            benchmark_files.append(path)
    
    if not benchmark_files:
        print("No files available for benchmarking")
        return
    
    print(f"Benchmarking entropy analysis with {len(benchmark_files)} files...")
    
    try:
        benchmark_results = entropy_performance_benchmark(benchmark_files)
        
        print("\nBenchmark Results:")
        for mode, results in benchmark_results.items():
            print(f"\n{mode.title()} Mode:")
            print(f"  Total Time: {results['total_time']:.2f}s")
            print(f"  Avg Time per File: {results['average_time_per_file']:.3f}s")
            print(f"  Files Processed: {results['files_processed']}")
            print(f"  Files Failed: {results['files_failed']}")
            
    except Exception as e:
        print(f"Benchmark failed: {e}")


def main():
    """Main demonstration function"""
    print("Sophisticated Entropy-Based Packer Detection System Demo")
    print("="*60)
    
    try:
        # Run all demonstrations
        demonstrate_basic_entropy_analysis()
        demonstrate_analysis_modes()
        demonstrate_batch_processing()
        demonstrate_report_generation()
        demonstrate_configuration_management()
        demonstrate_advanced_detection_integration()
        demonstrate_performance_benchmark()
        
        print("\n" + "="*60)
        print("Demo completed successfully!")
        print("\nKey Features Demonstrated:")
        print("• Multi-scale entropy analysis with advanced algorithms")
        print("• ML-based packer family classification")
        print("• Performance optimization for large files")
        print("• Batch processing with parallel execution")
        print("• Comprehensive reporting capabilities")
        print("• Configuration management with presets")
        print("• Integration with advanced detection engine")
        print("• Performance benchmarking across analysis modes")
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        logger.error(f"Demo error: {e}", exc_info=True)


if __name__ == "__main__":
    main()