#!/usr/bin/env python3
"""
Sample binary analysis script demonstrating Intellicrack usage.

This script shows how to use the Intellicrack library programmatically
for various binary analysis tasks.
"""

import os
import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from intellicrack.utils.binary_analysis import analyze_binary, identify_binary_format
    from intellicrack.core.analysis import (
        VulnerabilityEngine,
        SymbolicExecutionEngine,
        TaintAnalysisEngine,
        CFGExplorer
    )
    from intellicrack.core.network import (
        NetworkTrafficAnalyzer,
        ProtocolFingerprinter
    )
    from intellicrack.utils.report_generator import generate_report
    from intellicrack.core.reporting.pdf_generator import PDFReportGenerator
    from intellicrack.config import CONFIG
except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    print("Please ensure Intellicrack is properly installed.")
    sys.exit(1)


def example_basic_analysis():
    """Example: Basic binary analysis."""
    print("=== Example 1: Basic Binary Analysis ===")
    
    # Analyze a sample binary (use any executable on your system)
    binary_path = "/bin/ls"  # Replace with your target binary
    
    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        return
    
    # Perform basic analysis
    result = analyze_binary(binary_path)
    
    # Display results
    print(f"Binary: {binary_path}")
    print(f"Format: {result.get('file_type', 'Unknown')}")
    print(f"Architecture: {result.get('architecture', 'Unknown')}")
    print(f"Size: {result.get('size', 0)} bytes")
    print(f"Entropy: {result.get('entropy', 0):.2f}")
    
    # Check for packing
    if result.get('is_packed'):
        print("Warning: Binary appears to be packed!")
        print(f"Packer: {result.get('packer_info', 'Unknown')}")
    
    print()


def example_vulnerability_analysis():
    """Example: Vulnerability detection."""
    print("=== Example 2: Vulnerability Analysis ===")
    
    binary_path = "test_binary.exe"  # Replace with your target
    
    # Create a dummy binary for demonstration
    if not os.path.exists(binary_path):
        with open(binary_path, 'wb') as f:
            # Write a minimal PE header
            f.write(b'MZ' + b'\x00' * 58 + b'\x3c\x00\x00\x00')
            f.write(b'PE\x00\x00' + b'\x00' * 100)
            # Add some vulnerable-looking patterns
            f.write(b'strcpy' + b'\x00' * 10)
            f.write(b'gets' + b'\x00' * 10)
    
    try:
        # Initialize vulnerability engine
        vuln_engine = VulnerabilityEngine()
        
        # Analyze for vulnerabilities
        vulnerabilities = vuln_engine.analyze(binary_path)
        
        # Display findings
        if vulnerabilities.get('vulnerabilities'):
            print(f"Found {len(vulnerabilities['vulnerabilities'])} potential vulnerabilities:")
            for vuln in vulnerabilities['vulnerabilities']:
                print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")
                print(f"    Location: {vuln.get('address', 'Unknown')}")
                print(f"    Severity: {vuln.get('severity', 'Unknown')}")
        else:
            print("No vulnerabilities detected.")
    
    except Exception as e:
        print(f"Vulnerability analysis failed: {e}")
    
    finally:
        # Clean up dummy file
        if os.path.exists(binary_path) and os.path.getsize(binary_path) < 1000:
            os.remove(binary_path)
    
    print()


def example_license_analysis():
    """Example: License mechanism analysis."""
    print("=== Example 3: License Mechanism Analysis ===")
    
    # This example demonstrates how to analyze license protection
    binary_path = "licensed_app.exe"  # Replace with actual licensed software
    
    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        print("This example requires a real licensed application.")
        return
    
    try:
        # Analyze for license mechanisms
        from intellicrack.utils.runner_functions import run_deep_license_analysis, run_qiling_emulation, run_qemu_analysis
        
        license_info = run_deep_license_analysis(binary_path)
        
        # Display findings
        print(f"License Protection Analysis for: {binary_path}")
        
        if license_info.get('license_checks'):
            print(f"Found {len(license_info['license_checks'])} license check routines:")
            for check in license_info['license_checks']:
                print(f"  - Type: {check.get('type', 'Unknown')}")
                print(f"    Address: {check.get('address', 'Unknown')}")
                print(f"    Method: {check.get('method', 'Unknown')}")
        
        if license_info.get('protection_type'):
            print(f"Protection Type: {license_info['protection_type']}")
        
        if license_info.get('bypass_suggestions'):
            print("Bypass Suggestions:")
            for suggestion in license_info['bypass_suggestions']:
                print(f"  - {suggestion}")
        
        # Try Qiling emulation
        print("\n--- Qiling Emulation ---")
        qiling_results = run_qiling_emulation(None, binary_path, timeout=30)
        if qiling_results.get('status') == 'success':
            results = qiling_results.get('results', {})
            print(f"API Calls: {results.get('total_api_calls', 0)}")
            print(f"License Checks: {len(results.get('license_checks', []))}")
        else:
            print(f"Qiling failed: {qiling_results.get('error', 'Unknown')}")
    
    except Exception as e:
        print(f"License analysis failed: {e}")
    
    print()


def example_network_analysis():
    """Example: Network traffic analysis for license validation."""
    print("=== Example 4: Network License Analysis ===")
    
    # This example shows how to analyze network-based license checks
    try:
        # Initialize network analyzer
        traffic_analyzer = NetworkTrafficAnalyzer()
        
        # Start capture (requires appropriate permissions)
        print("Starting network capture...")
        print("Run your licensed application now...")
        
        # Simulate capture (in real usage, this would capture actual traffic)
        captured_data = {
            'connections': [
                {
                    'dest': 'license.example.com',
                    'port': 443,
                    'protocol': 'HTTPS',
                    'data_size': 1024
                }
            ],
            'license_endpoints': [
                'https://license.example.com/validate',
                'https://license.example.com/activate'
            ]
        }
        
        # Analyze captured traffic
        print("\nCaptured License-Related Traffic:")
        for conn in captured_data['connections']:
            print(f"  - {conn['dest']}:{conn['port']} ({conn['protocol']})")
        
        print("\nIdentified License Endpoints:")
        for endpoint in captured_data['license_endpoints']:
            print(f"  - {endpoint}")
        
        # Use protocol fingerprinter
        fingerprinter = ProtocolFingerprinter()
        
        # Analyze protocol (simulated)
        protocol_info = {
            'protocol_type': 'Custom HTTP-based',
            'authentication': 'Token-based',
            'encryption': 'TLS 1.3'
        }
        
        print("\nProtocol Analysis:")
        for key, value in protocol_info.items():
            print(f"  {key}: {value}")
    
    except Exception as e:
        print(f"Network analysis error: {e}")
        print("Note: Network analysis requires appropriate permissions.")
    
    print()


def example_report_generation():
    """Example: Generate analysis report."""
    print("=== Example 5: Report Generation ===")
    
    # Collect analysis results
    analysis_results = {
        'binary': 'example_app.exe',
        'timestamp': '2024-01-01 12:00:00',
        'analyses': {
            'basic': {
                'file_type': 'PE32+',
                'architecture': 'x64',
                'size': 524288,
                'entropy': 6.8
            },
            'vulnerabilities': {
                'count': 3,
                'critical': 1,
                'high': 1,
                'medium': 1
            },
            'license': {
                'protection_type': 'Online Activation',
                'license_server': 'license.example.com',
                'bypass_difficulty': 'Medium'
            }
        }
    }
    
    # Generate reports in different formats
    formats = ['text', 'json', 'html']
    
    for fmt in formats:
        try:
            output = generate_report(
                analysis_results,
                report_format=fmt,
                title="Intellicrack Analysis Report"
            )
            
            # Save report
            filename = f"sample_report.{fmt}"
            
            if fmt == 'json':
                with open(filename, 'w') as f:
                    json.dump(analysis_results, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write(output if isinstance(output, str) else str(output))
            
            print(f"Generated {fmt.upper()} report: {filename}")
        
        except Exception as e:
            print(f"Failed to generate {fmt} report: {e}")
    
    # Try PDF generation with proper PDFReportGenerator
    try:
        print("Generating comprehensive PDF report...")
        pdf_generator = PDFReportGenerator()
        
        pdf_path = pdf_generator.generate_report(
            analysis_results,
            report_type="comprehensive",
            output_path="sample_comprehensive_report.pdf"
        )
        
        if pdf_path:
            print(f"PDF report generated: {pdf_path}")
        else:
            print("PDF generation failed")
            
    except Exception as e:
        print(f"PDF generation error: {e}")
    
    print()


def example_advanced_usage():
    """Example: Advanced analysis with multiple engines."""
    print("=== Example 6: Advanced Multi-Engine Analysis ===")
    
    binary_path = "/usr/bin/python3"  # Use any available binary
    
    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        return
    
    # Perform comprehensive analysis using multiple engines
    results = {}
    
    # 1. Basic analysis
    print("Running basic analysis...")
    results['basic'] = analyze_binary(binary_path)
    
    # 2. Symbolic execution (if available)
    try:
        print("Running symbolic execution...")
        sym_engine = SymbolicExecutionEngine()
        results['symbolic'] = sym_engine.analyze(binary_path, max_depth=10)
    except Exception as e:
        print(f"  Symbolic execution not available: {e}")
    
    # 3. Control flow analysis
    try:
        print("Running CFG analysis...")
        cfg_explorer = CFGExplorer()
        results['cfg'] = cfg_explorer.analyze(binary_path)
    except Exception as e:
        print(f"  CFG analysis not available: {e}")
    
    # 4. Taint analysis
    try:
        print("Running taint analysis...")
        taint_engine = TaintAnalysisEngine()
        results['taint'] = taint_engine.analyze(binary_path)
    except Exception as e:
        print(f"  Taint analysis not available: {e}")
    
    # Display summary
    print("\n=== Analysis Summary ===")
    for analysis_type, data in results.items():
        if isinstance(data, dict):
            print(f"\n{analysis_type.upper()}:")
            for key, value in list(data.items())[:5]:  # Show first 5 items
                print(f"  {key}: {value}")
    
    print()


def main():
    """Run all examples."""
    print("Intellicrack Sample Binary Analysis")
    print("=" * 50)
    print()
    
    # Run examples
    example_basic_analysis()
    example_vulnerability_analysis()
    example_license_analysis()
    example_network_analysis()
    example_report_generation()
    example_advanced_usage()
    
    print("Examples completed!")
    print("\nFor more information, see the Intellicrack documentation.")


if __name__ == '__main__':
    main()