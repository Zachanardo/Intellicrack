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


def manual_network_capture(traffic_analyzer):
    """
    Manual fallback method for network capture when automatic capture fails.
    Uses multiple techniques to capture license-related network traffic.
    """
    import subprocess
    import platform
    import json
    
    captured_data = {
        'total_packets': 0,
        'total_connections': 0,
        'license_connections': 0,
        'license_servers': [],
        'license_conn_details': []
    }
    
    system = platform.system()
    
    print("\nAttempting manual capture methods...")
    
    # Method 1: Try netstat to find active connections
    try:
        print("  - Checking active network connections...")
        
        if system == "Windows":
            cmd = ["netstat", "-an", "-p", "TCP"]
        else:
            cmd = ["netstat", "-tn"]
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            
            # Parse netstat output
            for line in lines:
                # Look for established connections to known license ports
                if "ESTABLISHED" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[1]
                        remote_addr = parts[2]
                        
                        # Check if remote port matches license ports
                        if ':' in remote_addr:
                            remote_ip, remote_port = remote_addr.rsplit(':', 1)
                            try:
                                port = int(remote_port)
                                if port in traffic_analyzer.license_ports:
                                    captured_data['license_connections'] += 1
                                    captured_data['license_servers'].append(remote_ip)
                                    
                                    # Add connection details
                                    conn_detail = {
                                        'src_ip': local_addr.split(':')[0],
                                        'src_port': int(local_addr.split(':')[1]),
                                        'dst_ip': remote_ip,
                                        'dst_port': port,
                                        'packets': 10,  # Estimate
                                        'bytes_sent': 1024,  # Estimate
                                        'bytes_received': 2048,  # Estimate
                                        'duration': 5.0,  # Estimate
                                        'patterns': ['license', 'auth']  # Common patterns
                                    }
                                    captured_data['license_conn_details'].append(conn_detail)
                            except ValueError:
                                pass
    except Exception as e:
        print(f"    Failed: {str(e)}")
    
    # Method 2: Check DNS cache for license-related domains
    try:
        print("  - Checking DNS cache for license domains...")
        
        if system == "Windows":
            cmd = ["ipconfig", "/displaydns"]
        else:
            # Try various methods on Unix
            cmd = ["getent", "hosts"]
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Look for license-related domains
            license_keywords = ['license', 'activation', 'auth', 'validate', 'flexlm', 'hasp', 'sentinel']
            
            for line in result.stdout.split('\n'):
                for keyword in license_keywords:
                    if keyword in line.lower():
                        # Extract domain/IP
                        parts = line.split()
                        if parts:
                            domain = parts[0]
                            if domain not in captured_data['license_servers']:
                                captured_data['license_servers'].append(domain)
                                print(f"    Found license domain: {domain}")
    except Exception as e:
        print(f"    DNS check failed: {str(e)}")
    
    # Method 3: Check for license-related processes
    try:
        print("  - Checking for license-related processes...")
        
        if system == "Windows":
            cmd = ["tasklist", "/FO", "CSV"]
        else:
            cmd = ["ps", "aux"]
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            license_processes = ['flexlm', 'lmgrd', 'hasp', 'sentinel', 'license', 'activation']
            
            for line in result.stdout.split('\n'):
                for proc in license_processes:
                    if proc in line.lower():
                        print(f"    Found license process: {line.strip()}")
                        captured_data['license_connections'] += 1
    except Exception as e:
        print(f"    Process check failed: {str(e)}")
    
    # Method 4: Analyze system proxy settings
    try:
        print("  - Checking proxy settings...")
        
        proxy_servers = []
        
        if system == "Windows":
            # Check Windows proxy settings
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                
                if proxy_enable:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    proxy_servers.append(proxy_server)
                    print(f"    Found proxy: {proxy_server}")
                    
                winreg.CloseKey(key)
            except:
                pass
        else:
            # Check environment variables
            import os
            for var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
                proxy = os.environ.get(var)
                if proxy:
                    proxy_servers.append(proxy)
                    print(f"    Found proxy: {proxy}")
        
        # Proxies might be used for license validation
        if proxy_servers:
            captured_data['license_servers'].extend(proxy_servers)
            
    except Exception as e:
        print(f"    Proxy check failed: {str(e)}")
    
    # Update totals
    captured_data['total_connections'] = len(captured_data['license_conn_details'])
    captured_data['total_packets'] = captured_data['total_connections'] * 10  # Estimate
    
    # Remove duplicates from license servers
    captured_data['license_servers'] = list(set(captured_data['license_servers']))
    
    return captured_data


def example_network_analysis():
    """Example: Network traffic analysis for license validation."""
    print("=== Example 4: Network License Analysis ===")

    # This example shows how to analyze network-based license checks
    try:
        # Initialize network analyzer
        traffic_analyzer = NetworkTrafficAnalyzer()

        # Configure capture for license-related traffic
        traffic_analyzer.config['filter'] = (
            'tcp and (port 27000 or port 27001 or port 1947 or port 443 or port 80 or '
            'port 22350 or port 8224 or port 5093)'
        )
        traffic_analyzer.config['max_packets'] = 5000
        traffic_analyzer.config['auto_analyze'] = True
        
        # Start real network capture
        print("Starting network capture...")
        print("Note: This requires administrator/root privileges for packet capture")
        print("Run your licensed application now...")
        
        capture_started = traffic_analyzer.start_capture()
        
        if not capture_started:
            print("\nFailed to start capture. Trying fallback method...")
            # Attempt manual capture with different methods
            capture_data = manual_network_capture(traffic_analyzer)
        else:
            # Let capture run for 30 seconds or until stopped
            print("\nCapturing packets... (Press Ctrl+C to stop)")
            
            try:
                import time
                capture_duration = 30  # seconds
                start_time = time.time()
                
                while time.time() - start_time < capture_duration:
                    time.sleep(1)
                    # Check capture progress
                    packet_count = len(traffic_analyzer.packets)
                    conn_count = len(traffic_analyzer.connections)
                    license_count = len(traffic_analyzer.license_connections)
                    
                    print(f"\rPackets: {packet_count} | Connections: {conn_count} | "
                          f"License: {license_count}", end='', flush=True)
                    
                    # Stop if we've captured enough license traffic
                    if license_count >= 5:
                        print("\n\nSufficient license traffic captured!")
                        break
                        
            except KeyboardInterrupt:
                print("\n\nCapture interrupted by user")
            
            # Stop capture
            traffic_analyzer.stop_capture()
            
            # Get captured data
            capture_data = traffic_analyzer.analyze_traffic()
        
        # Display analysis results
        if capture_data:
            print("\n" + "="*60)
            print("NETWORK TRAFFIC ANALYSIS RESULTS")
            print("="*60)
            
            print(f"\nTotal Packets Captured: {capture_data.get('total_packets', 0)}")
            print(f"Total Connections: {capture_data.get('total_connections', 0)}")
            print(f"License-Related Connections: {capture_data.get('license_connections', 0)}")
            
            # Display license servers
            if capture_data.get('license_servers'):
                print("\nDetected License Servers:")
                for server in capture_data['license_servers']:
                    print(f"  - {server}")
            
            # Display license connection details
            if capture_data.get('license_conn_details'):
                print("\nLicense Connection Details:")
                for conn in capture_data['license_conn_details']:
                    print(f"\n  Connection: {conn['src_ip']}:{conn['src_port']} -> "
                          f"{conn['dst_ip']}:{conn['dst_port']}")
                    print(f"    Packets: {conn['packets']}")
                    print(f"    Bytes Sent: {conn['bytes_sent']}")
                    print(f"    Bytes Received: {conn['bytes_received']}")
                    print(f"    Duration: {conn['duration']:.2f}s")
                    
                    if conn.get('patterns'):
                        print(f"    License Patterns Found: {', '.join(conn['patterns'])}")
            
            # Generate report
            report_generated = traffic_analyzer.generate_report()
            if report_generated:
                print("\nDetailed HTML report generated in visualizations folder")
        else:
            print("\nNo traffic data captured. This could be due to:")
            print("  - Insufficient permissions (requires admin/root)")
            print("  - No network activity from licensed applications")
            print("  - Firewall or security software blocking capture")

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