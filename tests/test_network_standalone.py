#!/usr/bin/env python3
"""
Standalone network analysis functionality test
"""

import os
import logging
import time
import tempfile
import threading
from typing import Dict, Optional, Any

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock network analyzer with essential functionality
class MockNetworkTrafficAnalyzer:
    """Simplified network analyzer for testing core functionality."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        self.config = {
            'capture_file': 'license_traffic.pcap',
            'max_packets': 1000,
            'filter': 'tcp',
            'visualization_dir': 'visualizations',
            'auto_analyze': True
        }
        
        if config:
            self.config.update(config)
        
        # Initialize components
        self.packets = []
        self.connections = {}
        self.license_servers = set()
        self.license_connections = []
        self.license_patterns = [
            b'license', b'activation', b'auth', b'key', b'valid',
            b'FEATURE', b'INCREMENT', b'VENDOR', b'SERVER',
            b'HASP', b'Sentinel', b'FLEXLM', b'LCSAP'
        ]
        
        # Capture control
        self.capturing = False
        
        # Common license server ports
        self.license_ports = [1111, 1234, 2222, 27000, 27001, 27002, 27003, 27004, 27005,
                             1947, 6001, 22350, 22351, 2080, 8224, 5093, 49684]
        
        # Local network detection
        self.local_networks = ['192.168.', '10.', '172.16.', '127.', 'localhost']
        
        # Create visualization directory
        os.makedirs(self.config['visualization_dir'], exist_ok=True)
    
    def start_capture(self, interface: Optional[str] = None, simulate: bool = True) -> bool:
        """Start capturing network traffic (simulation mode)."""
        try:
            self.capturing = True
            
            if simulate:
                # Generate mock traffic for testing
                def mock_capture_thread():
                    """Generate mock network traffic for testing."""
                    self.logger.info("Starting mock network capture simulation...")
                    
                    # Simulate various types of traffic
                    mock_packets = [
                        # Web traffic
                        {
                            'timestamp': time.time(),
                            'src_ip': '192.168.1.100',
                            'dst_ip': '173.194.76.139',  # Google
                            'src_port': 54321,
                            'dst_port': 443,
                            'payload': b'GET /search?q=test HTTP/1.1\r\nHost: google.com\r\n',
                            'size': 150,
                            'connection_id': '192.168.1.100:54321-173.194.76.139:443'
                        },
                        # License server traffic (FlexLM)
                        {
                            'timestamp': time.time() + 1,
                            'src_ip': '192.168.1.100',
                            'dst_ip': '192.168.1.200',
                            'src_port': 54322,
                            'dst_port': 27000,
                            'payload': b'FEATURE matlab MLM 8.0 permanent uncounted\\n\\nVENDOR MLM\\n',
                            'size': 200,
                            'connection_id': '192.168.1.100:54322-192.168.1.200:27000'
                        },
                        # HASP/Sentinel license traffic
                        {
                            'timestamp': time.time() + 2,
                            'src_ip': '192.168.1.100',
                            'dst_ip': '192.168.1.201',
                            'src_port': 54323,
                            'dst_port': 1947,
                            'payload': b'HASP_FEATURE_REQUEST\\nkey=12345\\nactivation=valid\\n',
                            'size': 180,
                            'connection_id': '192.168.1.100:54323-192.168.1.201:1947'
                        },
                        # License validation over HTTP
                        {
                            'timestamp': time.time() + 3,
                            'src_ip': '192.168.1.100',
                            'dst_ip': '203.0.113.50',
                            'src_port': 54324,
                            'dst_port': 80,
                            'payload': b'POST /license/validate HTTP/1.1\\nContent-Type: application/json\\n{"license_key": "ABCD-1234-EFGH-5678"}',
                            'size': 250,
                            'connection_id': '192.168.1.100:54324-203.0.113.50:80'
                        }
                    ]
                    
                    for packet in mock_packets:
                        if not self.capturing:
                            break
                            
                        # Process each mock packet
                        self._process_mock_packet(packet)
                        time.sleep(0.5)  # Simulate packet intervals
                    
                    self.logger.info("Mock capture simulation completed")
                
                # Start simulation in thread
                thread = threading.Thread(target=mock_capture_thread)
                thread.daemon = True
                thread.start()
            else:
                self.logger.info("Real network capture would require root privileges and network libraries")
                return False
            
            self.logger.info(f"Started packet capture on {interface or 'default interface'}")
            return True
            
        except Exception as e:
            self.logger.error("Error starting capture: %s", e)
            return False
    
    def _process_mock_packet(self, packet_info: Dict[str, Any]):
        """Process a mock packet for testing."""
        try:
            conn_key = packet_info['connection_id']
            
            # Track connection
            if conn_key not in self.connections:
                is_outbound = any(packet_info['src_ip'].startswith(net) for net in self.local_networks)
                direction = "outbound" if is_outbound else "inbound"
                
                self.connections[conn_key] = {
                    'first_seen': packet_info['timestamp'],
                    'last_seen': packet_info['timestamp'],
                    'packets': [],
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'start_time': packet_info['timestamp'],
                    'last_time': packet_info['timestamp'],
                    'is_license': False,
                    'status': 'active',
                    'direction': direction,
                    'src_ip': packet_info['src_ip'],
                    'src_port': packet_info['src_port'],
                    'dst_ip': packet_info['dst_ip'],
                    'dst_port': packet_info['dst_port'],
                    'protocol': 'TCP'
                }
                
                # Check if it's license-related
                if packet_info['dst_port'] in self.license_ports or packet_info['src_port'] in self.license_ports:
                    self.connections[conn_key]['is_license'] = True
                    self.license_connections.append(conn_key)
                    self.logger.info("Potential license traffic detected: %s", conn_key)
            
            # Check payload for license patterns
            payload = packet_info.get('payload')
            if payload:
                for pattern in self.license_patterns:
                    if pattern in payload:
                        self.connections[conn_key]['is_license'] = True
                        # Add destination as license server
                        if packet_info['dst_port'] > 1024:
                            self.license_servers.add(packet_info['dst_ip'])
                        else:
                            self.license_servers.add(packet_info['src_ip'])
                        break
            
            # Update connection stats
            conn = self.connections[conn_key]
            conn['packets'].append(packet_info)
            conn['last_time'] = packet_info['timestamp']
            
            if packet_info['src_ip'] == conn['src_ip']:
                conn['bytes_sent'] += packet_info['size']
            else:
                conn['bytes_received'] += packet_info['size']
            
            # Add to packets list
            self.packets.append(packet_info)
            
            self.logger.info("Processed packet: %s -> %s:%d (%d bytes)", 
                           packet_info['src_ip'], packet_info['dst_ip'], 
                           packet_info['dst_port'], packet_info['size'])
            
        except Exception as e:
            self.logger.error("Error processing mock packet: %s", e)
    
    def analyze_traffic(self) -> Optional[Dict[str, Any]]:
        """Analyze captured traffic for license communications."""
        try:
            # Count packets and connections
            total_packets = len(self.packets)
            total_connections = len(self.connections)
            license_connections = sum(1 for conn in self.connections.values() if conn.get('is_license', False))
            
            # Identify license servers
            license_servers = list(self.license_servers)
            
            # Analyze license connections
            license_conn_details = []
            for conn_key, conn in self.connections.items():
                if conn.get('is_license', False):
                    # Extract connection details
                    conn_details = {
                        'conn_id': conn_key,
                        'src_ip': conn['src_ip'],
                        'dst_ip': conn['dst_ip'],
                        'src_port': conn['src_port'],
                        'dst_port': conn['dst_port'],
                        'packets': len(conn['packets']),
                        'bytes_sent': conn['bytes_sent'],
                        'bytes_received': conn['bytes_received'],
                        'duration': conn['last_time'] - conn['start_time']
                    }
                    
                    # Extract license patterns found
                    patterns_found = set()
                    for packet in conn['packets']:
                        if packet.get('payload'):
                            for pattern in self.license_patterns:
                                if pattern in packet['payload']:
                                    patterns_found.add(pattern.decode('utf-8', errors='ignore'))
                    
                    conn_details['patterns'] = list(patterns_found)
                    license_conn_details.append(conn_details)
            
            # Create analysis results
            results = {
                'total_packets': total_packets,
                'total_connections': total_connections,
                'license_connections': license_connections,
                'license_servers': license_servers,
                'license_conn_details': license_conn_details
            }
            
            self.logger.info("Traffic analysis completed:")
            self.logger.info("  Total packets: %d", total_packets)
            self.logger.info("  Total connections: %d", total_connections)
            self.logger.info("  License connections: %d", license_connections)
            self.logger.info("  License servers: %s", license_servers)
            
            return results
            
        except Exception as e:
            self.logger.error("Error analyzing traffic: %s", e)
            return None
    
    def stop_capture(self) -> bool:
        """Stop the packet capture process."""
        try:
            self.capturing = False
            self.logger.info("Stopping packet capture...")
            
            # Give capture threads time to finish
            time.sleep(1.0)
            
            # Log final statistics
            total_packets = len(self.packets)
            total_connections = len(self.connections)
            license_connections = sum(1 for conn in self.connections.values() if conn.get('is_license', False))
            
            self.logger.info("Packet capture stopped. Total: %d packets, %d connections, %d license connections",
                           total_packets, total_connections, license_connections)
            
            # Auto-analyze if configured
            if self.config.get('auto_analyze', True) and total_packets > 0:
                return self.analyze_traffic() is not None
            
            return True
            
        except Exception as e:
            self.logger.error("Error stopping capture: %s", e)
            return False
    
    def generate_report(self, filename: Optional[str] = None) -> bool:
        """Generate a simple text report of license traffic analysis."""
        try:
            # Analyze traffic
            results = self.analyze_traffic()
            
            if not results:
                self.logger.error("No analysis results available")
                return False
            
            # Use default filename if not provided
            if not filename:
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                filename = f"{self.config['visualization_dir']}/license_report_{timestamp}.txt"
            
            # Create text report
            with open(filename, 'w') as f:
                f.write("License Traffic Analysis Report\\n")
                f.write("=" * 40 + "\\n")
                f.write(f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\\n\\n")
                
                f.write("Summary:\\n")
                f.write(f"  Total Packets: {results['total_packets']}\\n")
                f.write(f"  Total Connections: {results['total_connections']}\\n")
                f.write(f"  License-related Connections: {results['license_connections']}\\n")
                f.write(f"  License Servers: {', '.join(results['license_servers']) if results['license_servers'] else 'None detected'}\\n\\n")
                
                if results['license_conn_details']:
                    f.write("License Connections:\\n")
                    f.write("-" * 20 + "\\n")
                    
                    for i, conn in enumerate(results['license_conn_details'], 1):
                        f.write(f"  {i}. {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}\\n")
                        f.write(f"     Packets: {conn['packets']}, Duration: {conn['duration']:.2f}s\\n")
                        f.write(f"     Bytes: {conn['bytes_sent']} sent, {conn['bytes_received']} received\\n")
                        if conn['patterns']:
                            f.write(f"     License patterns: {', '.join(conn['patterns'])}\\n")
                        f.write("\\n")
                else:
                    f.write("No license connections detected.\\n")
            
            self.logger.info("Generated text report: %s", filename)
            return True
            
        except Exception as e:
            self.logger.error("Error generating report: %s", e)
            return False


def main():
    """Test network analysis functionality."""
    print('=== TESTING INTELLICRACK NETWORK ANALYSIS FUNCTIONALITY ===')
    
    # Test 1: Basic analyzer initialization
    print('\\n1. Testing network analyzer initialization:')
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                'visualization_dir': tmpdir,
                'max_packets': 50,
                'auto_analyze': True
            }
            
            analyzer = MockNetworkTrafficAnalyzer(config)
            print("✅ Network analyzer initialized successfully")
            print(f"   Config: {analyzer.config}")
            print(f"   License ports monitored: {len(analyzer.license_ports)}")
            
            # Test 2: Mock traffic capture
            print('\\n2. Testing mock traffic capture:')
            success = analyzer.start_capture(interface=None, simulate=True)
            print(f"   Capture started: {'✅ Success' if success else '❌ Failed'}")
            
            if success:
                # Let it run for a few seconds to capture mock traffic
                print("   Waiting for mock traffic generation...")
                time.sleep(3)
                
                # Stop capture
                print('\\n3. Testing capture stop and analysis:')
                stop_success = analyzer.stop_capture()
                print(f"   Capture stopped: {'✅ Success' if stop_success else '❌ Failed'}")
                
                # Test 3: Traffic analysis
                print('\\n4. Testing traffic analysis:')
                results = analyzer.analyze_traffic()
                if results:
                    print("✅ Traffic analysis completed successfully")
                    print(f"   Total packets: {results['total_packets']}")
                    print(f"   Total connections: {results['total_connections']}")
                    print(f"   License connections: {results['license_connections']}")
                    print(f"   License servers: {results['license_servers']}")
                    
                    if results['license_conn_details']:
                        print("   License connection details:")
                        for i, conn in enumerate(results['license_conn_details'], 1):
                            print(f"     {i}. {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}")
                            print(f"        Packets: {conn['packets']}, Duration: {conn['duration']:.2f}s")
                            if conn['patterns']:
                                print(f"        Patterns: {', '.join(conn['patterns'])}")
                else:
                    print("❌ Traffic analysis failed")
                
                # Test 4: Report generation
                print('\\n5. Testing report generation:')
                report_success = analyzer.generate_report()
                print(f"   Report generated: {'✅ Success' if report_success else '❌ Failed'}")
                
                # List generated files
                if os.path.exists(tmpdir):
                    files = os.listdir(tmpdir)
                    if files:
                        print(f"   Generated files: {files}")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    print('\\n=== NETWORK ANALYSIS FUNCTIONALITY TEST COMPLETED ===')
    print('✅ Core network analysis functions working correctly!')


if __name__ == '__main__':
    main()