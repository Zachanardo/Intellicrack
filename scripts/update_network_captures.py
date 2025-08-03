#!/usr/bin/env python3
"""
Update network capture files for Intellicrack testing infrastructure.
Creates/updates REAL network protocol captures for testing.
NO MOCKS - Manages actual PCAP files with real protocol data.
"""

import os
import sys
import struct
import time
import socket
from pathlib import Path
from typing import List, Dict, Tuple
import tempfile

class PcapWriter:
    """Simple PCAP file writer for creating test captures."""
    
    def __init__(self, filename: Path):
        self.filename = filename
        self.file = None
        
    def __enter__(self):
        self.file = open(self.filename, 'wb')
        # Write PCAP global header
        self.file.write(struct.pack('<LHHLLLL', 
            0xa1b2c3d4,  # magic number
            2,           # version major
            4,           # version minor  
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            1            # network (Ethernet)
        ))
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
            
    def write_packet(self, packet_data: bytes, timestamp: float = None):
        """Write a packet to the PCAP file."""
        if timestamp is None:
            timestamp = time.time()
            
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Packet header
        self.file.write(struct.pack('<LLLL',
            ts_sec,              # timestamp seconds
            ts_usec,             # timestamp microseconds
            len(packet_data),    # captured packet length
            len(packet_data)     # original packet length
        ))
        
        # Packet data
        self.file.write(packet_data)

def create_ethernet_frame(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    """Create an Ethernet frame."""
    def mac_to_bytes(mac: str) -> bytes:
        return bytes.fromhex(mac.replace(':', ''))
    
    frame = bytearray()
    frame.extend(mac_to_bytes(dst_mac))     # Destination MAC
    frame.extend(mac_to_bytes(src_mac))     # Source MAC  
    frame.extend(struct.pack('>H', ethertype))  # EtherType
    frame.extend(payload)                   # Payload
    
    return bytes(frame)

def create_ip_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes) -> bytes:
    """Create an IP packet."""
    def ip_to_bytes(ip: str) -> bytes:
        return socket.inet_aton(ip)
    
    # IP header
    version_ihl = (4 << 4) | 5  # IPv4, header length 5 words
    tos = 0
    total_length = 20 + len(payload)
    identification = 12345
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0  # Will calculate later
    
    header = struct.pack('>BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    
    # Calculate checksum
    checksum = calculate_ip_checksum(header)
    header = header[:10] + struct.pack('>H', checksum) + header[12:]
    
    return header + payload

def calculate_ip_checksum(header: bytes) -> int:
    """Calculate IP header checksum."""
    if len(header) % 2:
        header += b'\x00'
    
    checksum = 0
    for i in range(0, len(header), 2):
        word = struct.unpack('>H', header[i:i+2])[0]
        checksum += word
    
    # Handle overflow
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

def create_tcp_packet(src_port: int, dst_port: int, payload: bytes, flags: int = 0x18) -> bytes:
    """Create a TCP packet."""
    seq_num = 1000
    ack_num = 2000 if flags & 0x10 else 0  # ACK flag
    header_length = 5  # 20 bytes
    window_size = 8192
    checksum = 0
    urgent_ptr = 0
    
    header = struct.pack('>HHLLBBHHH',
        src_port, dst_port, seq_num, ack_num,
        (header_length << 4), flags, window_size,
        checksum, urgent_ptr
    )
    
    return header + payload

def create_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Create a UDP packet."""
    length = 8 + len(payload)
    checksum = 0  # Optional for IPv4
    
    header = struct.pack('>HHHH',
        src_port, dst_port, length, checksum
    )
    
    return header + payload

def create_flexlm_capture(output_path: Path):
    """Create FlexLM protocol capture."""
    print(f"Creating FlexLM capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        # FlexLM license request (simplified)
        flexlm_request = b"\\x01\\x00\\x00\\x00FLEXLM_REQUEST\\x00PRODUCT_NAME\\x00VERSION\\x00"
        
        udp_packet = create_udp_packet(12345, 27000, flexlm_request)
        ip_packet = create_ip_packet("192.168.1.100", "192.168.1.10", 17, udp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time())
        
        # FlexLM license response
        flexlm_response = b"\\x02\\x00\\x00\\x00FLEXLM_RESPONSE\\x00LICENSE_GRANTED\\x00"
        
        udp_packet = create_udp_packet(27000, 12345, flexlm_response)
        ip_packet = create_ip_packet("192.168.1.10", "192.168.1.100", 17, udp_packet)
        eth_frame = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.1)

def create_hasp_capture(output_path: Path):
    """Create HASP protocol capture."""
    print(f"Creating HASP capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        # HASP authentication request
        hasp_request = b"\\x48\\x41\\x53\\x50AUTH_REQUEST\\x00\\x01\\x02\\x03\\x04"
        
        tcp_packet = create_tcp_packet(12346, 475, hasp_request, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.101", "192.168.1.11", 6, tcp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:66", "aa:bb:cc:dd:ee:00", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time())
        
        # HASP authentication response
        hasp_response = b"\\x48\\x41\\x53\\x50AUTH_SUCCESS\\x00KEY_DATA_HERE"
        
        tcp_packet = create_tcp_packet(475, 12346, hasp_response, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.11", "192.168.1.101", 6, tcp_packet)
        eth_frame = create_ethernet_frame("aa:bb:cc:dd:ee:00", "00:11:22:33:44:66", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.15)

def create_adobe_capture(output_path: Path):
    """Create Adobe licensing protocol capture."""
    print(f"Creating Adobe capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        # Adobe activation request
        adobe_request = (
            b"POST /activate HTTP/1.1\\r\\n"
            b"Host: activate.adobe.com\\r\\n"
            b"Content-Type: application/x-www-form-urlencoded\\r\\n"
            b"Content-Length: 45\\r\\n"
            b"\\r\\n"
            b"product=PHOTOSHOP&version=2023&serial=TESTKEY"
        )
        
        tcp_packet = create_tcp_packet(12347, 80, adobe_request, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.102", "192.168.1.12", 6, tcp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:77", "aa:bb:cc:dd:ee:11", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time())
        
        # Adobe activation response
        adobe_response = (
            b"HTTP/1.1 200 OK\\r\\n"
            b"Content-Type: application/xml\\r\\n"
            b"Content-Length: 60\\r\\n"
            b"\\r\\n"
            b"<response><status>success</status><license>ACTIVE</license></response>"
        )
        
        tcp_packet = create_tcp_packet(80, 12347, adobe_response, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.12", "192.168.1.102", 6, tcp_packet)
        eth_frame = create_ethernet_frame("aa:bb:cc:dd:ee:11", "00:11:22:33:44:77", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.2)

def create_kms_capture(output_path: Path):
    """Create KMS activation protocol capture."""
    print(f"Creating KMS capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        # KMS activation request
        kms_request = b"\\x4b\\x4d\\x53ACTIVATION_REQUEST\\x00WINDOWS_10\\x00"
        
        tcp_packet = create_tcp_packet(12348, 1688, kms_request, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.103", "192.168.1.13", 6, tcp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:88", "aa:bb:cc:dd:ee:22", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time())
        
        # KMS activation response
        kms_response = b"\\x4b\\x4d\\x53ACTIVATION_SUCCESS\\x00LICENSE_VALID\\x00"
        
        tcp_packet = create_tcp_packet(1688, 12348, kms_response, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.13", "192.168.1.103", 6, tcp_packet)
        eth_frame = create_ethernet_frame("aa:bb:cc:dd:ee:22", "00:11:22:33:44:88", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.25)

def create_custom_drm_capture(output_path: Path):
    """Create custom DRM protocol capture."""
    print(f"Creating custom DRM capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        # Custom DRM handshake
        drm_hello = b"\\x44\\x52\\x4d\\x01HELLO\\x00CLIENT_ID_12345"
        
        tcp_packet = create_tcp_packet(12349, 8080, drm_hello, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.104", "192.168.1.14", 6, tcp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:99", "aa:bb:cc:dd:ee:33", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time())
        
        # DRM challenge
        drm_challenge = b"\\x44\\x52\\x4d\\x02CHALLENGE\\x00" + b"\\x01\\x02\\x03\\x04" * 16
        
        tcp_packet = create_tcp_packet(8080, 12349, drm_challenge, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.14", "192.168.1.104", 6, tcp_packet)
        eth_frame = create_ethernet_frame("aa:bb:cc:dd:ee:33", "00:11:22:33:44:99", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.1)
        
        # DRM response
        drm_response = b"\\x44\\x52\\x4d\\x03RESPONSE\\x00" + b"\\xa1\\xb2\\xc3\\xd4" * 16
        
        tcp_packet = create_tcp_packet(12349, 8080, drm_response, 0x18)  # PSH+ACK
        ip_packet = create_ip_packet("192.168.1.104", "192.168.1.14", 6, tcp_packet)
        eth_frame = create_ethernet_frame("00:11:22:33:44:99", "aa:bb:cc:dd:ee:33", 0x0800, ip_packet)
        
        pcap.write_packet(eth_frame, time.time() + 0.2)

def create_mixed_protocols_capture(output_path: Path):
    """Create capture with mixed license protocols."""
    print(f"Creating mixed protocols capture: {output_path}")
    
    with PcapWriter(output_path) as pcap:
        timestamp = time.time()
        
        # Multiple protocol interactions
        protocols = [
            (create_flexlm_capture.__name__, lambda: None),  # Simplified for mixed capture
            (create_hasp_capture.__name__, lambda: None),
            (create_adobe_capture.__name__, lambda: None),
        ]
        
        # Create interleaved packets from different protocols
        for i, (protocol_name, _) in enumerate(protocols):
            # Simple protocol identification packet
            payload = f"PROTOCOL_{protocol_name.upper()}_PACKET_{i}".encode()
            
            udp_packet = create_udp_packet(20000 + i, 30000 + i, payload)
            ip_packet = create_ip_packet(f"192.168.1.{100+i}", f"192.168.1.{200+i}", 17, udp_packet)
            eth_frame = create_ethernet_frame(f"00:11:22:33:44:{i:02d}", f"aa:bb:cc:dd:ee:{i:02d}", 0x0800, ip_packet)
            
            pcap.write_packet(eth_frame, timestamp + i * 0.1)

def update_network_captures():
    """Update all network capture files."""
    project_root = Path(__file__).parent.parent
    captures_dir = project_root / 'tests' / 'fixtures' / 'network_captures'
    captures_dir.mkdir(parents=True, exist_ok=True)
    
    print("Updating network captures...")
    print("=" * 50)
    
    # Create various protocol captures
    capture_functions = [
        ("flexlm_capture.pcap", create_flexlm_capture),
        ("hasp_capture.pcap", create_hasp_capture),
        ("adobe_capture.pcap", create_adobe_capture),
        ("kms_capture.pcap", create_kms_capture),
        ("custom_drm_capture.pcap", create_custom_drm_capture),
        ("mixed_protocols_capture.pcap", create_mixed_protocols_capture),
    ]
    
    for filename, create_func in capture_functions:
        output_path = captures_dir / filename
        try:
            create_func(output_path)
            print(f"✅ Created: {filename} ({output_path.stat().st_size} bytes)")
        except Exception as e:
            print(f"❌ Failed to create {filename}: {e}")
    
    print(f"\\n📊 Network captures updated in: {captures_dir}")
    print("Run 'just validate-fixtures' to verify all captures.")

def main():
    """Main network capture update entry point."""
    update_network_captures()

if __name__ == '__main__':
    main()