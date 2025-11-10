#!/usr/bin/env python3
"""Generate simulated network protocol captures for testing.
Creates realistic protocol captures in PCAP format for various licensing protocols.
"""

import hashlib
import os
import random
import struct
import time
from pathlib import Path

# Scapy is optional - we'll create raw PCAP if not available
try:
    from scapy.all import Ether, wrpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPWriter:
    """Simple PCAP file writer for when Scapy is not available."""

    def __init__(self, filename: str):
        self.file = open(filename, "wb")
        self._write_header()

    def _write_header(self):
        """Write PCAP file header."""
        # PCAP Magic number, version, timezone, snaplen, network type
        header = struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,  # Magic number
            2,
            4,  # Version major, minor
            0,
            0,  # Timezone offset, accuracy
            65535,  # Snaplen
            1,  # Network type (Ethernet)
        )
        self.file.write(header)

    def write_packet(self, data: bytes, timestamp: float = None):
        """Write a packet to PCAP file."""
        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)

        # Packet header
        header = struct.pack(
            "<IIII",
            ts_sec,
            ts_usec,  # Timestamp
            len(data),
            len(data),  # Captured length, actual length
        )

        self.file.write(header)
        self.file.write(data)

    def close(self):
        """Close the PCAP file."""
        self.file.close()


def create_ethernet_frame(src_mac: str, dst_mac: str, payload: bytes) -> bytes:
    """Create an Ethernet frame."""
    src_bytes = bytes.fromhex(src_mac.replace(":", ""))
    dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    ether_type = b"\x08\x00"  # IPv4

    return dst_bytes + src_bytes + ether_type + payload


def create_ip_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes) -> bytes:
    """Create an IP packet."""
    version_ihl = 0x45  # Version 4, header length 20
    tos = 0
    total_length = 20 + len(payload)
    identification = random.randint(1, 65535)
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0  # Will be calculated

    src_addr = struct.pack(">BBBB", *map(int, src_ip.split(".")))
    dst_addr = struct.pack(">BBBB", *map(int, dst_ip.split(".")))

    header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_addr,
        dst_addr,
    )

    # Calculate checksum
    checksum = ip_checksum(header)
    header = header[:10] + struct.pack(">H", checksum) + header[12:]

    return header + payload


def ip_checksum(data: bytes) -> int:
    """Calculate IP header checksum."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total & 0xFFFF


def create_tcp_packet(
    src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes
) -> bytes:
    """Create a TCP packet."""
    window = 8192
    checksum = 0
    urgent = 0

    header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        0x50,
        flags,  # Header length (5 * 4 = 20 bytes), flags
        window,
        checksum,
        urgent,
    )

    return header + payload


def create_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Create a UDP packet."""
    length = 8 + len(payload)
    checksum = 0  # Optional for UDP

    header = struct.pack(">HHHH", src_port, dst_port, length, checksum)
    return header + payload


def create_flexlm_handshake(client_ip: str, server_ip: str) -> list[tuple[bytes, float]]:
    """Create FlexLM license server handshake."""
    packets = []
    timestamp = time.time()

    # Client hello
    flexlm_hello = struct.pack(
        ">HHI",
        0x0147,  # FlexLM version
        0x0001,  # Message type (hello)
        0x12345678,  # Transaction ID
    )
    flexlm_hello += b"INTELLICRACK_CLIENT\x00" * 2  # Client ID

    # Create full packet
    udp = create_udp_packet(52401, 27000, flexlm_hello)
    ip = create_ip_packet(client_ip, server_ip, 17, udp)  # 17 = UDP
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # Server response
    timestamp += 0.1
    flexlm_response = struct.pack(
        ">HHI",
        0x0147,  # FlexLM version
        0x0002,  # Message type (response)
        0x12345678,  # Transaction ID
    )
    flexlm_response += b"LICENSE_SERVER_v11.16.2\x00"
    flexlm_response += struct.pack(">I", 0xDEADBEEF)  # Server key

    udp = create_udp_packet(27000, 52401, flexlm_response)
    ip = create_ip_packet(server_ip, client_ip, 17, udp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    # License request
    timestamp += 0.05
    license_request = struct.pack(
        ">HHI",
        0x0147,
        0x0010,  # License request
        0x12345679,
    )
    license_request += b"FEATURE_ADVANCED_ANALYSIS\x00"
    license_request += b"1.0\x00"
    license_request += b"HOST_ID=ABCD1234\x00"

    tcp = create_tcp_packet(52402, 27000, 1000, 0, 0x02, license_request)  # SYN
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)  # 6 = TCP
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # License grant
    timestamp += 0.02
    license_grant = struct.pack(
        ">HHI",
        0x0147,
        0x0011,  # License grant
        0x12345679,
    )
    license_grant += b"LICENSE_GRANTED\x00"
    license_grant += struct.pack(">Q", int(time.time() + 86400))  # Expiry
    license_grant += hashlib.sha256(b"LICENSE_KEY").digest()

    tcp = create_tcp_packet(27000, 52402, 2000, 1001, 0x18, license_grant)  # PSH+ACK
    ip = create_ip_packet(server_ip, client_ip, 6, tcp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    return packets


def create_hasp_protocol(client_ip: str, server_ip: str) -> list[tuple[bytes, float]]:
    """Create HASP/Sentinel protocol communication."""
    packets = []
    timestamp = time.time()

    # HASP discovery broadcast
    hasp_discover = b"HASP_DISCOVER_v7.50\x00"
    hasp_discover += struct.pack(">I", 0x48415350)  # Magic 'HASP'

    udp = create_udp_packet(1947, 1947, hasp_discover)
    ip = create_ip_packet(client_ip, "255.255.255.255", 17, udp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", ip)
    packets.append((eth, timestamp))

    # Server announcement
    timestamp += 0.05
    hasp_announce = b"HASP_SERVER_READY\x00"
    hasp_announce += struct.pack(">I", 0x53455256)  # 'SERV'
    hasp_announce += b"SERVER_ID=HASP_SRV_001\x00"

    udp = create_udp_packet(1947, 1947, hasp_announce)
    ip = create_ip_packet(server_ip, client_ip, 17, udp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    # Login request
    timestamp += 0.1
    hasp_login = struct.pack(">II", 0x4C4F4749, 0x4E000000)  # 'LOGI', 'N'
    hasp_login += b"VENDOR_CODE=12345\x00"
    hasp_login += b"FEATURE_ID=100\x00"

    tcp = create_tcp_packet(52403, 1947, 3000, 0, 0x02, hasp_login)
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # Login response with session
    timestamp += 0.02
    session_id = struct.pack(">Q", random.randint(0x1000000000000000, 0x7FFFFFFFFFFFFFFF))
    hasp_session = struct.pack(">II", 0x53455353, 0x494F4E00)  # 'SESS', 'ION'
    hasp_session += session_id
    hasp_session += b"STATUS=OK\x00"
    hasp_session += b"SEATS_AVAILABLE=10\x00"

    tcp = create_tcp_packet(1947, 52403, 4000, 3001, 0x18, hasp_session)
    ip = create_ip_packet(server_ip, client_ip, 6, tcp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    return packets


def create_adobe_licensing(client_ip: str, server_ip: str) -> list[tuple[bytes, float]]:
    """Create Adobe licensing protocol communication."""
    packets = []
    timestamp = time.time()

    # Adobe license check
    adobe_check = b'<?xml version="1.0" encoding="UTF-8"?>'
    adobe_check += b"<License><Request>"
    adobe_check += b"<Product>Photoshop</Product>"
    adobe_check += b"<Version>2024.1.0</Version>"
    adobe_check += b"<MachineID>WIN-ABCD1234EFGH</MachineID>"
    adobe_check += b"</Request></License>"

    # HTTPS-like request (port 443)
    tcp = create_tcp_packet(52404, 443, 5000, 0, 0x02, adobe_check)
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # Server response
    timestamp += 0.15
    adobe_response = b'<?xml version="1.0" encoding="UTF-8"?>'
    adobe_response += b"<License><Response>"
    adobe_response += b"<Status>Authorized</Status>"
    adobe_response += (
        b"<LicenseKey>" + hashlib.sha256(b"ADOBE_LICENSE").hexdigest().encode() + b"</LicenseKey>"
    )
    adobe_response += b"<Expiry>" + str(int(time.time() + 2592000)).encode() + b"</Expiry>"
    adobe_response += b"<Features>All</Features>"
    adobe_response += b"</Response></License>"

    tcp = create_tcp_packet(443, 52404, 6000, 5001, 0x18, adobe_response)
    ip = create_ip_packet(server_ip, client_ip, 6, tcp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    return packets


def create_custom_drm_protocol(client_ip: str, server_ip: str) -> list[tuple[bytes, float]]:
    """Create custom DRM protocol communication."""
    packets = []
    timestamp = time.time()

    # Custom DRM handshake
    drm_magic = b"DRM\x00\x01\x00\x00\x00"
    drm_challenge = os.urandom(32)  # Random challenge

    drm_packet = drm_magic + drm_challenge
    drm_packet += struct.pack(">H", 0x0100)  # Protocol version
    drm_packet += b"CLIENT_INTELLICRACK_v1.0\x00"

    tcp = create_tcp_packet(9999, 9999, 7000, 0, 0x02, drm_packet)
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # Server challenge-response
    timestamp += 0.05
    drm_response = b"DRM\x00\x02\x00\x00\x00"
    drm_response += hashlib.sha256(drm_challenge + b"SERVER_SECRET").digest()
    drm_response += os.urandom(32)  # Server challenge
    drm_response += struct.pack(">I", 0xCAFEBABE)  # Server ID

    tcp = create_tcp_packet(9999, 9999, 8000, 7001, 0x18, drm_response)
    ip = create_ip_packet(server_ip, client_ip, 6, tcp)
    eth = create_ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", ip)
    packets.append((eth, timestamp))

    return packets


def create_kms_activation(client_ip: str, server_ip: str) -> list[tuple[bytes, float]]:
    """Create KMS (Key Management Service) activation protocol."""
    packets = []
    timestamp = time.time()

    # KMS RPC bind request
    rpc_bind = struct.pack(
        "<BBHHIHH",
        5,
        0,  # Version (2 bytes)
        11,  # Packet type (bind) (2 bytes)
        0x8000,  # Flags (2 bytes)
        0xDEAD,  # Call ID (4 bytes)
        0x5C,  # Frag length (2 bytes)
        0,  # Auth length (2 bytes)
    )

    # Add KMS interface UUID
    kms_uuid = bytes.fromhex("3c4728c53f5c254493828d0212967a64")
    rpc_bind += kms_uuid
    rpc_bind += struct.pack("<HH", 5, 0)  # Interface version

    tcp = create_tcp_packet(52405, 1688, 9000, 0, 0x02, rpc_bind)
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    # KMS activation request
    timestamp += 0.1
    activation_request = struct.pack(
        "<BBHHIHH",
        5,
        0,  # Version (2 bytes)
        0,  # Packet type (request) (2 bytes)
        0x8003,  # Flags (2 bytes)
        0xBEEF,  # Call ID (4 bytes)
        0x100,  # Frag length (2 bytes)
        0,  # Auth length (2 bytes)
    )

    # Add product key and hardware ID
    activation_request += b"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX\x00"
    activation_request += hashlib.sha256(b"HARDWARE_ID").digest()

    tcp = create_tcp_packet(52405, 1688, 9100, 100, 0x18, activation_request)
    ip = create_ip_packet(client_ip, server_ip, 6, tcp)
    eth = create_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ip)
    packets.append((eth, timestamp))

    return packets


def write_pcap_file(filename: Path, packets: list[tuple[bytes, float]]) -> None:
    """Write packets to PCAP file."""
    if SCAPY_AVAILABLE:
        # Use Scapy if available
        scapy_packets = []
        for packet_data, timestamp in packets:
            # Parse raw packet back to Scapy format
            packet = Ether(packet_data)
            packet.time = timestamp
            scapy_packets.append(packet)
        wrpcap(str(filename), scapy_packets)
    else:
        # Use our simple PCAP writer
        writer = PCAPWriter(str(filename))
        for packet_data, timestamp in packets:
            writer.write_packet(packet_data, timestamp)
        writer.close()


def generate_all_protocol_captures(output_dir: Path) -> dict[str, Path]:
    """Generate all protocol capture files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    client_ip = "192.168.1.100"
    server_ip = "192.168.1.200"

    protocols = {
        "flexlm": create_flexlm_handshake,
        "hasp": create_hasp_protocol,
        "adobe": create_adobe_licensing,
        "custom_drm": create_custom_drm_protocol,
        "kms": create_kms_activation,
    }

    generated_files = {}

    for protocol_name, creator in protocols.items():
        packets = creator(client_ip, server_ip)

        # Write main capture
        filename = output_dir / f"{protocol_name}_capture.pcap"
        write_pcap_file(filename, packets)
        generated_files[protocol_name] = filename

        print(f"OK Created {protocol_name} protocol capture: {filename}")

        # Create variant with different IPs
        alt_client = "10.0.0.50"
        alt_server = "10.0.0.1"
        alt_packets = creator(alt_client, alt_server)

        alt_filename = output_dir / f"{protocol_name}_capture_alt.pcap"
        write_pcap_file(alt_filename, alt_packets)

        print(f"OK Created {protocol_name} protocol capture (alternate): {alt_filename}")

    # Create a mixed capture with multiple protocols
    mixed_packets = []
    for protocol_name, creator in protocols.items():
        packets = creator(client_ip, server_ip)
        # Adjust timestamps to interleave packets
        base_time = time.time() + len(mixed_packets) * 0.5
        for i, (packet, _) in enumerate(packets):
            mixed_packets.append((packet, base_time + i * 0.1))

    mixed_filename = output_dir / "mixed_protocols_capture.pcap"
    write_pcap_file(mixed_filename, mixed_packets)
    print(f"OK Created mixed protocol capture: {mixed_filename}")

    return generated_files


def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    output_dir = script_dir.parent / "tests" / "fixtures" / "network_captures"

    print("Generating network protocol captures...")
    print(f"Output directory: {output_dir}")
    print(f"Scapy available: {SCAPY_AVAILABLE}")

    generated = generate_all_protocol_captures(output_dir)

    print(f"\nOK Generated {len(generated)} protocol captures")
    print("\nProtocol captures include:")
    print("- FlexLM license server handshake")
    print("- HASP/Sentinel dongle emulation")
    print("- Adobe licensing protocol")
    print("- Custom DRM protocol")
    print("- KMS activation protocol")
    print("\nAll captures are in standard PCAP format for analysis")


if __name__ == "__main__":
    main()
