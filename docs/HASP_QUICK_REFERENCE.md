# HASP Protocol Parser - Quick Reference

## Import Classes

```python
from intellicrack.core.network.protocols.hasp_parser import (
    HASPSentinelParser,      # Core protocol parser
    HASPPacketAnalyzer,      # PCAP analysis
    HASPUSBEmulator,         # USB dongle emulation
    HASPServerEmulator,      # License server
    HASPFeature,             # Feature definition
    HASPFeatureType,         # Feature types enum
    HASPCommandType,         # Command types enum
    HASPStatusCode,          # Status codes enum
)
```

## Quick Start Examples

### 1. Parse and Respond to HASP Request

```python
parser = HASPSentinelParser()

# Parse incoming packet
request = parser.parse_request(raw_packet_bytes)

# Generate valid response
response = parser.generate_response(request)

# Serialize for transmission
response_bytes = parser.serialize_response(response)
```

### 2. Analyze Network Capture

```python
from pathlib import Path

analyzer = HASPPacketAnalyzer()
packets = analyzer.parse_pcap_file(Path("capture.pcap"))
license_info = analyzer.extract_license_info_from_capture()

print(f"Servers: {len(license_info['discovered_servers'])}")
print(f"Features: {len(license_info['discovered_features'])}")
```

### 3. Start License Server

```python
server = HASPServerEmulator("0.0.0.0", 1947)

# Run in background thread
import threading
thread = threading.Thread(target=server.start_server)
thread.daemon = True
thread.start()
```

### 4. Emulate USB Dongle

```python
usb = HASPUSBEmulator()

# Get device descriptors
device_desc = usb.emulate_usb_device()

# Handle USB requests
response = usb.handle_control_transfer(
    request_type=0x21,
    request=0x03,  # CMD_ENCRYPT
    value=0,
    index=0,
    data=plaintext
)
```

### 5. Add Custom Feature

```python
from intellicrack.core.network.protocols.hasp_parser import (
    HASPFeature, HASPFeatureType
)

parser = HASPSentinelParser()

custom_feature = HASPFeature(
    feature_id=12345,
    name="MY_APP_PRO",
    vendor_code=0xDEADBEEF,
    feature_type=HASPFeatureType.PERPETUAL,
    expiry="permanent",
    max_users=100,
    encryption_supported=True,
    memory_size=4096,
    rtc_supported=True,
)

parser.add_feature(custom_feature)
```

### 6. Encrypt/Decrypt Data

```python
parser = HASPSentinelParser()

# AES-256 encryption
encrypted = parser.crypto.aes_encrypt(data, session_id)
decrypted = parser.crypto.aes_decrypt(encrypted, session_id)

# Legacy HASP4
encrypted = parser.crypto.hasp4_encrypt(data, seed=0x12345678)
decrypted = parser.crypto.hasp4_decrypt(encrypted, seed=0x12345678)

# Envelope (RSA+AES)
encrypted = parser.crypto.envelope_encrypt(data, session_id)
decrypted = parser.crypto.envelope_decrypt(encrypted, session_id)
```

## Command Types

```python
HASPCommandType.LOGIN              # 0x01
HASPCommandType.LOGOUT             # 0x02
HASPCommandType.ENCRYPT            # 0x03
HASPCommandType.DECRYPT            # 0x04
HASPCommandType.GET_SIZE           # 0x05
HASPCommandType.READ               # 0x06
HASPCommandType.WRITE              # 0x07
HASPCommandType.GET_RTC            # 0x08
HASPCommandType.SET_RTC            # 0x09
HASPCommandType.GET_INFO           # 0x0A
HASPCommandType.FEATURE_LOGIN      # 0x10
HASPCommandType.FEATURE_LOGOUT     # 0x11
HASPCommandType.GET_FEATURE_INFO   # 0x12
HASPCommandType.HEARTBEAT          # 0x13
```

## Status Codes

```python
HASPStatusCode.STATUS_OK           # 0x00000000 - Success
HASPStatusCode.FEATURE_NOT_FOUND   # 0x00000005 - Invalid feature
HASPStatusCode.NO_HASP             # 0x00000007 - No dongle
HASPStatusCode.TOO_MANY_USERS      # 0x00000008 - License limit
HASPStatusCode.NOT_LOGGED_IN       # 0x00000010 - No session
HASPStatusCode.FEATURE_EXPIRED     # 0x00000011 - Expired
HASPStatusCode.INVALID_VENDOR_CODE # 0x00000013 - Bad vendor code
```

## Feature Types

```python
HASPFeatureType.PERPETUAL    # Permanent license
HASPFeatureType.EXPIRATION   # Time-limited
HASPFeatureType.CONCURRENT   # Network concurrent
HASPFeatureType.COUNTED      # Usage counted
HASPFeatureType.TRIAL        # Trial version
```

## Pre-configured Vendors

| Vendor Code | Vendor Name | Application |
|-------------|-------------|-------------|
| 0x12345678  | AUTODESK    | AutoCAD, Inventor |
| 0x87654321  | BENTLEY     | MicroStation |
| 0x11223344  | SIEMENS     | NX |
| 0x56789ABC  | ANSYS       | Mechanical |
| 0xDDCCBBAA  | SOLIDWORKS  | Premium |
| 0xACE02468  | GENERIC     | Universal |

## Network Ports

- **1947**: Main HASP port (TCP/UDP)
- **475**: Legacy broadcast port

## USB Protocol

- **Vendor ID**: 0x0529 (Aladdin)
- **Product IDs**: 0x0001-0x0004
- **Packet Size**: 64 bytes

## Common Operations

### Check Session Status

```python
sessions = parser.get_active_sessions()
for session in sessions:
    print(f"Session {session['session_id']}: {session['uptime']}s uptime")
```

### Read Dongle Memory

```python
request = HASPRequest(
    command=HASPCommandType.READ,
    session_id=session_id,
    feature_id=100,
    vendor_code=0x12345678,
    scope="", format="", client_info={},
    encryption_data=b"",
    additional_params={"address": 0, "length": 256}
)
response = parser.generate_response(request)
memory_data = response.encryption_response
```

### Export License Data

```python
from pathlib import Path
parser.export_license_data(Path("license_export.xml"))
```

### Generate Spoofed Response

```python
analyzer = HASPPacketAnalyzer()
for packet in captured_packets:
    if packet.packet_type == "LOGIN":
        spoofed = analyzer.generate_spoofed_response(packet)
        # Send spoofed response to application
```

## Error Handling

```python
try:
    request = parser.parse_request(data)
    if request:
        response = parser.generate_response(request)
    else:
        # Invalid packet format
        pass
except Exception as e:
    logger.error(f"HASP error: {e}")
```

## Testing

Run test suite:
```bash
pixi run python test_hasp_implementation.py
```

## File Locations

- **Implementation**: `intellicrack/core/network/protocols/hasp_parser.py`
- **Tests**: `test_hasp_implementation.py`
- **Documentation**: `docs/HASP_IMPLEMENTATION_GUIDE.md`

## Performance Tips

1. Reuse parser instances for multiple requests
2. Use session-based encryption for better performance
3. Cache vendor code lookups
4. Process packets in batches for PCAP analysis
5. Use daemon threads for background server

## Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Will show:
- Parsed request details
- Generated response info
- Cryptographic operations
- Network events

## Integration Example

```python
# Complete workflow
from intellicrack.core.network.protocols.hasp_parser import (
    HASPPacketAnalyzer, HASPServerEmulator
)
from pathlib import Path

# 1. Analyze real traffic
analyzer = HASPPacketAnalyzer()
packets = analyzer.parse_pcap_file(Path("real_app.pcap"))
license_info = analyzer.extract_license_info_from_capture()

# 2. Configure server with discovered info
server = HASPServerEmulator("0.0.0.0", 1947)
for feature in license_info['discovered_features']:
    # Add features to server...
    pass

# 3. Start server
import threading
thread = threading.Thread(target=server.start_server)
thread.daemon = True
thread.start()

# 4. Application now connects to our emulated server
```

## Security Notes

This tool is for **controlled security research** only:
- Test only on software you own or have authorization to analyze
- Use in isolated environments
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Support

For issues or questions:
- Check `docs/HASP_IMPLEMENTATION_GUIDE.md` for detailed documentation
- Review test suite for usage examples
- Examine inline docstrings in source code

**Status**: Production-ready ✅
**Version**: 1.0
**Platform**: Windows (primary), Linux/macOS compatible
