"""Basic test runner for license protocol handler to check imports and functionality."""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))

try:
    from intellicrack.core.network.license_protocol_handler import (
        FlexLMProtocolHandler,
        HASPProtocolHandler,
        LicenseProtocolHandler,
    )
    MODULE_AVAILABLE = True
except ImportError:
    FlexLMProtocolHandler = None
    HASPProtocolHandler = None
    LicenseProtocolHandler = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")

if MODULE_AVAILABLE:
    print("OK Successfully imported license protocol handlers")

    # Test basic FlexLM functionality
    print("\n Testing FlexLM handler...")
    flexlm = FlexLMProtocolHandler()
    print(f"  - Initialized: {flexlm.__class__.__name__}")
    print(f"  - Port: {flexlm.flexlm_port}")
    print(f"  - Version: {flexlm.flexlm_version}")

    # Test FlexLM response generation
    hello_response = flexlm.generate_response(b"HELLO\n")
    print(f"  - HELLO response: {hello_response[:50]}")

    getlic_response = flexlm.generate_response(b"GETLIC AUTOCAD 2024 user1 host1 :0.0\n")
    print(f"  - GETLIC response: {getlic_response[:50]}")

    status_response = flexlm.generate_response(b"STATUS\n")
    print(f"  - STATUS response: {status_response[:50]}")

    print(f"  - Captured requests: {len(flexlm.captured_requests)}")

    # Test basic HASP functionality
    print("\n Testing HASP handler...")
    hasp = HASPProtocolHandler()
    print(f"  - Initialized: {hasp.__class__.__name__}")
    print(f"  - Port: {hasp.hasp_port}")
    print(f"  - Version: {hasp.hasp_version}")
    print(f"  - Memory size: 0x{hasp.hasp_memory_size:X}")

    # Test HASP response generation
    import struct

    login_response = hasp.generate_response(struct.pack("<II", 0x01, 0x00))
    print(f"  - Login response length: {len(login_response)}")

    get_size_response = hasp.generate_response(struct.pack("<II", 0x05, 0x00))
    print(f"  - Get size response length: {len(get_size_response)}")

    read_response = hasp.generate_response(struct.pack("<IIII", 0x06, 8, 0, 64))
    print(f"  - Read response length: {len(read_response)}")

    print(f"  - Captured requests: {len(hasp.captured_requests)}")

    # Test status methods
    print("\n Testing status methods...")
    flexlm_status = flexlm.get_status()
    print(f"  - FlexLM status: {flexlm_status}")

    hasp_status = hasp.get_status()
    print(f"  - HASP status: {hasp_status}")

    # Test clear data
    print("\n Testing clear data...")
    flexlm.clear_data()
    hasp.clear_data()
    print(f"  - FlexLM requests after clear: {len(flexlm.captured_requests)}")
    print(f"  - HASP requests after clear: {len(hasp.captured_requests)}")

    print("\nOK All basic tests passed successfully!")

except ImportError as e:
    print(f"FAIL Import error: {e}")
    sys.exit(1)

except Exception as e:
    print(f"FAIL Test error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n🎉 License protocol handler basic functionality verified!")
