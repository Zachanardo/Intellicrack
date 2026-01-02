"""Quick validation script for Denuvo ticket analyzer implementation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.protection.denuvo_ticket_analyzer import (
    DenuvoTicketAnalyzer,
    DenuvoTrigger,
    IntegrityCheck,
    TimingCheck,
    SteamAPIWrapper,
    HardwareBinding,
    OnlineActivation,
    DenuvoAnalysisResult,
)


def test_imports() -> None:
    """Test that all imports work."""
    print("[+] All imports successful")


def test_class_instantiation() -> None:
    """Test that analyzer can be instantiated."""
    analyzer = DenuvoTicketAnalyzer()
    print(f"[+] Analyzer instantiated successfully")
    print(f"    - Crypto available: {analyzer.crypto_available}")
    print(f"    - LIEF available: {analyzer.lief_available}")
    print(f"    - Capstone available: {analyzer.capstone_available}")
    print(f"    - Known keys: {len(analyzer.known_keys)}")
    print(f"    - Server endpoints: {len(analyzer.server_endpoints)}")
    print(f"    - Trigger patterns: {len(analyzer.trigger_patterns)}")
    print(f"    - Integrity patterns: {len(analyzer.integrity_patterns)}")
    print(f"    - Timing patterns: {len(analyzer.timing_patterns)}")


def test_dataclasses() -> None:
    """Test that all dataclasses can be created."""
    trigger = DenuvoTrigger(
        address=0x401000,
        type="ticket_validation",
        function_name="sub_401000",
        module=".text",
        confidence=0.95,
        description="Test trigger",
        opcode_sequence=b"\x48\x89\x5C\x24",
        referenced_imports=["CryptHashData"],
        cross_references=[0x402000],
    )
    print(f"[+] DenuvoTrigger created: {trigger.type} @ 0x{trigger.address:X}")

    integrity = IntegrityCheck(
        address=0x403000,
        type="crc32",
        target="Code section: .text",
        algorithm="CRC32C",
        confidence=0.92,
        check_size=256,
        frequency="High",
        bypass_difficulty="Medium",
    )
    print(f"[+] IntegrityCheck created: {integrity.type} - {integrity.algorithm}")

    timing = TimingCheck(
        address=0x404000,
        method="RDTSC",
        instruction="rdtsc",
        threshold_min=100000,
        threshold_max=1000000,
        confidence=0.95,
        bypass_method="Hook RDTSC instruction",
    )
    print(f"[+] TimingCheck created: {timing.method}")

    steam = SteamAPIWrapper(
        dll_path="steam_api64.dll",
        is_wrapper=True,
        original_exports=["SteamAPI_Init", "SteamAPI_Shutdown"],
        hooked_exports=["SteamAPI_Init"],
        denuvo_sections=[".denuvo"],
        confidence=0.85,
    )
    print(f"[+] SteamAPIWrapper created: {steam.dll_path}")

    hwid = HardwareBinding(
        binding_type="disk_serial",
        collection_address=0x405000,
        validation_address=0x406000,
        hash_algorithm="SHA256",
        components=["Disk Serial", "CPU Info"],
        confidence=0.90,
    )
    print(f"[+] HardwareBinding created: {hwid.binding_type}")

    online = OnlineActivation(
        endpoint_url="https://activation.denuvo.com/api/v1/activate",
        protocol="HTTPS",
        encryption_type="TLS 1.2",
        validation_address=0x407000,
        request_format="JSON",
        response_format="JSON",
    )
    print(f"[+] OnlineActivation created: {online.endpoint_url}")

    result = DenuvoAnalysisResult(
        version="7.x",
        triggers=[trigger],
        integrity_checks=[integrity],
        timing_checks=[timing],
        steam_wrapper=steam,
        hardware_bindings=[hwid],
        online_activation=online,
        protection_density=0.35,
        obfuscation_level="High (VM Protected)",
    )
    print(f"[+] DenuvoAnalysisResult created: Version {result.version}")
    print(f"    - Triggers: {len(result.triggers)}")
    print(f"    - Integrity checks: {len(result.integrity_checks)}")
    print(f"    - Timing checks: {len(result.timing_checks)}")
    print(f"    - Protection density: {result.protection_density}")


def test_pattern_loading() -> None:
    """Test pattern loading methods."""
    analyzer = DenuvoTicketAnalyzer()

    print(f"[+] Loaded {len(analyzer.trigger_patterns)} trigger patterns:")
    for name, info in list(analyzer.trigger_patterns.items())[:3]:
        print(f"    - {name}: {info['type']} (confidence: {info['confidence']})")

    print(f"[+] Loaded {len(analyzer.integrity_patterns)} integrity patterns:")
    for name, info in list(analyzer.integrity_patterns.items())[:3]:
        print(f"    - {name}: {info['algorithm']} (confidence: {info['confidence']})")

    print(f"[+] Loaded {len(analyzer.timing_patterns)} timing patterns:")
    for name, info in list(analyzer.timing_patterns.items())[:3]:
        print(f"    - {name}: {info['method']} (confidence: {info['confidence']})")


def main() -> None:
    """Run all validation tests."""
    print("=" * 70)
    print("Denuvo Ticket Analyzer - Implementation Validation")
    print("=" * 70)
    print()

    try:
        test_imports()
        print()

        test_class_instantiation()
        print()

        test_dataclasses()
        print()

        test_pattern_loading()
        print()

        print("=" * 70)
        print("[SUCCESS] All validation tests passed!")
        print("=" * 70)
        return 0

    except Exception as e:
        print()
        print("=" * 70)
        print(f"[ERROR] Validation failed: {e}")
        print("=" * 70)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
