"""Debug test for commercial license analyzer"""
import tempfile
import traceback

def create_test_binary(strings):
    """Create a test PE binary with embedded strings"""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        # Basic PE header
        f.write(b"MZ")  # DOS header magic
        f.write(b"\x90" * 58)  # Padding
        f.write(b"\x00\x00\x00\x00")  # PE offset placeholder
        f.write(b"\x00" * 64)  # DOS stub

        # PE header
        f.write(b"PE\x00\x00")  # PE signature
        f.write(b"\x64\x86")  # Machine (x64)
        f.write(b"\x01\x00")  # Number of sections

        # Padding to align strings
        f.write(b"\x00" * 512)

        # Embed the strings
        for string in strings:
            f.write(string)
            f.write(b"\x00")  # Null terminator

        # More padding
        f.write(b"\x00" * 1024)

        return f.name

try:
    from intellicrack.core.analysis.commercial_license_analyzer import CommercialLicenseAnalyzer

    print("Creating analyzer...")
    analyzer = CommercialLicenseAnalyzer()
    print(f"Analyzer created: {analyzer}")

    print("\nCreating test binary...")
    test_binary = create_test_binary([
        b"FLEXlm License Manager",
        b"lc_checkout",
        b"vendor daemon"
    ])
    print(f"Test binary created at: {test_binary}")

    print("\nCalling analyze_binary...")
    result = analyzer.analyze_binary(test_binary)
    print(f"Result type: {type(result)}")
    print(f"Result value: {result}")

    if result is None:
        print("ERROR: analyze_binary returned None")
    else:
        detected = result.get("detected_systems", [])
        print(f"Detected systems: {detected}")

except Exception as e:
    print(f"Exception occurred: {e}")
    traceback.print_exc()
