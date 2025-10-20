"""Debug extraction functionality."""
import binwalk
import os
import tempfile
import zipfile
from pathlib import Path

print("="*80)
print("EXTRACTION DEBUG TEST")
print("="*80)

# Create test ZIP
test_zip = 'extract_debug.zip'
with zipfile.ZipFile(test_zip, 'w') as zf:
    zf.writestr('test.txt', 'This should be extracted')
    zf.writestr('data.bin', b'\x00' * 100)

print(f"\n[1] Created test ZIP: {test_zip} ({os.path.getsize(test_zip)} bytes)")

# Test extraction
with tempfile.TemporaryDirectory() as tmpdir:
    print(f"\n[2] Extraction directory: {tmpdir}")

    print("\n[3] Running binwalk.scan() with extract=True...")
    results = list(binwalk.scan(test_zip, extract=True, directory=tmpdir, quiet=False, verbose=True))

    print(f"\n[4] Results returned: {len(results)} modules")

    for i, module in enumerate(results):
        print(f"\n  Module {i}:")
        print(f"    Results: {len(module.results)}")
        print(f"    Errors: {len(module.errors)}")

        if module.results:
            for result in module.results:
                print(f"      - {result}")

        if module.errors:
            for error in module.errors:
                print(f"      ERROR: {error}")

    # Check what files were created
    print(f"\n[5] Checking extraction directory contents...")
    extract_path = Path(tmpdir)

    all_items = list(extract_path.rglob('*'))
    print(f"  Total items found: {len(all_items)}")

    if all_items:
        print("  Items:")
        for item in all_items:
            rel_path = item.relative_to(extract_path)
            if item.is_file():
                print(f"    FILE: {rel_path} ({item.stat().st_size} bytes)")
            else:
                print(f"    DIR:  {rel_path}/")
    else:
        print("  No items found - extraction may have failed")

        # Check if binwalk created a subdirectory
        print(f"\n  Checking for extraction subdirectories...")
        for item in extract_path.iterdir():
            print(f"    {item.name}")

os.unlink(test_zip)
print(f"\n[6] Cleanup: Removed {test_zip}")
print("="*80)
