"""Demonstration of streaming analysis capabilities for large binaries.

This module demonstrates the production-ready streaming analysis features
of the BinaryAnalyzer, including chunk-based processing, memory-mapped
file access, progress tracking, and resumable operations for multi-GB files.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


def demo_automatic_streaming():
    """Demonstrate automatic streaming mode selection based on file size."""
    print("\n=== Automatic Streaming Mode Detection ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\ntoskrnl.exe")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Analyzing: {binary_path}")
    print(f"File size: {binary_path.stat().st_size:,} bytes")

    results = analyzer.analyze(binary_path)

    print(f"\nFormat: {results.get('format')}")
    print(f"Streaming mode: {results.get('streaming_mode', False)}")
    print(f"Analysis status: {results.get('analysis_status')}")

    if "hashes" in results:
        print("\nHashes:")
        for algo, hash_value in results["hashes"].items():
            print(f"  {algo}: {hash_value}")

    if "format_analysis" in results:
        print(f"\nFormat-specific analysis: {len(results['format_analysis'])} entries")

    print(f"\nStrings found: {len(results.get('strings', []))}")
    print(f"Entropy: {results.get('entropy', {}).get('overall_entropy', 'N/A')}")


def demo_forced_streaming():
    """Demonstrate forced streaming mode for small files."""
    print("\n=== Forced Streaming Mode ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\notepad.exe")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Analyzing: {binary_path}")
    print(f"File size: {binary_path.stat().st_size:,} bytes")
    print("Forcing streaming mode despite small size...")

    results = analyzer.analyze(binary_path, use_streaming=True)

    print(f"\nFormat: {results.get('format')}")
    print(f"Streaming mode: {results.get('streaming_mode', False)}")
    print(f"Analysis status: {results.get('analysis_status')}")


def demo_progress_tracking():
    """Demonstrate progress tracking for large file analysis."""
    print("\n=== Progress Tracking ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\ntdll.dll")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Analyzing: {binary_path}")
    print(f"File size: {binary_path.stat().st_size:,} bytes\n")

    def progress_callback(stage: str, current: int, total: int):
        percent = (current / total * 100) if total > 0 else 0
        print(f"[{percent:5.1f}%] {stage}")

    results = analyzer.analyze_with_progress(binary_path, progress_callback)

    print(f"\nAnalysis status: {results.get('analysis_status')}")
    print(f"Timestamp: {results.get('timestamp')}")


def demo_checkpoint_save_load():
    """Demonstrate checkpoint saving and loading for resumable operations."""
    print("\n=== Checkpoint Save/Load ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\kernel32.dll")
    checkpoint_path = Path("checkpoint_demo.json")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Analyzing: {binary_path}")
    results = analyzer.analyze(binary_path)

    print(f"Saving checkpoint to: {checkpoint_path}")
    success = analyzer.save_analysis_checkpoint(results, checkpoint_path)
    print(f"Checkpoint saved: {success}")

    print(f"\nLoading checkpoint from: {checkpoint_path}")
    loaded_results = analyzer.load_analysis_checkpoint(checkpoint_path)

    if loaded_results:
        print("Checkpoint loaded successfully")
        print(f"Format: {loaded_results.get('format')}")
        print(f"Analysis timestamp: {loaded_results.get('timestamp')}")
        print(f"File path: {loaded_results.get('path')}")
    else:
        print("Failed to load checkpoint")

    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print(f"\nCleanup: Removed {checkpoint_path}")


def demo_pattern_scanning():
    """Demonstrate chunk-based pattern scanning."""
    print("\n=== Pattern Scanning ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\kernel32.dll")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    patterns = [
        b"MZ",
        b"PE\x00\x00",
        b".text",
        b".data",
        b".rdata",
    ]

    print(f"Scanning: {binary_path}")
    print(f"Patterns: {len(patterns)}")

    results = analyzer.scan_for_patterns_streaming(binary_path, patterns, context_bytes=16)

    for pattern_hex, matches in results.items():
        if matches:
            print(f"\nPattern {pattern_hex}: {len(matches)} matches")
            for match in matches[:3]:
                print(f"  Offset: 0x{match['offset']:08x}")


def demo_license_string_scanning():
    """Demonstrate license-related string scanning."""
    print("\n=== License String Scanning ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\kernel32.dll")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Scanning for license strings: {binary_path}")

    results = analyzer.scan_for_license_strings_streaming(binary_path)

    if results and not isinstance(results, dict):
        print(f"\nFound {len(results)} license-related strings:")
        for match in results[:10]:
            if "string" in match:
                print(f"  Offset 0x{match['offset']:08x}: {match['string'][:50]}...")
                print(f"    Pattern: {match['pattern_matched']}")
    else:
        print("No license strings found or error occurred")


def demo_section_analysis():
    """Demonstrate section-specific analysis using memory mapping."""
    print("\n=== Section-Specific Analysis ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\notepad.exe")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    print(f"Analyzing sections: {binary_path}")

    section_ranges = [
        (0x0, 0x1000),
        (0x1000, 0x5000),
        (0x5000, 0x10000),
    ]

    print(f"Analyzing {len(section_ranges)} sections...")

    results = analyzer.analyze_sections_streaming(binary_path, section_ranges)

    for section_name, section_data in results.items():
        if "error" not in section_data:
            print(f"\n{section_name}:")
            print(f"  Range: {section_data['range']}")
            print(f"  Size: {section_data['size']:,} bytes")
            print(f"  Entropy: {section_data['entropy']}")
            print(f"  Characteristics: {section_data['characteristics']}")
            print(f"  Printable ratio: {section_data['printable_ratio']:.2%}")


def demo_large_file_handling():
    """Demonstrate handling of very large binaries."""
    print("\n=== Large File Handling ===\n")

    analyzer = BinaryAnalyzer()

    binary_path = Path(r"C:\Windows\System32\ntoskrnl.exe")

    if not binary_path.exists():
        print(f"Binary not found: {binary_path}")
        return

    file_size = binary_path.stat().st_size
    print(f"File: {binary_path}")
    print(f"Size: {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)")

    print("\nThresholds:")
    print(f"  Large file threshold: {analyzer.LARGE_FILE_THRESHOLD:,} bytes")
    print(f"  Chunk size: {analyzer.CHUNK_SIZE:,} bytes")
    print(f"  Hash chunk size: {analyzer.HASH_CHUNK_SIZE:,} bytes")

    streaming_mode = file_size > analyzer.LARGE_FILE_THRESHOLD
    print(f"\nWill use streaming: {streaming_mode}")

    print("\nPerforming streaming analysis...")
    results = analyzer.analyze(binary_path)

    print(f"Analysis complete: {results.get('analysis_status')}")
    print(f"Format detected: {results.get('format')}")

    if "format_analysis" in results and "sections" in results["format_analysis"]:
        sections = results["format_analysis"]["sections"]
        print(f"Sections found: {len(sections)}")
        for section in sections[:5]:
            print(f"  {section['name']}: {section['virtual_size']:,} bytes")


def main():
    """Run all streaming analysis demonstrations."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=" * 70)
    print("INTELLICRACK - STREAMING BINARY ANALYSIS DEMONSTRATION")
    print("=" * 70)

    try:
        demo_automatic_streaming()
        demo_forced_streaming()
        demo_progress_tracking()
        demo_checkpoint_save_load()
        demo_pattern_scanning()
        demo_license_string_scanning()
        demo_section_analysis()
        demo_large_file_handling()

        print("\n" + "=" * 70)
        print("DEMONSTRATION COMPLETE")
        print("=" * 70)

    except KeyboardInterrupt:
        print("\n\nDemonstration interrupted by user")
    except Exception as e:
        print(f"\n\nError during demonstration: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
