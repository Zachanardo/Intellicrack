#!/usr/bin/env python3
"""
Demonstration of AI-powered hex analysis capabilities.

This script shows how to use the enhanced AI bridge for intelligent
hex analysis in Intellicrack.
"""

import os
import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.hexview.ai_bridge import AIBinaryBridge, AIFeatureType


def demo_comprehensive_analysis():
    """Demonstrate comprehensive AI analysis of binary data."""
    print("=== AI-Powered Hex Analysis Demo ===\n")
    
    # Initialize AI bridge
    bridge = AIBinaryBridge()
    
    # Sample binary data (PE header)
    sample_data = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,  # MZ header
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    
    # Add some encrypted-looking data
    sample_data += bytes([0xA5, 0x3E, 0x9B, 0xF2, 0x7C, 0xE1, 0x45, 0x89] * 4)
    
    # Add some strings
    sample_data += b"\x00\x00Hello World!\x00License Key: ABC123\x00\x00"
    
    print("1. Performing comprehensive analysis...")
    result = bridge.analyze_comprehensive(sample_data, offset=0)
    
    print(f"\nFound {len(result.insights)} insights:")
    for insight in result.insights:
        print(f"  - [{insight.type.name}] {insight.description} (confidence: {insight.confidence:.2f})")
    
    print(f"\nDetected {len(result.patterns)} patterns:")
    for pattern in result.patterns[:5]:
        print(f"  - {pattern.pattern_type} at offset 0x{pattern.offset:X}: {pattern.interpretation}")
    
    if result.structures:
        print(f"\nIdentified structures:")
        for struct in result.structures:
            print(f"  - {struct.format_type} at offset 0x{struct.offset:X}")
    
    print(f"\nAnalysis completed in {result.execution_time:.3f} seconds")
    
    return result


def demo_pattern_search():
    """Demonstrate AI-powered pattern search."""
    print("\n\n=== AI Pattern Search Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # Create test data with various patterns
    test_data = b"START" + b"\x00" * 100
    test_data += b"License: TRIAL-VERSION\x00"
    test_data += bytes([i for i in range(256)])  # Gradient pattern
    test_data += b"\xFF" * 32  # Padding
    test_data += b"http://example.com/validate\x00"
    
    # Search for licensing-related patterns
    print("Searching for 'license' patterns...")
    matches = bridge.search_patterns_fuzzy(test_data, "license validation", max_results=5)
    
    for match in matches:
        print(f"  - Found at 0x{match.offset:X}: {match.interpretation} (confidence: {match.confidence:.2f})")
    
    # Search for URLs
    print("\nSearching for URL patterns...")
    url_matches = bridge.search_patterns_fuzzy(test_data, "http urls endpoints", max_results=5)
    
    for match in url_matches:
        print(f"  - Found at 0x{match.offset:X}: {match.interpretation}")


def demo_contextual_help():
    """Demonstrate contextual help feature."""
    print("\n\n=== Contextual Help Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # Encrypted-looking data
    encrypted_data = bytes([
        0x8B, 0x4C, 0x24, 0x04, 0xE8, 0x1F, 0xAE, 0x22,
        0x3B, 0xCA, 0x91, 0x5D, 0x7F, 0xA2, 0x35, 0xBE,
    ] * 8)
    
    print("Getting contextual help for high-entropy region...")
    help_info = bridge.get_contextual_help(encrypted_data, offset=0x1000, size=len(encrypted_data))
    
    print("\nQuick insights:")
    for insight in help_info["quick_insights"]:
        print(f"  - {insight['description']}")
    
    print("\nSuggested actions:")
    for action in help_info["suggested_actions"]:
        print(f"  - {action['action']}: {action['description']}")
    
    print("\nTips:")
    for tip in help_info["tips"]:
        print(f"  - {tip}")


def demo_region_comparison():
    """Demonstrate region comparison feature."""
    print("\n\n=== Region Comparison Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # Two similar regions with slight differences
    region1 = b"HEADER_V1\x00" + b"\x41" * 20 + b"END"
    region2 = b"HEADER_V2\x00" + b"\x41" * 20 + b"END"
    
    print("Comparing two similar regions...")
    comparison = bridge.compare_regions(region1, 0x100, region2, 0x200)
    
    print(f"\nSimilarity score: {comparison['similarity_score']:.2%}")
    print(f"Identical bytes: {comparison['identical_bytes']}")
    print(f"Different bytes: {comparison['different_bytes']}")
    
    print("\nInsights:")
    for insight in comparison["insights"]:
        print(f"  - {insight['description']}")


def demo_action_suggestions():
    """Demonstrate next action suggestions."""
    print("\n\n=== Action Suggestions Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # PE file with interesting patterns
    pe_data = b"MZ\x90\x00" + b"\x00" * 60
    pe_data += b"\x80\x00\x00\x00"  # PE offset
    pe_data += b"\x00" * 124
    pe_data += b"PE\x00\x00"  # PE signature
    
    print("Getting suggestions for PE file analysis...")
    suggestions = bridge.suggest_next_action(pe_data, current_offset=0, 
                                           user_goal="find license validation")
    
    print("\nNext offset suggestions:")
    for offset_info in suggestions["next_offsets"]:
        print(f"  - Go to 0x{offset_info['offset']:X}: {offset_info['reason']}")
    
    print("\nAnalysis suggestions:")
    for analysis in suggestions["analysis_suggestions"]:
        print(f"  - {analysis['action']}: {analysis['description']}")
    
    print("\nSearch suggestions:")
    for search in suggestions["search_suggestions"]:
        print(f"  - Search for '{search['pattern']}': {search['description']}")


async def demo_async_analysis():
    """Demonstrate asynchronous analysis capabilities."""
    print("\n\n=== Async Analysis Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # Large binary data
    large_data = os.urandom(4096)
    
    print("Performing async analysis on 4KB of data...")
    result = await bridge.hex_analyzer.analyze_region_async(large_data, offset=0)
    
    print(f"\nAsync analysis completed in {result.execution_time:.3f} seconds")
    print(f"Found {len(result.insights)} insights")
    print(f"Detected {len(result.anomalies)} anomalies")


def demo_export_report():
    """Demonstrate report export functionality."""
    print("\n\n=== Report Export Demo ===\n")
    
    bridge = AIBinaryBridge()
    
    # Analyze multiple regions
    analyses = []
    
    # Region 1: Header
    header_data = b"INTELLICRACK\x00\x01\x00\x00"
    analyses.append(bridge.analyze_comprehensive(header_data, offset=0))
    
    # Region 2: Encrypted section
    encrypted_data = os.urandom(256)
    analyses.append(bridge.analyze_comprehensive(encrypted_data, offset=0x1000))
    
    # Region 3: String table
    string_data = b"License=TRIAL\x00Version=1.0\x00User=Demo\x00"
    analyses.append(bridge.analyze_comprehensive(string_data, offset=0x2000))
    
    # Generate report
    print("Generating analysis report...")
    report = bridge.export_analysis_report(header_data + encrypted_data + string_data, analyses)
    
    # Save report
    report_path = Path("ai_analysis_report.md")
    report_path.write_text(report)
    print(f"\nReport saved to: {report_path}")
    
    # Show preview
    print("\nReport preview:")
    print("-" * 60)
    print(report[:500] + "...")


def main():
    """Run all demonstrations."""
    try:
        # Basic demos
        demo_comprehensive_analysis()
        demo_pattern_search()
        demo_contextual_help()
        demo_region_comparison()
        demo_action_suggestions()
        
        # Async demo
        print("\n\n=== Running Async Demo ===")
        asyncio.run(demo_async_analysis())
        
        # Report demo
        demo_export_report()
        
        print("\n\n=== All demos completed successfully! ===")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()