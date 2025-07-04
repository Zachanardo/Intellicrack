#!/usr/bin/env python3
"""Test script to verify protection results display properly in the UI."""

import json
import os
import sys
import tempfile
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QApplication

from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    IntellicrackProtectionCore,
    ProtectionAnalysis,
    ProtectionType,
)
from intellicrack.ui.widgets.intellicrack_protection_widget import IntellicrackProtectionWidget

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set up Qt for testing
os.environ['QT_QPA_PLATFORM'] = 'offscreen'


def create_test_analysis():
    """Create a test ProtectionAnalysis object with sample data."""
    return ProtectionAnalysis(
        file_path="/test/binary.exe",
        file_type="PE64",
        architecture="AMD64",
        detections=[
            DetectionResult(
                name="Sentinel HASP",
                version="7.103",
                type=ProtectionType.LICENSE,
                confidence=95.0,
                details={"info": "Hardware dongle protection", "type": "Protector"},
                bypass_recommendations=["Use API monitoring to trace license checks"]
            ),
            DetectionResult(
                name="VMProtect",
                version="3.8.4",
                type=ProtectionType.PROTECTOR,
                confidence=90.0,
                details={"info": "Code virtualization", "type": "Protector"},
                bypass_recommendations=["Consider using devirtualization tools"]
            )
        ],
        is_packed=True,
        is_protected=True,
        has_overlay=False,
        has_resources=True,
        sections=[
            {"name": ".text", "size": 4096},
            {"name": ".data", "size": 2048},
            {"name": ".vmp0", "size": 8192},
            {"name": ".vmp1", "size": 4096}
        ],
        imports=["kernel32.dll", "user32.dll", "hasp_windows_x64.dll"]
    )

def test_die_widget_display():
    """Test that protection widget properly displays protection results."""
    app = QApplication(sys.argv)
    
    # Create widget
    widget = IntellicrackProtectionWidget()
    widget.show()
    
    # Create test data
    test_analysis = create_test_analysis()
    
    # Update widget with test data
    widget.display_results(test_analysis)
    
    # Verify tree has items
    tree = widget.detection_tree
    root = tree.invisibleRootItem()
    
    print("=== Testing Protection Widget Display ===")
    
    # Check detection items
    type_count = 0
    detection_count = 0
    
    for i in range(root.childCount()):
        type_item = root.child(i)
        type_count += 1
        print(f"✓ Protection type displayed: {type_item.text(0)}")
        
        # Check detections under this type
        for j in range(type_item.childCount()):
            det_item = type_item.child(j)
            detection_count += 1
            print(f"  - {det_item.text(0)} ({det_item.text(1)}) - Version: {det_item.text(2)}")
    
    if type_count > 0 and detection_count > 0:
        print(f"✓ Successfully displayed {type_count} types with {detection_count} detections")
    else:
        print(f"✗ Failed to display detections (types: {type_count}, detections: {detection_count})")
        return False
    
    # Check summary text
    summary_text = widget.summary_text.toPlainText()
    if summary_text:
        print(f"✓ Summary displayed: {len(summary_text)} characters")
        print(f"  Preview: {summary_text[:100]}...")
    else:
        print("✗ No summary displayed")
        return False
    
    # Check technical details text  
    tech_details_text = widget.tech_details_text.toPlainText()
    if tech_details_text:
        print(f"✓ Technical details displayed: {len(tech_details_text)} characters")
        print(f"  Preview: {tech_details_text[:100]}...")
    else:
        print("✗ No technical details displayed")
        return False
        
    # Check bypass recommendations
    bypass_text = widget.bypass_text.toPlainText()
    if bypass_text:
        print(f"✓ Bypass recommendations displayed: {len(bypass_text)} characters")
    else:
        print("✗ No bypass recommendations displayed")
    
    print("\n✓ Protection widget display test PASSED")
    return True

def test_die_binary_analysis():
    """Test analyzing a real binary with the protection engine."""
    print("\n=== Testing Real Binary Analysis ===")
    
    # Create a test executable
    test_binary = None
    try:
        # Create a minimal test binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Write a minimal PE header
            f.write(b'MZ')  # DOS header signature
            f.write(b'\x00' * 100)  # Padding
            test_binary = f.name
        
        # Test with protection detector
        detector = IntellicrackProtectionCore()
        result = detector.detect_protections(test_binary)
        
        if result:
            print(f"✓ Protection analysis completed successfully")
            print(f"  File type: {result.file_type}")
            print(f"  Architecture: {result.architecture}")
            print(f"  Detections: {len(result.detections)}")
            print(f"  Is Protected: {result.is_protected}")
            print(f"  Is Packed: {result.is_packed}")
            return True
        else:
            print(f"✗ Protection analysis failed")
            return False
            
    except Exception as e:
        print(f"✗ Error during binary analysis: {str(e)}")
        return False
    finally:
        # Clean up
        if test_binary and os.path.exists(test_binary):
            os.unlink(test_binary)

def test_llm_integration_with_die():
    """Test that LLM tools can properly use protection engine results."""
    print("\n=== Testing LLM Integration with Protection Engine ===")
    
    try:
        from intellicrack.ai.ai_assistant_enhanced import IntellicrackAIAssistant
        from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool

        # Initialize tool
        tool = ProtectionAnalyzerTool()
        
        # Create test binary path
        test_path = "/test/binary.exe"
        
        # Test analyze method
        # Create a real test file
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 100)
            test_file = f.name
            
        try:
            result = tool.analyze(test_file, detailed=True)
            
            if result and result.get("success", False):
                print("✓ ProtectionAnalyzerTool analyze method works")
                print(f"  Result keys: {list(result.keys())}")
                
                # Check if it has expected structure
                if "protection_analysis" in result:
                    print("✓ Has protection_analysis section")
                    return True
                else:
                    print("✗ Missing protection_analysis section")
                    return False
            else:
                print(f"✗ Analysis failed: {result.get('error', 'Unknown error')}")
                return False
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)
            
    except Exception as e:
        print(f"✗ LLM integration test failed: {str(e)}")
        return False

def main():
    """Run all UI display tests."""
    print("=" * 60)
    print("Testing Protection Engine UI Display and Integration")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Widget Display", test_die_widget_display()))
    results.append(("Binary Analysis", test_die_binary_analysis()))
    results.append(("LLM Integration", test_llm_integration_with_die()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    
    # Exit code
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()
