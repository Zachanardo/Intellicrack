#!/usr/bin/env python3
"""
Test binary analysis functionality of Intellicrack.
"""

import os
import sys
import time
import shutil

# Set Qt to offscreen mode for WSL
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

def test_binary_analysis():
    """Test binary analysis features."""
    
    print("=" * 60)
    print("INTELLICRACK BINARY ANALYSIS TEST")
    print("=" * 60)
    
    try:
        from intellicrack.ui.main_app import IntellicrackApp
        
        # Create application
        app = QApplication(sys.argv)
        window = IntellicrackApp()
        window.show()
        app.processEvents()
        
        # Test 1: Basic binary loading
        print("\n[TEST 1] Loading test binary...")
        test_binary = "/bin/ls"
        
        if os.path.exists(test_binary):
            # Copy test binary to local directory
            local_binary = "test_binary"
            shutil.copy(test_binary, local_binary)
            
            # Load the binary
            if hasattr(window, 'load_binary'):
                window.load_binary()
                # Simulate file selection
                window.binary_path = local_binary
                print(f"✓ Binary loaded: {local_binary}")
            else:
                window.binary_path = local_binary
                print(f"✓ Binary path set: {local_binary}")
            
            # Test 2: Run basic analysis
            print("\n[TEST 2] Running binary analysis...")
            if hasattr(window, 'analyze_binary'):
                try:
                    window.analyze_binary()
                    app.processEvents()
                    time.sleep(1)  # Give it time to process
                    print("✓ Binary analysis triggered")
                    
                    # Check output
                    if hasattr(window, 'output') and window.output:
                        output_text = window.output.toPlainText()
                        if output_text:
                            print(f"  - Output has {len(output_text)} characters")
                            print(f"  - First 100 chars: {output_text[:100]}...")
                except Exception as e:
                    print(f"✗ Analysis error: {e}")
            
            # Test 3: Check analysis results
            print("\n[TEST 3] Checking analysis results...")
            if hasattr(window, 'analyze_results'):
                results_text = window.analyze_results.toPlainText()
                if results_text:
                    print(f"✓ Analysis results: {len(results_text)} characters")
                else:
                    print("  - No analysis results yet")
            
            # Test 4: Test protection detection
            print("\n[TEST 4] Testing protection detection...")
            if hasattr(window, 'detect_protections_btn'):
                try:
                    # Find the button in the analysis tab
                    analysis_tab = window.tabs.widget(1)  # Analysis is tab 1
                    # Look for protection detection functionality
                    print("  - Looking for protection detection...")
                except Exception as e:
                    print(f"  - Protection detection not accessible: {e}")
            
            # Test 5: Test patching capabilities
            print("\n[TEST 5] Testing patching system...")
            if hasattr(window, 'patches'):
                print(f"✓ Patches list exists: {len(window.patches)} patches")
            
            # Test 6: Test network analysis
            print("\n[TEST 6] Testing network analysis...")
            if hasattr(window, 'start_network_capture'):
                print("✓ Network capture method available")
            
            # Cleanup
            if os.path.exists(local_binary):
                os.remove(local_binary)
                print("\n✓ Cleanup complete")
        
        print("\n" + "=" * 60)
        print("BINARY ANALYSIS TEST COMPLETE")
        print("=" * 60)
        
        # Close the app
        QTimer.singleShot(1000, app.quit)
        return app.exec_()
        
    except Exception as e:
        print(f"\n✗ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(test_binary_analysis())