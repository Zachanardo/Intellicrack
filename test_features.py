#!/usr/bin/env python3
"""
Comprehensive feature testing for Intellicrack application.
Tests all major functionality and reports any bugs.
"""

import os
import sys
import time
from pathlib import Path

# Set Qt to offscreen mode for WSL
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication, QFileDialog
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtTest import QTest

def test_intellicrack_features():
    """Test all major features of Intellicrack."""
    
    print("=" * 60)
    print("INTELLICRACK FEATURE TESTING")
    print("=" * 60)
    
    try:
        # Import IntellicrackApp
        from intellicrack.ui.main_app import IntellicrackApp
        
        # Create application
        app = QApplication(sys.argv)
        print("✓ QApplication created successfully")
        
        # Create main window
        window = IntellicrackApp()
        print("✓ IntellicrackApp created successfully")
        print(f"  - Window title: {window.windowTitle()}")
        print(f"  - Window size: {window.size()}")
        
        # Show window (even in offscreen mode)
        window.show()
        app.processEvents()
        print("✓ Window shown")
        
        # Test 1: Check all tabs exist
        print("\n[TEST 1] Checking tabs...")
        if hasattr(window, 'tabs'):
            tab_widget = window.tabs
            tab_count = tab_widget.count()
            print(f"✓ Found {tab_count} tabs")
            for i in range(tab_count):
                tab_text = tab_widget.tabText(i)
                print(f"  - Tab {i}: {tab_text}")
        else:
            print("✗ No tabs attribute found")
        
        # Test 2: Load a binary file
        print("\n[TEST 2] Testing binary loading...")
        test_binary = "/bin/ls"  # Use a system binary for testing
        if os.path.exists(test_binary):
            window.binary_path = test_binary
            print(f"✓ Set binary path to: {test_binary}")
            
            # Try to trigger binary analysis
            if hasattr(window, 'analyze_binary'):
                print("  - Found analyze_binary method")
                try:
                    window.analyze_binary()
                    app.processEvents()
                    print("✓ Binary analysis triggered")
                except Exception as e:
                    print(f"✗ Error during analysis: {e}")
        
        # Test 3: Check plugin system
        print("\n[TEST 3] Testing plugin system...")
        if hasattr(window, 'plugins_loaded'):
            print(f"✓ Plugins loaded: {window.plugins_loaded}")
        else:
            print("  - No plugins_loaded attribute")
        
        # Test 4: Check ML predictor
        print("\n[TEST 4] Testing ML predictor...")
        if hasattr(window, 'ml_predictor'):
            if window.ml_predictor is not None:
                print("✓ ML predictor initialized")
            else:
                print("  - ML predictor is None (model not loaded)")
        
        # Test 5: Check network components
        print("\n[TEST 5] Testing network components...")
        network_components = [
            'network_license_server',
            'ssl_interceptor',
            'protocol_fingerprinter'
        ]
        for comp in network_components:
            if hasattr(window, comp):
                print(f"✓ {comp} attribute exists")
            else:
                print(f"  - {comp} not found")
        
        # Test 6: Check analysis engines
        print("\n[TEST 6] Testing analysis engines...")
        engines = [
            'symbolic_executor',
            'taint_analyzer',
            'concolic_executor',
            'rop_chain_generator',
            'cfg_explorer'
        ]
        for engine in engines:
            if hasattr(window, engine):
                obj = getattr(window, engine)
                if obj is not None:
                    print(f"✓ {engine} initialized: {type(obj).__name__}")
                else:
                    print(f"  - {engine} is None")
            else:
                print(f"  - {engine} not found")
        
        # Test 7: Check UI components
        print("\n[TEST 7] Testing UI components...")
        ui_components = [
            ('output', 'Output text widget'),
            ('output_text', 'Output text area'),
            ('status_bar', 'Status bar'),
            ('progress_bar', 'Progress bar'),
            ('analyze_results', 'Analysis results'),
            ('tabs', 'Tab widget'),
            ('binary_path', 'Binary path storage')
        ]
        for comp, desc in ui_components:
            if hasattr(window, comp):
                print(f"✓ {comp} exists ({desc})")
            else:
                print(f"  - {comp} not found ({desc})")
        
        # Test 8: Test configuration
        print("\n[TEST 8] Testing configuration...")
        if hasattr(window, 'save_config'):
            try:
                window.save_config()
                print("✓ Configuration save tested")
            except Exception as e:
                print(f"✗ Error saving config: {e}")
        
        # Test 9: Check Ghidra integration
        print("\n[TEST 9] Testing Ghidra integration...")
        from intellicrack.config import CONFIG
        ghidra_path = CONFIG.get('ghidra_path')
        if ghidra_path and os.path.exists(ghidra_path):
            print(f"✓ Ghidra found at: {ghidra_path}")
        else:
            print(f"✗ Ghidra not found at: {ghidra_path}")
        
        # Test 10: Memory and performance
        print("\n[TEST 10] Testing memory optimization...")
        if hasattr(window, 'memory_optimizer'):
            if window.memory_optimizer is not None:
                print("✓ Memory optimizer initialized")
            else:
                print("  - Memory optimizer is None")
        
        print("\n" + "=" * 60)
        print("TESTING COMPLETE")
        print("=" * 60)
        
        # Keep the app running for a moment
        QTimer.singleShot(2000, app.quit)
        return app.exec_()
        
    except Exception as e:
        print(f"\n✗ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(test_intellicrack_features())