import sys
import os
sys.path.insert(0, 'C:\\Intellicrack')

print("Testing PyQt6 compatibility fixes...")

# Test 1: Qt enum fixes
try:
    from PyQt6.QtCore import Qt
    print("✓ Qt imported successfully")
    
    # Test Qt.Orientation
    try:
        horizontal = Qt.Orientation.Horizontal
        vertical = Qt.Orientation.Vertical
        print("✓ Qt.Orientation.Horizontal and .Vertical work")
    except AttributeError as e:
        print(f"✗ Qt.Orientation error: {e}")
    
    # Test Qt.WindowType
    try:
        stay_on_top = Qt.WindowType.WindowStaysOnTopHint
        print("✓ Qt.WindowType.WindowStaysOnTopHint works")
    except AttributeError as e:
        print(f"✗ Qt.WindowType error: {e}")
    
    # Test Qt.AlignmentFlag
    try:
        align_center = Qt.AlignmentFlag.AlignCenter
        print("✓ Qt.AlignmentFlag.AlignCenter works")
    except AttributeError as e:
        print(f"✗ Qt.AlignmentFlag error: {e}")
        
except ImportError as e:
    print(f"✗ Failed to import Qt: {e}")

# Test 2: Widget imports
try:
    from PyQt6.QtGui import QAction
    print("✓ QAction imported from QtGui")
except ImportError as e:
    print(f"✗ Failed to import QAction: {e}")

# Test 3: QFrame enums
try:
    from PyQt6.QtWidgets import QFrame
    box = QFrame.Shape.Box
    raised = QFrame.Shadow.Raised
    print("✓ QFrame.Shape.Box and QFrame.Shadow.Raised work")
except Exception as e:
    print(f"✗ QFrame enum error: {e}")

# Test 4: QDialogButtonBox enums
try:
    from PyQt6.QtWidgets import QDialogButtonBox
    ok = QDialogButtonBox.StandardButton.Ok
    cancel = QDialogButtonBox.StandardButton.Cancel
    print("✓ QDialogButtonBox.StandardButton.Ok and .Cancel work")
except Exception as e:
    print(f"✗ QDialogButtonBox enum error: {e}")

# Test 5: QSizePolicy enums
try:
    from PyQt6.QtWidgets import QSizePolicy
    minimum = QSizePolicy.Policy.Minimum
    print("✓ QSizePolicy.Policy.Minimum works")
except Exception as e:
    print(f"✗ QSizePolicy enum error: {e}")

# Test 6: QAbstractItemView enums
try:
    from PyQt6.QtWidgets import QAbstractItemView
    single = QAbstractItemView.SelectionMode.SingleSelection
    print("✓ QAbstractItemView.SelectionMode.SingleSelection works")
except Exception as e:
    print(f"✗ QAbstractItemView enum error: {e}")

# Test 7: ScrollBarPolicy
try:
    as_needed = Qt.ScrollBarPolicy.ScrollBarAsNeeded
    print("✓ Qt.ScrollBarPolicy.ScrollBarAsNeeded works")
except Exception as e:
    print(f"✗ Qt.ScrollBarPolicy error: {e}")

# Test 8: QRegularExpression
try:
    from PyQt6.QtCore import QRegularExpression
    regex = QRegularExpression("test")
    print("✓ QRegularExpression imported and created")
except Exception as e:
    print(f"✗ QRegularExpression error: {e}")

# Test 9: WebEngine
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    print("✓ QWebEngineView imported successfully")
except ImportError as e:
    print(f"✗ Failed to import QWebEngineView: {e}")

print("\nAll tests completed!")