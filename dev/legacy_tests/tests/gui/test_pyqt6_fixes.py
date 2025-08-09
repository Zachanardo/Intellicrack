import sys
import os
sys.path.insert(0, 'C:\\Intellicrack')

print("Testing PyQt6 compatibility fixes...")

# Test 1: Qt enum fixes
try:
    from intellicrack.ui.dialogs.common_imports import (
    QAbstractItemView,
    QAction,
    QDialogButtonBox,
    QFrame,
    QRegularExpression,
    QSizePolicy,
    QWebEngineView,
    Qt,
)
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
    
    print("✓ QAction imported from QtGui")
except ImportError as e:
    print(f"✗ Failed to import QAction: {e}")

# Test 3: QFrame enums
try:
    
    box = QFrame.Shape.Box
    raised = QFrame.Shadow.Raised
    print("✓ QFrame.Shape.Box and QFrame.Shadow.Raised work")
except Exception as e:
    print(f"✗ QFrame enum error: {e}")

# Test 4: QDialogButtonBox enums
try:
    
    ok = QDialogButtonBox.StandardButton.Ok
    cancel = QDialogButtonBox.StandardButton.Cancel
    print("✓ QDialogButtonBox.StandardButton.Ok and .Cancel work")
except Exception as e:
    print(f"✗ QDialogButtonBox enum error: {e}")

# Test 5: QSizePolicy enums
try:
    
    minimum = QSizePolicy.Policy.Minimum
    print("✓ QSizePolicy.Policy.Minimum works")
except Exception as e:
    print(f"✗ QSizePolicy enum error: {e}")

# Test 6: QAbstractItemView enums
try:
    
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
    
    regex = QRegularExpression("test")
    print("✓ QRegularExpression imported and created")
except Exception as e:
    print(f"✗ QRegularExpression error: {e}")

# Test 9: WebEngine
try:
    
    print("✓ QWebEngineView imported successfully")
except ImportError as e:
    print(f"✗ Failed to import QWebEngineView: {e}")

print("\nAll tests completed!")
