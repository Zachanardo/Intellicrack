#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Diagnostic script for Intel Arc Graphics issues with Qt."""

import os
import sys
import subprocess

print("Intel Arc Graphics Diagnostic Tool")
print("=" * 60)

# Check Python and Qt versions
print("\n1. PYTHON AND QT VERSIONS:")
print(f"Python: {sys.version}")

try:
    from PyQt6.QtCore import QT_VERSION_STR, PYQT_VERSION_STR
    print(f"Qt: {QT_VERSION_STR}")
    print(f"PyQt5: {PYQT_VERSION_STR}")
except ImportError:
    print("PyQt5 not installed!")

# Check OpenGL info
print("\n2. OPENGL INFORMATION:")
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QOpenGLContext, QSurfaceFormat
    
    app = QApplication(sys.argv)
    
    # Create OpenGL context
    context = QOpenGLContext()
    format = QSurfaceFormat()
    format.setMajorVersion(3)
    format.setMinorVersion(3)
    context.setFormat(format)
    
    if context.create():
        print(f"OpenGL Vendor: {context.format().vendor()}")
        print(f"OpenGL Version: {context.format().version()}")
        print(f"OpenGL Profile: {context.format().profile()}")
    else:
        print("Failed to create OpenGL context")
        
except Exception as e:
    print(f"Error checking OpenGL: {e}")

# Check GPU info
print("\n3. GPU DETECTION:")
try:
    import pyopencl as cl
    platforms = cl.get_platforms()
    for platform in platforms:
        print(f"Platform: {platform.name} ({platform.vendor})")
        devices = platform.get_devices()
        for device in devices:
            print(f"  Device: {device.name}")
            print(f"  Type: {cl.device_type.to_string(device.type)}")
            print(f"  Driver: {device.driver_version}")
except Exception as e:
    print(f"PyOpenCL not available: {e}")

# Check environment variables
print("\n4. CURRENT QT ENVIRONMENT VARIABLES:")
qt_vars = [var for var in os.environ if var.startswith('QT_')]
if qt_vars:
    for var in sorted(qt_vars):
        print(f"{var}: {os.environ[var]}")
else:
    print("No Qt environment variables set")

# Test different Qt configurations
print("\n5. TESTING QT CONFIGURATIONS:")
configs = [
    ("Software", {"QT_OPENGL": "software"}),
    ("Desktop", {"QT_OPENGL": "desktop"}),
    ("ANGLE", {"QT_OPENGL": "angle", "QT_ANGLE_PLATFORM": "d3d11"}),
    ("ANGLE D3D9", {"QT_OPENGL": "angle", "QT_ANGLE_PLATFORM": "d3d9"}),
]

for name, env_vars in configs:
    print(f"\nTesting {name} configuration...")
    
    # Create test script
    test_script = f'''
import os
import sys
{chr(10).join(f'os.environ["{k}"] = "{v}"' for k, v in env_vars.items())}

try:
    from PyQt6.QtWidgets import QApplication, QWidget
    from PyQt6.QtCore import Qt
    
    app = QApplication(sys.argv)
    QApplication.setAttribute(Qt.AA_UseSoftwareOpenGL, {"software" in str(env_vars.get("QT_OPENGL", ""))})
    
    window = QWidget()
    window.setWindowTitle("Test")
    window.resize(200, 100)
    window.show()
    
    # Close immediately
    from PyQt6.QtCore import QTimer
    QTimer.singleShot(100, app.quit)
    
    exit_code = app.exec()
    print(f"SUCCESS: {name} configuration works!")
    sys.exit(0)
except Exception as e:
    print(f"FAILED: {name} - {{e}}")
    sys.exit(1)
'''
    
    # Run test
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"✓ {name} configuration: SUCCESS")
        else:
            print(f"✗ {name} configuration: FAILED")
            if result.stderr:
                print(f"  Error: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        print(f"✗ {name} configuration: TIMEOUT (likely crashed)")
    except Exception as e:
        print(f"✗ {name} configuration: ERROR - {e}")

print("\n6. RECOMMENDATIONS:")
print("- If ANGLE configuration works, use that for Intel Arc")
print("- If only Software works, use safe mode")
print("- Update Intel Arc drivers to latest version")
print("- Consider using Mesa3D drivers as alternative")

print("\nDiagnostic complete!")