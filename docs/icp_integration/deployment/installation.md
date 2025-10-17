# ICP Integration - Installation Guide

Comprehensive installation and setup procedures for the ICP (Intellicrack Protection) Engine integration with die-python.

## System Requirements

### Hardware Requirements

**Minimum Requirements:**
```
CPU: 2+ cores, 2.0 GHz or higher
RAM: 4 GB available memory
Storage: 2 GB free disk space
Network: Internet connection for package downloads
```

**Recommended Requirements:**
```
CPU: 4+ cores, 3.0 GHz or higher
RAM: 8 GB available memory
Storage: 10 GB free disk space (SSD preferred)
Network: High-speed internet connection
Graphics: Hardware acceleration support (optional)
```

**Performance Considerations:**
- Additional 1GB RAM per concurrent analysis
- SSD storage improves analysis performance
- Multiple CPU cores enable parallel processing
- GPU acceleration available for advanced features

### Software Requirements

**Operating System Support:**

| OS | Version | Architecture | Status |
|----|---------|--------------|--------|
| Windows | 10, 11 | x64 | Fully Supported |
| Windows | Server 2019, 2022 | x64 | Fully Supported |
| Windows 11 | 22H2+ | x64, ARM64 | Fully Supported |

**Python Requirements:**
```
Python Version: 3.12.0 or higher
Package Manager: pip 23.0 or higher
Virtual Environment: venv or conda recommended
```

**Core Dependencies:**
```
die-python >= 0.4.0    (Protection analysis engine)
PyQt5 >= 5.15.0        (GUI framework)
nanobind >= 1.0.0      (die-python dependency)
psutil >= 5.9.0        (System monitoring, optional)
```

### Environment Setup

**Development vs Production:**

| Component | Development | Production |
|-----------|-------------|------------|
| Python | System Python OK | Dedicated Python installation |
| Virtual Env | Recommended | Required |
| Dependencies | Latest versions | Pinned versions |
| Configuration | Flexible | Locked configuration |
| Logging | Debug level | Info/Warning level |

## Pre-Installation Checklist

**System Preparation:**
```
□ Verify OS compatibility and architecture
□ Check available disk space (minimum 2GB)
□ Ensure administrative/sudo privileges
□ Confirm internet connectivity
□ Update system package manager
□ Install build tools (if compiling from source)
□ Check firewall and security software settings
```

**Python Environment Verification:**
```bash
# Check Python version
python --version
# Should output: Python 3.12.x or higher

# Check pip version
pip --version
# Should output: pip 23.x.x or higher

# Check virtual environment capability
python -m venv --help
# Should display venv help without errors
```

## Installation Procedures

### Method 1: Standard Installation (Recommended)

**Step 1: Create Virtual Environment**

Windows:
```cmd
# Create virtual environment
python -m venv intellicrack_env

# Activate virtual environment
intellicrack_env\Scripts\activate

# Verify activation
where python
# Should point to virtual environment
```

Windows 11 Terminal:
```bash
# Create virtual environment
python3 -m venv intellicrack_env

# Activate virtual environment
source intellicrack_env/bin/activate

# Verify activation
which python
# Should point to virtual environment
```

**Step 2: Upgrade Package Tools**
```bash
# Upgrade pip and setuptools
python -m pip install --upgrade pip setuptools wheel

# Install build dependencies
python -m pip install --upgrade build setuptools-scm
```

**Step 3: Install Core Dependencies**
```bash
# Install PyQt5 first (GUI framework)
pip install PyQt5>=5.15.0

# Install system monitoring (optional but recommended)
pip install psutil>=5.9.0

# Install additional utilities
pip install requests>=2.28.0 packaging>=21.0
```

**Step 4: Install die-python**

Option A - Via pip (Recommended):
```bash
# Install die-python from PyPI
pip install die-python>=0.4.0

# Verify installation
python -c "import die; print(f'die-python {die.__version__}')"
```

Option B - From source (Advanced):
```bash
# Clone die-python repository
git clone https://github.com/horsicq/die-python.git
cd die-python

# Install build dependencies
pip install nanobind cmake

# Build and install
python -m pip install .

# Verify installation
python -c "import die; print(f'die-python {die.__version__}')"
```

**Step 5: Install Intellicrack with ICP Integration**
```bash
# Navigate to Intellicrack root directory
cd /path/to/intellicrack

# Install in development mode (for active development)
pip install -e .

# OR install normally
pip install .

# Verify ICP integration
python -c "from intellicrack.protection.icp_backend import ICPBackend; print('ICP integration ready')"
```

### Method 2: Docker Installation

**Dockerfile for ICP Integration:**
```dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    qt5-qmake \
    qtbase5-dev \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install die-python
RUN pip install die-python>=0.4.0

# Copy application code
COPY . .

# Install Intellicrack
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 intellicrack
USER intellicrack

# Verify installation
RUN python -c "from intellicrack.protection.icp_backend import ICPBackend; print('ICP ready')"

CMD ["python", "intellicrack/ui/main.py"]
```

**Build and Run:**
```bash
# Build Docker image
docker build -t intellicrack-icp:latest .

# Run container
docker run -it --rm \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -e DISPLAY=$DISPLAY \
  intellicrack-icp:latest
```

### Method 3: Conda Installation

**Create Conda Environment:**
```bash
# Initialize pixi project
pixi init

# Activate environment
pixi shell

# Install packages
pixi add pyqt psutil

# Install pip packages
pip install die-python>=0.4.0

# Install Intellicrack
cd /path/to/intellicrack
pip install -e .
```

## Platform-Specific Instructions

### Windows Installation

**Prerequisites:**
```powershell
# Install Microsoft C++ Build Tools (if needed)
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Install Git for Windows (if needed)
# Download from: https://git-scm.com/download/win

# Install Python 3.12+ from python.org
# Ensure "Add Python to PATH" is checked
```

**Windows-Specific Steps:**
```cmd
# Open Command Prompt as Administrator
# Verify Python installation
python --version

# Create project directory
mkdir C:\intellicrack
cd C:\intellicrack

# Clone repository (if applicable)
git clone <intellicrack-repo-url> .

# Follow standard installation steps above
```

**Windows Troubleshooting:**
```
Issue: "python" command not found
Solution: Add Python to PATH or use "py" command

Issue: Permission denied during installation
Solution: Run Command Prompt as Administrator

Issue: SSL certificate verification failed
Solution: pip install --trusted-host pypi.org --trusted-host pypi.python.org <package>
```


## Configuration and Validation

### Initial Configuration

**Create Configuration Directory:**
```bash
# Create config directory
mkdir -p ~/.intellicrack/config

# Create basic configuration file
cat > ~/.intellicrack/config/icp.conf << EOF
[icp]
engine_path = auto
timeout = 30
max_concurrent = 4
log_level = INFO

[analysis]
default_scan_mode = DEEP
auto_trigger = true
cache_results = false

[performance]
memory_limit = 1GB
temp_directory = /tmp/intellicrack
cleanup_temp = true
EOF
```

**Environment Variables:**
```bash
# Add to Environment Variables (Windows 11)
export INTELLICRACK_CONFIG_DIR="$HOME/.intellicrack/config"
export INTELLICRACK_LOG_LEVEL="INFO"
export INTELLICRACK_ICP_TIMEOUT="30"

# Windows: Add to system environment variables
# INTELLICRACK_CONFIG_DIR = %USERPROFILE%\.intellicrack\config
# INTELLICRACK_LOG_LEVEL = INFO
# INTELLICRACK_ICP_TIMEOUT = 30
```

### Validation Scripts

**Basic Functionality Test:**
```python
#!/usr/bin/env python3
"""
ICP Integration Validation Script
Tests core functionality after installation
"""

import sys
import os
import asyncio
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")

    try:
        import die
        print(f"✓ die-python {die.__version__} imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import die-python: {e}")
        return False

    try:
        from intellicrack.protection.icp_backend import ICPBackend, ScanMode
        print("✓ ICP backend imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import ICP backend: {e}")
        return False

    try:
        from PyQt5.QtWidgets import QApplication
        print("✓ PyQt5 imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import PyQt5: {e}")
        return False

    return True

def test_icp_backend():
    """Test ICP backend functionality"""
    print("\nTesting ICP backend...")

    try:
        from intellicrack.protection.icp_backend import ICPBackend, ScanMode

        # Create backend instance
        backend = ICPBackend()
        print("✓ ICP backend created successfully")

        # Test engine version
        version = backend.get_engine_version()
        print(f"✓ Engine version: {version}")

        # Test scan modes
        modes = backend.get_available_scan_modes()
        print(f"✓ Available scan modes: {modes}")

        # Test die-python availability
        available = backend.is_die_python_available()
        if available:
            print("✓ die-python is available and functional")
        else:
            print("✗ die-python is not available")
            return False

        return True

    except Exception as e:
        print(f"✗ ICP backend test failed: {e}")
        return False

def test_analysis(test_file=None):
    """Test analysis functionality with a test file"""
    print("\nTesting analysis functionality...")

    if not test_file:
        # Try to find a system binary for testing
        test_files = [
            "/bin/ls",  # Linux
            "/usr/bin/python3",  # Linux
            "C:\\Windows\\System32\\notepad.exe",  # Windows
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"  # macOS
        ]

        for file_path in test_files:
            if os.path.exists(file_path):
                test_file = file_path
                break

        if not test_file:
            print("⚠ No test file found, skipping analysis test")
            return True

    try:
        from intellicrack.protection.icp_backend import ICPBackend, ScanMode

        backend = ICPBackend()

        async def run_test():
            result = await backend.analyze_file(test_file, ScanMode.NORMAL)
            return result

        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_test())
        loop.close()

        if result.error:
            print(f"✗ Analysis failed: {result.error}")
            return False
        else:
            print(f"✓ Analysis successful: {len(result.all_detections)} detections")
            for detection in result.all_detections[:3]:  # Show first 3
                print(f"   - {detection.type}: {detection.name}")
            return True

    except Exception as e:
        print(f"✗ Analysis test failed: {e}")
        return False

def main():
    """Main validation function"""
    print("ICP Integration Validation")
    print("=" * 40)

    tests = [
        ("Import Tests", test_imports),
        ("Backend Tests", test_icp_backend),
        ("Analysis Tests", test_analysis)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        if test_func():
            passed += 1
            print(f"✓ {test_name} PASSED")
        else:
            print(f"✗ {test_name} FAILED")

    print("\n" + "=" * 40)
    print(f"Validation Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! ICP integration is ready.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

**Performance Benchmark Script:**
```python
#!/usr/bin/env python3
"""
ICP Performance Benchmark Script
Tests performance characteristics after installation
"""

import asyncio
import time
import os
import psutil
from pathlib import Path

async def benchmark_analysis_speed():
    """Benchmark analysis speed across different scan modes"""
    print("Running performance benchmarks...")

    from intellicrack.protection.icp_backend import ICPBackend, ScanMode

    # Find test files
    test_files = []
    for pattern in ["/bin/*", "/usr/bin/*", "C:\\Windows\\System32\\*.exe"]:
        test_files.extend(Path().glob(pattern))
        if len(test_files) >= 5:
            break

    if not test_files:
        print("No test files found for benchmarking")
        return

    backend = ICPBackend()
    modes = [ScanMode.NORMAL, ScanMode.DEEP, ScanMode.HEURISTIC]

    results = {}

    for mode in modes:
        print(f"\nBenchmarking {mode.name} mode...")
        times = []

        for test_file in test_files[:3]:  # Test first 3 files
            start_time = time.time()

            try:
                result = await backend.analyze_file(str(test_file), mode)
                end_time = time.time()

                if not result.error:
                    analysis_time = end_time - start_time
                    times.append(analysis_time)
                    print(f"  {test_file.name}: {analysis_time:.3f}s")

            except Exception as e:
                print(f"  {test_file.name}: ERROR - {e}")

        if times:
            avg_time = sum(times) / len(times)
            results[mode.name] = avg_time
            print(f"  Average: {avg_time:.3f}s")

    return results

def check_system_resources():
    """Check system resources and requirements"""
    print("\nSystem Resource Check:")
    print("-" * 30)

    # Memory check
    memory = psutil.virtual_memory()
    print(f"Memory: {memory.total // (1024**3)} GB total, {memory.available // (1024**3)} GB available")

    if memory.available < 2 * (1024**3):  # 2GB
        print("⚠ Warning: Less than 2GB available memory")
    else:
        print("✓ Sufficient memory available")

    # Disk space check
    disk = psutil.disk_usage('/')
    print(f"Disk: {disk.total // (1024**3)} GB total, {disk.free // (1024**3)} GB free")

    if disk.free < 5 * (1024**3):  # 5GB
        print("⚠ Warning: Less than 5GB free disk space")
    else:
        print("✓ Sufficient disk space available")

    # CPU check
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    print(f"CPU: {cpu_count} cores")
    if cpu_freq:
        print(f"     {cpu_freq.current:.0f} MHz current frequency")

    if cpu_count < 2:
        print("⚠ Warning: Less than 2 CPU cores available")
    else:
        print("✓ Sufficient CPU cores available")

async def main():
    """Main benchmark function"""
    print("ICP Performance Benchmark")
    print("=" * 40)

    check_system_resources()

    try:
        results = await benchmark_analysis_speed()

        if results:
            print(f"\nPerformance Summary:")
            print("-" * 30)
            for mode, time_val in results.items():
                print(f"{mode}: {time_val:.3f}s average")

            # Performance assessment
            normal_time = results.get('NORMAL', 0)
            if normal_time < 0.1:
                print("\n✓ Excellent performance")
            elif normal_time < 0.5:
                print("\n✓ Good performance")
            else:
                print("\n⚠ Performance may need optimization")

    except Exception as e:
        print(f"Benchmark failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

**Save Validation Scripts:**
```bash
# Create scripts directory
mkdir -p ~/.intellicrack/intellicrack/scripts

# Save validation script
cat > ~/.intellicrack/intellicrack/scripts/validate_installation.py << 'EOF'
[Insert validation script above]
EOF

# Save benchmark script
cat > ~/.intellicrack/intellicrack/scripts/benchmark_performance.py << 'EOF'
[Insert benchmark script above]
EOF

# Make executable
chmod +x ~/.intellicrack/intellicrack/scripts/*.py
```

### Running Validation

**Execute Validation Tests:**
```bash
# Activate virtual environment
intellicrack_env\Scripts\activate  # Windows 11
# OR
intellicrack_env\Scripts\activate     # Windows

# Run validation script
python ~/.intellicrack/intellicrack/scripts/validate_installation.py

# Run performance benchmark
python ~/.intellicrack/intellicrack/scripts/benchmark_performance.py
```

**Expected Output:**
```
ICP Integration Validation
========================================

Import Tests:
✓ die-python 0.4.0 imported successfully
✓ ICP backend imported successfully
✓ PyQt5 imported successfully
✓ Import Tests PASSED

Backend Tests:
✓ ICP backend created successfully
✓ Engine version: die-python 0.4.0 (DIE 3.09)
✓ Available scan modes: ['NORMAL', 'DEEP', 'HEURISTIC', 'AGGRESSIVE', 'ALL']
✓ die-python is available and functional
✓ Backend Tests PASSED

Analysis Tests:
✓ Analysis successful: 2 detections
   - Format: PE64
   - Compiler: Microsoft Visual C++
✓ Analysis Tests PASSED

========================================
Validation Results: 3/3 tests passed
🎉 All tests passed! ICP integration is ready.
```

## Troubleshooting Installation Issues

### Common Problems and Solutions

**Issue 1: die-python Installation Fails**
```
Error: Failed building wheel for die-python
Solution:
1. Install build dependencies:
   - Windows: Visual Studio Build Tools
   - Windows 11: Visual Studio Build Tools, CMake
2. Upgrade pip: pip install --upgrade pip setuptools wheel
3. Try installing from source: pip install --no-binary die-python die-python
```

**Issue 2: PyQt5 Import Errors**
```
Error: ModuleNotFoundError: No module named 'PyQt5'
Solution:
1. Install system Qt5 development packages
2. Reinstall PyQt5: pip uninstall PyQt5 && pip install PyQt5
3. Check virtual environment activation
```

**Issue 3: Permission Denied Errors**
```
Error: PermissionError: [Errno 13] Permission denied
Solution:
1. Use virtual environment instead of system Python
2. Run with appropriate privileges (sudo/Administrator)
3. Check file and directory permissions
```

**Issue 4: SSL Certificate Verification**
```
Error: SSL: CERTIFICATE_VERIFY_FAILED
Solution:
1. Update certificates: pip install --upgrade certifi
2. Use trusted hosts: pip install --trusted-host pypi.org <package>
3. Configure corporate proxy/firewall settings
```

### Advanced Troubleshooting

**Dependency Conflict Resolution:**
```bash
# Check for dependency conflicts
pip check

# Create fresh environment if conflicts found
deactivate
rm -rf intellicrack_env
python -m venv intellicrack_env
source intellicrack_env/bin/activate

# Install with specific versions
pip install PyQt5==5.15.7 die-python==0.4.0
```

**Build from Source (Advanced):**
```bash
# If binary packages fail, build from source
pip install --no-binary :all: --force-reinstall die-python

# Or with specific compiler flags
export CC=gcc
export CXX=g++
pip install die-python
```

### Getting Help

**Information to Gather for Support:**
```bash
# System information
uname -a                    # OS and kernel
python --version           # Python version
pip --version              # Pip version

# Package information
pip list | grep -i die      # die-python installation
pip list | grep -i pyqt     # PyQt5 installation

# Environment information
env | grep INTELLICRACK     # Environment variables
which python               # Python executable path

# Error logs
tail -n 50 ~/.intellicrack/logs/installation.log
```

**Support Channels:**
- GitHub Issues: Report installation problems with full logs
- Documentation: Check online documentation for updates
- Community Forums: Get help from other users
- Commercial Support: Available for enterprise deployments

---

*This installation guide covers standard deployment scenarios. For advanced production deployments, see [Deployment Guide](deployment.md) and [Operations Guide](operations.md).*
