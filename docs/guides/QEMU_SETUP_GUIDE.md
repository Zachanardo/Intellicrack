# QEMU Setup Guide for Intellicrack

This guide will help you set up QEMU virtual machines for safely testing license bypasses and patches before deploying them to production software.

## Prerequisites

### 1. Install QEMU

#### Windows
Download and install QEMU from: https://www.qemu.org/download/#windows

Add QEMU to your PATH:
1. Default installation path: `C:\Program Files\qemu`
2. Add to PATH: `C:\Program Files\qemu`

#### Linux/WSL
```bash
sudo apt-get update
sudo apt-get install qemu-system-x86 qemu-utils qemu-system-arm
```

#### macOS
```bash
brew install qemu
```

### 2. Verify Installation
```bash
qemu-img --version
qemu-system-x86_64 --version
```

## Quick Setup

### Automatic Setup (Recommended)

#### Windows:
```batch
setup_qemu_images.bat
```

#### Linux/macOS:
```bash
./setup_qemu_images.sh
```

This will:
1. Set up Windows test environments for license bypass testing
2. Create proper directory structure for VM images
3. Configure safe testing environments

## Image Types

### 1. Windows Test Environments (Recommended)
Pre-configured Windows-compatible systems for license testing:
- **ReactOS**: ~120MB, Windows-compatible OS for basic PE testing
- **Windows Evaluation**: 90-180 day trial versions from Microsoft
- **Custom Windows VMs**: Full Windows installations for complex software testing

### 2. Custom Images

#### Create Empty Disk
```bash
qemu-img create -f qcow2 mydisk.qcow2 10G
```

#### Install Windows from ISO
```bash
# Install Windows for license testing
qemu-system-x86_64 \
  -hda windows-test.qcow2 \
  -cdrom windows-10.iso \
  -m 4096 \
  -smp 2 \
  -enable-kvm
```

### 3. Windows Images

#### Option A: Evaluation Versions
1. Download from Microsoft Evaluation Center
2. 90-180 day trial period
3. Full Windows functionality

#### Option B: ReactOS (Open Source)
- Windows-compatible OS
- Much smaller (~120MB)
- Good for testing basic Windows PE license patches
- Perfect for initial bypass testing

## Running QEMU VMs

### Basic VM Launch
```bash
# Windows VM for license testing
qemu-system-x86_64 \
  -hda windows-test.qcow2 \
  -m 4096 \
  -smp 2 \
  -enable-kvm

# ReactOS VM for basic PE testing
qemu-system-x86_64 \
  -cdrom reactos-0.4.14.iso \
  -m 2048 \
  -enable-kvm
```

### With Intellicrack Integration
When using Intellicrack, VMs are launched automatically for testing license patches in safe environments.

## Directory Structure
```
data/qemu_images/
├── reactos-0.4.14.iso          # ReactOS live ISO
├── windows-test.qcow2           # Windows test environment
├── custom-test.qcow2            # Custom test disk
└── snapshots/                   # VM snapshots for rollback
```

## License Testing Workflow

### 1. Prepare Test Environment
```bash
# Create a Windows test disk
qemu-img create -f qcow2 license-test.qcow2 20G
```

### 2. Install Software to Test
```bash
# Boot Windows VM and install the software with licensing
qemu-system-x86_64 \
  -hda license-test.qcow2 \
  -cdrom windows.iso \
  -m 4096 -smp 2
```

### 3. Create Clean Snapshot
```bash
# Save clean state before testing patches
qemu-img snapshot -c clean_install license-test.qcow2
```

### 4. Test License Bypass
```bash
# Apply patch and test
# If something breaks, restore snapshot:
qemu-img snapshot -a clean_install license-test.qcow2
```

## Tips and Tricks

### 1. Snapshots
Save VM state for quick restoration:
```bash
qemu-img snapshot -c clean_state mydisk.qcow2
qemu-img snapshot -a clean_state mydisk.qcow2  # Restore
```

### 2. Shared Folders
Share files between host and VM:
```bash
qemu-system-x86_64 \
  -hda mydisk.qcow2 \
  -virtfs local,path=/host/path,mount_tag=shared,security_model=none
```

Inside VM:
```bash
mount -t 9p -o trans=virtio shared /mnt
```

### 3. Performance
Enable KVM acceleration (Linux):
```bash
# Check KVM support
egrep -c '(vmx|svm)' /proc/cpuinfo

# Enable KVM
sudo modprobe kvm-intel  # or kvm-amd
```

### 4. Network Configuration
```bash
# NAT networking (default)
-netdev user,id=net0,hostfwd=tcp::2222-:22

# Bridge networking
-netdev bridge,id=net0,br=br0
```

## Troubleshooting

### "QEMU not found"
- Ensure QEMU is installed and in PATH
- Windows: Restart terminal after installation
- Check with: `where qemu-img` (Windows) or `which qemu-img` (Linux/macOS)

### "KVM not available"
- Normal in WSL2 - will use TCG acceleration
- Linux: Check virtualization in BIOS
- Windows: Use HAXM or WHPX instead

### Slow Performance
- Enable hardware acceleration (KVM/HAXM/WHPX)
- Allocate more RAM (-m 4096)
- Use virtio drivers for better I/O

### Can't Connect to VM
- Check firewall settings
- Use port forwarding: `-netdev user,id=net0,hostfwd=tcp::2222-:22`
- SSH: `ssh -p 2222 user@localhost`

## Resources

- QEMU Documentation: https://www.qemu.org/docs/master/
- Windows Test Images:
  - Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/
  - ReactOS: https://reactos.org/download/
- License Testing Tools:
  - HASP HL Dumper: For Sentinel HASP dongles
  - FlexLM Tools: For FlexNet licensing
  - CodeMeter Tools: For Wibu-Systems protection