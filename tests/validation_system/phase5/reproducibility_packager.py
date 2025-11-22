"""
Reproducibility Packager for Intellicrack Validation Framework.

Creates comprehensive packages that allow exact reproduction of validation tests,
including environment snapshots, configuration dumps, and execution recordings.
"""

import os
import sys
import json
import hashlib
import shutil
import subprocess
import platform
import psutil
import zipfile
import tarfile
import pickle
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import base64
import sqlite3
import yaml
import toml
import git
import virtualenv
import cpuinfo
import GPUtil
from intellicrack.handlers.wmi_handler import wmi
import winreg
from cryptography.fernet import Fernet


@dataclass
class SystemSnapshot:
    """Complete system state at time of validation."""
    timestamp: str
    platform: str
    platform_version: str
    architecture: str
    processor: str
    cpu_count: int
    cpu_freq: float
    memory_total: int
    memory_available: int
    disk_usage: dict[str, dict]
    gpu_info: list[dict]
    network_interfaces: list[dict]
    environment_variables: dict[str, str]
    installed_software: list[dict]
    system_dlls: list[str]
    kernel_version: str
    security_software: list[str]
    virtualization: dict[str, bool]


@dataclass
class DependencySnapshot:
    """Complete dependency state for reproduction."""
    python_version: str
    python_executable: str
    pip_packages: list[dict]
    conda_packages: list[dict]
    system_packages: list[str]
    dll_dependencies: list[dict]
    virtual_env: str | None
    requirements_txt: str
    environment_yml: str
    pipfile: str | None
    poetry_lock: str | None


@dataclass
class ConfigurationSnapshot:
    """All configuration files and settings."""
    intellicrack_config: dict
    frida_config: dict
    ghidra_config: dict
    environment_config: dict
    tool_paths: dict[str, str]
    api_keys: dict[str, str]  # Encrypted
    license_keys: dict[str, str]  # Encrypted
    debug_settings: dict
    performance_settings: dict


class EnvironmentRecorder:
    """Records complete environment state for reproducibility."""

    def __init__(self):
        self.wmi_client = wmi.WMI() if platform.system() == "Windows" else None

    def capture_system_snapshot(self) -> SystemSnapshot:
        """Capture complete system state."""

        # Basic system info
        system_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "cpu_freq": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available
        }

        # Disk usage
        disk_usage = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage[partition.device] = {
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
            except:
                continue

        # GPU information
        gpu_info = []
        try:
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                gpu_info.append({
                    "id": gpu.id,
                    "name": gpu.name,
                    "driver": gpu.driver,
                    "memory_total": gpu.memoryTotal,
                    "memory_used": gpu.memoryUsed,
                    "temperature": gpu.temperature
                })
        except:
            pass

        # Network interfaces
        network_interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            iface_info = {"name": iface, "addresses": []}
            for addr in addrs:
                iface_info["addresses"].append({
                    "family": addr.family.name,
                    "address": addr.address,
                    "netmask": addr.netmask
                })
            network_interfaces.append(iface_info)

        # Environment variables
        env_vars = dict(os.environ)

        # Installed software (Windows)
        installed_software = self._get_installed_software()

        # System DLLs
        system_dlls = self._get_system_dlls()

        # Kernel version
        kernel_version = platform.release()

        # Security software
        security_software = self._detect_security_software()

        # Virtualization detection
        virtualization = self._detect_virtualization()

        return SystemSnapshot(
            timestamp=system_info["timestamp"],
            platform=system_info["platform"],
            platform_version=system_info["platform_version"],
            architecture=system_info["architecture"],
            processor=system_info["processor"],
            cpu_count=system_info["cpu_count"],
            cpu_freq=system_info["cpu_freq"],
            memory_total=system_info["memory_total"],
            memory_available=system_info["memory_available"],
            disk_usage=disk_usage,
            gpu_info=gpu_info,
            network_interfaces=network_interfaces,
            environment_variables=env_vars,
            installed_software=installed_software,
            system_dlls=system_dlls,
            kernel_version=kernel_version,
            security_software=security_software,
            virtualization=virtualization
        )

    def _get_installed_software(self) -> list[dict]:
        """Get list of installed software on Windows."""
        software_list = []

        if platform.system() != "Windows":
            return software_list

        # Query Windows Registry for installed programs
        reg_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]

        for reg_path in reg_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                            software_list.append({
                                "name": name,
                                "version": version,
                                "publisher": publisher
                            })
                        except:
                            pass
                        winreg.CloseKey(subkey)
                    except:
                        pass
                winreg.CloseKey(key)
            except:
                pass

        # Also check using WMI
        if self.wmi_client:
            try:
                for product in self.wmi_client.Win32_Product():
                    software_list.append({
                        "name": product.Name,
                        "version": product.Version,
                        "vendor": product.Vendor
                    })
            except:
                pass

        return software_list

    def _get_system_dlls(self) -> list[str]:
        """Get list of system DLLs."""
        dlls = []

        if platform.system() == "Windows":
            system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
            if system32.exists():
                dlls = [f.name for f in system32.glob("*.dll")][:100]  # Limit to 100 for size

        return dlls

    def _detect_security_software(self) -> list[str]:
        """Detect installed security software."""
        security_software = []

        if platform.system() == "Windows" and self.wmi_client:
            try:
                # Check for antivirus
                for av in self.wmi_client.AntiVirusProduct():
                    security_software.append(f"Antivirus: {av.displayName}")

                # Check for firewall
                for fw in self.wmi_client.FirewallProduct():
                    security_software.append(f"Firewall: {fw.displayName}")
            except:
                pass

        # Check for common security tools in processes
        security_processes = [
            "MsMpEng.exe",  # Windows Defender
            "avp.exe",      # Kaspersky
            "avgnt.exe",    # Avira
            "avguard.exe",  # Avira
            "bdagent.exe",  # Bitdefender
            "nod32.exe",    # ESET
            "mcshield.exe"  # McAfee
        ]

        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] in security_processes:
                    security_software.append(f"Process: {proc.info['name']}")
            except:
                pass

        return security_software

    def _detect_virtualization(self) -> dict[str, bool]:
        """Detect if running in virtualized environment."""
        virt = {
            "vmware": False,
            "virtualbox": False,
            "hyperv": False,
            "qemu": False,
            "xen": False
        }

        # Check CPU info for hypervisor
        try:
            cpu_info = cpuinfo.get_cpu_info()
            if "hypervisor" in cpu_info.get("brand_raw", "").lower():
                # Try to identify which hypervisor
                brand = cpu_info.get("brand_raw", "").lower()
                if "vmware" in brand:
                    virt["vmware"] = True
                elif "virtualbox" in brand:
                    virt["virtualbox"] = True
                elif "microsoft" in brand:
                    virt["hyperv"] = True
                elif "qemu" in brand:
                    virt["qemu"] = True
                elif "xen" in brand:
                    virt["xen"] = True
        except:
            pass

        # Windows-specific checks
        if platform.system() == "Windows" and self.wmi_client:
            try:
                for item in self.wmi_client.Win32_ComputerSystem():
                    if "vmware" in item.Manufacturer.lower():
                        virt["vmware"] = True
                    elif "microsoft" in item.Manufacturer.lower():
                        virt["hyperv"] = True
                    elif "innotek" in item.Manufacturer.lower():  # VirtualBox
                        virt["virtualbox"] = True
            except:
                pass

        return virt

    def capture_dependency_snapshot(self) -> DependencySnapshot:
        """Capture all dependencies for reproduction."""

        # Python information
        python_info = {
            "version": sys.version,
            "executable": sys.executable
        }

        # Pip packages
        pip_packages = []
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                pip_packages = json.loads(result.stdout)
        except:
            pass

        # Conda packages (if in conda environment)
        conda_packages = []
        if ".pixi" in sys.executable.lower():
            try:
                result = subprocess.run(
                    ["conda", "list", "--json"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    conda_packages = json.loads(result.stdout)
            except:
                pass

        # System packages (Windows)
        system_packages = []
        if platform.system() == "Windows":
            # Check for chocolatey packages
            try:
                result = subprocess.run(
                    ["choco", "list", "--local-only"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    system_packages = result.stdout.strip().split("\n")
            except:
                pass

        # DLL dependencies
        dll_dependencies = self._get_dll_dependencies()

        # Virtual environment
        virtual_env = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_DEFAULT_ENV")

        # Generate requirements.txt
        requirements_txt = self._generate_requirements_txt(pip_packages)

        # Generate environment.yml
        environment_yml = self._generate_environment_yml(conda_packages)

        # Check for Pipfile
        pipfile = None
        if Path("Pipfile").exists():
            with open("Pipfile") as f:
                pipfile = f.read()

        # Check for poetry.lock
        poetry_lock = None
        if Path("poetry.lock").exists():
            with open("poetry.lock") as f:
                poetry_lock = f.read()

        return DependencySnapshot(
            python_version=python_info["version"],
            python_executable=python_info["executable"],
            pip_packages=pip_packages,
            conda_packages=conda_packages,
            system_packages=system_packages,
            dll_dependencies=dll_dependencies,
            virtual_env=virtual_env,
            requirements_txt=requirements_txt,
            environment_yml=environment_yml,
            pipfile=pipfile,
            poetry_lock=poetry_lock
        )

    def _get_dll_dependencies(self) -> list[dict]:
        """Get DLL dependencies for Python and key libraries."""
        dll_deps = []

        if platform.system() != "Windows":
            return dll_deps

        # Use dumpbin or similar to get DLL dependencies
        key_files = [
            sys.executable,  # Python.exe
            Path(sys.prefix) / "DLLs" / "sqlite3.dll",
            Path(sys.prefix) / "DLLs" / "_ssl.pyd"
        ]

        for file_path in key_files:
            if file_path.exists():
                try:
                    # Try using dumpbin
                    result = subprocess.run(
                        ["dumpbin", "/dependents", str(file_path)],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        # Parse output
                        lines = result.stdout.split("\n")
                        for line in lines:
                            if ".dll" in line.lower():
                                dll_name = line.strip()
                                if dll_name:
                                    dll_deps.append({
                                        "file": str(file_path),
                                        "dependency": dll_name
                                    })
                except:
                    pass

        return dll_deps

    def _generate_requirements_txt(self, pip_packages: list[dict]) -> str:
        """Generate requirements.txt from pip packages."""
        requirements = []
        for package in pip_packages:
            requirements.append(f"{package.get('name')}=={package.get('version')}")
        return "\n".join(requirements)

    def _generate_environment_yml(self, conda_packages: list[dict]) -> str:
        """Generate environment.yml from conda packages."""
        env_dict = {
            "name": "intellicrack_validation",
            "dependencies": []
        }

        for package in conda_packages:
            env_dict["dependencies"].append(
                f"{package.get('name')}={package.get('version')}"
            )

        return yaml.dump(env_dict, default_flow_style=False)


class ExecutionRecorder:
    """Records test execution for perfect reproduction."""

    def __init__(self, recording_dir: Path):
        self.recording_dir = recording_dir
        self.recording_dir.mkdir(parents=True, exist_ok=True)
        self.recordings_db = self.recording_dir / "recordings.db"
        self._initialize_database()

    def _initialize_database(self):
        """Initialize recording database."""
        conn = sqlite3.connect(self.recordings_db)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT,
                arguments TEXT,
                environment TEXT,
                stdin_data BLOB,
                stdout_data BLOB,
                stderr_data BLOB,
                return_code INTEGER,
                execution_time REAL,
                memory_usage INTEGER,
                file_changes TEXT
            )
        """)

        conn.commit()
        conn.close()

    def record_execution(
        self,
        test_id: str,
        command: str,
        arguments: list[str],
        environment: dict[str, str],
        working_dir: Path
    ) -> dict:
        """Record a test execution with full reproducibility data."""

        # Snapshot files before execution
        files_before = self._snapshot_directory(working_dir)

        # Prepare execution
        start_time = datetime.now()
        process_env = os.environ.copy()
        process_env.update(environment)

        # Execute and record
        process = subprocess.Popen(
            [command] + arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_env,
            cwd=working_dir
        )

        # Record stdin if interactive
        stdin_data = b""

        # Get output
        stdout_data, stderr_data = process.communicate()
        return_code = process.returncode

        execution_time = (datetime.now() - start_time).total_seconds()

        # Snapshot files after execution
        files_after = self._snapshot_directory(working_dir)
        file_changes = self._detect_file_changes(files_before, files_after)

        # Get memory usage
        memory_usage = 0
        try:
            process_info = psutil.Process(process.pid)
            memory_usage = process_info.memory_info().rss
        except:
            pass

        # Store recording
        conn = sqlite3.connect(self.recordings_db)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO recordings (
                test_id, command, arguments, environment,
                stdin_data, stdout_data, stderr_data,
                return_code, execution_time, memory_usage, file_changes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            test_id, command, json.dumps(arguments),
            json.dumps(environment), stdin_data,
            stdout_data, stderr_data, return_code,
            execution_time, memory_usage, json.dumps(file_changes)
        ))

        conn.commit()
        conn.close()

        return {
            "test_id": test_id,
            "command": command,
            "arguments": arguments,
            "return_code": return_code,
            "execution_time": execution_time,
            "memory_usage": memory_usage,
            "file_changes": file_changes
        }

    def _snapshot_directory(self, directory: Path) -> dict[str, str]:
        """Create snapshot of directory state."""
        snapshot = {}

        for file_path in directory.rglob("*"):
            if file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    snapshot[str(file_path)] = file_hash
                except:
                    pass

        return snapshot

    def _detect_file_changes(self, before: dict[str, str], after: dict[str, str]) -> dict:
        """Detect file changes between snapshots."""
        changes = {
            "created": [],
            "modified": [],
            "deleted": []
        }

        # Find created and modified files
        for file_path, file_hash in after.items():
            if file_path not in before:
                changes["created"].append(file_path)
            elif before[file_path] != file_hash:
                changes["modified"].append(file_path)

        # Find deleted files
        for file_path in before:
            if file_path not in after:
                changes["deleted"].append(file_path)

        return changes


class ReproducibilityPackager:
    """
    Creates comprehensive reproducibility packages that allow exact
    recreation of validation test environments and executions.
    """

    def __init__(self, validation_dir: Path):
        self.validation_dir = validation_dir
        self.package_dir = validation_dir / "reproducibility_packages"
        self.package_dir.mkdir(exist_ok=True)
        self.env_recorder = EnvironmentRecorder()
        self.exec_recorder = ExecutionRecorder(validation_dir / "recordings")

        # Encryption for sensitive data
        self.cipher_key = Fernet.generate_key()
        self.cipher = Fernet(self.cipher_key)

    def create_reproducibility_package(
        self,
        test_results: list[Any],
        test_configs: dict,
        evidence_dir: Path
    ) -> Path:
        """Create complete reproducibility package."""

        package_name = f"repro_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        package_path = self.package_dir / package_name
        package_path.mkdir()

        print(f"Creating reproducibility package: {package_name}")

        # 1. Capture environment snapshots
        print("  Capturing system snapshot...")
        system_snapshot = self.env_recorder.capture_system_snapshot()
        self._save_snapshot(package_path / "system_snapshot.json", asdict(system_snapshot))

        print("  Capturing dependency snapshot...")
        dependency_snapshot = self.env_recorder.capture_dependency_snapshot()
        self._save_snapshot(package_path / "dependency_snapshot.json", asdict(dependency_snapshot))

        # 2. Capture configuration
        print("  Capturing configuration...")
        config_snapshot = self._capture_configuration()
        self._save_snapshot(package_path / "config_snapshot.json", asdict(config_snapshot))

        # 3. Create virtual machine specification
        print("  Creating VM specification...")
        vagrant_file = self._generate_vagrantfile(system_snapshot)
        (package_path / "Vagrantfile").write_text(vagrant_file)

        # 5. Package test binaries and inputs
        print("  Packaging test binaries...")
        self._package_test_binaries(package_path / "test_binaries", test_configs)

        # 6. Package evidence files
        print("  Packaging evidence...")
        self._package_evidence(package_path / "evidence", evidence_dir)

        # 7. Create execution scripts
        print("  Creating execution scripts...")
        self._create_execution_scripts(package_path, test_configs)

        # 8. Create validation scripts
        print("  Creating validation scripts...")
        self._create_validation_scripts(package_path)

        # 9. Create Git repository for version control
        print("  Initializing Git repository...")
        self._initialize_git_repo(package_path)

        # 10. Generate checksums
        print("  Generating checksums...")
        checksums = self._generate_checksums(package_path)
        (package_path / "checksums.sha256").write_text(checksums)

        # 11. Create compressed archive
        print("  Creating archive...")
        archive_path = self._create_archive(package_path)

        # 12. Generate reproduction instructions
        print("  Generating instructions...")
        instructions = self._generate_reproduction_instructions(
            system_snapshot, dependency_snapshot, package_name
        )
        (package_path / "REPRODUCE.md").write_text(instructions)

        print(f"OK Reproducibility package created: {archive_path}")

        return archive_path

    def _capture_configuration(self) -> ConfigurationSnapshot:
        """Capture all configuration settings."""

        # Intellicrack configuration
        intellicrack_config = {}
        config_file = Path("intellicrack_config.json")
        if config_file.exists():
            with open(config_file) as f:
                intellicrack_config = json.load(f)

        # Frida configuration
        frida_config = {}
        frida_config_file = Path.home() / ".frida" / "config.json"
        if frida_config_file.exists():
            with open(frida_config_file) as f:
                frida_config = json.load(f)

        # Tool paths
        tool_paths = self._discover_tool_paths()

        # Environment configuration
        env_config = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", ""),
            "INTELLICRACK_HOME": os.environ.get("INTELLICRACK_HOME", "")
        }

        # Encrypt sensitive data
        api_keys = self._encrypt_sensitive_data({
            k: v for k, v in os.environ.items()
            if "API" in k or "KEY" in k or "TOKEN" in k
        })

        return ConfigurationSnapshot(
            intellicrack_config=intellicrack_config,
            frida_config=frida_config,
            ghidra_config={},  # Would load from Ghidra config
            environment_config=env_config,
            tool_paths=tool_paths,
            api_keys=api_keys,
            license_keys={},  # Would load from license storage
            debug_settings={},  # Would load from debug config
            performance_settings={}  # Would load from performance config
        )

    def _discover_tool_paths(self) -> dict[str, str]:
        """Discover paths to all required tools."""
        tools = {}

        # Common tools to find
        tool_names = [
            "python", "pip", "frida", "frida-server",
            "radare2", "r2", "ghidra", "x64dbg",
            "ida", "ida64", "ollydbg", "windbg",
            "gdb", "objdump", "nm", "strings",
            "upx", "pestudio", "processhacker"
        ]

        for tool in tool_names:
            tool_path = shutil.which(tool)
            if tool_path:
                tools[tool] = tool_path

        return tools

    def _encrypt_sensitive_data(self, data: dict) -> dict:
        """Encrypt sensitive configuration data."""
        encrypted = {}
        for key, value in data.items():
            if value:
                encrypted[key] = self.cipher.encrypt(value.encode()).decode()
        return encrypted

    def _generate_vagrantfile(self, system: SystemSnapshot) -> str:
        """Generate Vagrantfile for VM-based reproduction."""
        return f"""# Intellicrack Validation VM
Vagrant.configure("2") do |config|
  config.vm.box = "gusztavvargadr/windows-10"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "{system.memory_total // (1024**3)}GB"
    vb.cpus = {system.cpu_count}
    vb.customize ["modifyvm", :id, "--vram", "128"]
    vb.customize ["modifyvm", :id, "--accelerate3d", "on"]
  end

  # Provision with required software
  config.vm.provision "shell", inline: <<-SHELL
    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    # Install Python
    choco install -y python3

    # Install development tools
    choco install -y git visualstudio2019community

    # Clone Intellicrack
    git clone https://github.com/intellicrack/intellicrack.git C:\\intellicrack

    # Install dependencies
    cd C:\\intellicrack
    pip install -r requirements.txt
  SHELL
end
"""

    def _package_test_binaries(self, output_dir: Path, test_configs: dict):
        """Package all test binaries with metadata."""
        output_dir.mkdir(parents=True, exist_ok=True)

        binaries_metadata = {}

        for test_id, config in test_configs.items():
            if "binary_path" in config:
                binary_path = Path(config["binary_path"])
                if binary_path.exists():
                    # Copy binary
                    dest_path = output_dir / f"{test_id}_{binary_path.name}"
                    shutil.copy2(binary_path, dest_path)

                    # Calculate hash
                    with open(dest_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()

                    # Store metadata
                    binaries_metadata[test_id] = {
                        "original_path": str(binary_path),
                        "packaged_path": str(dest_path),
                        "sha256": file_hash,
                        "size": dest_path.stat().st_size,
                        "protection": config.get("protection_type", "unknown")
                    }

        # Save metadata
        with open(output_dir / "binaries_metadata.json", "w") as f:
            json.dump(binaries_metadata, f, indent=2)

    def _package_evidence(self, output_dir: Path, evidence_dir: Path):
        """Package evidence files with verification."""
        if evidence_dir.exists():
            shutil.copytree(evidence_dir, output_dir, dirs_exist_ok=True)

    def _create_execution_scripts(self, package_path: Path, test_configs: dict):
        """Create scripts to re-run validation tests."""

        # Windows batch script
        batch_script = """@echo off
echo Starting Intellicrack Validation Reproduction
echo =============================================

REM Set environment
set INTELLICRACK_HOME=%~dp0
set PYTHONPATH=%INTELLICRACK_HOME%;%PYTHONPATH%

REM Activate virtual environment if exists
if exist venv\\Scripts\\activate.bat (
    call venv\\Scripts\\activate.bat
)

REM Run validation
python -m tests.validation_system.runner --reproduce --config reproduce_config.json

echo.
echo Validation reproduction complete
pause
"""
        (package_path / "run_validation.bat").write_text(batch_script)

        # PowerShell script
        ps_script = """# Intellicrack Validation Reproduction
Write-Host "Starting Intellicrack Validation Reproduction" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green

# Set environment
$env:INTELLICRACK_HOME = $PSScriptRoot
$env:PYTHONPATH = "$PSScriptRoot;$env:PYTHONPATH"

# Check Python
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Run validation
Write-Host "Running validation tests..." -ForegroundColor Yellow
python -m tests.validation_system.runner --reproduce --config reproduce_config.json

Write-Host "Validation reproduction complete" -ForegroundColor Green
"""
        (package_path / "run_validation.ps1").write_text(ps_script)

        # Create configuration for reproduction
        reproduce_config = {
            "mode": "reproduce",
            "test_configs": test_configs,
            "evidence_dir": "evidence",
            "results_dir": "results",
            "binary_dir": "test_binaries"
        }

        with open(package_path / "reproduce_config.json", "w") as f:
            json.dump(reproduce_config, f, indent=2)

    def _create_validation_scripts(self, package_path: Path):
        """Create scripts to validate reproduction accuracy."""

        validation_script = """import json
import hashlib
from pathlib import Path

def validate_reproduction():
    \"\"\"Validate that reproduction matches original results.\"\"\"

    print("Validating reproduction accuracy...")

    # Load original checksums
    with open("checksums.sha256") as f:
        original_checksums = {}
        for line in f:
            if line.strip():
                hash_val, file_path = line.strip().split("  ", 1)
                original_checksums[file_path] = hash_val

    # Validate files
    mismatches = []
    for file_path, expected_hash in original_checksums.items():
        path = Path(file_path)
        if path.exists():
            with open(path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash != expected_hash:
                mismatches.append(file_path)
                print(f"  FAIL {file_path}: Hash mismatch")
        else:
            mismatches.append(file_path)
            print(f"  FAIL {file_path}: File missing")

    if mismatches:
        print(f"\\nFAIL Validation failed: {len(mismatches)} mismatches")
        return False
    else:
        print("\\nOK Validation successful: All files match")
        return True

if __name__ == "__main__":
    validate_reproduction()
"""
        (package_path / "validate_reproduction.py").write_text(validation_script)

    def _initialize_git_repo(self, package_path: Path):
        """Initialize Git repository for version control."""
        try:
            repo = git.Repo.init(package_path)
            repo.git.add(".")
            repo.index.commit("Initial reproducibility package")

            # Create .gitignore
            gitignore = """# Evidence files
evidence/**/*.dmp
evidence/**/*.pcap
evidence/**/*.mp4

# Large binaries
test_binaries/**/*.exe
test_binaries/**/*.dll

# Temporary files
*.tmp
*.log
__pycache__/
"""
            (package_path / ".gitignore").write_text(gitignore)

        except:
            pass  # Git not available

    def _generate_checksums(self, package_path: Path) -> str:
        """Generate SHA256 checksums for all files."""
        checksums = []

        for file_path in package_path.rglob("*"):
            if file_path.is_file() and not file_path.name.startswith("."):
                try:
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    relative_path = file_path.relative_to(package_path)
                    checksums.append(f"{file_hash}  {relative_path}")
                except:
                    pass

        return "\n".join(checksums)

    def _create_archive(self, package_path: Path) -> Path:
        """Create compressed archive of package."""
        archive_path = package_path.with_suffix(".tar.gz")

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(package_path, arcname=package_path.name)

        return archive_path

    def _generate_reproduction_instructions(
        self,
        system: SystemSnapshot,
        deps: DependencySnapshot,
        package_name: str
    ) -> str:
        """Generate detailed reproduction instructions."""

        instructions = f"""# Intellicrack Validation Reproduction Instructions

## Package: {package_name}
## Generated: {datetime.now(timezone.utc).isoformat()}

## System Requirements

### Hardware
- CPU: {system.cpu_count} cores minimum
- RAM: {system.memory_total // (1024**3)}GB minimum
- Disk: 50GB free space
- GPU: Optional (improves performance)

### Software
- OS: {system.platform} {system.platform_version}
- Python: {deps.python_version.split()[0]}
- Architecture: {system.architecture}

## Reproduction Methods

### Method 1: Virtual Machine (Recommended)

1. Install VirtualBox and Vagrant
2. Extract the package archive
3. Navigate to the package directory
4. Start VM:
   ```
   vagrant up
   vagrant ssh
   ```

### Method 2: Native Installation

1. Ensure system meets requirements above
2. Install Python {deps.python_version.split()[0]}
3. Extract the package archive
4. Run setup:
   ```
   run_validation.bat
   ```
   or
   ```
   powershell.exe -ExecutionPolicy Bypass .\\run_validation.ps1
   ```

## Validation

After reproduction, validate accuracy:
```
python validate_reproduction.py
```

## Troubleshooting

### Missing Dependencies
- Check requirements.txt and environment.yml
- Install missing system packages from system_snapshot.json

### Permission Errors
- Run as Administrator on Windows
- Ensure VM software has proper privileges

### Network Issues
- Some tests may require internet access
- Check firewall settings

## Evidence Files

Evidence is stored in the `evidence/` directory:
- Memory dumps: `*.dmp`
- Network captures: `*.pcap`
- Screenshots: `*.png`
- Videos: `*.mp4`

## Support

For issues with reproduction, include:
1. System snapshot (system_snapshot.json)
2. Error logs
3. Validation script output

---
End of Instructions
"""

        return instructions

    def _save_snapshot(self, path: Path, data: dict):
        """Save snapshot data as JSON."""
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
