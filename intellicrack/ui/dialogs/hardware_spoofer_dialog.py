"""Hardware Fingerprint Spoofer Dialog - Advanced hardware ID manipulation.

Provides comprehensive interface for spoofing hardware identifiers to bypass hardware-locked licenses.
"""

import json
import os
import random
import re  # Add this import for regex validation
import string
import subprocess
import uuid
import winreg
from datetime import datetime
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,  # Add this import
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer
from intellicrack.utils.logger import logger

# Constants for duplicated literals
WMIC_VALUE_FLAG = "/value"
SERIAL_NUMBER_PREFIX = "SerialNumber="
NAME_PREFIX = "Name="
VOLUME_SERIAL_PREFIX = "VolumeSerialNumber="
MANUFACTURER_PREFIX = "Manufacturer="
VERSION_PREFIX = "SMBIOSBIOSVersion="
BIOS_SERIAL_PREFIX = "SerialNumber="
AMI_MANUFACTURER = "American Megatrends Inc."
PHOENIX_MANUFACTURER = "Phoenix Technologies"
AWARD_MANUFACTURER = "Award Software"
DELL_MANUFACTURER = "Dell Inc."
HP_MANUFACTURER = "HP"
VOLUME_SERIALS_LABEL = "Volume Serials"
MAC_ADDRESSES_LABEL = "MAC Addresses"
DELETE_SELECTED_LABEL = "Delete Selected"
VIRTUAL_MACHINE_LABEL = "Virtual Machine"
JSON_FILES_FILTER = "JSON Files (*.json)"
ADD_VOLUME_LABEL = "Add Volume"
INTELLICRACK_DIR = ".intellicrack"
NO_PROFILE_MSG = "No profile selected."
DEFAULT_CPU_ID = "BFEBFBFF000906EA"
DEFAULT_MB_SERIAL = "Default string"
DEFAULT_HDD_SERIAL = "WD-WCC1234567890"
DEFAULT_MAC = "00-11-22-33-44-55"
DEFAULT_VOLUME_SERIAL = "1234-5678"
DEFAULT_PRODUCT_ID = "00000-00000-00000-00000"
DEFAULT_BIOS_SERIAL = "System Serial Number"
DEFAULT_BIOS_VERSION = "1.0.0"
DEFAULT_BIOS_INFO = {"serial": DEFAULT_BIOS_SERIAL, "version": DEFAULT_BIOS_VERSION, "manufacturer": AMI_MANUFACTURER}
PROCESSOR_ID_PREFIX = "ProcessorId="


class HardwareSpoofingWorker(QThread):
    """Worker thread for hardware spoofing operations."""

    status_update = pyqtSignal(str, str)  # message, color
    spoof_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the HardwareSpoofingDialog with spoofer and UI components.

        Args:
            parent: Parent widget for this dialog. Defaults to None.

        """
        super().__init__(parent)
        self.spoofer = HardwareFingerPrintSpoofer()
        self.worker_thread = None
        self.init_ui()
        self.load_settings()

    def run(self) -> None:
        """Execute spoofing operation."""
        try:
            self.status_update.emit("Starting hardware spoofing operation...", "blue")

            if self.action == "capture":
                self.capture_hardware_info()
            elif self.action == "generate":
                self.generate_spoofed_ids()
            elif self.action == "apply":
                self.apply_spoofing()
            elif self.action == "restore":
                self.restore_original()
            elif self.action == "verify":
                self.verify_spoofing()

        except Exception as e:
            self.error_occurred.emit(str(e))
            self.status_update.emit(f"Error: {str(e)}", "red")

    def capture_hardware_info(self) -> None:
        """Capture current hardware information."""
        self.progress_update.emit("Capturing hardware information...")

        hardware_info: Dict[str, Any] = {}

        # CPU ID
        self.progress_update.emit("Reading CPU ID...")
        cpu_id = self.get_cpu_id()
        hardware_info["cpu_id"] = cpu_id

        # Motherboard Serial
        self.progress_update.emit("Reading motherboard serial...")
        mb_serial = self.get_motherboard_serial()
        hardware_info["motherboard_serial"] = mb_serial

        # Hard Drive Serial
        self.progress_update.emit("Reading hard drive serial...")
        hdd_serial = self.get_hdd_serial()
        hardware_info["hdd_serial"] = hdd_serial

        # MAC Addresses
        self.progress_update.emit("Reading MAC addresses...")
        mac_addresses = self.get_mac_addresses()
        hardware_info["mac_addresses"] = mac_addresses

        # Volume Serial
        self.progress_update.emit("Reading volume serial numbers...")
        volume_serials = self.get_volume_serials()
        hardware_info["volume_serials"] = volume_serials

        # BIOS Information
        self.progress_update.emit("Reading BIOS information...")
        bios_info = self.get_bios_info()
        hardware_info["bios_info"] = bios_info

        # Windows Product ID
        self.progress_update.emit("Reading Windows Product ID...")
        product_id = self.get_windows_product_id()
        hardware_info["product_id"] = product_id

        # Machine GUID
        self.progress_update.emit("Reading Machine GUID...")
        machine_guid = self.get_machine_guid()
        hardware_info["machine_guid"] = machine_guid

        self.spoof_complete.emit(hardware_info)
        self.status_update.emit("Hardware information captured successfully", "green")

    def get_cpu_id(self) -> str:
        """Get CPU ID using WMI."""
        try:
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(["wmic", "cpu", "get", "ProcessorId", wmic_flag_clean], capture_output=True, text=True, shell=False)
            for line in result.stdout.split("\n"):
                if PROCESSOR_ID_PREFIX in line:
                    return line.split("=")[1].strip()
        except Exception as e:
            logger.debug(f"CPU ID extraction failed: {e}")
        return DEFAULT_CPU_ID  # Default Intel CPU ID

    def get_motherboard_serial(self) -> str:
        """Get motherboard serial number."""
        try:
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(
                ["wmic", "baseboard", "get", "SerialNumber", wmic_flag_clean], capture_output=True, text=True, shell=False
            )
            for line in result.stdout.split("\n"):
                if SERIAL_NUMBER_PREFIX in line:
                    return line.split("=")[1].strip()
        except Exception as e:
            logger.debug(f"Motherboard serial extraction failed: {e}")
        return DEFAULT_MB_SERIAL

    def get_hdd_serial(self) -> str:
        """Get primary hard drive serial."""
        try:
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "SerialNumber", wmic_flag_clean], capture_output=True, text=True, shell=False
            )
            for line in result.stdout.split("\n"):
                if SERIAL_NUMBER_PREFIX in line:
                    serial = line.split("=")[1].strip()
                    if serial:
                        return serial
        except Exception as e:
            logger.debug(f"HDD serial extraction failed: {e}")
        return DEFAULT_HDD_SERIAL

    def get_mac_addresses(self) -> List[str]:
        """Get all network adapter MAC addresses."""
        macs: List[str] = []
        try:
            result = subprocess.run(["getmac", "/v", "/fo", "csv"], capture_output=True, text=True, shell=False)
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.split(",")
                if len(parts) > 2 and parts[2].strip('"'):
                    mac = parts[2].strip('"')
                    if mac and mac != "N/A":
                        macs.append(mac)
        except Exception as e:
            logger.debug(f"MAC address extraction failed: {e}")

        if not macs:
            macs = [DEFAULT_MAC]
        return macs

    def get_volume_serials(self) -> Dict[str, str]:
        """Get volume serial numbers for all drives."""
        volumes: Dict[str, str] = {}
        try:
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "Name,VolumeSerialNumber", wmic_flag_clean], capture_output=True, text=True, shell=False
            )

            current_name = None
            for line in result.stdout.split("\n"):
                if NAME_PREFIX in line:
                    current_name = line.split("=")[1].strip()
                elif VOLUME_SERIAL_PREFIX in line and current_name:
                    serial = line.split("=")[1].strip()
                    if serial:
                        volumes[current_name] = serial
        except Exception as e:
            logger.debug(f"Volume serial extraction failed: {e}")

        if not volumes:
            volumes = {"C:": DEFAULT_VOLUME_SERIAL}
        return volumes

    def get_bios_info(self) -> Dict[str, str]:
        """Get BIOS information."""
        bios_info: Dict[str, str] = {}
        try:
            # BIOS Serial Number
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(["wmic", "bios", "get", "SerialNumber", wmic_flag_clean], capture_output=True, text=True, shell=False)
            for line in result.stdout.split("\n"):
                if BIOS_SERIAL_PREFIX in line:
                    bios_info["serial"] = line.split("=")[1].strip()

            # BIOS Version
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(
                ["wmic", "bios", "get", "SMBIOSBIOSVersion", wmic_flag_clean], capture_output=True, text=True, shell=False
            )
            for line in result.stdout.split("\n"):
                if VERSION_PREFIX in line:
                    bios_info["version"] = line.split("=")[1].strip()

            # BIOS Manufacturer
            # Sanitize WMIC_VALUE_FLAG to prevent command injection
            wmic_flag_clean = str(WMIC_VALUE_FLAG).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(["wmic", "bios", "get", "Manufacturer", wmic_flag_clean], capture_output=True, text=True, shell=False)
            for line in result.stdout.split("\n"):
                if MANUFACTURER_PREFIX in line:
                    bios_info["manufacturer"] = line.split("=")[1].strip()
        except Exception as e:
            logger.debug(f"BIOS info extraction failed: {e}")

        if not bios_info:
            bios_info = DEFAULT_BIOS_INFO
        return bios_info

    def get_windows_product_id(self) -> str:
        """Get Windows Product ID from registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                product_id, _ = winreg.QueryValueEx(key, "ProductId")
                return product_id
        except Exception:
            return DEFAULT_PRODUCT_ID

    def get_machine_guid(self) -> str:
        """Get Machine GUID from registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return machine_guid
        except Exception:
            return str(uuid.uuid4())

    def generate_spoofed_ids(self) -> None:
        """Generate realistic spoofed hardware IDs."""
        self.progress_update.emit("Generating spoofed identifiers...")

        spoofed_info: Dict[str, Any] = {}

        # Generate CPU ID (Intel format)
        cpu_vendors = ["BFEBFBFF", "AFEBFBFF", "CFEBFBFF"]  # Intel prefixes
        # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
        cpu_id = random.choice(cpu_vendors) + "".join(random.choices("0123456789ABCDEF", k=8))  # noqa: S311, S311
        spoofed_info["cpu_id"] = cpu_id

        # Generate motherboard serial
        mb_prefixes = ["MB", "SN", "System", "Base"]
        # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
        mb_serial = random.choice(mb_prefixes) + "-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))  # noqa: S311, S311
        spoofed_info["motherboard_serial"] = mb_serial

        # Generate HDD serial (realistic format)
        hdd_brands = ["WD-WCC", "ST", "HGST", "TOSHIBA"]
        # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
        hdd_serial = random.choice(hdd_brands) + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))  # noqa: S311, S311
        spoofed_info["hdd_serial"] = hdd_serial

        # Generate MAC addresses
        mac_addresses: List[str] = []
        oui_prefixes = ["00:1B:44", "00:50:56", "00:0C:29", "08:00:27"]  # Common OUIs
        for _ in range(2):
            # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
            oui = random.choice(oui_prefixes)  # noqa: S311
            nic = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])  # noqa: S311
            mac_addresses.append(f"{oui}:{nic}")
        spoofed_info["mac_addresses"] = mac_addresses

        # Generate volume serials
        volumes: Dict[str, str] = {}
        for drive in ["C:", "D:"]:
            # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
            serial = f"{random.randint(1000, 9999):04X}-{random.randint(1000, 9999):04X}"  # noqa: S311, S311
            volumes[drive] = serial
        spoofed_info["volume_serials"] = volumes

        # Generate BIOS info
        bios_manufacturers = [AMI_MANUFACTURER, PHOENIX_MANUFACTURER, AWARD_MANUFACTURER, DELL_MANUFACTURER, HP_MANUFACTURER]
        bios_info = {
            "serial": "".join(random.choices(string.ascii_uppercase + string.digits, k=15)),  # noqa: S311
            "version": f"{random.randint(1, 5)}.{random.randint(0, 99)}.{random.randint(0, 999)}",  # noqa: S311, S311, S311
            "manufacturer": random.choice(bios_manufacturers),  # noqa: S311
        }
        spoofed_info["bios_info"] = bios_info

        # Generate Windows Product ID
        # Note: Using random module for generating fake hardware IDs, not cryptographic purposes
        product_id = f"{random.randint(10000, 99999):05d}-{random.randint(10000, 99999):05d}-{random.randint(10000, 99999):05d}-{random.randint(10000, 99999):05d}"  # noqa: S311, S311, S311, S311
        spoofed_info["product_id"] = product_id

        # Generate Machine GUID
        machine_guid = str(uuid.uuid4())
        spoofed_info["machine_guid"] = machine_guid

        self.spoof_complete.emit(spoofed_info)
        self.status_update.emit("Spoofed identifiers generated successfully", "green")

    def apply_spoofing(self) -> None:
        """Apply hardware spoofing."""
        self.progress_update.emit("Applying hardware spoofing...")

        success_count = 0
        fail_count = 0

        # Handler dictionary for specific spoofing
        handlers = {
            "volume_serials": self._apply_volume_spoofing,
            "mac_addresses": self._apply_mac_spoofing,
            "product_id": self._apply_product_spoofing,
            "machine_guid": self._apply_machine_guid_spoofing,
        }

        for key, handler in handlers.items():
            if key in self.params:
                try:
                    count = handler(self.params[key])
                    success_count += count
                except Exception as e:
                    fail_count += 1
                    self.progress_update.emit(f"Failed to apply {key}: {str(e)}")

        # Apply advanced spoofing using the backend
        if hasattr(self, "spoofer") and self.spoofer:
            self.progress_update.emit("Applying advanced spoofing techniques...")
            try:
                self.spoofer.apply_all_spoofing()
                success_count += 5  # Additional methods from backend
            except Exception:
                fail_count += 1

        results = {"success_count": success_count, "fail_count": fail_count, "total": success_count + fail_count}

        self.spoof_complete.emit(results)

        if fail_count == 0:
            self.status_update.emit(f"All spoofing methods applied successfully ({success_count} methods)", "green")
        else:
            self.status_update.emit(f"Spoofing completed with {fail_count} failures out of {success_count + fail_count}", "orange")

    def _apply_volume_spoofing(self, volumes: Dict[str, str]) -> int:
        """Apply volume serial spoofing."""
        success_count = 0
        for drive, serial in volumes.items():
            self.progress_update.emit(f"Spoofing volume serial for {drive}...")
            if self.spoof_volume_serial(drive, serial):
                success_count += 1
        return success_count

    def _apply_mac_spoofing(self, mac_addresses: List[str]) -> int:
        """Apply MAC address spoofing."""
        success_count = 0
        for i, mac in enumerate(mac_addresses):
            self.progress_update.emit(f"Spoofing MAC address {i + 1}...")
            if self.spoof_mac_address(i, mac):
                success_count += 1
        return success_count

    def _apply_product_spoofing(self, product_id: str) -> int:
        """Apply product ID spoofing."""
        self.progress_update.emit("Spoofing Windows Product ID...")
        if self.spoof_product_id(product_id):
            return 1
        return 0

    def _apply_machine_guid_spoofing(self, guid: str) -> int:
        """Apply machine GUID spoofing."""
        self.progress_update.emit("Spoofing Machine GUID...")
        if self.spoof_machine_guid(guid):
            return 1
        return 0

    def spoof_volume_serial(self, drive: str, serial: str) -> bool:
        """Spoof volume serial number."""
        try:
            # This requires admin privileges
            # Using diskpart or other methods
            drive_letter = drive.replace(":", "")

            # Create diskpart script
            script = f"select volume {drive_letter}\nuniqueid disk ID={serial}"
            script_file = "temp_diskpart.txt"

            with open(script_file, "w") as f:
                f.write(script)

            # Sanitize script_file to prevent command injection
            script_file_clean = str(script_file).replace(";", "").replace("|", "").replace("&", "")
            result = subprocess.run(["diskpart", "/s", script_file_clean], capture_output=True, text=True, shell=False)

            os.remove(script_file)
            return "successfully" in result.stdout.lower()
        except Exception:
            return False

    def spoof_mac_address(self, index: int, mac: str) -> bool:
        """Spoof MAC address in registry."""
        try:
            # Find network adapter in registry
            adapter_key = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if subkey_name.isdigit() and int(subkey_name) == index:
                            subkey_path = f"{adapter_key}\\{subkey_name}"
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_WRITE) as subkey:
                                # Set NetworkAddress value
                                clean_mac = mac.replace(":", "").replace("-", "")
                                winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, clean_mac)
                                return True
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug(f"MAC address spoofing failed: {e}")
        return False

    def spoof_product_id(self, product_id: str) -> bool:
        """Spoof Windows Product ID in registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, product_id)
                return True
        except Exception:
            return False

    def spoof_machine_guid(self, guid: str) -> bool:
        """Spoof Machine GUID in registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, guid)
                return True
        except Exception:
            return False

    def restore_original(self) -> None:
        """Restore original hardware IDs."""
        self.progress_update.emit("Restoring original hardware identifiers...")

        # Remove spoofed MAC addresses
        try:
            adapter_key = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if subkey_name.isdigit():
                            subkey_path = f"{adapter_key}\\{subkey_name}"
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_WRITE) as subkey:
                                try:
                                    winreg.DeleteValue(subkey, "NetworkAddress")
                                    self.progress_update.emit(f"Removed spoofed MAC for adapter {i}")
                                except OSError:
                                    pass
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug(f"MAC address restoration failed: {e}")

        # Restore using backend
        if hasattr(self, "spoofer") and self.spoofer:
            self.spoofer.restore_original()

        self.spoof_complete.emit({"restored": True})
        self.status_update.emit("Original hardware identifiers restored", "green")

    def verify_spoofing(self) -> None:
        """Verify if spoofing is active."""
        self.progress_update.emit("Verifying spoofing status...")

        # Capture current hardware info
        current_info = {
            "cpu_id": self.get_cpu_id(),
            "motherboard_serial": self.get_motherboard_serial(),
            "hdd_serial": self.get_hdd_serial(),
            "mac_addresses": self.get_mac_addresses(),
            "volume_serials": self.get_volume_serials(),
            "product_id": self.get_windows_product_id(),
            "machine_guid": self.get_machine_guid(),
        }

        # Compare with expected spoofed values
        if "expected" in self.params:
            differences = []
            for key, expected_value in self.params["expected"].items():
                if key in current_info and current_info[key] != expected_value:
                    differences.append(f"{key}: Expected {expected_value}, Got {current_info[key]}")

            if differences:
                self.spoof_complete.emit({"verified": False, "differences": differences})
                self.status_update.emit("Spoofing verification failed - some values don't match", "orange")
            else:
                self.spoof_complete.emit({"verified": True})
                self.status_update.emit("Spoofing verified successfully - all values match", "green")
        else:
            self.spoof_complete.emit({"current": current_info})
            self.status_update.emit("Current hardware information retrieved", "blue")


class HardwareSpoofingDialog(QDialog):
    """Advanced Hardware Fingerprint Spoofing Dialog."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        """Initialize the HardwareSpoofingDialog with spoofer and UI components.

        Args:
            parent: Parent widget for this dialog. Defaults to None.

        """
        super().__init__(parent)
        self.spoofer = HardwareFingerPrintSpoofer()
        self.current_hardware: Dict[str, Any] = {}
        self.spoofed_hardware: Dict[str, Any] = {}
        self.worker_thread: Optional[HardwareSpoofingWorker] = None

        self.init_ui()
        self.load_saved_profiles()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("Hardware Fingerprint Spoofer - Defeat Hardware-Locked Licensing")
        self.setMinimumSize(900, 600)

        layout = QVBoxLayout(self)

        # Create tab widget
        self.tab_widget = QTabWidget()

        # Tab 1: Hardware Information
        self.info_tab = self.create_info_tab()
        self.tab_widget.addTab(self.info_tab, "Hardware Information")

        # Tab 2: Spoofing Configuration
        self.config_tab = self.create_config_tab()
        self.tab_widget.addTab(self.config_tab, "Spoofing Configuration")

        # Tab 3: Profiles
        self.profiles_tab = self.create_profiles_tab()
        self.tab_widget.addTab(self.profiles_tab, "Profiles")

        # Tab 4: Advanced Options
        self.advanced_tab = self.create_advanced_tab()
        self.tab_widget.addTab(self.advanced_tab, "Advanced")

        layout.addWidget(self.tab_widget)

        # Status bar
        self.create_status_bar(layout)

        # Control buttons
        self.create_control_buttons(layout)

    def create_info_tab(self) -> QWidget:
        """Create hardware information display tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Current hardware group
        current_group = QGroupBox("Current Hardware Identifiers")
        current_layout = QVBoxLayout()

        # Hardware info table
        self.hardware_table = QTableWidget()
        self.hardware_table.setColumnCount(3)
        self.hardware_table.setHorizontalHeaderLabels(["Identifier", "Current Value", "Spoofed Value"])
        self.hardware_table.horizontalHeader().setStretchLastSection(True)

        # Initialize with common identifiers
        identifiers = [
            "CPU ID",
            "Motherboard Serial",
            "Hard Drive Serial",
            "MAC Address 1",
            "MAC Address 2",
            "Volume Serial (C:)",
            "BIOS Serial",
            "BIOS Version",
            "Windows Product ID",
            "Machine GUID",
        ]

        self.hardware_table.setRowCount(len(identifiers))
        for i, identifier in enumerate(identifiers):
            self.hardware_table.setItem(i, 0, QTableWidgetItem(identifier))
            self.hardware_table.setItem(i, 1, QTableWidgetItem("Not captured"))
            self.hardware_table.setItem(i, 2, QTableWidgetItem("Not set"))

        current_layout.addWidget(self.hardware_table)

        # Capture button
        capture_layout = QHBoxLayout()
        self.capture_btn = QPushButton("Capture Current Hardware")
        self.capture_btn.clicked.connect(self.capture_hardware)
        capture_layout.addWidget(self.capture_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_hardware_info)
        capture_layout.addWidget(self.refresh_btn)

        capture_layout.addStretch()

        self.export_btn = QPushButton("Export Info")
        self.export_btn.clicked.connect(self.export_hardware_info)
        capture_layout.addWidget(self.export_btn)

        current_layout.addLayout(capture_layout)

        current_group.setLayout(current_layout)
        layout.addWidget(current_group)

        # Detection info
        detection_group = QGroupBox("Hardware-Based License Detection")
        detection_layout = QVBoxLayout()

        self.detection_text = QTextEdit()
        self.detection_text.setReadOnly(True)
        self.detection_text.setMaximumHeight(100)
        self.detection_text.setPlainText(
            "Many software licenses are tied to hardware identifiers. Common methods include:\n"
            "• Volume serial numbers (most common)\n"
            "• MAC addresses for network licensing\n"
            "• CPU ID for high-security applications\n"
            "• Combined hardware fingerprint hashing"
        )

        detection_layout.addWidget(self.detection_text)
        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)

        return tab

    def create_config_tab(self) -> QWidget:
        """Create spoofing configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Spoofing methods
        methods_group = QGroupBox("Spoofing Methods")
        methods_layout = QVBoxLayout()

        self.spoof_methods: Dict[str, QCheckBox] = {}
        methods = [
            (VOLUME_SERIALS_LABEL, "Spoof disk volume serial numbers", True),
            (MAC_ADDRESSES_LABEL, "Spoof network adapter MAC addresses", True),
            ("CPU ID", "Spoof processor ID (requires driver)", False),
            ("Motherboard", "Spoof motherboard serial number", False),
            ("Hard Drive", "Spoof hard drive serial", False),
            ("BIOS", "Spoof BIOS information", True),
            ("Windows Product ID", "Spoof Windows Product ID", True),
            ("Machine GUID", "Spoof Machine GUID", True),
            ("WMI Data", "Spoof WMI hardware queries", False),
        ]

        for method, description, enabled in methods:
            check = QCheckBox(f"{method} - {description}")
            check.setChecked(enabled)
            self.spoof_methods[method] = check
            methods_layout.addWidget(check)

        methods_group.setLayout(methods_layout)
        layout.addWidget(methods_group)

        # Generation options
        gen_group = QGroupBox("ID Generation Options")
        gen_layout = QVBoxLayout()

        # Generation mode
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Generation Mode:"))
        self.gen_mode_combo = QComboBox()
        self.gen_mode_combo.addItems(["Random Realistic", "Based on Template", "Incremental from Original", "Custom Pattern"])
        mode_layout.addWidget(self.gen_mode_combo)
        mode_layout.addStretch()
        gen_layout.addLayout(mode_layout)

        # Seed for reproducibility
        seed_layout = QHBoxLayout()
        seed_label = QLabel("Random Seed:")
        seed_label.setToolTip("Enter a seed value for reproducible hardware ID generation. Leave empty for random generation.")
        seed_layout.addWidget(seed_label)
        self.seed_input = QLineEdit()
        self.seed_input.setToolTip("Enter any string or number to use as a generation seed. Same seed produces same IDs.")
        self.seed_input.setMaxLength(32)
        seed_layout.addWidget(self.seed_input)
        gen_layout.addLayout(seed_layout)

        # Generate button
        gen_btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Spoofed IDs")
        self.generate_btn.clicked.connect(self.generate_spoofed_ids)
        gen_btn_layout.addWidget(self.generate_btn)

        self.customize_btn = QPushButton("Customize Values")
        self.customize_btn.clicked.connect(self.customize_values)
        gen_btn_layout.addWidget(self.customize_btn)
        gen_btn_layout.addStretch()

        gen_layout.addLayout(gen_btn_layout)

        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)

        # Preview
        preview_group = QGroupBox("Spoofed Values Preview")
        preview_layout = QVBoxLayout()

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setMaximumHeight(150)

        preview_layout.addWidget(self.preview_text)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        return tab

    def create_profiles_tab(self) -> QWidget:
        """Create profiles management tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Profiles list
        profiles_group = QGroupBox("Saved Profiles")
        profiles_layout = QVBoxLayout()

        # Profile table
        self.profiles_table = QTableWidget()
        self.profiles_table.setColumnCount(4)
        self.profiles_table.setHorizontalHeaderLabels(["Name", "Description", "Created", "Actions"])

        profiles_layout.addWidget(self.profiles_table)

        # Profile buttons
        profile_btn_layout = QHBoxLayout()

        self.save_profile_btn = QPushButton("Save Current as Profile")
        self.save_profile_btn.clicked.connect(self.save_profile)
        profile_btn_layout.addWidget(self.save_profile_btn)

        self.load_profile_btn = QPushButton("Load Selected")
        self.load_profile_btn.clicked.connect(self.load_profile)
        profile_btn_layout.addWidget(self.load_profile_btn)

        self.delete_profile_btn = QPushButton(DELETE_SELECTED_LABEL)
        self.delete_profile_btn.clicked.connect(self.delete_profile)
        profile_btn_layout.addWidget(self.delete_profile_btn)

        profile_btn_layout.addStretch()

        self.import_profile_btn = QPushButton("Import")
        self.import_profile_btn.clicked.connect(self.import_profile)
        profile_btn_layout.addWidget(self.import_profile_btn)

        self.export_profile_btn = QPushButton("Export")
        self.export_profile_btn.clicked.connect(self.export_profile)
        profile_btn_layout.addWidget(self.export_profile_btn)

        profiles_layout.addLayout(profile_btn_layout)

        profiles_group.setLayout(profiles_layout)
        layout.addWidget(profiles_group)

        # Quick profiles
        quick_group = QGroupBox("Quick Profiles")
        quick_layout = QVBoxLayout()

        quick_profiles = [
            ("Clean Slate", "Generate completely new hardware identity"),
            ("Minor Change", "Change only non-critical identifiers"),
            (VIRTUAL_MACHINE_LABEL, "Emulate VMware/VirtualBox hardware"),
            ("OEM System", "Emulate Dell/HP/Lenovo OEM system"),
            ("Gaming PC", "High-end gaming hardware profile"),
        ]

        for name, description in quick_profiles:
            btn = QPushButton(f"{name} - {description}")
            btn.clicked.connect(lambda checked, n=name: self.apply_quick_profile(n))
            quick_layout.addWidget(btn)

        quick_group.setLayout(quick_layout)
        layout.addWidget(quick_group)

        return tab

    def create_advanced_tab(self) -> QWidget:
        """Create advanced options tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Driver options
        driver_group = QGroupBox("Driver-Level Spoofing")
        driver_layout = QVBoxLayout()

        driver_info = QLabel(
            "Driver-level spoofing provides deeper system integration but requires:\n"
            "• Administrator privileges\n"
            "• Driver signature bypass (Test Mode)\n"
            "• System restart for some changes"
        )
        driver_layout.addWidget(driver_info)

        self.install_driver_btn = QPushButton("Install Spoofing Driver")
        self.install_driver_btn.clicked.connect(self.install_driver)
        driver_layout.addWidget(self.install_driver_btn)

        driver_group.setLayout(driver_layout)
        layout.addWidget(driver_group)

        # Hook options
        hook_group = QGroupBox("API Hook Configuration")
        hook_layout = QVBoxLayout()

        self.hook_methods: Dict[str, QCheckBox] = {}
        hooks = [
            ("WMI Queries", "Hook WMI hardware queries"),
            ("Registry Access", "Hook registry hardware key access"),
            ("DeviceIoControl", "Hook device control calls"),
            ("CPUID Instruction", "Hook CPUID instruction (ring 0)"),
            ("SMBIOS Data", "Hook SMBIOS/DMI data access"),
        ]

        for hook, description in hooks:
            check = QCheckBox(f"{hook} - {description}")
            self.hook_methods[hook] = check
            hook_layout.addWidget(check)

        hook_group.setLayout(hook_layout)
        layout.addWidget(hook_group)

        # Persistence options
        persist_group = QGroupBox("Persistence Options")
        persist_layout = QVBoxLayout()

        self.persist_reboot = QCheckBox("Persist spoofing after reboot")
        self.persist_service = QCheckBox("Install as system service")
        self.persist_startup = QCheckBox("Add to startup (user-level)")

        persist_layout.addWidget(self.persist_reboot)
        persist_layout.addWidget(self.persist_service)
        persist_layout.addWidget(self.persist_startup)

        persist_group.setLayout(persist_layout)
        layout.addWidget(persist_group)

        # Anti-detection
        detection_group = QGroupBox("Anti-Detection Features")
        detection_layout = QVBoxLayout()

        self.anti_detect_checks: Dict[str, QCheckBox] = {}
        detections = [
            ("Randomize Timing", "Add random delays to spoof operations"),
            ("Clean Event Logs", "Remove spoofing traces from event logs"),
            ("Hide from Task Manager", "Hide spoofing processes"),
            ("Bypass Integrity Checks", "Bypass hardware integrity validation"),
        ]

        for detection, description in detections:
            check = QCheckBox(f"{detection} - {description}")
            self.anti_detect_checks[detection] = check
            detection_layout.addWidget(check)

        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)

        layout.addStretch()

        return tab

    def create_status_bar(self, parent_layout: QVBoxLayout) -> None:
        """Create status bar."""
        status_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("QLabel { padding: 5px; }")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.spoof_status_label = QLabel("Spoofing: Inactive")
        self.spoof_status_label.setStyleSheet("QLabel { padding: 5px; color: gray; }")
        status_layout.addWidget(self.spoof_status_label)

        parent_layout.addLayout(status_layout)

    def create_control_buttons(self, parent_layout: QVBoxLayout) -> None:
        """Create main control buttons."""
        button_layout = QHBoxLayout()

        self.apply_btn = QPushButton("Apply Spoofing")
        self.apply_btn.clicked.connect(self.apply_spoofing)
        self.apply_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")

        self.restore_btn = QPushButton("Restore Original")
        self.restore_btn.clicked.connect(self.restore_original)

        self.verify_btn = QPushButton("Verify Spoofing")
        self.verify_btn.clicked.connect(self.verify_spoofing)

        button_layout.addWidget(self.apply_btn)
        button_layout.addWidget(self.restore_btn)
        button_layout.addWidget(self.verify_btn)
        button_layout.addStretch()

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)

        parent_layout.addLayout(button_layout)

    @pyqtSlot()
    def capture_hardware(self) -> None:
        """Capture current hardware information."""
        self.status_label.setText("Capturing hardware information...")

        # Create worker thread
        self.worker_thread = HardwareSpoofingWorker(self.spoofer, "capture", {})
        self.worker_thread.status_update.connect(self.on_status_update)
        self.worker_thread.progress_update.connect(self.on_progress_update)
        self.worker_thread.spoof_complete.connect(self.on_capture_complete)
        self.worker_thread.error_occurred.connect(self.on_error)

        self.worker_thread.start()

    @pyqtSlot(dict)
    def on_capture_complete(self, hardware_info: Dict[str, Any]) -> None:
        """Handle captured hardware information."""
        self.current_hardware = hardware_info

        # Update table
        row = 0
        if "cpu_id" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["cpu_id"])))
            row += 1

        if "motherboard_serial" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["motherboard_serial"])))
            row += 1

        if "hdd_serial" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["hdd_serial"])))
            row += 1

        if "mac_addresses" in hardware_info:
            for i, mac in enumerate(hardware_info["mac_addresses"][:2]):
                self.hardware_table.setItem(row + i, 1, QTableWidgetItem(str(mac)))
            row += 2

        if "volume_serials" in hardware_info:
            if "C:" in hardware_info["volume_serials"]:
                self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["volume_serials"]["C:"])))
            row += 1

        if "bios_info" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["bios_info"].get("serial", ""))))
            self.hardware_table.setItem(row + 1, 1, QTableWidgetItem(str(hardware_info["bios_info"].get("version", ""))))
            row += 2

        if "product_id" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["product_id"])))
            row += 1

        if "machine_guid" in hardware_info:
            self.hardware_table.setItem(row, 1, QTableWidgetItem(str(hardware_info["machine_guid"])))

    @pyqtSlot()
    def generate_spoofed_ids(self) -> None:
        """Generate spoofed hardware IDs."""
        self.status_label.setText("Generating spoofed identifiers...")

        # Get selected methods
        params: Dict[str, bool] = {}
        for method, check in self.spoof_methods.items():
            if check.isChecked():
                params[method] = True

        # Check for seed
        if self.seed_input.text():
            random.seed(self.seed_input.text())

        # Create worker thread
        self.worker_thread = HardwareSpoofingWorker(self.spoofer, "generate", params)
        self.worker_thread.status_update.connect(self.on_status_update)
        self.worker_thread.progress_update.connect(self.on_progress_update)
        self.worker_thread.spoof_complete.connect(self.on_generate_complete)
        self.worker_thread.error_occurred.connect(self.on_error)

        self.worker_thread.start()

    @pyqtSlot(dict)
    def on_generate_complete(self, spoofed_info: Dict[str, Any]) -> None:
        """Handle generated spoofed IDs."""
        self.spoofed_hardware = spoofed_info

        self._update_hardware_table(spoofed_info)

        # Update preview
        preview_text = "Generated Spoofed Values:\n\n"
        for key, value in spoofed_info.items():
            if isinstance(value, dict):
                preview_text += f"{key}:\n"
                for k, v in value.items():
                    preview_text += f"  {k}: {v}\n"
            elif isinstance(value, list):
                preview_text += f"{key}:\n"
                for v in value:
                    preview_text += f"  - {v}\n"
            else:
                preview_text += f"{key}: {value}\n"

        self.preview_text.setPlainText(preview_text)

    def _update_hardware_table(self, spoofed_info: Dict[str, Any]) -> None:
        """Update the hardware table with spoofed values."""
        # Simple key to row mapping
        simple_updates = [
            ("cpu_id", 0),
            ("motherboard_serial", 1),
            ("hdd_serial", 2),
            ("product_id", 8),
            ("machine_guid", 9),
        ]

        for key, row in simple_updates:
            if key in spoofed_info:
                item = QTableWidgetItem(str(spoofed_info[key]))
                item.setBackground(QColor(255, 255, 200))
                self.hardware_table.setItem(row, 2, item)

        # Special handling for MAC addresses
        if "mac_addresses" in spoofed_info:
            row = 3
            for i, mac in enumerate(spoofed_info["mac_addresses"][:2]):
                item = QTableWidgetItem(str(mac))
                item.setBackground(QColor(255, 255, 200))
                self.hardware_table.setItem(row + i, 2, item)

        # Special handling for volume serials
        if "volume_serials" in spoofed_info:
            row = 5
            if "C:" in spoofed_info["volume_serials"]:
                item = QTableWidgetItem(str(spoofed_info["volume_serials"]["C:"]))
                item.setBackground(QColor(255, 255, 200))
                self.hardware_table.setItem(row, 2, item)

        # Special handling for BIOS info
        if "bios_info" in spoofed_info:
            row = 6
            bios = spoofed_info["bios_info"]
            item_serial = QTableWidgetItem(str(bios.get("serial", "")))
            item_serial.setBackground(QColor(255, 255, 200))
            self.hardware_table.setItem(row, 2, item_serial)

            item_version = QTableWidgetItem(str(bios.get("version", "")))
            item_version.setBackground(QColor(255, 255, 200))
            self.hardware_table.setItem(row + 1, 2, item_version)

    @pyqtSlot()
    def apply_spoofing(self) -> None:
        """Apply hardware spoofing."""
        if not self.spoofed_hardware:
            QMessageBox.warning(self, "Warning", "No spoofed values generated. Generate IDs first.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm Spoofing",
            "Apply hardware spoofing? This will modify system settings.\n\nSome changes may require restart.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.status_label.setText("Applying hardware spoofing...")

            # Create worker thread
            self.worker_thread = HardwareSpoofingWorker(self.spoofer, "apply", self.spoofed_hardware)
            self.worker_thread.status_update.connect(self.on_status_update)
            self.worker_thread.progress_update.connect(self.on_progress_update)
            self.worker_thread.spoof_complete.connect(self.on_apply_complete)
            self.worker_thread.error_occurred.connect(self.on_error)

            self.worker_thread.start()

    @pyqtSlot(dict)
    def on_apply_complete(self, results: Dict[str, int]) -> None:
        """Handle spoofing application completion."""
        if results.get("success_count", 0) > 0:
            self.spoof_status_label.setText("Spoofing: Active")
            self.spoof_status_label.setStyleSheet("QLabel { padding: 5px; color: green; font-weight: bold; }")

            QMessageBox.information(
                self,
                "Spoofing Applied",
                f"Successfully applied {results['success_count']} spoofing methods.\n\n"
                f"Some changes may require system restart to take effect.",
            )
        else:
            QMessageBox.warning(self, "Spoofing Failed", "Failed to apply spoofing. Ensure you have administrator privileges.")

    @pyqtSlot()
    def restore_original(self) -> None:
        """Restore original hardware IDs."""
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            "Restore original hardware identifiers?\n\nThis will remove all spoofing.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.status_label.setText("Restoring original hardware...")

            # Create worker thread
            self.worker_thread = HardwareSpoofingWorker(self.spoofer, "restore", {})
            self.worker_thread.status_update.connect(self.on_status_update)
            self.worker_thread.progress_update.connect(self.on_progress_update)
            self.worker_thread.spoof_complete.connect(self.on_restore_complete)
            self.worker_thread.error_occurred.connect(self.on_error)

            self.worker_thread.start()

    @pyqtSlot(dict)
    def on_restore_complete(self, results: dict) -> None:
        """Handle restore completion."""
        if results.get("restored"):
            self.spoof_status_label.setText("Spoofing: Inactive")
            self.spoof_status_label.setStyleSheet("QLabel { padding: 5px; color: gray; }")

            # Clear spoofed values from table
            for row in range(self.hardware_table.rowCount()):
                item = QTableWidgetItem("Not set")
                item.setBackground(QColor(255, 255, 255))
                self.hardware_table.setItem(row, 2, item)

            QMessageBox.information(self, "Restored", "Original hardware identifiers restored.")

    @pyqtSlot()
    def verify_spoofing(self) -> None:
        """Verify if spoofing is active."""
        self.status_label.setText("Verifying spoofing status...")

        params: Dict[str, Any] = {}
        if self.spoofed_hardware:
            params["expected"] = self.spoofed_hardware

        # Create worker thread
        self.worker_thread = HardwareSpoofingWorker(self.spoofer, "verify", params)
        self.worker_thread.status_update.connect(self.on_status_update)
        self.worker_thread.progress_update.connect(self.on_progress_update)
        self.worker_thread.spoof_complete.connect(self.on_verify_complete)
        self.worker_thread.error_occurred.connect(self.on_error)

        self.worker_thread.start()

    @pyqtSlot(dict)
    def on_verify_complete(self, results: Dict[str, Any]) -> None:
        """Handle verification completion."""
        if "verified" in results:
            if results["verified"]:
                QMessageBox.information(self, "Verification", "Spoofing is active and verified.")
            else:
                differences = "\n".join(results.get("differences", []))
                QMessageBox.warning(self, "Verification Failed", f"Some spoofed values don't match:\n\n{differences}")
        else:
            # Just showing current values
            self.on_capture_complete(results.get("current", {}))

    @pyqtSlot()
    def refresh_hardware_info(self) -> None:
        """Refresh hardware information display."""
        self.capture_hardware()

    @pyqtSlot()
    def export_hardware_info(self) -> None:
        """Export hardware information to file."""
        if not self.current_hardware:
            QMessageBox.warning(self, "Warning", "No hardware information to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Hardware Info", f"hardware_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", JSON_FILES_FILTER
        )

        if file_path:
            with open(file_path, "w") as f:
                json.dump(self.current_hardware, f, indent=2)
            QMessageBox.information(self, "Exported", "Hardware information exported successfully.")

    @pyqtSlot()
    def import_profile(self) -> None:
        """Import profile from file."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Profile", "", JSON_FILES_FILTER)

        if file_path:
            with open(file_path, "r") as f:
                profile = json.load(f)

            self.save_profile_to_file(profile)
            self.load_saved_profiles()

            QMessageBox.information(self, "Imported", f"Profile '{profile.get('name', 'Unknown')}' imported.")

    @pyqtSlot()
    def save_profile(self) -> None:
        """Save current spoofing configuration as profile."""
        if not self.spoofed_hardware:
            QMessageBox.warning(self, "Warning", "No spoofed configuration to save.")
            return

        # Get profile name from user
        name, ok = QInputDialog.getText(self, "Save Profile", "Enter profile name:")

        if ok and name:
            profile = {
                "name": name,
                "created": datetime.now().isoformat(),
                "hardware": self.spoofed_hardware,
                "methods": {k: v.isChecked() for k, v in self.spoof_methods.items()},
            }

            # Save to profiles
            self.save_profile_to_file(profile)
            self.load_saved_profiles()

            QMessageBox.information(self, "Saved", f"Profile '{name}' saved successfully.")

    def save_profile_to_file(self, profile: Dict[str, Any]) -> None:
        """Save profile to file."""
        profiles_dir = os.path.join(os.path.expanduser("~"), INTELLICRACK_DIR, "hw_profiles")
        os.makedirs(profiles_dir, exist_ok=True)

        file_path = os.path.join(profiles_dir, f"{profile['name']}.json")
        with open(file_path, "w") as f:
            json.dump(profile, f, indent=2)

    @pyqtSlot()
    def load_profile(self) -> None:
        """Load selected profile."""
        current_row = self.profiles_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", NO_PROFILE_MSG)
            return

        profile_name = self.profiles_table.item(current_row, 0).text()

        # Load profile
        profiles_dir = os.path.join(os.path.expanduser("~"), INTELLICRACK_DIR, "hw_profiles")
        file_path = os.path.join(profiles_dir, f"{profile_name}.json")

        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                profile = json.load(f)

            # Apply profile
            self.spoofed_hardware = profile.get("hardware", {})

            # Update methods
            for method, checked in profile.get("methods", {}).items():
                if method in self.spoof_methods:
                    self.spoof_methods[method].setChecked(checked)

            # Update display
            self.on_generate_complete(self.spoofed_hardware)

            QMessageBox.information(self, "Loaded", f"Profile '{profile_name}' loaded.")

    @pyqtSlot()
    def delete_profile(self) -> None:
        """Delete selected profile."""
        current_row = self.profiles_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", NO_PROFILE_MSG)
            return

        profile_name = self.profiles_table.item(current_row, 0).text()

        reply = QMessageBox.question(
            self, "Confirm Delete", f"Delete profile '{profile_name}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            profiles_dir = os.path.join(os.path.expanduser("~"), INTELLICRACK_DIR, "hw_profiles")
            file_path = os.path.join(profiles_dir, f"{profile_name}.json")

            if os.path.exists(file_path):
                os.remove(file_path)
                self.load_saved_profiles()
                QMessageBox.information(self, "Deleted", f"Profile '{profile_name}' deleted.")

    @pyqtSlot()
    def export_profile(self) -> None:
        """Export selected profile."""
        current_row = self.profiles_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", NO_PROFILE_MSG)
            return

        profile_name = self.profiles_table.item(current_row, 0).text()

        # Load profile
        profiles_dir = os.path.join(os.path.expanduser("~"), INTELLICRACK_DIR, "hw_profiles")
        source_path = os.path.join(profiles_dir, f"{profile_name}.json")

        if os.path.exists(source_path):
            file_path, _ = QFileDialog.getSaveFileName(self, "Export Profile", f"{profile_name}.json", JSON_FILES_FILTER)

            if file_path:
                with open(source_path, "r") as f:
                    profile = json.load(f)

                with open(file_path, "w") as f:
                    json.dump(profile, f, indent=2)

                QMessageBox.information(self, "Exported", f"Profile '{profile_name}' exported.")

    @pyqtSlot(str)
    def apply_quick_profile(self, profile_name: str) -> None:
        """Apply a quick profile."""
        # Generate appropriate IDs based on profile
        if profile_name == "Clean Slate":
            # Generate completely new identity
            self.gen_mode_combo.setCurrentText("Random Realistic")
            for check in self.spoof_methods.values():
                check.setChecked(True)

        elif profile_name == "Minor Change":
            # Only change non-critical IDs
            for method, check in self.spoof_methods.items():
                check.setChecked(method in [VOLUME_SERIALS_LABEL, MAC_ADDRESSES_LABEL])

        elif profile_name == VIRTUAL_MACHINE_LABEL:
            # Generate VMware-like IDs
            self.spoofed_hardware = {
                "cpu_id": "BFEBFBFF000306A9",
                "motherboard_serial": "VMware-42 1A 2B 3C 4D 5E 6F 70",
                "mac_addresses": ["00:50:56:C0:00:08", "00:50:56:C0:00:01"],
                "bios_info": {"manufacturer": PHOENIX_MANUFACTURER, "version": "6.00", "serial": "VMware-42 1a 2b 3c"},
            }
            self.on_generate_complete(self.spoofed_hardware)
            return

        # Generate IDs
        self.generate_spoofed_ids()

    @pyqtSlot()
    def install_driver(self) -> None:
        """Install spoofing driver."""
        QMessageBox.information(
            self,
            "Driver Installation",
            "Driver installation requires:\n"
            "1. Administrator privileges\n"
            "2. Test signing mode enabled\n"
            "3. System restart\n\n"
            "Driver provides kernel-level spoofing for maximum effectiveness.",
        )

    def load_saved_profiles(self) -> None:
        """Load saved profiles into table."""
        self.profiles_table.setRowCount(0)

        profiles_dir = os.path.join(os.path.expanduser("~"), INTELLICRACK_DIR, "hw_profiles")
        if not os.path.exists(profiles_dir):
            return

        for file_name in os.listdir(profiles_dir):
            if file_name.endswith(".json"):
                file_path = os.path.join(profiles_dir, file_name)

                try:
                    with open(file_path, "r") as f:
                        profile = json.load(f)

                    row = self.profiles_table.rowCount()
                    self.profiles_table.insertRow(row)

                    self.profiles_table.setItem(row, 0, QTableWidgetItem(profile.get("name", "Unknown")))
                    self.profiles_table.setItem(row, 1, QTableWidgetItem(profile.get("description", "")))
                    self.profiles_table.setItem(row, 2, QTableWidgetItem(profile.get("created", "")))

                    # Add action buttons
                    action_widget = QWidget()
                    action_layout = QHBoxLayout(action_widget)
                    action_layout.setContentsMargins(0, 0, 0, 0)

                    load_btn = QPushButton("Load")
                    load_btn.clicked.connect(lambda: self.load_profile())
                    action_layout.addWidget(load_btn)

                    self.profiles_table.setCellWidget(row, 3, action_widget)

                except Exception as e:
                    print(f"Failed to load profile {file_name}: {e}")

    @pyqtSlot(str, str)
    def on_status_update(self, message: str, color: str) -> None:
        """Handle status updates."""
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"QLabel {{ padding: 5px; color: {color}; }}")

    @pyqtSlot(str)
    def on_progress_update(self, message: str) -> None:
        """Handle progress updates."""
        self.status_label.setText(message)

    @pyqtSlot(str)
    def on_error(self, error_msg: str) -> None:
        """Handle errors."""
        QMessageBox.critical(self, "Error", error_msg)
        self.status_label.setText(f"Error: {error_msg}")
        self.status_label.setStyleSheet("QLabel { padding: 5px; color: red; }")

    def customize_values(self) -> None:
        """Open dialog to customize spoofed values."""
        current = (
            self.spoofed_hardware
            if self.spoofed_hardware
            else {
                "cpu_id": DEFAULT_CPU_ID,
                "motherboard_serial": "MB-" + os.urandom(8).hex().upper(),
                "hdd_serial": "WD-WCC" + os.urandom(5).hex().upper(),
                "mac_addresses": [DEFAULT_MAC],
                "volume_serials": {"C:": DEFAULT_VOLUME_SERIAL},
                "bios_info": {"manufacturer": AMI_MANUFACTURER, "version": "2.0.0", "serial": "BIOS-" + os.urandom(6).hex().upper()},
                "product_id": DEFAULT_PRODUCT_ID,
                "machine_guid": str(uuid.uuid4()),
            }
        )

        dialog = CustomizeHardwareDialog(self, current)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.spoofed_hardware = dialog.get_spoofed_hardware()
            self.on_generate_complete(self.spoofed_hardware)


class CustomizeHardwareDialog(QDialog):
    """Dedicated dialog for customizing hardware spoofing values."""

    def __init__(self, parent: Optional[QWidget] = None, current_hardware: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the CustomizeHardwareDialog with hardware configuration options.

        Args:
            parent: Parent widget for this dialog. Defaults to None.
            current_hardware: Current hardware information to use as baseline. Defaults to None.

        """
        super().__init__(parent)
        self.current_hardware = current_hardware or self._get_default_hardware()
        self.spoofed_hardware: Dict[str, Any] = {}
        self.basic_widgets: Optional[Dict[str, QLineEdit]] = None
        self.bios_widgets: Optional[Dict[str, QLineEdit]] = None
        self.mac_list: Optional[QListWidget] = None
        self.vol_table: Optional[QTableWidget] = None
        self.template_combo: Optional[QComboBox] = None
        self.generate_btn: Optional[QPushButton] = None
        self.init_ui()

    def _get_default_hardware(self) -> Dict[str, Any]:
        """Get default hardware configuration."""
        return {
            "cpu_id": DEFAULT_CPU_ID,
            "motherboard_serial": f"MB-{os.urandom(8).hex().upper()}",
            "hdd_serial": f"WD-WCC{os.urandom(5).hex().upper()}",
            "mac_addresses": [DEFAULT_MAC],
            "volume_serials": {"C:": DEFAULT_VOLUME_SERIAL},
            "bios_info": {"manufacturer": AMI_MANUFACTURER, "version": "2.0.0", "serial": f"BIOS-{os.urandom(6).hex().upper()}"},
            "product_id": DEFAULT_PRODUCT_ID,
            "machine_guid": str(uuid.uuid4()),
        }

    def init_ui(self) -> None:
        """Initialize the customize dialog UI."""
        self.setWindowTitle("Customize Hardware Values")
        self.setModal(True)
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QFormLayout(scroll_widget)

        # Create sections
        self.basic_widgets = self._create_basic_fields(scroll_layout, self.current_hardware)
        self.bios_widgets = self._create_bios_section(scroll_layout, self.current_hardware)
        self.mac_list = self._create_mac_section(scroll_layout, self.current_hardware)
        self.vol_table = self._create_volume_section(scroll_layout, self.current_hardware)

        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        # Preset templates
        template_layout = QHBoxLayout()
        template_label = QLabel("Load Template:")
        self.template_combo = QComboBox()
        self.template_combo.addItems(
            ["Custom", "Generic PC", "Dell OptiPlex", "HP ProBook", "Lenovo ThinkPad", "ASUS ROG", "MSI Gaming", "Virtual Machine"]
        )
        self.template_combo.currentIndexChanged.connect(self._on_template_changed)

        template_layout.addWidget(template_label)
        template_layout.addWidget(self.template_combo)
        template_layout.addStretch()
        layout.addLayout(template_layout)

        # Buttons
        button_layout = QHBoxLayout()

        self.generate_btn = QPushButton("Auto-Generate All")
        self.generate_btn.setToolTip("Generate random values for all fields")
        self.generate_btn.clicked.connect(self.auto_generate)

        save_btn = QPushButton("Apply Values")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self.save)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(self.generate_btn)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

    def _create_basic_fields(self, scroll_layout: QFormLayout, current: Dict[str, Any]) -> Dict[str, QLineEdit]:
        """Create basic hardware field edits and return dict of widgets."""
        widgets: Dict[str, QLineEdit] = {}

        # CPU ID field
        widgets["cpu_edit"] = QLineEdit(current.get("cpu_id", DEFAULT_CPU_ID))
        widgets["cpu_edit"].setToolTip("CPU ProcessorId value. Format: BFEBFBFF000906EA")
        scroll_layout.addRow("CPU ID:", widgets["cpu_edit"])

        # Motherboard Serial field
        widgets["mb_edit"] = QLineEdit(current.get("motherboard_serial", f"MB-{os.urandom(8).hex().upper()}"))
        widgets["mb_edit"].setToolTip("Motherboard serial number. Example: MB-A1B2C3D4E5F6")
        scroll_layout.addRow("Motherboard Serial:", widgets["mb_edit"])

        # Hard Drive Serial field
        widgets["hdd_edit"] = QLineEdit(current.get("hdd_serial", f"WD-WCC{os.urandom(5).hex().upper()}"))
        widgets["hdd_edit"].setToolTip("Primary hard drive serial number. Example: WD-WCC1234567890")
        scroll_layout.addRow("HDD Serial:", widgets["hdd_edit"])

        # Windows Product ID field
        widgets["product_edit"] = QLineEdit(current.get("product_id", DEFAULT_PRODUCT_ID))
        widgets["product_edit"].setToolTip("Windows Product ID. Example: 12345-67890-12345-AAAAA")
        scroll_layout.addRow("Windows Product ID:", widgets["product_edit"])

        # Machine GUID field
        widgets["guid_edit"] = QLineEdit(current.get("machine_guid", str(uuid.uuid4())))
        widgets["guid_edit"].setToolTip("Windows Machine GUID. Example: 12345678-1234-5678-9012-123456789012")
        scroll_layout.addRow("Machine GUID:", widgets["guid_edit"])

        return widgets

    def _create_bios_section(self, scroll_layout: QFormLayout, current: Dict[str, Any]) -> Dict[str, QLineEdit]:
        """Create BIOS information fields and return dict of widgets."""
        widgets: Dict[str, QLineEdit] = {}

        bios_group = QGroupBox("BIOS Information")
        bios_layout = QFormLayout()
        bios_info = current.get("bios_info", {})

        widgets["bios_mfr_edit"] = QLineEdit(bios_info.get("manufacturer", AMI_MANUFACTURER))
        widgets["bios_mfr_edit"].setToolTip("BIOS manufacturer name")
        bios_layout.addRow("Manufacturer:", widgets["bios_mfr_edit"])

        widgets["bios_ver_edit"] = QLineEdit(bios_info.get("version", "2.0.0"))
        widgets["bios_ver_edit"].setToolTip("BIOS version number")
        bios_layout.addRow("Version:", widgets["bios_ver_edit"])

        widgets["bios_serial_edit"] = QLineEdit(bios_info.get("serial", f"BIOS-{os.urandom(6).hex().upper()}"))
        widgets["bios_serial_edit"].setToolTip("BIOS serial number")
        bios_layout.addRow("Serial:", widgets["bios_serial_edit"])

        bios_group.setLayout(bios_layout)
        scroll_layout.addRow(bios_group)

        return widgets

    def _create_mac_section(self, scroll_layout: QFormLayout, current: Dict[str, Any]) -> QListWidget:
        """Create MAC addresses section."""
        mac_group = QGroupBox("MAC Addresses")
        mac_layout = QVBoxLayout()
        mac_list = QListWidget()
        mac_list.setMaximumHeight(100)

        for mac in current.get("mac_addresses", []):
            mac_list.addItem(mac)

        mac_button_layout = QHBoxLayout()
        add_mac_btn = QPushButton("Add MAC")
        edit_mac_btn = QPushButton("Edit Selected")
        del_mac_btn = QPushButton("Delete Selected")
        mac_button_layout.addWidget(add_mac_btn)
        mac_button_layout.addWidget(edit_mac_btn)
        mac_button_layout.addWidget(del_mac_btn)

        mac_layout.addWidget(mac_list)
        mac_layout.addLayout(mac_button_layout)
        mac_group.setLayout(mac_layout)
        scroll_layout.addRow(mac_group)

        # Connect buttons
        add_mac_btn.clicked.connect(self.add_mac_address)
        edit_mac_btn.clicked.connect(self.edit_mac_address)
        del_mac_btn.clicked.connect(self.delete_mac_address)

        self.mac_list = mac_list
        return mac_list

    def _create_volume_section(self, scroll_layout: QFormLayout, current: Dict[str, Any]) -> QTableWidget:
        """Create volume serials section."""
        vol_group = QGroupBox("Volume Serials")
        vol_layout = QVBoxLayout()
        vol_table = QTableWidget()
        vol_table.setColumnCount(2)
        vol_table.setHorizontalHeaderLabels(["Drive", "Serial"])
        vol_table.setMaximumHeight(150)
        vol_table.horizontalHeader().setStretchLastSection(True)

        vol_serials = current.get("volume_serials", {})
        vol_table.setRowCount(len(vol_serials))
        for i, (drive, serial) in enumerate(vol_serials.items()):
            vol_table.setItem(i, 0, QTableWidgetItem(drive))
            vol_table.setItem(i, 1, QTableWidgetItem(serial))

        vol_button_layout = QHBoxLayout()
        add_vol_btn = QPushButton(ADD_VOLUME_LABEL)
        del_vol_btn = QPushButton("Delete Selected")
        vol_button_layout.addWidget(add_vol_btn)
        vol_button_layout.addWidget(del_vol_btn)

        vol_layout.addWidget(vol_table)
        vol_layout.addLayout(vol_button_layout)
        vol_group.setLayout(vol_layout)
        scroll_layout.addRow(vol_group)

        # Connect buttons
        add_vol_btn.clicked.connect(self.add_volume_serial)
        del_vol_btn.clicked.connect(self.delete_volume_serial)

        self.vol_table = vol_table
        return vol_table

    def add_mac_address(self) -> None:
        """Add new MAC address."""
        mac, ok = QInputDialog.getText(self, "Add MAC Address", "Enter MAC address (Example: 00-11-22-33-44-55):")
        if ok and mac:
            # Validate MAC format
            if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
                self.mac_list.addItem(mac.upper().replace(":", "-"))
            else:
                QMessageBox.warning(self, "Invalid Format", "MAC address must be in format 00-11-22-33-44-55")

    def edit_mac_address(self) -> None:
        """Edit selected MAC address."""
        item = self.mac_list.currentItem()
        if item:
            new_mac, ok = QInputDialog.getText(self, "Edit MAC Address", "Enter new MAC address:", text=item.text())
            if ok and new_mac:
                if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", new_mac):
                    item.setText(new_mac.upper().replace(":", "-"))
                else:
                    QMessageBox.warning(self, "Invalid Format", "MAC address must be in format 00-11-22-33-44-55")

    def delete_mac_address(self) -> None:
        """Delete selected MAC address."""
        row = self.mac_list.currentRow()
        if row >= 0:
            self.mac_list.takeItem(row)

    def add_volume_serial(self) -> None:
        """Add new volume serial."""
        drive, ok1 = QInputDialog.getText(self, ADD_VOLUME_LABEL, "Enter drive letter (e.g., D:):")
        if ok1 and drive:
            serial, ok2 = QInputDialog.getText(self, ADD_VOLUME_LABEL, "Enter serial (e.g., 1234-5678):")
            if ok2 and serial:
                row = self.vol_table.rowCount()
                self.vol_table.insertRow(row)
                self.vol_table.setItem(row, 0, QTableWidgetItem(drive.upper()))
                self.vol_table.setItem(row, 1, QTableWidgetItem(serial.upper()))

    def delete_volume_serial(self) -> None:
        """Delete selected volume serial."""
        row = self.vol_table.currentRow()
        if row >= 0:
            self.vol_table.removeRow(row)

    def auto_generate(self) -> None:
        """Auto-generate random values for all fields."""
        # Basic fields
        self.basic_widgets["cpu_edit"].setText(f"BFEBFBFF{os.urandom(4).hex().upper()}")
        self.basic_widgets["mb_edit"].setText(f"MB-{os.urandom(8).hex().upper()}")
        self.basic_widgets["hdd_edit"].setText(f"WD-{os.urandom(10).hex().upper()}")
        import secrets
        self.basic_widgets["product_edit"].setText(
            f"{secrets.randbelow(99999 - 10000) + 10000:05d}-{secrets.randbelow(99999 - 10000) + 10000:05d}-{secrets.randbelow(99999 - 10000) + 10000:05d}-AAAAA"
        )
        self.basic_widgets["guid_edit"].setText(str(uuid.uuid4()))

        # BIOS
        self.bios_widgets["bios_serial_edit"].setText(f"BIOS-{os.urandom(6).hex().upper()}")

        # Generate random MAC if list is empty
        if self.mac_list.count() == 0:
            rand_mac_parts = [f"{random.randint(0, 255):02X}" for _ in range(6)]  # noqa: S311
            rand_mac_parts[1] = f"{int(rand_mac_parts[1], 16) | 0x02:02X}"  # Set locally administered bit
            rand_mac = "-".join(rand_mac_parts)
            self.mac_list.addItem(rand_mac)

    def _on_template_changed(self, index: int) -> None:
        """Handle template selection change."""
        self._load_template(index)

    def _load_template(self, index: int) -> None:
        """Load template values for hardware fields."""
        if index == 0:  # Custom
            return
        templates = {
            1: {  # Generic PC
                "cpu_id": DEFAULT_CPU_ID,
                "motherboard_serial": f"MB-GEN{os.urandom(6).hex().upper()}",
                "hdd_serial": f"ST1000DM003-{os.urandom(4).hex().upper()}",
            },
            2: {  # Dell OptiPlex
                "cpu_id": "BFEBFBFF000806EC",
                "motherboard_serial": f"DELL-{os.urandom(8).hex().upper()}",
                "hdd_serial": "TOSHIBA-MQ01ABF050",
            },
            3: {  # HP ProBook
                "cpu_id": "BFEBFBFF000806E9",
                "motherboard_serial": f"HP-{os.urandom(10).hex().upper()}",
                "hdd_serial": "HGST-HTS721010A9E630",
            },
            4: {  # Lenovo ThinkPad
                "cpu_id": "BFEBFBFF000806EA",
                "motherboard_serial": f"LENOVO-{os.urandom(8).hex().upper()}",
                "hdd_serial": "SAMSUNG-MZVLB512HAJQ",
            },
            5: {  # ASUS ROG
                "cpu_id": "BFEBFBFF000A0671",
                "motherboard_serial": f"ASUS-ROG-{os.urandom(6).hex().upper()}",
                "hdd_serial": "WD-BLACK-SN850",
            },
            6: {  # MSI Gaming
                "cpu_id": "BFEBFBFF000A0672",
                "motherboard_serial": f"MSI-GAMING-{os.urandom(5).hex().upper()}",
                "hdd_serial": "CORSAIR-MP600",
            },
            7: {  # Virtual Machine
                "cpu_id": "BFEBFBFF000306F2",
                "motherboard_serial": f"VMware-42{os.urandom(8).hex().upper()}",
                "hdd_serial": "VMware-Virtual-Disk",
                "bios_manufacturer": PHOENIX_MANUFACTURER,
                "bios_version": "6.00",
                "bios_serial": f"VMware-{os.urandom(6).hex().upper()}",
            },
        }
        if index in templates:
            template = templates[index]
            if "cpu_id" in template:
                self.basic_widgets["cpu_edit"].setText(template["cpu_id"])
            if "motherboard_serial" in template:
                self.basic_widgets["mb_edit"].setText(template["motherboard_serial"])
            if "hdd_serial" in template:
                self.basic_widgets["hdd_edit"].setText(template["hdd_serial"])
            if "bios_manufacturer" in template:
                self.bios_widgets["bios_mfr_edit"].setText(template["bios_manufacturer"])
            if "bios_version" in template:
                self.bios_widgets["bios_ver_edit"].setText(template["bios_version"])
            if "bios_serial" in template:
                self.bios_widgets["bios_serial_edit"].setText(template["bios_serial"])

    def save(self) -> None:
        """Save the customized values."""
        # Collect all MAC addresses
        mac_addrs = [self.mac_list.item(i).text() for i in range(self.mac_list.count())]

        # Collect all volume serials
        vol_sers = {}
        for i in range(self.vol_table.rowCount()):
            drive_item = self.vol_table.item(i, 0)
            serial_item = self.vol_table.item(i, 1)
            if drive_item and serial_item:
                vol_sers[drive_item.text()] = serial_item.text()

        # Build spoofed hardware dict
        self.spoofed_hardware = {
            "cpu_id": self.basic_widgets["cpu_edit"].text() or DEFAULT_CPU_ID,
            "motherboard_serial": self.basic_widgets["mb_edit"].text() or "MB-DEFAULT",
            "hdd_serial": self.basic_widgets["hdd_edit"].text() or DEFAULT_HDD_SERIAL,
            "mac_addresses": mac_addrs if mac_addrs else [DEFAULT_MAC],
            "volume_serials": vol_sers if vol_sers else {"C:": DEFAULT_VOLUME_SERIAL},
            "bios_info": {
                "manufacturer": self.bios_widgets["bios_mfr_edit"].text() or AMI_MANUFACTURER,
                "version": self.bios_widgets["bios_ver_edit"].text() or "2.0.0",
                "serial": self.bios_widgets["bios_serial_edit"].text() or "BIOS-DEFAULT",
            },
            "product_id": self.basic_widgets["product_edit"].text() or DEFAULT_PRODUCT_ID,
            "machine_guid": self.basic_widgets["guid_edit"].text() or str(uuid.uuid4()),
        }

        self.accept()

    def get_spoofed_hardware(self) -> Dict[str, Any]:
        """Get the customized spoofed hardware values."""
        return self.spoofed_hardware
