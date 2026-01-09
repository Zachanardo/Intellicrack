"""Hardware Fingerprint Generator for License Binding.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import platform
import secrets
import shutil
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class HardwareFingerprint:
    """Hardware fingerprint for license binding.

    Stores hardware identifiers used to bind licenses to specific machines.
    Each field represents a different hardware component identifier.

    Attributes:
        cpu_id: Processor identifier string.
        motherboard_id: Motherboard serial or identifier.
        disk_serial: Primary disk serial number.
        mac_address: Network interface MAC address.
        gpu_id: Graphics processor identifier.
        ram_size: Total RAM in gigabytes.
        os_version: Operating system version string.
        hostname: Machine hostname.
    """

    cpu_id: str = field(default="")
    motherboard_id: str = field(default="")
    disk_serial: str = field(default="")
    mac_address: str = field(default="")
    gpu_id: str = field(default="")
    ram_size: int = field(default=0)
    os_version: str = field(default="")
    hostname: str = field(default="")

    def generate_hash(self) -> str:
        """Generate unique SHA256 hash from hardware fingerprint components.

        Creates a 16-character hash by combining CPU ID, motherboard ID, disk serial,
        and MAC address components, then truncating the SHA256 digest.

        Returns:
            16-character hexadecimal SHA256 hash string derived from hardware identifiers.
        """
        data = f"{self.cpu_id}{self.motherboard_id}{self.disk_serial}{self.mac_address}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


class HardwareFingerprintGenerator:
    """Generate hardware fingerprints for license binding.

    Provides cross-platform methods to collect hardware identifiers
    used for binding software licenses to specific machines.
    """

    def __init__(self) -> None:
        """Initialize hardware fingerprint generator for license binding."""
        self.logger = logging.getLogger(f"{__name__}.Fingerprint")

    def _safe_subprocess_run(
        self, cmd_parts: list[str], timeout: int = 10
    ) -> subprocess.CompletedProcess[str] | None:
        """Safely execute subprocess commands with full path validation.

        Args:
            cmd_parts: List of command parts [executable, *args].
            timeout: Command timeout in seconds.

        Returns:
            CompletedProcess object or None if command unavailable.
        """
        if not cmd_parts:
            return None
        executable = cmd_parts[0]
        full_path = shutil.which(executable)
        if not full_path:
            self.logger.debug("Command not found: %s", executable)
            return None
        safe_cmd = [full_path, *cmd_parts[1:]]
        try:
            return subprocess.run(
                safe_cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            self.logger.debug("Command execution failed: %s", e, exc_info=True)
            return None

    def _get_cpu_id_windows(self) -> str:
        """Get CPU ID on Windows.

        Returns:
            CPU ID string.
        """
        result = self._safe_subprocess_run(
            ["wmic", "cpu", "get", "ProcessorId", "/format:value"]
        )
        if result and result.stdout:
            for line in result.stdout.split("\n"):
                if line.startswith("ProcessorId="):
                    if cpu_id := line.split("=")[1].strip():
                        return cpu_id
        return hashlib.sha256(platform.processor().encode()).hexdigest()[:16]

    def _get_cpu_id_linux(self) -> str:
        """Get CPU ID on Linux.

        Returns:
            CPU ID string.
        """
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if "Serial" in line:
                        return line.split(":")[1].strip()
                    if "model name" in line:
                        model = line.split(":")[1].strip()
                        return hashlib.sha256(model.encode()).hexdigest()[:16]
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        return hashlib.sha256(
            f"{platform.processor()}{platform.machine()}{platform.node()}".encode()
        ).hexdigest()[:16]

    def _get_cpu_id_darwin(self) -> str:
        """Get CPU ID on macOS.

        Returns:
            CPU ID string.
        """
        result = self._safe_subprocess_run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if result and result.stdout:
            return hashlib.sha256(result.stdout.strip().encode()).hexdigest()[:16]
        return hashlib.sha256(
            f"{platform.processor()}{platform.machine()}".encode()
        ).hexdigest()[:16]

    def _get_cpu_id_default(self) -> str:
        """Get CPU ID for other systems.

        Returns:
            CPU ID string.
        """
        return hashlib.sha256(
            f"{platform.processor()}{platform.machine()}{platform.node()}".encode()
        ).hexdigest()[:16]

    def _get_motherboard_id_windows(self) -> str:
        """Get motherboard ID on Windows.

        Returns:
            Motherboard ID string.
        """
        result = self._safe_subprocess_run(
            ["wmic", "baseboard", "get", "SerialNumber", "/format:value"]
        )
        if result and result.stdout:
            for line in result.stdout.split("\n"):
                if line.startswith("SerialNumber="):
                    if board_id := line.split("=")[1].strip():
                        return board_id
        result = self._safe_subprocess_run(
            ["wmic", "baseboard", "get", "Product,Manufacturer", "/format:value"]
        )
        if result and result.stdout:
            return hashlib.sha256(result.stdout.strip().encode()).hexdigest()[:16]
        return hashlib.sha256(
            f"{platform.node()}{platform.platform()}".encode()
        ).hexdigest()[:16]

    def _get_motherboard_id_linux(self) -> str:
        """Get motherboard ID on Linux.

        Returns:
            Motherboard ID string.
        """
        try:
            with open("/sys/class/dmi/id/board_serial", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        board_info = ""
        try:
            with open("/sys/class/dmi/id/board_vendor", encoding="utf-8") as f:
                board_info += f.read().strip()
            with open("/sys/class/dmi/id/board_name", encoding="utf-8") as f:
                board_info += f.read().strip()
            if board_info:
                return hashlib.sha256(board_info.encode()).hexdigest()[:16]
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        return hashlib.sha256(
            f"{platform.node()}{platform.platform()}".encode()
        ).hexdigest()[:16]

    def _get_motherboard_id_darwin(self) -> str:
        """Get motherboard ID on macOS.

        Returns:
            Motherboard ID string.
        """
        result = self._safe_subprocess_run(["system_profiler", "SPHardwareDataType"])
        if result and result.stdout:
            for line in result.stdout.split("\n"):
                if "Serial Number" in line:
                    if serial := line.split(":")[1].strip():
                        return serial
            return hashlib.sha256(result.stdout.encode()).hexdigest()[:16]
        return hashlib.sha256(
            f"{platform.node()}{platform.version()}".encode()
        ).hexdigest()[:16]

    def _get_motherboard_id_default(self) -> str:
        """Get motherboard ID for other systems.

        Returns:
            Motherboard ID string.
        """
        return hashlib.sha256(
            f"{platform.node()}{platform.platform()}".encode()
        ).hexdigest()[:16]

    def _get_disk_serial_windows(self) -> str:
        """Get disk serial number on Windows system.

        Returns:
            Disk serial number string or hash if unavailable.
        """
        result = self._safe_subprocess_run(
            [
                "wmic",
                "logicaldisk",
                "where",
                "drivetype=3",
                "get",
                "VolumeSerialNumber",
                "/format:value",
            ]
        )
        if result and result.stdout:
            for line in result.stdout.split("\n"):
                if line.startswith("VolumeSerialNumber="):
                    if serial := line.split("=")[1].strip():
                        return serial
        return hashlib.sha256(
            f"{platform.node()}{platform.system()}disk".encode()
        ).hexdigest()[:16]

    def _get_disk_serial_linux(self) -> str:
        """Get disk serial number on Linux system.

        Returns:
            Disk serial number string or hash if unavailable.
        """
        result = self._safe_subprocess_run(["lsblk", "-no", "SERIAL", "/dev/sda"])
        if result and result.stdout:
            if serial := result.stdout.strip():
                return serial
        result = self._safe_subprocess_run(["ls", "-l", "/dev/disk/by-id/"])
        if result and result.stdout:
            for line in result.stdout.split("\n"):
                if "ata-" in line and "part" not in line:
                    parts = line.split("ata-")[1].split()[0]
                    return hashlib.sha256(parts.encode()).hexdigest()[:16]
        try:
            if hasattr(os, "statvfs"):
                stat_info = os.statvfs("/")
                return hashlib.sha256(
                    f"{stat_info.f_blocks}{stat_info.f_bsize}".encode()
                ).hexdigest()[:16]
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        return hashlib.sha256(
            f"{platform.node()}{platform.system()}disk".encode()
        ).hexdigest()[:16]

    def _get_disk_serial_darwin(self) -> str:
        """Get disk serial number on macOS system.

        Returns:
            Disk serial number string or hash if unavailable.
        """
        try:
            if diskutil_path := shutil.which("diskutil"):
                result = subprocess.run(
                    [diskutil_path, "info", "disk0"],
                    check=False,
                    capture_output=True,
                    text=True,
                    shell=False,
                )
                for line in result.stdout.split("\n"):
                    if "Volume UUID" in line or "Disk / Partition UUID" in line:
                        if serial := line.split(":")[1].strip():
                            return serial
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        try:
            if hasattr(os, "statvfs"):
                stat_info = os.statvfs("/")
                return hashlib.sha256(
                    f"{stat_info.f_blocks}{stat_info.f_bsize}".encode()
                ).hexdigest()[:16]
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        return hashlib.sha256(
            f"{platform.node()}{platform.system()}disk".encode()
        ).hexdigest()[:16]

    def _get_disk_serial_default(self) -> str:
        """Get disk serial number for other systems.

        Returns:
            Disk serial number string or hash if unavailable.
        """
        try:
            if hasattr(os, "statvfs"):
                stat_info = os.statvfs("/")
                return hashlib.sha256(
                    f"{stat_info.f_blocks}{stat_info.f_bsize}".encode()
                ).hexdigest()[:16]
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        return hashlib.sha256(
            f"{platform.node()}{platform.system()}disk".encode()
        ).hexdigest()[:16]

    def _get_mac_address(self) -> str:
        """Get MAC address cross-platform.

        Returns:
            MAC address string in standard format.
        """
        try:
            mac_num = uuid.getnode()
            if not (mac_num >> 40) % 2:
                return ":".join(
                    [f"{mac_num >> ele & 255:02X}" for ele in range(0, 8 * 6, 8)][::-1]
                )
            try:
                import netifaces

                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    if iface == "lo" or iface.startswith("vir"):
                        continue
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_LINK in addrs:
                        mac_addr: str = str(addrs[netifaces.AF_LINK][0]["addr"])
                        if mac_addr and mac_addr != "00:00:00:00:00:00":
                            return mac_addr.upper()
            except ImportError:
                self.logger.debug("Exception caught in fallback path", exc_info=False)
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        mac_bytes = [secrets.randbelow(256) for _ in range(6)]
        mac_bytes[0] = mac_bytes[0] & 252 | 2
        return ":".join(f"{b:02X}" for b in mac_bytes)

    def _get_ram_size(self) -> int:
        """Get total RAM size in GB cross-platform.

        Returns:
            Total RAM size in gigabytes.
        """
        try:
            from intellicrack.handlers.psutil_handler import psutil

            return int(psutil.virtual_memory().total / 1024**3)
        except Exception:
            self.logger.debug("Exception caught in fallback path", exc_info=False)
        if platform.system() == "Windows":
            result = self._safe_subprocess_run(
                ["wmic", "computersystem", "get", "TotalPhysicalMemory", "/format:value"]
            )
            if result and result.stdout:
                for line in result.stdout.split("\n"):
                    if line.startswith("TotalPhysicalMemory="):
                        with contextlib.suppress(ValueError, IndexError):
                            mem_bytes = int(line.split("=")[1].strip())
                            return int(mem_bytes / 1024**3)
        elif platform.system() == "Linux":
            with (
                contextlib.suppress(OSError, ValueError, IndexError),
                open("/proc/meminfo", encoding="utf-8") as f,
            ):
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_kb = int(line.split()[1])
                        return int(mem_kb / 1024**2)
        elif platform.system() == "Darwin":
            result = self._safe_subprocess_run(["sysctl", "-n", "hw.memsize"])
            if result and result.stdout:
                with contextlib.suppress(ValueError):
                    mem_bytes = int(result.stdout.strip())
                    return int(mem_bytes / 1024**3)
        return 8

    def generate_fingerprint(self) -> HardwareFingerprint:
        """Generate hardware fingerprint from system with reduced complexity.

        Returns:
            HardwareFingerprint object containing system identifiers.
        """
        try:
            fingerprint = HardwareFingerprint()
            cpu_handlers: dict[str, Callable[[], str]] = {
                "Windows": self._get_cpu_id_windows,
                "Linux": self._get_cpu_id_linux,
                "Darwin": self._get_cpu_id_darwin,
            }
            motherboard_handlers: dict[str, Callable[[], str]] = {
                "Windows": self._get_motherboard_id_windows,
                "Linux": self._get_motherboard_id_linux,
                "Darwin": self._get_motherboard_id_darwin,
            }
            disk_handlers: dict[str, Callable[[], str]] = {
                "Windows": self._get_disk_serial_windows,
                "Linux": self._get_disk_serial_linux,
                "Darwin": self._get_disk_serial_darwin,
            }
            system = platform.system()
            handler = cpu_handlers.get(system, self._get_cpu_id_default)
            fingerprint.cpu_id = handler()
            handler = motherboard_handlers.get(system, self._get_motherboard_id_default)
            fingerprint.motherboard_id = handler()
            handler = disk_handlers.get(system, self._get_disk_serial_default)
            fingerprint.disk_serial = handler()
            fingerprint.mac_address = self._get_mac_address()
            fingerprint.ram_size = self._get_ram_size()
            try:
                fingerprint.os_version = platform.platform()
            except Exception:
                fingerprint.os_version = f"{platform.system()} {platform.release()}"
            try:
                fingerprint.hostname = socket.gethostname()
            except Exception:
                fingerprint.hostname = platform.node()
            return fingerprint
        except Exception:
            self.logger.exception("Fingerprint generation failed")
            return self._generate_fallback_fingerprint()

    def _generate_fallback_fingerprint(self) -> HardwareFingerprint:
        """Generate fallback fingerprint when normal generation fails.

        Returns:
            HardwareFingerprint object with randomly generated system identifiers.
        """
        hex_chars = "0123456789ABCDEF"
        cpu_id = "".join(secrets.choice(hex_chars) for _ in range(16))
        board_id = "".join(secrets.choice(hex_chars) for _ in range(12))
        disk_serial = "".join(secrets.choice(hex_chars) for _ in range(8))
        mac_bytes = [secrets.randbelow(256) for _ in range(6)]
        mac_bytes[0] = mac_bytes[0] & 252 | 2
        mac_address = ":".join(f"{b:02X}" for b in mac_bytes)
        ram_options = [4, 8, 16, 32, 64]
        ram_size = ram_options[secrets.randbelow(len(ram_options))]
        hostname = platform.node() or f"PC-{secrets.randbelow(9000) + 1000}"
        return HardwareFingerprint(
            cpu_id=f"CPU{cpu_id}",
            motherboard_id=f"MB{board_id}",
            disk_serial=f"DSK{disk_serial}",
            mac_address=mac_address,
            ram_size=ram_size,
            os_version=platform.platform() or "Windows 10 Pro",
            hostname=hostname,
        )
