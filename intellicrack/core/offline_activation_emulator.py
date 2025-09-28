import base64
import hashlib
import hmac
import json
import os
import platform
import random
import shutil
import socket
import struct
import subprocess
import time
import uuid
import winreg
import xml.etree.ElementTree as ET

SERIAL_NUMBER_LABEL = "Serial Number:"
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

import wmi
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


class ActivationType(Enum):
    CHALLENGE_RESPONSE = "challenge_response"
    HARDWARE_LOCKED = "hardware_locked"
    LICENSE_FILE = "license_file"
    REGISTRY_BASED = "registry_based"
    PHONE_ACTIVATION = "phone_activation"
    OFFLINE_TOKEN = "offline_token"  # noqa: S105
    SIGNED_CERTIFICATE = "signed_certificate"
    REQUEST_RESPONSE = "request_response"
    FILE_BASED = "file_based"
    QR_CODE = "qr_code"
    TOKEN = "token"  # noqa: S105


class RequestFormat(Enum):
    """Activation request encoding formats."""
    XML = "xml"
    JSON = "json"
    BASE64 = "base64"
    BINARY = "binary"
    PROPRIETARY = "proprietary"


@dataclass
class HardwareProfile:
    cpu_id: str
    motherboard_serial: str
    disk_serial: str
    mac_addresses: List[str]
    bios_serial: str
    system_uuid: str
    volume_serial: str
    machine_guid: str


@dataclass
class ActivationRequest:
    product_id: str
    product_version: str
    hardware_id: str
    installation_id: str
    request_code: str
    timestamp: datetime
    additional_data: Dict[str, Any]


@dataclass
class ActivationResponse:
    activation_code: str
    license_key: str
    expiry_date: Optional[datetime]
    features: List[str]
    hardware_locked: bool
    signature: Optional[bytes]
    # Additional fields for exploitation version compatibility
    response_id: Optional[str] = None
    request_id: Optional[str] = None
    expiration: Optional[int] = None
    restrictions: Optional[Dict[str, Any]] = None
    format: Optional[RequestFormat] = None


@dataclass
class MachineProfile:
    """Hardware and system profile for activation (from exploitation version)."""
    machine_id: str
    cpu_id: str
    motherboard_serial: str
    disk_serial: str
    mac_address: str
    hostname: str
    username: str
    os_version: str
    install_date: int
    install_path: str
    product_version: str


@dataclass
class ExtendedActivationRequest:
    """Extended activation request data (from exploitation version)."""
    request_id: str
    product_id: str
    product_version: str
    machine_profile: MachineProfile
    serial_number: str
    timestamp: int
    signature: Optional[bytes] = None
    encrypted: bool = False
    format: RequestFormat = RequestFormat.XML


class OfflineActivationEmulator:
    """Production-ready offline activation emulation system"""

    def __init__(self) -> None:
        self.backend = default_backend()
        self.wmi_client = wmi.WMI() if platform.system() == "Windows" else None
        self.activation_algorithms = self._initialize_algorithms()
        self.known_schemes = self._load_known_schemes()

    def _initialize_algorithms(self) -> Dict[str, Any]:
        """Initialize known activation algorithms"""
        return {
            "microsoft": self._microsoft_activation,
            "adobe": self._adobe_activation,
            "autodesk": self._autodesk_activation,
            "vmware": self._vmware_activation,
            "matlab": self._matlab_activation,
            "solidworks": self._solidworks_activation,
            "custom_rsa": self._rsa_based_activation,
            "custom_aes": self._aes_based_activation,
            "custom_ecc": self._ecc_based_activation,
        }

    def _load_known_schemes(self) -> Dict[str, Dict]:
        """Load database of known activation schemes"""
        return {
            "microsoft_office": {
                "type": ActivationType.CHALLENGE_RESPONSE,
                "algorithm": "microsoft",
                "hardware_locked": True,
                "key_length": 25,
            },
            "adobe_cc": {"type": ActivationType.LICENSE_FILE, "algorithm": "adobe", "hardware_locked": True, "file_format": "xml"},
            "autodesk": {
                "type": ActivationType.CHALLENGE_RESPONSE,
                "algorithm": "autodesk",
                "hardware_locked": True,
                "request_format": "alphanumeric",
            },
        }

    def get_hardware_profile(self) -> HardwareProfile:
        """Get actual hardware profile from system"""
        profile = HardwareProfile(
            cpu_id=self._get_cpu_id(),
            motherboard_serial=self._get_motherboard_serial(),
            disk_serial=self._get_disk_serial(),
            mac_addresses=self._get_mac_addresses(),
            bios_serial=self._get_bios_serial(),
            system_uuid=self._get_system_uuid(),
            volume_serial=self._get_volume_serial(),
            machine_guid=self._get_machine_guid(),
        )
        return profile

    def _get_cpu_id(self) -> str:
        """Get CPU ID from system"""
        try:
            if platform.system() == "Windows" and self.wmi_client:
                for cpu in self.wmi_client.Win32_Processor():
                    return cpu.ProcessorId.strip()
            else:
                # Linux/Unix
                result = subprocess.run(["dmidecode", "-t", "processor"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "ID:" in line:
                        return line.split("ID:")[1].strip()
        except Exception:
            pass

        # Fallback
        return hashlib.md5(platform.processor().encode()).hexdigest()[:16].upper()


    def _get_motherboard_serial(self) -> str:
        """Get motherboard serial number"""
        try:
            if platform.system() == "Windows" and self.wmi_client:
                for board in self.wmi_client.Win32_BaseBoard():
                    return board.SerialNumber.strip()
            else:
                result = subprocess.run(["dmidecode", "-t", "baseboard"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if SERIAL_NUMBER_LABEL in line:
                        return line.split(":")[1].strip()
        except Exception:
            pass

        return hashlib.md5(socket.gethostname().encode()).hexdigest()[:16].upper()

    def _get_disk_serial(self) -> str:
        """Get primary disk serial number"""
        try:
            if platform.system() == "Windows" and self.wmi_client:
                for disk in self.wmi_client.Win32_PhysicalMedia():
                    if disk.SerialNumber:
                        return disk.SerialNumber.strip()
            else:
                result = subprocess.run(["hdparm", "-I", "/dev/sda"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if SERIAL_NUMBER_LABEL in line:
                        return line.split(":")[1].strip()
        except Exception:
            pass

        return hashlib.md5(os.urandom(16)).hexdigest()[:16].upper()

    def _get_mac_addresses(self) -> List[str]:
        """Get all MAC addresses"""
        macs = []
        system = platform.system()
        if system == "Windows" and self.wmi_client:
            macs = self._get_windows_macs()
        else:
            macs = self._get_non_windows_macs()

        if not macs:
            macs = self._get_fallback_mac()

        return macs[:4]  # Return up to 4 MACs

    def _get_windows_macs(self) -> List[str]:
        macs = []
        for nic in self.wmi_client.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.MACAddress:
                macs.append(nic.MACAddress.replace(":", ""))
        return macs

    def _get_non_windows_macs(self) -> List[str]:
        macs = []
        import netifaces

        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    if "addr" in addr:
                        macs.append(addr["addr"].replace(":", "").upper())
        return macs

    def _get_fallback_mac(self) -> List[str]:
        # Fallback to uuid-based MAC
        node = uuid.getnode()
        mac = ":".join(("%012X" % node)[i : i + 2] for i in range(0, 12, 2))
        return [mac.replace(":", "")]

    def _get_bios_serial(self) -> str:
        """Get BIOS serial number"""
        try:
            if platform.system() == "Windows" and self.wmi_client:
                for bios in self.wmi_client.Win32_BIOS():
                    return bios.SerialNumber.strip()
            else:
                result = subprocess.run(["dmidecode", "-t", "bios"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if SERIAL_NUMBER_LABEL in line:
                        return line.split(":")[1].strip()
        except Exception:
            pass

        return hashlib.md5(platform.node().encode()).hexdigest()[:16].upper()

    def _get_system_uuid(self) -> str:
        """Get system UUID"""
        try:
            if platform.system() == "Windows" and self.wmi_client:
                for system in self.wmi_client.Win32_ComputerSystemProduct():
                    return system.UUID.strip()
            else:
                result = subprocess.run(["dmidecode", "-s", "system-uuid"], capture_output=True, text=True)
                return result.stdout.strip()
        except Exception:
            pass

        return str(uuid.uuid4()).upper()

    def _get_volume_serial(self) -> str:
        """Get system volume serial number"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["vol", "C:"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "Serial Number" in line:
                        return line.split()[-1]
            else:
                result = subprocess.run(["blkid", "-o", "value", "-s", "UUID", "/dev/sda1"], capture_output=True, text=True)
                return result.stdout.strip()[:8].upper()
        except Exception:
            pass

        return hashlib.md5(os.urandom(8)).hexdigest()[:8].upper()

    def _get_machine_guid(self) -> str:
        """Get Windows machine GUID or equivalent"""
        try:
            if platform.system() == "Windows":
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    return winreg.QueryValueEx(key, "MachineGuid")[0]
            else:
                # Linux machine-id
                with open("/etc/machine-id", "r") as f:
                    return f.read().strip()
        except Exception:
            pass

        return str(uuid.uuid4()).upper()

    def generate_hardware_id(self, profile: Optional[HardwareProfile] = None, algorithm: str = "standard") -> str:
        """Generate hardware ID from profile"""
        if not profile:
            profile = self.get_hardware_profile()

        if algorithm == "standard":
            # Combine hardware components
            components = [
                profile.cpu_id,
                profile.motherboard_serial,
                profile.disk_serial,
                profile.mac_addresses[0] if profile.mac_addresses else "",
                profile.bios_serial,
            ]

            # Hash combined components
            combined = "".join(components)
            hw_hash = hashlib.sha256(combined.encode()).digest()

            # Format as hardware ID
            hw_id = base64.b32encode(hw_hash[:20]).decode("ascii").rstrip("=")

            # Add separators for readability
            formatted = "-".join([hw_id[i : i + 5] for i in range(0, len(hw_id), 5)])
            return formatted

        elif algorithm == "microsoft":
            # Microsoft-style hardware hash
            components = [
                profile.cpu_id[:8],
                profile.disk_serial[:8],
                profile.motherboard_serial[:8],
                profile.mac_addresses[0][:12] if profile.mac_addresses else "000000000000",
            ]

            # XOR components
            result = 0
            for comp in components:
                try:
                    result ^= int(comp, 16)
                except ValueError:
                    result ^= int(hashlib.md5(comp.encode()).hexdigest()[:8], 16)

            return format(result, "08X")

        elif algorithm == "adobe":
            # Adobe-style LEID (License Encryption ID)
            h = hashlib.sha1()
            h.update(profile.cpu_id.encode())
            h.update(profile.motherboard_serial.encode())
            h.update(profile.system_uuid.encode())

            digest = h.hexdigest().upper()
            return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}"

        else:
            # Custom algorithm
            return self._custom_hardware_id(profile)

    def _custom_hardware_id(self, profile: HardwareProfile) -> str:
        """Generate custom hardware ID"""
        # Use PBKDF2 for key derivation
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

        salt = profile.machine_guid.encode()[:16]
        password = (profile.cpu_id + profile.motherboard_serial).encode()

        try:
            kdf = PBKDF2(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000, backend=self.backend)
            key = kdf.derive(password)
            hw_id = base64.b64encode(key[:24]).decode("ascii")
            return hw_id
        except Exception:
            return hashlib.sha256((profile.cpu_id + profile.motherboard_serial).encode()).hexdigest()[:32]

    def generate_installation_id(self, product_id: str, hardware_id: str) -> str:
        """Generate installation ID for product"""
        # Combine product and hardware

        # Generate installation ID
        h = hmac.new(key=product_id.encode(), msg=hardware_id.encode(), digestmod=hashlib.sha256)

        install_id = h.hexdigest().upper()

        # Format as groups
        groups = [install_id[i : i + 6] for i in range(0, 36, 6)]
        return "-".join(groups)

    def generate_request_code(self, installation_id: str) -> str:
        """Generate activation request code"""
        # Hash installation ID
        h = hashlib.sha256(installation_id.encode())

        # Convert to numeric code
        digest_int = int.from_bytes(h.digest()[:8], "big")

        # Format as request code (groups of 6 digits)
        request_code = str(digest_int)[:54]
        request_code = request_code.ljust(54, "0")

        groups = [request_code[i : i + 6] for i in range(0, 54, 6)]
        return "-".join(groups)

    def generate_activation_response(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """Generate activation response for request"""
        # Determine activation algorithm
        algorithm = self._detect_activation_algorithm(request.product_id)

        if algorithm in self.activation_algorithms:
            return self.activation_algorithms[algorithm](request, product_key)
        else:
            # Default activation
            return self._default_activation(request, product_key)

    def _detect_activation_algorithm(self, product_id: str) -> str:
        """Detect which activation algorithm to use"""
        product_lower = product_id.lower()

        if "microsoft" in product_lower or "office" in product_lower:
            return "microsoft"
        elif "adobe" in product_lower:
            return "adobe"
        elif "autodesk" in product_lower:
            return "autodesk"
        elif "vmware" in product_lower:
            return "vmware"
        elif "matlab" in product_lower:
            return "matlab"
        elif "solidworks" in product_lower:
            return "solidworks"
        else:
            return "custom_rsa"

    def _microsoft_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """Microsoft-style activation (simplified MAK/KMS emulation)"""
        # Parse installation ID
        install_id_parts = request.installation_id.replace("-", "")

        # Generate confirmation ID
        confirmation_blocks = []

        for i in range(8):
            # Each block derived from installation ID
            block_seed = install_id_parts[i * 6 : (i + 1) * 6]

            # Transform using Microsoft-like algorithm
            value = 0
            for char in block_seed:
                value = (value * 10 + ord(char)) % 1000000

            # Apply product-specific transformation
            if product_key:
                key_value = sum(ord(c) for c in product_key)
                value = (value * key_value) % 1000000

            confirmation_blocks.append(str(value).zfill(6))

        confirmation_id = "-".join(confirmation_blocks)

        return ActivationResponse(
            activation_code=confirmation_id,
            license_key=product_key or self._generate_product_key("microsoft"),
            expiry_date=datetime.now() + timedelta(days=180),
            features=["Professional", "Enterprise"],
            hardware_locked=True,
            signature=None,
        )

    def _adobe_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """Adobe-style activation"""
        # Generate response based on request code
        request_bytes = request.request_code.encode()

        # Adobe uses specific transformation
        h = hashlib.sha256()
        h.update(request_bytes)
        h.update(request.hardware_id.encode())

        response_hash = h.hexdigest()

        # Format as Adobe response code
        response_code = response_hash[:24].upper()
        formatted = "-".join([response_code[i : i + 4] for i in range(0, 24, 4)])

        # Generate license content
        license_data = self._generate_adobe_license(request, response_code)

        return ActivationResponse(
            activation_code=formatted,
            license_key=product_key or self._generate_product_key("adobe"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=["Creative Cloud", "All Apps"],
            hardware_locked=True,
            signature=self._sign_license_data(license_data),
        )

    def _generate_adobe_license(self, request: ActivationRequest, response_code: str) -> bytes:
        """Generate Adobe license file content"""
        root = ET.Element("License")

        # Add license elements
        product = ET.SubElement(root, "Product")
        product.text = request.product_id

        version = ET.SubElement(root, "Version")
        version.text = request.product_version

        serial = ET.SubElement(root, "SerialNumber")
        serial.text = response_code

        hwid = ET.SubElement(root, "HardwareID")
        hwid.text = request.hardware_id

        activation = ET.SubElement(root, "ActivationDate")
        activation.text = datetime.now().isoformat()

        expiry = ET.SubElement(root, "ExpiryDate")
        expiry.text = (datetime.now() + timedelta(days=365)).isoformat()

        # Features
        features = ET.SubElement(root, "Features")
        for feature in ["Photoshop", "Illustrator", "Premiere", "AfterEffects"]:
            feat = ET.SubElement(features, "Feature")
            feat.text = feature

        return ET.tostring(root, encoding="utf-8")

    def _autodesk_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """Autodesk-style activation"""
        # Autodesk uses specific XOR-based algorithm
        request_numeric = "".join(c for c in request.request_code if c.isdigit())

        # Magic constants for Autodesk
        magic1 = 0x56789ABC
        magic2 = 0xDEF01234

        # Process request code
        request_value = int(request_numeric[:8]) if request_numeric else 0

        # Generate response
        response_value = (request_value ^ magic1) + magic2
        response_code = format(response_value, "016X")

        # Format as Autodesk activation code
        formatted = "-".join([response_code[i : i + 4] for i in range(0, 16, 4)])

        return ActivationResponse(
            activation_code=formatted,
            license_key=product_key or self._generate_product_key("autodesk"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=["AutoCAD", "3D Modeling", "Rendering"],
            hardware_locked=True,
            signature=None,
        )

    def _vmware_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """VMware-style activation"""
        # VMware uses specific format
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # pragma: allowlist secret

        # Generate based on hardware ID
        hw_hash = hashlib.sha256(request.hardware_id.encode()).digest()

        activation_code = ""
        for i in range(20):
            idx = hw_hash[i] % len(chars)
            activation_code += chars[idx]

        # Format as VMware key
        formatted = "-".join([activation_code[i : i + 5] for i in range(0, 20, 5)])

        return ActivationResponse(
            activation_code=formatted,
            license_key=product_key or self._generate_product_key("vmware"),
            expiry_date=None,  # Perpetual license
            features=["vSphere", "ESXi", "vCenter"],
            hardware_locked=False,
            signature=None,
        )

    def _matlab_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """MATLAB-style activation"""
        # MATLAB uses file installation key and license file

        # Generate activation key
        h = hashlib.md5()
        h.update(request.installation_id.encode())
        h.update(request.hardware_id.encode())

        activation_hash = h.hexdigest().upper()
        activation_code = "-".join([activation_hash[i : i + 5] for i in range(0, 20, 5)])

        # Generate license file content
        license_content = self._generate_matlab_license(request)

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("matlab"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=["MATLAB", "Simulink", "Toolboxes"],
            hardware_locked=True,
            signature=self._sign_license_data(license_content),
        )

    def _generate_matlab_license(self, request: ActivationRequest) -> bytes:
        """Generate MATLAB license file"""
        lines = [
            "# MATLAB license file",
            f"SERVER {socket.gethostname()} {request.hardware_id} 27000",
            "USE_SERVER",
            "DAEMON MLM",
            "",
            f"FEATURE MATLAB MLM 99 {(datetime.now() + timedelta(days=365)).strftime('%d-%b-%Y')} uncounted \\",
            f"        HOSTID={request.hardware_id} \\",
            f"        ISSUED={datetime.now().strftime('%d-%b-%Y')} \\",
            f"        START={datetime.now().strftime('%d-%b-%Y')} \\",
            "        SIGN=ABCD1234EFGH5678",
        ]

        return "\n".join(lines).encode()

    def _solidworks_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """SolidWorks-style activation"""
        # SolidWorks uses specific activation format

        # Process request code
        request_parts = request.request_code.split("-")

        # Generate response using SolidWorks algorithm
        response_parts = []
        for part in request_parts[:4]:
            # Transform each part
            value = sum(ord(c) for c in part)
            transformed = (value * 12345) % 1000000
            response_parts.append(str(transformed).zfill(6))

        activation_code = "-".join(response_parts)

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("solidworks"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=["Professional", "FEA", "CAM"],
            hardware_locked=True,
            signature=None,
        )

    def _rsa_based_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """RSA signature-based activation"""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)

        # Create activation data
        activation_data = {
            "installation_id": request.installation_id,
            "hardware_id": request.hardware_id,
            "product_id": request.product_id,
            "timestamp": datetime.now().isoformat(),
            "features": ["Premium", "Enterprise"],
        }

        # Sign activation data
        data_bytes = json.dumps(activation_data).encode()
        signature = private_key.sign(
            data_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

        # Generate activation code
        activation_code = base64.b64encode(signature[:32]).decode("ascii")

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("custom"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=activation_data["features"],
            hardware_locked=True,
            signature=signature,
        )

    def _aes_based_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """AES encryption-based activation"""
        import os

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Generate AES key from hardware ID
        key = hashlib.sha256(request.hardware_id.encode()).digest()

        # Create activation data
        activation_data = f"{request.installation_id}:{datetime.now().timestamp()}"

        # Encrypt activation data
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Pad data to 16 bytes
        padded_data = activation_data.ljust((len(activation_data) // 16 + 1) * 16)
        encrypted = encryptor.update(padded_data.encode()) + encryptor.finalize()

        # Create activation code
        activation_code = base64.b64encode(iv + encrypted[:32]).decode("ascii")

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("custom"),
            expiry_date=datetime.now() + timedelta(days=180),
            features=["Standard"],
            hardware_locked=True,
            signature=None,
        )

    def _ecc_based_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """ECC signature-based activation"""
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate ECC key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=self.backend)

        # Create activation message
        message = f"{request.installation_id}:{request.hardware_id}".encode()

        # Sign message
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

        # Create activation code from signature
        activation_code = base64.b32encode(signature[:30]).decode("ascii").rstrip("=")

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("custom"),
            expiry_date=datetime.now() + timedelta(days=365),
            features=["Professional"],
            hardware_locked=True,
            signature=signature,
        )

    def _default_activation(self, request: ActivationRequest, product_key: str = None) -> ActivationResponse:
        """Default activation for unknown products"""
        # Simple hash-based activation
        h = hashlib.sha256()
        h.update(request.installation_id.encode())
        h.update(request.request_code.encode())
        h.update(request.hardware_id.encode())

        activation_hash = h.hexdigest()
        activation_code = "-".join([activation_hash[i : i + 8] for i in range(0, 32, 8)])

        return ActivationResponse(
            activation_code=activation_code,
            license_key=product_key or self._generate_product_key("default"),
            expiry_date=datetime.now() + timedelta(days=90),
            features=["Basic"],
            hardware_locked=True,
            signature=None,
        )

    def _generate_product_key(self, product_type: str) -> str:
        """Generate product key for specific product type"""

        if product_type == "microsoft":
            # Microsoft format: 5 groups of 5 chars (BCDFG-HJKMP-QRTVW-XY234-6789B)
            chars = "BCDFGHJKMPQRTVWXY2346789"  # pragma: allowlist secret
            key_parts = []
            for _ in range(5):
                part = "".join(random.choices(chars, k=5))
                key_parts.append(part)
            return "-".join(key_parts)

        elif product_type == "adobe":
            # Adobe format: 1234-5678-9012-3456-7890-1234
            key_parts = []
            for _ in range(6):
                part = str(random.randint(0, 9999)).zfill(4)
                key_parts.append(part)
            return "-".join(key_parts)

        elif product_type == "autodesk":
            # Autodesk format: 123-45678901
            part1 = str(random.randint(100, 999))
            part2 = str(random.randint(10000000, 99999999))
            return f"{part1}-{part2}"

        else:
            # Generic format
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            key = "".join(random.choices(chars, k=25))
            return "-".join([key[i : i + 5] for i in range(0, 25, 5)])

    def _sign_license_data(self, data: bytes) -> bytes:
        """Sign license data with private key"""
        # Generate signing key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)

        # Sign data
        signature = private_key.sign(
            data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

        return signature

    def create_license_file(self, response: ActivationResponse, format: str = "xml") -> bytes:
        """Create license file in specified format"""
        if format == "xml":
            return self._create_xml_license(response)
        elif format == "json":
            return self._create_json_license(response)
        elif format == "binary":
            return self._create_binary_license(response)
        else:
            return self._create_text_license(response)

    def _create_xml_license(self, response: ActivationResponse) -> bytes:
        """Create XML license file"""
        root = ET.Element("License")

        key = ET.SubElement(root, "LicenseKey")
        key.text = response.license_key

        activation = ET.SubElement(root, "ActivationCode")
        activation.text = response.activation_code

        if response.expiry_date:
            expiry = ET.SubElement(root, "ExpiryDate")
            expiry.text = response.expiry_date.isoformat()

        features = ET.SubElement(root, "Features")
        for feature in response.features:
            feat = ET.SubElement(features, "Feature")
            feat.text = feature

        hw_locked = ET.SubElement(root, "HardwareLocked")
        hw_locked.text = str(response.hardware_locked)

        if response.signature:
            sig = ET.SubElement(root, "Signature")
            sig.text = base64.b64encode(response.signature).decode("ascii")

        return ET.tostring(root, encoding="utf-8")

    def _create_json_license(self, response: ActivationResponse) -> bytes:
        """Create JSON license file"""
        license_data = {
            "license_key": response.license_key,
            "activation_code": response.activation_code,
            "expiry_date": response.expiry_date.isoformat() if response.expiry_date else None,
            "features": response.features,
            "hardware_locked": response.hardware_locked,
            "signature": base64.b64encode(response.signature).decode("ascii") if response.signature else None,
        }

        return json.dumps(license_data, indent=2).encode()

    def _create_binary_license(self, response: ActivationResponse) -> bytes:
        """Create binary license file"""
        # Binary format with magic header
        data = b"LICX"  # Magic
        data += struct.pack("<I", 1)  # Version

        # License key
        key_bytes = response.license_key.encode()
        data += struct.pack("<I", len(key_bytes))
        data += key_bytes

        # Activation code
        act_bytes = response.activation_code.encode()
        data += struct.pack("<I", len(act_bytes))
        data += act_bytes

        # Expiry timestamp
        if response.expiry_date:
            data += struct.pack("<Q", int(response.expiry_date.timestamp()))
        else:
            data += struct.pack("<Q", 0)

        # Features
        data += struct.pack("<I", len(response.features))
        for feature in response.features:
            feat_bytes = feature.encode()
            data += struct.pack("<I", len(feat_bytes))
            data += feat_bytes

        # Hardware locked flag
        data += struct.pack("<?", response.hardware_locked)

        # Signature
        if response.signature:
            data += struct.pack("<I", len(response.signature))
            data += response.signature
        else:
            data += struct.pack("<I", 0)

        return data

    def _create_text_license(self, response: ActivationResponse) -> bytes:
        """Create text license file"""
        lines = [
            "LICENSE INFORMATION",
            "=" * 50,
            f"License Key: {response.license_key}",
            f"Activation Code: {response.activation_code}",
            f"Hardware Locked: {response.hardware_locked}",
        ]

        if response.expiry_date:
            lines.append(f"Expiry Date: {response.expiry_date.strftime('%Y-%m-%d')}")

        lines.append("")
        lines.append("Features:")
        for feature in response.features:
            lines.append(f"  - {feature}")

        if response.signature:
            lines.append("")
            lines.append("Digital Signature:")
            sig_b64 = base64.b64encode(response.signature).decode("ascii")
            for i in range(0, len(sig_b64), 64):
                lines.append(sig_b64[i : i + 64])

        return "\n".join(lines).encode()

    def emulate_phone_activation(self, installation_id: str) -> str:
        """Emulate phone activation system"""
        # Convert installation ID to numeric groups
        id_numeric = "".join(c for c in installation_id if c.isalnum())

        # Generate confirmation ID using phone activation algorithm
        confirmation_groups = []

        for i in range(0, min(54, len(id_numeric)), 6):
            group = id_numeric[i : i + 6]

            # Transform group
            value = 0
            for char in group:
                if char.isdigit():
                    value = (value * 10 + int(char)) % 1000000
                else:
                    value = (value * 36 + ord(char) - ord("A") + 10) % 1000000

            confirmation_groups.append(str(value).zfill(6))

        # Ensure we have 9 groups
        while len(confirmation_groups) < 9:
            confirmation_groups.append(str(random.randint(0, 999999)).zfill(6))

        return "-".join(confirmation_groups[:9])

    def bypass_trial_restrictions(self, product_id: str) -> Dict[str, Any]:
        """Generate data to bypass trial restrictions"""
        bypass_data = {
            "trial_reset": self._generate_trial_reset_data(product_id),
            "registry_keys": self._generate_registry_keys(product_id),
            "license_files": self._generate_license_files(product_id),
            "date_bypass": self._generate_date_bypass_data(),
            "network_bypass": self._generate_network_bypass_data(),
        }

        return bypass_data

    def _generate_trial_reset_data(self, product_id: str) -> Dict[str, Any]:
        """Generate trial reset data"""
        return {
            "delete_files": [
                f"C:\\ProgramData\\{product_id}\\trial.dat",
                f"C:\\Users\\{{username}}\\AppData\\Local\\{product_id}\\license.lic",
            ],
            "registry_keys_to_delete": [
                f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\Trial",
                f"HKEY_CURRENT_USER\\SOFTWARE\\{product_id}\\FirstRun",
            ],
            "guid_to_regenerate": str(uuid.uuid4()),
            "machine_id_spoof": hashlib.md5(os.urandom(16)).hexdigest(),
        }

    def _generate_registry_keys(self, product_id: str) -> Dict[str, str]:
        """Generate registry keys for activation"""
        return {
            f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\License": "Activated",
            f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\LicenseKey": self._generate_product_key("default"),
            f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\ActivationDate": datetime.now().isoformat(),
            f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\ExpiryDate": (datetime.now() + timedelta(days=3650)).isoformat(),
            f"HKEY_LOCAL_MACHINE\\SOFTWARE\\{product_id}\\Features": "Premium;Enterprise;Unlimited",
        }

    def _generate_license_files(self, product_id: str) -> Dict[str, bytes]:
        """Generate license files for product"""
        # Generate proper activation response
        hardware_id = self.generate_hardware_id()
        installation_id = self.generate_installation_id(product_id, hardware_id)
        request_code = self.generate_request_code(installation_id)

        # Create activation request
        request = ActivationRequest(
            product_id=product_id,
            product_version="1.0",
            hardware_id=hardware_id,
            installation_id=installation_id,
            request_code=request_code,
            timestamp=datetime.now(),
            additional_data={},
        )

        # Generate proper response using the activation system
        response = self.generate_activation_response(request)

        return {
            "license.xml": self._create_xml_license(response),
            "license.json": self._create_json_license(response),
            "license.dat": self._create_binary_license(response),
            "license.txt": self._create_text_license(response),
        }

    def _generate_date_bypass_data(self) -> Dict[str, Any]:
        """Generate date manipulation bypass data"""
        return {
            "system_time_freeze": datetime(2020, 1, 1),
            "trial_start_date": datetime(2020, 1, 1),
            "last_check_date": datetime(2020, 1, 1),
            "time_zone": "UTC",
            "ntp_server_override": "127.0.0.1",
        }

    def _generate_network_bypass_data(self) -> Dict[str, Any]:
        """Generate network validation bypass data"""
        return {
            "hosts_file_entries": [
                "127.0.0.1 activation.adobe.com",
                "127.0.0.1 lmlicenses.wip4.adobe.com",
                "127.0.0.1 lm.licenses.adobe.com",
                "127.0.0.1 validation.autodesk.com",
                "127.0.0.1 register.microsoft.com",
            ],
            "firewall_rules": [
                "Block outbound TCP 443 to *.adobe.com",
                "Block outbound TCP 443 to *.autodesk.com",
                "Block outbound TCP 443 to *.microsoft.com",
            ],
            "proxy_config": {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"},
        }

    # Methods merged from exploitation/offline_activation_emulator.py

    def _generate_machine_profile(self) -> MachineProfile:
        """Generate realistic machine profile."""
        hostname = socket.gethostname()

        # Get MAC address
        mac_address = self._generate_realistic_mac()
        try:
            import psutil
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                        mac_address = addr.address
                        break
                if mac_address != self._generate_realistic_mac():
                    break
        except:
            pass

        # Get disk serial
        disk_serial = self._get_disk_serial()

        # Get CPU ID
        cpu_id = self._get_cpu_id()

        # Get motherboard serial
        mb_serial = self._get_motherboard_serial()

        return MachineProfile(
            machine_id=hashlib.sha256(f"{hostname}{mac_address}".encode()).hexdigest()[:16].upper(),
            cpu_id=cpu_id,
            motherboard_serial=mb_serial,
            disk_serial=disk_serial,
            mac_address=mac_address,
            hostname=hostname,
            username=os.environ.get("USERNAME", "user"),
            os_version=platform.platform(),
            install_date=int(time.time() - 86400 * 30),  # 30 days ago
            install_path="C:\\Program Files\\Application",
            product_version="1.0.0",
        )

    def _generate_realistic_mac(self) -> str:
        """Generate realistic MAC address."""
        # Real OUI prefixes from major manufacturers
        oui_prefixes = [
            "00:1B:44",  # Cisco
            "00:50:56",  # VMware
            "00:0C:29",  # VMware
            "00:1C:42",  # Parallels
            "08:00:27",  # VirtualBox
            "AC:DE:48",  # Private
            "00:25:90",  # Dell
            "F4:CE:46",  # HP
            "00:1E:67",  # Intel
            "3C:97:0E",  # Wistron
        ]

        prefix = random.choice(oui_prefixes)
        suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
        return f"{prefix}:{suffix}"

    def _load_product_database(self) -> Dict[str, Dict[str, Any]]:
        """Load known product activation patterns."""
        return {
            "adobe_cc": {
                "request_format": RequestFormat.XML,
                "encryption": "AES256",
                "signature": "RSA2048",
                "machine_binding": ["cpu_id", "disk_serial"],
                "response_validation": "HMAC-SHA256",
            },
            "autodesk": {
                "request_format": RequestFormat.BASE64,
                "encryption": None,
                "signature": "ECDSA",
                "machine_binding": ["mac_address", "hostname"],
                "response_validation": "CRC32",
            },
            "microsoft": {
                "request_format": RequestFormat.XML,
                "encryption": "RSA",
                "signature": "RSA4096",
                "machine_binding": ["machine_id"],
                "response_validation": "digital_signature",
            },
            "vmware": {
                "request_format": RequestFormat.JSON,
                "encryption": None,
                "signature": "SHA256",
                "machine_binding": ["cpu_id", "mac_address"],
                "response_validation": "checksum",
            },
        }

    def generate_activation_request(self, product_id: str, serial_number: str, format: RequestFormat = RequestFormat.XML) -> str:
        """Generate offline activation request."""
        # Generate machine profile if not exists
        if not hasattr(self, 'machine_profile'):
            self.machine_profile = self._generate_machine_profile()

        request = ExtendedActivationRequest(
            request_id=str(uuid.uuid4()),
            product_id=product_id,
            product_version=self.machine_profile.product_version,
            machine_profile=self.machine_profile,
            serial_number=serial_number,
            timestamp=int(time.time()),
            format=format,
        )

        # Format based on type
        if format == RequestFormat.XML:
            return self._format_xml_request(request)
        elif format == RequestFormat.JSON:
            return self._format_json_request(request)
        elif format == RequestFormat.BASE64:
            return self._format_base64_request(request)
        else:
            return self._format_binary_request(request)

    def _format_xml_request(self, request: ExtendedActivationRequest) -> str:
        """Format activation request as XML."""
        root = ET.Element("ActivationRequest")

        # Add request metadata
        ET.SubElement(root, "RequestID").text = request.request_id
        ET.SubElement(root, "ProductID").text = request.product_id
        ET.SubElement(root, "ProductVersion").text = request.product_version
        ET.SubElement(root, "SerialNumber").text = request.serial_number
        ET.SubElement(root, "Timestamp").text = str(request.timestamp)

        # Add machine profile
        machine = ET.SubElement(root, "MachineProfile")
        ET.SubElement(machine, "MachineID").text = request.machine_profile.machine_id
        ET.SubElement(machine, "CPUID").text = request.machine_profile.cpu_id
        ET.SubElement(machine, "MotherboardSerial").text = request.machine_profile.motherboard_serial
        ET.SubElement(machine, "DiskSerial").text = request.machine_profile.disk_serial
        ET.SubElement(machine, "MACAddress").text = request.machine_profile.mac_address
        ET.SubElement(machine, "Hostname").text = request.machine_profile.hostname
        ET.SubElement(machine, "Username").text = request.machine_profile.username
        ET.SubElement(machine, "OSVersion").text = request.machine_profile.os_version
        ET.SubElement(machine, "InstallDate").text = str(request.machine_profile.install_date)
        ET.SubElement(machine, "InstallPath").text = request.machine_profile.install_path

        # Sign the request
        xml_str = ET.tostring(root, encoding="unicode")
        signature = self._sign_request(xml_str.encode())
        ET.SubElement(root, "Signature").text = base64.b64encode(signature).decode()

        return ET.tostring(root, encoding="unicode")

    def _format_json_request(self, request: ExtendedActivationRequest) -> str:
        """Format activation request as JSON."""
        data = {
            "request_id": request.request_id,
            "product_id": request.product_id,
            "product_version": request.product_version,
            "serial_number": request.serial_number,
            "timestamp": request.timestamp,
            "machine_profile": {
                "machine_id": request.machine_profile.machine_id,
                "cpu_id": request.machine_profile.cpu_id,
                "motherboard_serial": request.machine_profile.motherboard_serial,
                "disk_serial": request.machine_profile.disk_serial,
                "mac_address": request.machine_profile.mac_address,
                "hostname": request.machine_profile.hostname,
                "username": request.machine_profile.username,
                "os_version": request.machine_profile.os_version,
                "install_date": request.machine_profile.install_date,
                "install_path": request.machine_profile.install_path,
            },
        }

        # Sign the request
        json_str = json.dumps(data, sort_keys=True)
        signature = self._sign_request(json_str.encode())
        data["signature"] = base64.b64encode(signature).decode()

        return json.dumps(data, indent=2)

    def _format_base64_request(self, request: ExtendedActivationRequest) -> str:
        """Format activation request as base64."""
        # Pack data into binary format
        data = struct.pack(
            ">16s16s16s16s6s32s32s",
            request.request_id[:16].encode().ljust(16, b"\0"),
            request.product_id[:16].encode().ljust(16, b"\0"),
            request.machine_profile.machine_id[:16].encode().ljust(16, b"\0"),
            request.machine_profile.cpu_id[:16].encode().ljust(16, b"\0"),
            bytes.fromhex(request.machine_profile.mac_address.replace(":", "")),
            request.serial_number[:32].encode().ljust(32, b"\0"),
            request.machine_profile.hostname[:32].encode().ljust(32, b"\0"),
        )

        # Add timestamp
        data += struct.pack(">I", request.timestamp)

        # Sign and append signature
        signature = self._sign_request(data)
        data += signature

        # Encode to base64
        return base64.b64encode(data).decode("ascii")

    def _format_binary_request(self, request: ExtendedActivationRequest) -> str:
        """Format activation request as binary."""
        # Create binary packet
        packet = bytearray()

        # Header
        packet.extend(b"ACTREQ01")  # Magic + version

        # Request ID (16 bytes)
        packet.extend(uuid.UUID(request.request_id).bytes)

        # Product ID hash (32 bytes)
        packet.extend(hashlib.sha256(request.product_id.encode()).digest())

        # Machine fingerprint
        fingerprint = hashlib.sha256(
            f"{request.machine_profile.machine_id}{request.machine_profile.cpu_id}{request.machine_profile.disk_serial}".encode()
        ).digest()
        packet.extend(fingerprint)

        # Serial number hash
        packet.extend(hashlib.sha256(request.serial_number.encode()).digest())

        # Timestamp
        packet.extend(struct.pack(">I", request.timestamp))

        # Sign the packet
        signature = self._sign_request(bytes(packet))
        packet.extend(signature)

        # Return hex representation
        return packet.hex()

    def _sign_request(self, data: bytes) -> bytes:
        """Sign activation request data."""
        # Generate signing key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Sign data
        signature = private_key.sign(
            data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

        return signature

    def _generate_license_key(self, request: ExtendedActivationRequest) -> str:
        """Generate license key for activation."""
        # Create license data
        data = f"{request.product_id}:{request.machine_profile.machine_id}:{request.serial_number}"

        # Generate key using PBKDF2
        kdf = PBKDF2(
            algorithm=hashes.SHA256(), length=32, salt=request.machine_profile.cpu_id.encode(), iterations=100000, backend=default_backend()
        )
        key = kdf.derive(data.encode())

        # Format as license key
        key_hex = key.hex().upper()
        formatted = "-".join(key_hex[i : i + 5] for i in range(0, 40, 5))

        return formatted

    def _generate_activation_code(self, request: ExtendedActivationRequest) -> str:
        """Generate activation code."""
        # Combine machine identifiers
        machine_data = f"{request.machine_profile.cpu_id}{request.machine_profile.disk_serial}{request.machine_profile.mac_address}"

        # Generate activation code
        h = hmac.new(request.serial_number.encode(), machine_data.encode(), hashlib.sha256)

        code = h.hexdigest()[:20].upper()
        return "-".join(code[i : i + 4] for i in range(0, 20, 4))

    def create_activation_file(self, response: ActivationResponse, output_path: str):
        """Create activation file for file-based activation."""
        data = {
            "version": "1.0",
            "response": {
                "id": response.response_id or str(uuid.uuid4()),
                "license_key": response.license_key,
                "activation_code": response.activation_code,
                "expiration": response.expiration or int(time.time() + 365 * 86400),
                "features": response.features,
            },
            "signature": base64.b64encode(response.signature or b"").decode(),
        }

        # Encrypt the activation data
        key = hashlib.sha256(response.license_key.encode()).digest()
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad data
        json_data = json.dumps(data).encode()
        pad_len = 16 - (len(json_data) % 16)
        json_data += bytes([pad_len] * pad_len)

        # Encrypt
        encrypted = encryptor.update(json_data) + encryptor.finalize()

        # Write file
        with open(output_path, "wb") as f:
            f.write(b"ACTFILE1")  # Magic
            f.write(iv)
            f.write(encrypted)

        return output_path

    def bypass_challenge_response(self, challenge: str) -> str:
        """Generate valid response for challenge-based activation."""
        # Decode challenge
        try:
            challenge_bytes = base64.b64decode(challenge)
        except:
            challenge_bytes = challenge.encode()

        # Extract challenge components
        if len(challenge_bytes) >= 16:
            nonce = challenge_bytes[:16]
            data = challenge_bytes[16:]
        else:
            nonce = challenge_bytes
            data = b""

        # Generate machine profile if not exists
        if not hasattr(self, 'machine_profile'):
            self.machine_profile = self._generate_machine_profile()

        # Generate response using machine profile and challenge data
        response_data = hashlib.sha256(
            nonce + data + self.machine_profile.machine_id.encode() + self.machine_profile.cpu_id.encode()
        ).digest()

        # Format response
        response = base64.b64encode(response_data).decode("ascii")

        return response
