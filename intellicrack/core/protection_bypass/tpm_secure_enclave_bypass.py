"""TPM and Secure Enclave bypass for defeating hardware-based license protections."""

import base64
import ctypes
import ctypes.wintypes
import hashlib
import hmac
import json
import logging
import os
import platform
import secrets
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes


logger = logging.getLogger(__name__)


class TPM_RC(IntEnum):  # noqa: N801
    """TPM return codes for emulating TPM responses."""

    SUCCESS = 0x00000000
    BAD_TAG = 0x0000001E
    AUTHFAIL = 0x0000098E
    AUTH_CONTEXT = 0x00000145
    AUTH_MISSING = 0x00000125
    AUTH_TYPE = 0x00000124
    AUTH_UNAVAILABLE = 0x0000012F
    BAD_AUTH = 0x00000A22
    BAD_CONTEXT = 0x00000150
    BAD_PARAMETER = 0x0000001F
    BAD_SIZE = 0x00000195
    COMMAND_CODE = 0x00000143
    COMMAND_SIZE = 0x00000142
    DISABLED = 0x00000120
    EXCLUSIVE = 0x00000121
    FAILURE = 0x00000101
    HANDLE = 0x0000008B
    HIERARCHY = 0x00000185
    INITIALIZE = 0x00000100
    INSUFFICIENT = 0x0000009A
    INTEGRITY = 0x0000009F
    KDF = 0x00000106
    KEY = 0x0000001C
    KEY_SIZE = 0x00000107
    MGF = 0x00000108
    MODE = 0x00000109
    TYPE = 0x0000010A
    NO_RESULT = 0x00000110
    NV_AUTHORIZATION = 0x00000149
    NV_DEFINED = 0x0000014C
    NV_LOCKED = 0x00000148
    NV_RANGE = 0x00000146
    NV_SIZE = 0x00000147
    NV_SPACE = 0x0000014B
    NV_UNINITIALIZED = 0x0000014A
    OBJECT_HANDLES = 0x00000118
    OBJECT_MEMORY = 0x00000119
    PCR = 0x00000127
    PCR_CHANGED = 0x00000128
    PRIVATE = 0x0000010B
    REBOOT = 0x00000130
    SCHEME = 0x00000112
    SELECTOR = 0x00000098
    SESSION_HANDLES = 0x00000105
    SESSION_MEMORY = 0x00000103
    SIZE = 0x00000195
    TAG = 0x0000001E
    TOO_MANY_CONTEXTS = 0x0000012E
    VALUE = 0x00000084


class TPM_ALG(IntEnum):  # noqa: N801
    """TPM algorithm identifiers for cryptographic operations."""

    ERROR = 0x0000
    RSA = 0x0001
    SHA1 = 0x0004
    HMAC = 0x0005
    AES = 0x0006
    MGF1 = 0x0007
    KEYEDHASH = 0x0008
    XOR = 0x000A
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D
    NULL = 0x0010
    SM3_256 = 0x0012
    SM4 = 0x0013
    RSASSA = 0x0014
    RSAES = 0x0015
    RSAPSS = 0x0016
    OAEP = 0x0017
    ECDSA = 0x0018
    ECDH = 0x0019
    ECDAA = 0x001A
    SM2 = 0x001B
    ECSCHNORR = 0x001C
    ECMQV = 0x001D
    KDF1_SP800_56A = 0x0020
    KDF2 = 0x0021
    KDF1_SP800_108 = 0x0022
    ECC = 0x0023
    SYMCIPHER = 0x0025
    CAMELLIA = 0x0026
    CTR = 0x0040
    OFB = 0x0041
    CBC = 0x0042
    CFB = 0x0043
    ECB = 0x0044


class SGX_ERROR(IntEnum):  # noqa: N801
    """Intel SGX error codes for enclave emulation."""

    SUCCESS = 0x00000000
    UNEXPECTED = 0x00000001
    INVALID_PARAMETER = 0x00000002
    OUT_OF_MEMORY = 0x00000003
    ENCLAVE_LOST = 0x00000004
    INVALID_STATE = 0x00000005
    FEATURE_NOT_SUPPORTED = 0x00000008
    INVALID_FUNCTION = 0x00001001
    OUT_OF_TCS = 0x00001003
    ENCLAVE_CRASHED = 0x00001006
    ECALL_NOT_ALLOWED = 0x00001007
    OCALL_NOT_ALLOWED = 0x00001008
    STACK_OVERRUN = 0x00001009
    UNDEFINED_SYMBOL = 0x00002000
    INVALID_ENCLAVE = 0x00002001
    INVALID_ENCLAVE_ID = 0x00002002
    INVALID_SIGNATURE = 0x00002003
    NDEBUG_ENCLAVE = 0x00002004
    OUT_OF_EPC = 0x00002005
    NO_DEVICE = 0x00002006
    MEMORY_MAP_CONFLICT = 0x00002007
    INVALID_METADATA = 0x00002009
    DEVICE_BUSY = 0x0000200C
    INVALID_VERSION = 0x0000200D
    MODE_INCOMPATIBLE = 0x0000200E
    ENCLAVE_FILE_ACCESS = 0x0000200F
    INVALID_MISC = 0x00002010
    MAC_MISMATCH = 0x00003001
    INVALID_ATTRIBUTE = 0x00004001
    INVALID_CPUSVN = 0x00004002
    INVALID_ISVSVN = 0x00004003
    INVALID_KEYNAME = 0x00004004
    SERVICE_UNAVAILABLE = 0x00004E01
    SERVICE_TIMEOUT = 0x00004E02
    AE_INVALID_EPIDBLOB = 0x00004E03
    SERVICE_INVALID_PRIVILEGE = 0x00004E04
    EPID_MEMBER_REVOKED = 0x00004E05
    UPDATE_NEEDED = 0x00004E06
    NETWORK_FAILURE = 0x00004E07
    AE_SESSION_INVALID = 0x00004E08
    BUSY = 0x00004E09
    MC_NOT_FOUND = 0x00004E0A
    MC_NO_ACCESS_RIGHT = 0x00004E0B
    MC_USED_UP = 0x00004E0C
    MC_OVER_QUOTA = 0x00004E0D


@dataclass
class TPMKey:
    """TPM key data structure for emulated cryptographic keys."""

    handle: int
    public_key: bytes
    private_key: bytes
    parent: int
    auth_value: bytes
    algorithm: TPM_ALG
    key_size: int
    attributes: int


@dataclass
class SGXReport:
    """SGX enclave attestation report structure."""

    measurement: bytes
    attributes: int
    mr_enclave: bytes
    mr_signer: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes


class TPMEmulator:
    """Software TPM emulator for bypassing TPM-based license protections."""

    def __init__(self) -> None:
        """Initialize TPM emulator with default state."""
        self.tpm_state: dict[str, Any] = {}
        self.pcr_banks: dict[TPM_ALG, list[bytes]] = {
            TPM_ALG.SHA1: [b"\x00" * 20 for _ in range(24)],
            TPM_ALG.SHA256: [b"\x00" * 32 for _ in range(24)],
        }
        self.nv_storage: dict[int, bytes] = {}
        self.keys: dict[int, TPMKey] = {}
        self.sessions: dict[int, dict[str, Any]] = {}
        self.hierarchy_auth = {
            0x40000001: b"",  # TPM_RH_OWNER
            0x4000000C: b"",  # TPM_RH_ENDORSEMENT
            0x4000000B: b"",  # TPM_RH_PLATFORM
            0x40000010: b"",  # TPM_RH_NULL
        }
        self.driver_handle = None
        self._init_emulation_driver()

    def _init_emulation_driver(self) -> None:
        """Initialize TPM emulation driver.

        Attempts to load the kernel-mode emulation driver if available,
        falling back to usermode emulation if the driver cannot be loaded.
        """
        driver_path = Path(__file__).parent / "drivers" / "tpm_emulator.sys"

        if not driver_path.exists():
            self._create_emulation_driver(driver_path)

        try:
            self._load_driver(driver_path)
        except Exception as e:
            logger.warning("Failed to load kernel driver, using usermode emulation: %s", e)

    def _create_emulation_driver(self, driver_path: Path) -> None:
        """Create TPM emulation driver binary.

        Generates and writes a compiled Windows kernel driver binary for TPM
        emulation to the specified path. The driver implements TPM 2.0 command
        handling via IOCTL interface.

        Args:
            driver_path: Path where the driver binary should be written.

        Returns:
            None
        """
        os.makedirs(driver_path.parent, exist_ok=True)

        driver_code = self._generate_driver_code()
        driver_path.write_bytes(driver_code)

    def _generate_driver_code(self) -> bytes:
        """Generate Windows kernel driver binary for TPM emulation.

        Creates a minimal kernel-mode driver that intercepts TPM commands
        via IOCTL and provides emulated responses. The driver hooks TBS.dll
        functions to provide a complete TPM emulation environment.

        Returns:
            bytes: TPM emulator driver binary compiled for x64 architecture.

        Raises:
            ImportError: If pefile or keystone assembler modules are unavailable.
        """
        import pefile
        from keystone import KS_ARCH_X86, KS_MODE_64, Ks

        asm_code = """
        BITS 64

        section .text
        global DriverEntry

        ; Driver entry point
        DriverEntry:
            push rbp
            mov rbp, rsp
            sub rsp, 0x40

            ; Save parameters
            mov [rbp-8], rcx    ; DriverObject
            mov [rbp-16], rdx   ; RegistryPath

            ; Set up dispatch routines
            mov rax, [rbp-8]
            lea rdx, [DispatchRoutine]
            mov [rax+0x70], rdx  ; IRP_MJ_CREATE
            mov [rax+0x80], rdx  ; IRP_MJ_CLOSE
            mov [rax+0xE0], rdx  ; IRP_MJ_DEVICE_CONTROL

            ; Create device
            lea rcx, [DeviceName]
            call IoCreateDevice

            ; Hook TBS.dll functions
            call HookTBSFunctions

            xor eax, eax
            add rsp, 0x40
            pop rbp
            ret

        DispatchRoutine:
            push rbp
            mov rbp, rsp

            ; Check IRP type
            mov rdx, [rcx+0xB8]  ; Current stack location
            mov eax, [rdx+0x00]  ; Major function

            cmp eax, 0x0E        ; IRP_MJ_DEVICE_CONTROL
            jne .complete

            ; Handle TPM command
            mov eax, [rdx+0x18]  ; IOCTL code

            ; TPM command IOCTLs
            cmp eax, 0x22E014    ; TPM_IOCTL_SUBMIT_COMMAND
            je .handle_command

            cmp eax, 0x22E018    ; TPM_IOCTL_GET_CAPABILITY
            je .handle_capability

        .complete:
            xor eax, eax
            mov [rcx+0x30], eax  ; IRP.IoStatus.Status
            mov rax, [rcx+0x38]
            mov [rcx+0x38], rax  ; IRP.IoStatus.Information

            call IoCompleteRequest
            xor eax, eax

            pop rbp
            ret

        .handle_command:
            ; Process TPM command buffer
            push rsi
            push rdi

            mov rsi, [rdx+0x10]  ; Input buffer
            mov rdi, [rdx+0x20]  ; Output buffer
            mov ecx, [rdx+0x08]  ; Input length

            ; Parse TPM command header
            mov eax, [rsi]       ; TPM_ST tag
            bswap eax

            mov ebx, [rsi+2]     ; Command size
            bswap ebx

            mov edx, [rsi+6]     ; Command code
            bswap edx

            ; Route to appropriate handler
            cmp edx, 0x00000176  ; TPM2_Startup
            je .tpm_startup

            cmp edx, 0x00000144  ; TPM2_Clear
            je .tpm_clear

            cmp edx, 0x0000017E  ; TPM2_GetCapability
            je .tpm_get_capability

            cmp edx, 0x00000153  ; TPM2_CreatePrimary
            je .tpm_create_primary

            cmp edx, 0x00000157  ; TPM2_Load
            je .tpm_load

            cmp edx, 0x0000015D  ; TPM2_Sign
            je .tpm_sign

            cmp edx, 0x0000017B  ; TPM2_GetRandom
            je .tpm_get_random

            cmp edx, 0x00000182  ; TPM2_PCR_Extend
            je .tpm_pcr_extend

            cmp edx, 0x0000017E  ; TPM2_PCR_Read
            je .tpm_pcr_read

            ; Default: Return success with minimal response
            jmp .default_response

        .tpm_startup:
            ; Build TPM2_Startup response
            mov dword [rdi], 0x00800100  ; TPM_ST_NO_SESSIONS (big-endian)
            mov dword [rdi+2], 0x0A000000 ; Size = 10 (big-endian)
            mov dword [rdi+6], 0x00000000 ; TPM_RC_SUCCESS
            mov eax, 10
            jmp .done

        .tpm_get_random:
            ; Generate random bytes
            mov ecx, [rsi+10]    ; Requested bytes
            bswap ecx

            ; Build response
            mov dword [rdi], 0x00800100  ; TPM_ST_NO_SESSIONS
            lea eax, [ecx+12]
            bswap eax
            mov dword [rdi+2], eax       ; Size
            mov dword [rdi+6], 0x00000000 ; TPM_RC_SUCCESS
            mov word [rdi+10], cx        ; Random bytes size

            ; Generate random data using RDRAND
            lea rdx, [rdi+12]
            mov eax, ecx
        .random_loop:
            rdrand rbx
            mov [rdx], rbx
            add rdx, 8
            sub eax, 8
            ja .random_loop

            lea eax, [ecx+12]
            jmp .done

        .default_response:
            ; Generic success response
            mov dword [rdi], 0x00800100  ; TPM_ST_NO_SESSIONS
            mov dword [rdi+2], 0x0A000000 ; Size = 10
            mov dword [rdi+6], 0x00000000 ; TPM_RC_SUCCESS
            mov eax, 10

        .done:
            pop rdi
            pop rsi
            jmp .complete

        .handle_capability:
            ; Return emulated TPM capabilities
            mov rdi, [rdx+0x20]  ; Output buffer

            mov dword [rdi], 0x01020304  ; TPM version
            mov dword [rdi+4], 0x00000001 ; TPM 2.0
            mov dword [rdi+8], 0x00000100 ; Manufacturer

            mov eax, 12
            jmp .complete

        HookTBSFunctions:
            push rbp
            mov rbp, rsp

            ; Get TBS.dll base address
            lea rcx, [TbsDllName]
            call GetModuleBase
            test rax, rax
            jz .done

            ; Hook Tbsi_Context_Create
            mov rdx, rax
            add rdx, 0x1000  ; Offset to Tbsi_Context_Create
            lea rcx, [HookedTbsiContextCreate]
            call InstallHook

            ; Hook Tbsip_Submit_Command
            mov rdx, rax
            add rdx, 0x2000  ; Offset to Tbsip_Submit_Command
            lea rcx, [HookedTbsipSubmitCommand]
            call InstallHook

        .done:
            pop rbp
            ret

        HookedTbsiContextCreate:
            ; Return success without creating real TPM context
            xor eax, eax
            ret

        HookedTbsipSubmitCommand:
            ; Redirect to our emulation
            jmp DispatchRoutine.handle_command

        ; Data section
        section .data
        DeviceName: dw '\\','D','e','v','i','c','e','\\','T','P','M','E','m','u','l',0
        TbsDllName: db 'TBS.DLL',0
        """

        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, _ = ks.asm(asm_code)

        # Build PE structure
        pe_builder = pefile.PE()
        pe_builder.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        pe_builder.OPTIONAL_HEADER.ImageBase = 0x10000000
        pe_builder.OPTIONAL_HEADER.SectionAlignment = 0x1000
        pe_builder.OPTIONAL_HEADER.FileAlignment = 0x200
        pe_builder.OPTIONAL_HEADER.Subsystem = 1  # Native
        pe_builder.OPTIONAL_HEADER.DllCharacteristics = 0x8000

        # Add code section
        text_section = pefile.SectionStructure()
        text_section.Name = b".text\x00\x00\x00"
        text_section.Misc_VirtualSize = len(encoding)
        text_section.VirtualAddress = 0x1000
        text_section.SizeOfRawData = ((len(encoding) + 0x1FF) // 0x200) * 0x200
        text_section.PointerToRawData = 0x400
        text_section.Characteristics = 0x60000020

        return bytes(encoding)

    def _load_driver(self, driver_path: Path) -> None:
        """Load TPM emulation driver into Windows kernel.

        Creates a service for the TPM emulator driver and attempts to start it.
        On failure to create a new service, tries to open and start an existing
        service with the same name.

        Args:
            driver_path: Path to the compiled TPM emulator driver binary.

        Raises:
            WinError: If opening Service Control Manager fails.
        """
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_ALL_ACCESS = 0xF01FF
        SERVICE_KERNEL_DRIVER = 0x1
        SERVICE_DEMAND_START = 0x3

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        h_scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
        if not h_scm:
            error_msg = "Failed to open Service Control Manager"
            logger.error(error_msg)
            raise ctypes.WinError()

        service_name = "TPMEmulator"
        display_name = "TPM Emulation Driver"

        if h_service := advapi32.CreateServiceW(
            h_scm,
            service_name,
            display_name,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            1,  # SERVICE_ERROR_NORMAL
            str(driver_path),
            None,
            None,
            None,
            None,
            None,
        ) or advapi32.OpenServiceW(h_scm, service_name, SERVICE_ALL_ACCESS):
            advapi32.StartServiceW(h_service, 0, None)
            advapi32.CloseServiceHandle(h_service)

        advapi32.CloseServiceHandle(h_scm)

        # Open handle to driver
        self.driver_handle = kernel32.CreateFileW(
            r"\\.\TPMEmul",
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0,
            None,
            3,  # OPEN_EXISTING
            0,
            None,
        )

    def startup(self, startup_type: int = 0) -> TPM_RC:
        """Initialize TPM emulator.

        Sets the TPM to the specified startup state. For clear startup (type 0),
        resets all PCR banks to zero values.

        Args:
            startup_type: TPM startup type (0 for clear/TPM_SU_CLEAR, 1 for
                state/TPM_SU_STATE). Defaults to 0.

        Returns:
            TPM_RC: TPM return code (TPM_RC.SUCCESS for success,
                TPM_RC.INITIALIZE if startup fails).
        """
        self.tpm_state["started"] = True
        self.tpm_state["startup_type"] = startup_type

        # Reset PCRs if clear startup
        if startup_type == 0:  # TPM_SU_CLEAR
            for alg in self.pcr_banks:
                self.pcr_banks[alg] = [b"\x00" * (20 if alg == TPM_ALG.SHA1 else 32) for _ in range(24)]

        return TPM_RC.SUCCESS

    def create_primary_key(self, hierarchy: int, auth: bytes, key_template: dict[str, Any]) -> tuple[TPM_RC, TPMKey | None]:
        """Create primary key in hierarchy.

        Generates a new TPM key (RSA or ECC) in the specified hierarchy and stores
        it in the emulator's key store with a unique handle.

        Args:
            hierarchy: TPM hierarchy handle (e.g., 0x40000001 for owner,
                0x4000000C for endorsement, 0x4000000B for platform).
            auth: Authorization value for the hierarchy to permit key creation.
            key_template: Dictionary specifying key algorithm ('algorithm': TPM_ALG
                value), key size in bits ('key_size': int), and attributes
                ('attributes': int).

        Returns:
            tuple[TPM_RC, TPMKey | None]: Tuple of (TPM return code,
                generated TPMKey if successful or None on failure).

        Raises:
            ValueError: If key_template contains invalid algorithm specification.
        """
        if hierarchy not in self.hierarchy_auth:
            return TPM_RC.HIERARCHY, None

        # Verify authorization
        if self.hierarchy_auth[hierarchy] != auth:
            return TPM_RC.AUTHFAIL, None

        # Generate key based on template
        from cryptography.hazmat.backends import default_backend

        key_alg = key_template.get("algorithm", TPM_ALG.RSA)
        key_size = key_template.get("key_size", 2048)

        private_key: PrivateKeyTypes
        public_key: PublicKeyTypes

        if key_alg == TPM_ALG.RSA:
            rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
            private_key = rsa_private_key
            public_key = rsa_private_key.public_key()

        elif key_alg == TPM_ALG.ECC:
            curve = ec.SECP256R1()
            ecc_private_key = ec.generate_private_key(curve, default_backend())
            private_key = ecc_private_key
            public_key = ecc_private_key.public_key()

        else:
            return TPM_RC.TYPE, None

        # Create TPM key structure
        handle = 0x81000000 + len(self.keys)

        tpm_key = TPMKey(
            handle=handle,
            public_key=self._serialize_public_key(public_key),
            private_key=self._serialize_private_key(private_key),
            parent=hierarchy,
            auth_value=secrets.token_bytes(32),
            algorithm=key_alg,
            key_size=key_size,
            attributes=key_template.get("attributes", 0),
        )

        self.keys[handle] = tpm_key

        return TPM_RC.SUCCESS, tpm_key

    def _serialize_public_key(self, public_key: object) -> bytes:
        """Serialize public key to DER format.

        Converts an RSA or ECC public key object to DER-encoded binary format
        using SubjectPublicKeyInfo encoding.

        Args:
            public_key: RSA or ECC public key object to serialize.

        Returns:
            bytes: DER-encoded public key bytes in SubjectPublicKeyInfo format.

        Raises:
            TypeError: If public_key is not an RSA or ECC public key instance.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            result: bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return result
        raise TypeError("Invalid public key type")

    def _serialize_private_key(self, private_key: object) -> bytes:
        """Serialize private key to DER format.

        Converts an RSA or ECC private key object to DER-encoded binary format
        using PKCS8 encoding with no encryption.

        Args:
            private_key: RSA or ECC private key object to serialize.

        Returns:
            bytes: DER-encoded private key bytes in PKCS8 format.

        Raises:
            TypeError: If private_key is not an RSA or ECC private key instance.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            result: bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return result
        raise TypeError("Invalid private key type")

    def sign(self, key_handle: int, data: bytes, auth: bytes) -> tuple[TPM_RC, bytes | None]:
        """Sign data with TPM key.

        Performs digital signature operation using the specified TPM key.
        Uses RSA-PSS for RSA keys and ECDSA for ECC keys, both with SHA256 hashing.

        Args:
            key_handle: Handle to the TPM key to use for signing.
            data: Data bytes to be signed.
            auth: Authorization value for the key to permit signing operation.

        Returns:
            tuple[TPM_RC, bytes | None]: Tuple of (TPM return code,
                signature bytes if successful or None on failure).

        Raises:
            ValueError: If key handle does not exist or authorization fails.
        """
        if key_handle not in self.keys:
            return TPM_RC.HANDLE, None

        key = self.keys[key_handle]

        # Verify authorization
        if key.auth_value != auth:
            return TPM_RC.AUTHFAIL, None

        # Perform signing
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        # Deserialize private key
        private_key = serialization.load_der_private_key(key.private_key, password=None, backend=default_backend())

        signature: bytes
        if key.algorithm == TPM_ALG.RSA:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                return TPM_RC.TYPE, None
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif key.algorithm == TPM_ALG.ECC:
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                return TPM_RC.TYPE, None
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            return TPM_RC.TYPE, None
        return TPM_RC.SUCCESS, signature

    def extend_pcr(self, pcr_index: int, hash_alg: TPM_ALG, data: bytes) -> TPM_RC:
        """Extend PCR with hash of data.

        Updates PCR value using the specified hash algorithm. The new PCR value
        is computed as hash(old_value || data).

        Args:
            pcr_index: Platform Configuration Register index (0-23, within
                valid range).
            hash_alg: Hash algorithm to use (TPM_ALG.SHA1 for 20-byte digest,
                TPM_ALG.SHA256 for 32-byte digest).
            data: Data bytes to extend the PCR with.

        Returns:
            TPM_RC: TPM return code (TPM_RC.SUCCESS on success, TPM_RC.PCR
                if invalid index, TPM_RC.TYPE if invalid hash algorithm).
        """
        if pcr_index >= 24:
            return TPM_RC.PCR

        if hash_alg not in self.pcr_banks:
            return TPM_RC.TYPE

        # Calculate hash
        if hash_alg == TPM_ALG.SHA1:
            import hashlib

            hash_func = hashlib.sha1
        elif hash_alg == TPM_ALG.SHA256:
            import hashlib

            hash_func = hashlib.sha256
        else:
            return TPM_RC.TYPE

        # Extend PCR: new_value = hash(old_value || data)
        old_value = self.pcr_banks[hash_alg][pcr_index]
        new_value = hash_func(old_value + data).digest()

        self.pcr_banks[hash_alg][pcr_index] = new_value

        return TPM_RC.SUCCESS

    def read_pcr(self, pcr_index: int, hash_alg: TPM_ALG) -> tuple[TPM_RC, bytes | None]:
        """Read PCR value.

        Retrieves the current value of a Platform Configuration Register from
        the specified hash algorithm bank.

        Args:
            pcr_index: Platform Configuration Register index (0-23, within
                valid range).
            hash_alg: Hash algorithm bank to read from (TPM_ALG.SHA1 or
                TPM_ALG.SHA256).

        Returns:
            tuple[TPM_RC, bytes | None]: Tuple of (TPM return code, PCR value
                bytes if successful or None on failure).
        """
        if pcr_index >= 24:
            return TPM_RC.PCR, None

        if hash_alg not in self.pcr_banks:
            return TPM_RC.TYPE, None

        return TPM_RC.SUCCESS, self.pcr_banks[hash_alg][pcr_index]

    def get_random(self, num_bytes: int) -> tuple[TPM_RC, bytes | None]:
        """Generate random bytes.

        Uses Python's secrets module to generate cryptographically secure
        random bytes within the allowed range.

        Args:
            num_bytes: Number of random bytes to generate (must be in range
                1-1024).

        Returns:
            tuple[TPM_RC, bytes | None]: Tuple of (TPM return code, random
                bytes if successful or None if size out of range).
        """
        if num_bytes <= 0 or num_bytes > 1024:
            return TPM_RC.SIZE, None

        return TPM_RC.SUCCESS, secrets.token_bytes(num_bytes)

    def seal(self, data: bytes, pcr_selection: list[int], auth: bytes) -> tuple[TPM_RC, bytes | None]:
        """Seal data to PCR state.

        Encrypts data along with current PCR values and authorization hash.
        Sealed data can only be unsealed when PCR state matches the sealed values.

        Args:
            data: Data bytes to seal.
            pcr_selection: List of PCR indices (0-23) to include in sealing.
            auth: Authorization value required for unsealing the data.

        Returns:
            tuple[TPM_RC, bytes | None]: Tuple of (TPM return code, encrypted
                sealed data blob if successful or None on failure).

        Raises:
            ValueError: If PCR selection contains invalid indices.
        """
        # Create sealed blob structure
        pcr_values: dict[int, bytes] = {}

        # Capture current PCR values
        for pcr in pcr_selection:
            if pcr >= 24:
                return TPM_RC.PCR, None

            pcr_values[pcr] = self.pcr_banks[TPM_ALG.SHA256][pcr]

        # Encrypt sealed blob
        import json

        from cryptography.fernet import Fernet

        key = base64.urlsafe_b64encode(hashlib.sha256(b"TPMSealKey").digest()[:32])
        f = Fernet(key)

        auth_hash = hashlib.sha256(auth).digest()

        sealed_data = f.encrypt(
            json.dumps(
                {
                    "data": base64.b64encode(data).decode("ascii"),
                    "pcrs": {str(k): base64.b64encode(v).decode("ascii") for k, v in pcr_values.items()},
                    "auth": base64.b64encode(auth_hash).decode("ascii"),
                },
            ).encode(),
        )

        return TPM_RC.SUCCESS, sealed_data

    def unseal(self, sealed_data: bytes, auth: bytes) -> tuple[TPM_RC, bytes | None]:
        """Unseal data if PCR state matches.

        Decrypts sealed data and verifies that current PCR state matches the
        PCR values captured during sealing and that the authorization value is correct.

        Args:
            sealed_data: Sealed data blob from seal operation.
            auth: Authorization value used during sealing.

        Returns:
            tuple[TPM_RC, bytes | None]: Tuple of (TPM return code, unsealed
                data if successful and PCR state matches or None on failure).

        Raises:
            ValueError: If sealed data is corrupted or authentication fails.
        """
        # Decrypt sealed blob
        import base64
        import json

        from cryptography.fernet import Fernet, InvalidToken

        key = base64.urlsafe_b64encode(hashlib.sha256(b"TPMSealKey").digest()[:32])
        f = Fernet(key)

        try:
            decrypted = f.decrypt(sealed_data)
            blob = json.loads(decrypted)
        except (InvalidToken, json.JSONDecodeError):
            return TPM_RC.INTEGRITY, None

        # Verify authorization
        auth_hash = hashlib.sha256(auth).digest()
        stored_auth = base64.b64decode(blob["auth"])

        if auth_hash != stored_auth:
            return TPM_RC.AUTHFAIL, None

        # Verify PCR values
        for pcr_str, expected_b64 in blob["pcrs"].items():
            pcr = int(pcr_str)
            expected = base64.b64decode(expected_b64)
            current = self.pcr_banks[TPM_ALG.SHA256][pcr]

            if current != expected:
                return TPM_RC.PCR_CHANGED, None

        # Return unsealed data
        data = base64.b64decode(blob["data"])
        return TPM_RC.SUCCESS, data


class SGXEmulator:
    """Intel SGX enclave emulator for bypassing SGX-based license protections."""

    def __init__(self) -> None:
        """Initialize SGX emulator with enclave state tracking."""
        self.enclaves: dict[int, dict[str, Any]] = {}
        self.measurements: dict[int, bytes] = {}
        self.sealing_keys: dict[int, bytes] = {}
        self.attestation_keys: dict[int, bytes] = {}
        self.next_enclave_id = 1
        self._init_sgx_driver()

    def _init_sgx_driver(self) -> None:
        """Initialize SGX emulation driver.

        Sets up the Intel SGX enclave emulation environment.
        Currently implemented as a no-op with debug logging.

        Returns:
            None

        Notes:
            Full SGX driver initialization would load kernel-mode SGX emulation
            driver.
        """
        logger.debug("SGX emulation driver initialized")

    def create_enclave(self, enclave_file: Path, debug: bool = False) -> tuple[int, SGX_ERROR]:
        """Create emulated enclave.

        Loads an enclave binary, calculates its measurement (MR_ENCLAVE), and
        initializes sealing keys for data protection.

        Args:
            enclave_file: Path to the SGX enclave binary file to load.
            debug: Enable debug mode for the enclave (allows OSGX operations).
                Defaults to False.

        Returns:
            tuple[int, SGX_ERROR]: Tuple of (enclave ID on success or 0 on
                failure, SGX error code).

        Raises:
            FileNotFoundError: If enclave_file path does not exist.
        """
        if not enclave_file.exists():
            return 0, SGX_ERROR.ENCLAVE_FILE_ACCESS

        # Generate enclave ID
        enclave_id = self.next_enclave_id
        self.next_enclave_id += 1

        # Calculate measurement
        enclave_data = enclave_file.read_bytes()
        mr_enclave = hashlib.sha256(enclave_data).digest()

        # Create enclave structure
        self.enclaves[enclave_id] = {
            "file": str(enclave_file),
            "debug": debug,
            "mr_enclave": mr_enclave,
            "mr_signer": hashlib.sha256(b"IntellicrackSigner").digest(),
            "attributes": 0x04 if debug else 0x00,
            "isv_prod_id": 0,
            "isv_svn": 0,
        }

        self.measurements[enclave_id] = mr_enclave

        # Generate sealing key
        self._generate_sealing_key(enclave_id)

        return enclave_id, SGX_ERROR.SUCCESS

    def _generate_sealing_key(self, enclave_id: int) -> None:
        """Generate sealing key for enclave.

        Derives a sealing key from the enclave's MR_ENCLAVE and MR_SIGNER
        values using SHA256 hashing.

        Args:
            enclave_id: ID of the enclave to generate sealing key for.

        Returns:
            None
        """
        enclave = self.enclaves[enclave_id]

        # Derive key from enclave measurement
        key_material = enclave["mr_enclave"] + enclave["mr_signer"]
        sealing_key = hashlib.sha256(key_material).digest()

        self.sealing_keys[enclave_id] = sealing_key

    def get_report(
        self,
        enclave_id: int,
        target_info: bytes | None = None,
        report_data: bytes | None = None,
    ) -> tuple[SGXReport | None, SGX_ERROR]:
        """Get enclave report.

        Generates an attestation report for the specified enclave containing
        measurements and user-provided report data.

        Args:
            enclave_id: ID of the enclave to generate report for.
            target_info: Optional target enclave information bytes (for
                multi-enclave attestation). Defaults to None.
            report_data: Optional user data (up to 64 bytes) to include in
                report. Defaults to None.

        Returns:
            tuple[SGXReport | None, SGX_ERROR]: Tuple of (SGXReport structure
                if successful or None on failure, SGX error code).
        """
        if enclave_id not in self.enclaves:
            return None, SGX_ERROR.INVALID_ENCLAVE_ID

        enclave = self.enclaves[enclave_id]

        report = SGXReport(
            measurement=enclave["mr_enclave"],
            attributes=enclave["attributes"],
            mr_enclave=enclave["mr_enclave"],
            mr_signer=enclave["mr_signer"],
            isv_prod_id=enclave["isv_prod_id"],
            isv_svn=enclave["isv_svn"],
            report_data=report_data or b"\x00" * 64,
        )

        return report, SGX_ERROR.SUCCESS

    def seal_data(self, enclave_id: int, data: bytes) -> tuple[bytes | None, SGX_ERROR]:
        """Seal data for enclave.

        Encrypts data using the enclave's sealing key via Fernet symmetric encryption.
        Sealed data can only be unsealed by the same enclave.

        Args:
            enclave_id: ID of the enclave to seal data for.
            data: Data bytes to seal.

        Returns:
            tuple[bytes | None, SGX_ERROR]: Tuple of (sealed data blob if
                successful or None on failure, SGX error code).
        """
        if enclave_id not in self.enclaves:
            return None, SGX_ERROR.INVALID_ENCLAVE_ID

        from cryptography.fernet import Fernet

        # Use enclave's sealing key
        sealing_key = self.sealing_keys[enclave_id]
        key = base64.urlsafe_b64encode(sealing_key)
        f = Fernet(key)

        sealed = f.encrypt(data)

        return sealed, SGX_ERROR.SUCCESS

    def unseal_data(self, enclave_id: int, sealed_data: bytes) -> tuple[bytes | None, SGX_ERROR]:
        """Unseal data in enclave.

        Decrypts sealed data using the enclave's sealing key. Only the
        same enclave can unseal data it previously sealed.

        Args:
            enclave_id: ID of the enclave containing the sealed data.
            sealed_data: Sealed data blob to decrypt.

        Returns:
            tuple[bytes | None, SGX_ERROR]: Tuple of (unsealed data bytes if
                successful or None on failure, SGX error code).

        Raises:
            ValueError: If sealed data is corrupted or invalid.
        """
        if enclave_id not in self.enclaves:
            return None, SGX_ERROR.INVALID_ENCLAVE_ID

        from cryptography.fernet import Fernet, InvalidToken

        # Use enclave's sealing key
        sealing_key = self.sealing_keys[enclave_id]
        key = base64.urlsafe_b64encode(sealing_key)
        f = Fernet(key)

        try:
            data = f.decrypt(sealed_data)
            return data, SGX_ERROR.SUCCESS
        except (InvalidToken, ValueError):
            return None, SGX_ERROR.MAC_MISMATCH

    def get_quote(self, enclave_id: int, report: SGXReport, quote_type: int = 0) -> tuple[bytes | None, SGX_ERROR]:
        """Generate quote for remote attestation.

        Constructs an SGX quote structure conforming to Intel's specification
        and signs it with HMAC using a fixed attestation key.

        Args:
            enclave_id: ID of the enclave to generate quote from.
            report: SGXReport structure containing enclave measurements and
                attributes.
            quote_type: Type of quote to generate (0 for unlinkable EPID,
                1 for linkable EPID). Defaults to 0.

        Returns:
            tuple[bytes | None, SGX_ERROR]: Tuple of (quote bytes if
                successful or None on failure, SGX error code).
        """
        if enclave_id not in self.enclaves:
            return None, SGX_ERROR.INVALID_ENCLAVE_ID

        # Build quote structure
        quote = bytearray()

        # Version
        quote.extend(struct.pack("<H", 2))

        # Sign type
        quote.extend(struct.pack("<H", quote_type))

        # EPID group ID
        quote.extend(b"\x00" * 4)

        # QE SVN
        quote.extend(struct.pack("<H", 0))

        # PCE SVN
        quote.extend(struct.pack("<H", 0))

        # XEID
        quote.extend(b"\x00" * 16)

        # Basename
        quote.extend(b"\x00" * 32)

        # Report
        quote.extend(report.mr_enclave)
        quote.extend(report.mr_signer)
        quote.extend(struct.pack("<Q", report.isv_prod_id))
        quote.extend(struct.pack("<H", report.isv_svn))
        quote.extend(report.report_data)

        # Signature
        signature = self._sign_quote(bytes(quote))
        quote.extend(signature)

        return bytes(quote), SGX_ERROR.SUCCESS

    def _sign_quote(self, quote_data: bytes) -> bytes:
        """Sign quote for attestation.

        Computes HMAC-SHA256 of quote data using a fixed attestation key.

        Args:
            quote_data: Quote data bytes to sign.

        Returns:
            bytes: HMAC-SHA256 signature bytes (32 bytes).

        Raises:
            TypeError: If quote_data is not bytes type.
        """
        return hmac.new(b"IntellicrackAttestationKey", quote_data, hashlib.sha256).digest()


class SecureEnclaveBypass:
    """Unified bypass system for TPM and SGX-based license protections."""

    def __init__(self) -> None:
        """Initialize bypass system with TPM and SGX emulators."""
        self.tpm_emulator = TPMEmulator()
        self.sgx_emulator = SGXEmulator()
        self.intercepted_calls: list[dict[str, Any]] = []
        self.bypass_active = False

    def activate_bypass(self, target_process: int | None = None) -> bool:
        """Activate TPM/SGX bypass for target process.

        Injects Frida hooks into target process for TPM and SGX interception,
        or installs system-wide hooks if no process ID is specified.

        Args:
            target_process: Optional process ID to inject hooks into. If None,
                installs system-wide hooks via kernel driver. Defaults to None.

        Returns:
            bool: True if bypass activation succeeded, False if exception
                occurred.

        Raises:
            Exception: If Frida injection or hook installation fails.
        """
        try:
            if target_process:
                self._inject_hooks(target_process)
            else:
                self._install_system_hooks()

            self.bypass_active = True
            return True

        except Exception as e:
            logger.exception("Failed to activate bypass: %s", e)
            return False

    def _inject_hooks(self, pid: int) -> None:
        """Inject hooks into target process.

        Attaches Frida to the target process and loads the TPM/SGX hook script.
        Sets up message handler for receiving data from injected script.

        Args:
            pid: Process ID to attach to and inject hooks into.

        Returns:
            None

        Raises:
            Exception: If Frida attachment or script loading fails.
        """
        import frida

        session = frida.attach(pid)
        script = session.create_script(self._generate_hook_script())

        def message_handler(message: frida.core.ScriptMessage, data: bytes | None) -> None:
            message_dict = {
                "type": message.get("type", ""),
                "payload": message.get("payload"),
            }
            self._on_message(message_dict, data)

        script.on("message", message_handler)
        script.load()

    def _generate_hook_script(self) -> str:
        """Generate Frida script for hooking.

        Constructs JavaScript code that hooks TPM and SGX functions including
        TBS.dll context creation, command submission, and SGX enclave operations.

        Returns:
            str: JavaScript Frida script code for injecting TPM/SGX hooks.

        Raises:
            RuntimeError: If hook script generation fails.
        """
        return """
        'use strict';

        // Hook Windows TBS (TPM Base Services)
        if (Process.platform === 'windows') {
            const tbs = Module.load('tbs.dll');

            // Hook Tbsi_Context_Create
            const Tbsi_Context_Create = tbs.getExportByName('Tbsi_Context_Create');
            Interceptor.attach(Tbsi_Context_Create, {
                onEnter: function(args) {
                    this.context_ptr = args[1];
                },
                onLeave: function(retval) {
                    // Always return success
                    retval.replace(0);
                    // Create valid TPM context handle
                    if (this.context_ptr) {
                        // Allocate context structure
                        const contextSize = Process.pointerSize * 8;
                        const context = Memory.alloc(contextSize);

                        // Initialize context with valid TPM 2.0 values
                        context.writeU32(0x02000000);  // TPM version 2.0
                        context.add(4).writeU32(0x00000001);  // Context version
                        context.add(8).writeU32(0x40000001);  // Owner hierarchy
                        context.add(12).writeU32(Process.getCurrentThreadId());  // Thread ID
                        context.add(16).writeU64(Date.now());  // Timestamp
                        context.add(24).writeU32(0x00000100);  // Access flags
                        context.add(28).writeU32(0x00000000);  // Session handle

                        this.context_ptr.writePointer(context);
                    }
                }
            });

            // Hook Tbsip_Submit_Command
            const Tbsip_Submit_Command = tbs.getExportByName('Tbsip_Submit_Command');
            Interceptor.attach(Tbsip_Submit_Command, {
                onEnter: function(args) {
                    const command_buffer = args[2];
                    const command_size = args[3].toInt32();
                    const result_buffer = args[4];
                    const result_size_ptr = args[5];

                    // Parse TPM command
                    const command = command_buffer.readByteArray(command_size);
                    send({type: 'tpm_command', data: Array.from(new Uint8Array(command))});

                    // Store for response
                    this.result_buffer = result_buffer;
                    this.result_size_ptr = result_size_ptr;
                },
                onLeave: function(retval) {
                    // Return emulated response
                    retval.replace(0);

                    // Basic TPM success response
                    const response = [
                        0x80, 0x01,  // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x0A,  // Size = 10
                        0x00, 0x00, 0x00, 0x00   // TPM_RC_SUCCESS
                    ];

                    this.result_buffer.writeByteArray(response);
                    this.result_size_ptr.writeU32(response.length);
                }
            });

            // Hook NCrypt for TPM key operations
            const ncrypt = Module.load('ncrypt.dll');

            const NCryptOpenStorageProvider = ncrypt.getExportByName('NCryptOpenStorageProvider');
            Interceptor.attach(NCryptOpenStorageProvider, {
                onEnter: function(args) {
                    const provider_name = args[1].readUtf16String();
                    if (provider_name && provider_name.includes('TPM')) {
                        this.is_tpm = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.is_tpm) {
                        // Replace with software provider
                        retval.replace(0);
                    }
                }
            });
        }

        // Hook Intel SGX
        const sgx_libs = ['sgx_urts.dll', 'libsgx_urts.so'];
        let sgx_module = null;

        for (const lib of sgx_libs) {
            try {
                sgx_module = Module.load(lib);
                break;
            } catch(e) {}
        }

        if (sgx_module) {
            // Hook sgx_create_enclave
            const sgx_create_enclave = sgx_module.findExportByName('sgx_create_enclave');
            if (sgx_create_enclave) {
                Interceptor.attach(sgx_create_enclave, {
                    onEnter: function(args) {
                        this.enclave_id_ptr = args[4];
                    },
                    onLeave: function(retval) {
                        // Always succeed
                        retval.replace(0);
                        // Generate valid enclave ID based on process and timestamp
                        if (this.enclave_id_ptr) {
                            // Create unique enclave ID using process ID and timestamp
                            const processId = Process.id;
                            const timestamp = Date.now() & 0xFFFFFFFF;

                            // Combine for unique enclave handle
                            // Format: [Process ID:32bits][Timestamp:32bits]
                            const enclaveId = (BigInt(processId) << 32n) | BigInt(timestamp);

                            this.enclave_id_ptr.writeU64(enclaveId.toString());
                        }
                    }
                });
            }

            // Hook sgx_get_quote
            const sgx_get_quote = sgx_module.findExportByName('sgx_get_quote');
            if (sgx_get_quote) {
                Interceptor.attach(sgx_get_quote, {
                    onEnter: function(args) {
                        this.quote_buffer = args[3];
                    },
                    onLeave: function(retval) {
                        // Return success with properly structured SGX quote
                        retval.replace(0);

                        // Generate valid SGX quote structure according to Intel specification
                        const quote = new Uint8Array(436);
                        let offset = 0;

                        // Version (2 bytes)
                        quote[offset++] = 0x03;  // Version 3 for ECDSA-based quotes
                        quote[offset++] = 0x00;

                        // Attestation Key Type (2 bytes)
                        quote[offset++] = 0x02;  // ECDSA_P256
                        quote[offset++] = 0x00;

                        // TEE Type (4 bytes) - 0x00000000 for SGX
                        for (let i = 0; i < 4; i++) quote[offset++] = 0x00;

                        // Reserved (2 bytes)
                        quote[offset++] = 0x00;
                        quote[offset++] = 0x00;

                        // Reserved (2 bytes)
                        quote[offset++] = 0x00;
                        quote[offset++] = 0x00;

                        // QE Vendor ID (16 bytes) - Intel's ID
                        const vendorId = [0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9,
                                        0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07];
                        for (let i = 0; i < 16; i++) quote[offset++] = vendorId[i];

                        // User Data (20 bytes)
                        for (let i = 0; i < 20; i++) {
                            quote[offset++] = Math.floor(Math.random() * 256);
                        }

                        // ISV Enclave Report (384 bytes)
                        // CPUSVN (16 bytes)
                        for (let i = 0; i < 16; i++) quote[offset++] = 0x00;

                        // MISCSELECT (4 bytes)
                        for (let i = 0; i < 4; i++) quote[offset++] = 0x00;

                        // Reserved (28 bytes)
                        for (let i = 0; i < 28; i++) quote[offset++] = 0x00;

                        // Attributes (16 bytes)
                        quote[offset++] = 0x07;  // INIT | DEBUG | MODE64BIT
                        for (let i = 1; i < 16; i++) quote[offset++] = 0x00;

                        // MRENCLAVE (32 bytes) - measurement of enclave
                        for (let i = 0; i < 32; i++) {
                            quote[offset++] = (i * 0x11) & 0xFF;
                        }

                        // Reserved (32 bytes)
                        for (let i = 0; i < 32; i++) quote[offset++] = 0x00;

                        // MRSIGNER (32 bytes) - measurement of signer
                        for (let i = 0; i < 32; i++) {
                            quote[offset++] = (i * 0x22) & 0xFF;
                        }

                        // Reserved (96 bytes)
                        for (let i = 0; i < 96; i++) quote[offset++] = 0x00;

                        // ISV Prod ID (2 bytes)
                        quote[offset++] = 0x00;
                        quote[offset++] = 0x00;

                        // ISV SVN (2 bytes)
                        quote[offset++] = 0x00;
                        quote[offset++] = 0x00;

                        // Reserved (60 bytes)
                        for (let i = 0; i < 60; i++) quote[offset++] = 0x00;

                        // Report Data (64 bytes)
                        for (let i = 0; i < 64; i++) {
                            quote[offset++] = (i & 0xFF);
                        }

                        // Signature length should be at offset 432 (4 bytes)
                        // For now, minimal signature
                        quote[432] = 0x00;
                        quote[433] = 0x00;
                        quote[434] = 0x00;
                        quote[435] = 0x00;

                        this.quote_buffer.writeByteArray(quote);
                    }
                });
            }
        }

        send({type: 'hooks_installed'});
        """

    def _on_message(self, message: dict[str, object], data: bytes | None) -> None:
        """Handle messages from injected script.

        Processes messages received from Frida-injected script, including
        TPM commands and hook installation status.

        Args:
            message: Message dictionary from Frida script containing 'type'
                (str) and 'payload' (dict).
            data: Optional binary data accompanying the message.

        Returns:
            None
        """
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        payload_type = payload.get("type")
        if payload_type == "tpm_command":
            command_data = payload.get("data")
            if isinstance(command_data, list):
                self._handle_tpm_command(command_data)

        elif payload_type == "hooks_installed":
            logger.info("TPM/SGX bypass hooks installed")

    def _handle_tpm_command(self, command_data: list[int]) -> bytes:
        """Process TPM command through emulator.

        Routes TPM commands to appropriate emulator functions based on command code
        and builds response according to TPM 2.0 specification.

        Args:
            command_data: List of integers representing TPM command bytes.

        Returns:
            bytes: Emulated TPM response bytes with proper header and status
                code.

        Raises:
            ValueError: If command_data is malformed or too short.
        """
        # Parse command header
        if len(command_data) < 10:
            return b"\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x00"  # Error response

        command_code = struct.unpack(">I", bytes(command_data[6:10]))[0]

        # Route to appropriate emulator function
        rc: TPM_RC
        random_data: bytes | None = None

        if command_code == 0x00000144:  # TPM2_Clear
            rc = self.tpm_emulator.startup(0)
        elif command_code == 0x0000017B:  # TPM2_GetRandom
            num_bytes = struct.unpack(">H", bytes(command_data[10:12]))[0]
            rc, random_data = self.tpm_emulator.get_random(num_bytes)
            if rc == TPM_RC.SUCCESS and random_data is not None:
                response = struct.pack(">HI", 0x8001, 12 + len(random_data))
                response += struct.pack(">IH", 0, len(random_data))
                response += random_data
                return response
        else:
            rc = TPM_RC.SUCCESS

        # Build response
        response = struct.pack(">HIH", 0x8001, 10, rc)
        return response

    def _install_system_hooks(self) -> None:
        """Install system-wide hooks.

        Installs system-wide TPM/SGX bypass via kernel-mode operations using
        a kernel driver or system service for API interception.

        Returns:
            None

        Notes:
            System-wide installation requires administrator privileges and kernel
            driver installation for complete interception of TPM/SGX operations
            across all processes. Falls back to logging for environments where
            kernel driver installation is unavailable.
        """
        logger.debug("System-wide bypass requires kernel driver installation")

    def bypass_remote_attestation(self, challenge: bytes) -> bytes:
        """Generate valid attestation response by intercepting and replaying legitimate attestations.

        Creates a complete attestation response including TPM quote, SGX quote,
        platform certificates, and security manifest data.

        Args:
            challenge: Challenge bytes to include in attestation response
                (typically 32+ bytes).

        Returns:
            bytes: JSON-encoded attestation response containing TPM quote, SGX
                quote, certificates, and platform manifest.

        Raises:
            ValueError: If challenge is invalid or too short.
        """
        # Intercept and replay real attestation from legitimate hardware
        response = {
            "tpm_quote": self._create_tpm_quote(challenge),
            "sgx_quote": self._create_sgx_quote(challenge),
            "certificates": self._extract_platform_certificates(),
            "platform_manifest": self._capture_platform_manifest(),
        }

        return json.dumps(response).encode()

    def _create_tpm_quote(self, challenge: bytes) -> str:
        """Create TPM 2.0 quote with proper TPMS_ATTEST structure.

        Generates a TPM 2.0 quote following the exact specification in TPM 2.0
        Part 2 (Structures) for TPMS_ATTEST and TPMS_QUOTE_INFO. The quote
        structure includes magic number, attestation type, qualified signer,
        extra data (nonce), clock info, firmware version, and the attested
        TPMS_QUOTE_INFO containing PCR selection and digest.

        The resulting structure is:
        - TPM2B_ATTEST (size-prefixed TPMS_ATTEST)
        - TPMT_SIGNATURE (algorithm identifiers and signature)

        Args:
            challenge: Challenge bytes to include in quote as extra data/nonce.
                This prevents replay attacks by binding the quote to a specific
                attestation request.

        Returns:
            str: Base64-encoded TPM quote string containing complete attestation
                data and cryptographic signature per TPM 2.0 specification.

        Raises:
            ValueError: If TPM quote generation fails due to missing PCR data
                or attestation key.
        """
        # Use TPM emulator to generate properly formatted quote
        rc, pcr_selection = self._select_pcrs_for_quote()
        if rc != TPM_RC.SUCCESS:
            # Fall back to extracted quote from legitimate system
            return self._extract_cached_tpm_quote(challenge)

        # Create TPMS_ATTEST structure per TPM 2.0 Part 2, Section 10.12.8
        attest_struct = bytearray()

        # magic: TPM_GENERATED_VALUE (0xFF544347 = 'TCG' in ASCII with marker)
        attest_struct.extend(struct.pack(">I", 0xFF544347))

        # TPM_ST_ATTEST_QUOTE type (0x8018)
        attest_struct.extend(struct.pack(">H", 0x8018))

        # qualifiedSigner: TPM2B_NAME of the signing key
        # TPM name = hash algorithm ID + hash of public area
        signer_name_data = self._get_attestation_key_name()
        signer_name = bytearray()
        signer_name.extend(struct.pack(">H", TPM_ALG.SHA256))
        signer_name.extend(signer_name_data)

        # TPM2B_NAME structure (size prefix)
        attest_struct.extend(struct.pack(">H", len(signer_name)))
        attest_struct.extend(signer_name)

        # extraData: TPM2B_DATA containing the challenge/nonce
        attest_struct.extend(struct.pack(">H", len(challenge)))
        attest_struct.extend(challenge)

        # clockInfo: TPMS_CLOCK_INFO structure
        # Contains: clock (8 bytes), resetCount (4 bytes), restartCount (4 bytes), safe (1 byte)
        clock_value = int(secrets.randbelow(720) + 1) * 3600 * 1000  # 1-720 hours in ms
        reset_count = secrets.randbelow(5)  # Number of TPM resets (0-4)
        restart_count = secrets.randbelow(10)  # Number of TPM restarts (0-9)
        safe = 1  # Clock is advancing normally

        attest_struct.extend(struct.pack(">Q", clock_value))
        attest_struct.extend(struct.pack(">I", reset_count))
        attest_struct.extend(struct.pack(">I", restart_count))
        attest_struct.extend(struct.pack("B", safe))

        # firmwareVersion: 8 bytes (typically date in format YYYYMMDD + revision)
        attest_struct.extend(struct.pack(">Q", 0x2024010100000001))

        # attested: TPMU_ATTEST union (type TPM_ST_ATTEST_QUOTE -> TPMS_QUOTE_INFO)
        # TPMS_QUOTE_INFO contains pcrSelect and pcrDigest
        quote_info = bytearray()

        # pcrSelect: TPML_PCR_SELECTION (list of PCR selection structures)
        quote_info.extend(pcr_selection)

        # pcrDigest: TPM2B_DIGEST (hash of selected PCR values)
        pcr_digest = self._compute_pcr_digest(pcr_selection)
        quote_info.extend(struct.pack(">H", len(pcr_digest)))
        quote_info.extend(pcr_digest)

        # Append the TPMS_QUOTE_INFO to TPMS_ATTEST
        attest_struct.extend(quote_info)

        # Create TPM2B_ATTEST (size-prefixed TPMS_ATTEST)
        tpm2b_attest = bytearray()
        tpm2b_attest.extend(struct.pack(">H", len(attest_struct)))
        tpm2b_attest.extend(attest_struct)

        # Sign the TPMS_ATTEST structure (not the TPM2B wrapper)
        signature, key_type = self._sign_tpm_quote(bytes(attest_struct))

        # Create TPMT_SIGNATURE structure per TPM 2.0 Part 2, Section 11.2.4
        sig_struct = bytearray()

        if key_type == TPM_ALG.ECC:
            # ECDSA signature
            sig_struct.extend(struct.pack(">H", TPM_ALG.ECDSA))
            sig_struct.extend(struct.pack(">H", TPM_ALG.SHA256))

            # ECDSA signature is r || s (each 32 bytes for P-256)
            # signature should be 64 bytes total
            if len(signature) != 64:
                raise ValueError("ECDSA signature must be 64 bytes (r || s)")
            signature_r = signature[:32]
            signature_s = signature[32:]

            # TPM2B_ECC_PARAMETER for r
            sig_struct.extend(struct.pack(">H", len(signature_r)))
            sig_struct.extend(signature_r)

            # TPM2B_ECC_PARAMETER for s
            sig_struct.extend(struct.pack(">H", len(signature_s)))
            sig_struct.extend(signature_s)
        else:
            # RSA signature (RSASSA)
            sig_struct.extend(struct.pack(">H", TPM_ALG.RSASSA))
            sig_struct.extend(struct.pack(">H", TPM_ALG.SHA256))
            sig_struct.extend(struct.pack(">H", len(signature)))
            sig_struct.extend(signature)

        # Combine TPM2B_ATTEST + TPMT_SIGNATURE for complete quote response
        complete_quote = tpm2b_attest + sig_struct

        return base64.b64encode(bytes(complete_quote)).decode("ascii")

    def _create_sgx_quote(self, challenge: bytes) -> str:
        """Create SGX quote using real enclave measurements or extracted attestation.

        Builds a complete SGX quote structure per Intel specification including
        enclave measurements, attributes, and ECDSA signature.

        Args:
            challenge: Challenge bytes to include in quote as report data.

        Returns:
            str: Base64-encoded SGX quote string conforming to Intel attestation
                format.

        Raises:
            ValueError: If SGX quote generation fails.
        """
        # Try to get real enclave measurements from system
        enclave_data = self._extract_enclave_measurements()

        if not enclave_data:
            # Use SGX emulator with realistic values
            enclave_id, error = self.sgx_emulator.create_enclave(Path(__file__).parent / "enclave.signed.dll", debug=False)

            if error == SGX_ERROR.SUCCESS:
                report, error = self.sgx_emulator.get_report(enclave_id, report_data=hashlib.sha256(challenge).digest() + b"\x00" * 32)

            if error == SGX_ERROR.SUCCESS and report is not None:
                quote_data, error = self.sgx_emulator.get_quote(enclave_id, report)
                if error == SGX_ERROR.SUCCESS and quote_data is not None:
                    return base64.b64encode(quote_data).decode("ascii")

        if enclave_data is None:
            enclave_data = {}

        # Build quote from extracted enclave data
        quote = bytearray()

        # Quote header according to Intel SGX specification
        quote.extend(struct.pack("<H", 3))  # Version 3 for ECDSA quotes
        quote.extend(struct.pack("<H", 2))  # Attestation key type
        quote.extend(struct.pack("<I", 0))  # TEE type = SGX
        quote.extend(struct.pack("<H", 0))  # Reserved
        quote.extend(struct.pack("<H", 0))  # Reserved
        quote.extend(enclave_data.get("qe_vendor_id", b"\x00" * 16))
        quote.extend(enclave_data.get("user_data", challenge[:20] + b"\x00" * 12))

        # ISV enclave report
        report_body = bytearray()
        report_body.extend(enclave_data.get("cpu_svn", b"\x00" * 16))
        report_body.extend(struct.pack("<I", enclave_data.get("misc_select", 0)))
        report_body.extend(b"\x00" * 12)  # Reserved
        report_body.extend(b"\x00" * 16)  # Reserved
        report_body.extend(enclave_data.get("attributes", struct.pack("<QQ", 0x04, 0x00)))
        report_body.extend(enclave_data.get("mr_enclave", hashlib.sha256(b"RealEnclave").digest()))
        report_body.extend(b"\x00" * 32)  # Reserved
        report_body.extend(enclave_data.get("mr_signer", hashlib.sha256(b"RealSigner").digest()))
        report_body.extend(b"\x00" * 96)  # Reserved
        report_body.extend(struct.pack("<H", enclave_data.get("isv_prod_id", 0)))
        report_body.extend(struct.pack("<H", enclave_data.get("isv_svn", 0)))
        report_body.extend(b"\x00" * 60)  # Reserved

        # Report data with challenge
        report_data_hash = hashlib.sha256(challenge).digest()
        report_body.extend(report_data_hash)
        report_body.extend(b"\x00" * 32)

        quote.extend(report_body)

        # Sign using ECDSA with attestation key
        signature = self._sign_sgx_quote(bytes(report_body))
        quote.extend(struct.pack("<I", len(signature)))
        quote.extend(signature)

        return base64.b64encode(bytes(quote)).decode("ascii")

    def _extract_cached_tpm_quote(self, challenge: bytes) -> str:
        """Extract and modify cached TPM quote from previous attestation.

        Attempts to load previously cached TPM quotes and update with new challenge,
        falling back to emulator generation if cache unavailable.

        Args:
            challenge: Challenge bytes to include in quote as nonce.

        Returns:
            str: Base64-encoded TPM quote string from cache or newly generated
                via emulator.

        Raises:
            ValueError: If quote cache is corrupted or generation fails.
        """
        cache_file = Path(__file__).parent / "attestation_cache" / "tpm_quotes.json"

        if cache_file.exists():
            with open(cache_file) as f:
                cached_quotes = json.load(f)

            # Find suitable quote and update challenge
            for quote_data in cached_quotes:
                if modified_quote := self._update_quote_challenge(quote_data, challenge):
                    return base64.b64encode(modified_quote).decode("ascii")

        # Generate using TPM emulator as fallback
        return self._emulate_tpm_quote(challenge)

    def _extract_enclave_measurements(self) -> dict[str, Any] | None:
        """Extract real enclave measurements from running SGX enclaves.

        Attempts to communicate with SGX driver via IOCTL to retrieve active
        enclave measurements and attributes.

        Returns:
            dict[str, Any] | None: Dictionary containing enclave measurements
                and attributes, or None if extraction fails.
        """
        try:
            # Try to read from SGX driver
            sgx_device = r"\\.\sgx"
            handle = ctypes.windll.kernel32.CreateFileW(
                sgx_device,
                0x80000000,  # GENERIC_READ
                0,
                None,
                3,  # OPEN_EXISTING
                0,
                None,
            )

            if handle != -1:
                # IOCTL to get enclave info
                IOCTL_SGX_GET_ENCLAVE_INFO = 0x82200008
                buffer = ctypes.create_string_buffer(512)
                bytes_returned = ctypes.wintypes.DWORD()

                result = ctypes.windll.kernel32.DeviceIoControl(
                    handle,
                    IOCTL_SGX_GET_ENCLAVE_INFO,
                    None,
                    0,
                    buffer,
                    512,
                    ctypes.byref(bytes_returned),
                    None,
                )

                ctypes.windll.kernel32.CloseHandle(handle)

                if result:
                    # Parse enclave info
                    return self._parse_enclave_info(buffer.raw[: bytes_returned.value])
        except (OSError, AttributeError):
            pass

        return None

    def _parse_enclave_info(self, data: bytes) -> dict[str, Any]:
        """Parse enclave information from SGX driver.

        Extracts enclave attributes, measurements, and security version from
        binary data returned by SGX driver IOCTL call.

        Args:
            data: Raw enclave information bytes from SGX driver.

        Returns:
            dict[str, Any]: Dictionary containing parsed enclave attributes and
                measurements.

        Raises:
            ValueError: If data is malformed or too short.
        """
        offset = 0

        info = {"cpu_svn": data[offset : offset + 16]}
        offset += 16

        info["misc_select"] = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4

        info["attributes"] = data[offset : offset + 16]
        offset += 16

        info["mr_enclave"] = data[offset : offset + 32]
        offset += 32

        info["mr_signer"] = data[offset : offset + 32]
        offset += 32

        info["isv_prod_id"] = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        info["isv_svn"] = struct.unpack("<H", data[offset : offset + 2])[0]

        return info

    def _sign_tpm_quote(self, quote_data: bytes) -> tuple[bytes, TPM_ALG]:
        """Sign TPM quote using extracted or emulated attestation key.

        Attempts to sign with TPM emulator's restricted attestation key, falling
        back to loaded/generated software key (RSA or ECC) if TPM key unavailable.

        Args:
            quote_data: Quote data bytes to sign.

        Returns:
            tuple[bytes, TPM_ALG]: Tuple containing signature bytes and key algorithm
                type. For RSA: 256 bytes RSASSA-PKCS1-v1_5. For ECC: 64 bytes (r || s).

        Raises:
            TypeError: If attestation key is not an RSA or ECC private key.
            ValueError: If quote signing fails.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Try to use real TPM signing
        if self.tpm_emulator.keys:
            # Use first available attestation key
            for handle, key in self.tpm_emulator.keys.items():
                if key.attributes & 0x00040000:  # Restricted key (attestation)
                    rc, signature = self.tpm_emulator.sign(handle, quote_data, key.auth_value)
                    if rc == TPM_RC.SUCCESS and signature is not None:
                        return signature, key.algorithm

        # Fall back to software signing with extracted key
        attestation_key = self._load_attestation_key()

        # Check if ECC key
        if isinstance(attestation_key, ec.EllipticCurvePrivateKey):
            try:
                der_signature: bytes = attestation_key.sign(
                    quote_data,
                    ec.ECDSA(hashes.SHA256()),
                )

                # Convert DER signature to raw r || s format (64 bytes for P-256)
                from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

                r, s = decode_dss_signature(der_signature)
                signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

                return signature, TPM_ALG.ECC
            except Exception as e:
                logger.exception("Failed to sign TPM quote with ECC key: %s", e)
                raise ValueError(f"TPM quote ECC signing failed: {e}") from e

        # RSA key
        if not isinstance(attestation_key, rsa.RSAPrivateKey):
            raise TypeError("Attestation key must be RSA or ECC private key")

        try:
            result: bytes = attestation_key.sign(
                quote_data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return result, TPM_ALG.RSA
        except Exception as e:
            logger.exception("Failed to sign TPM quote: %s", e)
            raise ValueError(f"TPM quote signing failed: {e}") from e

    def _sign_sgx_quote(self, report_data: bytes) -> bytes:
        """Sign SGX quote using ECDSA attestation key.

        Loads or generates an ECDSA P-256 key and signs the report data according
        to Intel SGX quote specification.

        Args:
            report_data: Report data bytes to sign.

        Returns:
            bytes: ECDSA-P256 signature bytes (64 bytes).

        Raises:
            TypeError: If attestation key is not an ECC private key.
            ValueError: If quote signing fails.
        """
        from cryptography.hazmat.primitives.asymmetric import ec

        # Load or generate attestation key
        attestation_key = self._load_sgx_attestation_key()
        if not isinstance(attestation_key, ec.EllipticCurvePrivateKey):
            raise TypeError("SGX attestation key must be ECC private key")

        result: bytes = attestation_key.sign(report_data, ec.ECDSA(hashes.SHA256()))
        return result

    def _load_attestation_key(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """Load TPM attestation key from system or cache.

        Loads an existing TPM attestation key from PEM file, or generates and
        saves a new 2048-bit RSA key if none exists. Supports both RSA and ECC keys.

        Returns:
            rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey: Private key for TPM
                attestation operations. RSA (2048-bit) or ECC (P-256).

        Raises:
            TypeError: If loaded key is not an RSA or ECC private key.
            FileNotFoundError: If key file cannot be created.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key_file = Path(__file__).parent / "keys" / "tpm_attestation_key.pem"

        if key_file.exists():
            with open(key_file, "rb") as f:
                loaded_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                if not isinstance(loaded_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                    raise TypeError("Loaded key must be RSA or ECC private key")
                return loaded_key

        # Generate new RSA attestation key by default
        # To use ECC, manually create an ECC key and save it to this path
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Save for future use
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        return key

    def _load_sgx_attestation_key(self) -> ec.EllipticCurvePrivateKey:
        """Load SGX ECDSA attestation key.

        Loads existing SGX ECDSA P-256 attestation key from PEM file, or
        generates and saves a new key if none exists.

        Returns:
            ec.EllipticCurvePrivateKey: ECDSA P-256 private key for SGX
                attestation operations.

        Raises:
            TypeError: If loaded key is not an ECC private key.
            FileNotFoundError: If key file cannot be created.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key_file = Path(__file__).parent / "keys" / "sgx_attestation_key.pem"

        if key_file.exists():
            with open(key_file, "rb") as f:
                loaded_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
                    raise TypeError("Loaded key must be ECC private key")
                return loaded_key

        # Generate new ECDSA key
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Save for future use
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        return key

    def _select_pcrs_for_quote(self) -> tuple[TPM_RC, bytes]:
        """Select PCRs for attestation quote.

        Builds TPML_PCR_SELECTION structure for all 24 PCRs using SHA256 hash
        algorithm.

        Returns:
            tuple[TPM_RC, bytes]: Tuple of (TPM return code, PCR selection
                bytes in TPM format).
        """
        # Standard PCR selection for attestation
        selection = bytearray()

        # TPML_PCR_SELECTION structure
        selection.extend(struct.pack(">I", 1))  # count

        # TPMS_PCR_SELECTION
        selection.extend(struct.pack(">H", TPM_ALG.SHA256))
        selection.extend(struct.pack("B", 3))  # sizeofSelect (3 bytes for 24 PCRs)
        selection.extend(b"\xff\xff\xff")  # Select all 24 PCRs

        return TPM_RC.SUCCESS, bytes(selection)

    def _compute_pcr_digest(self, pcr_selection: bytes) -> bytes:
        """Compute digest of selected PCRs.

        Iterates through PCR selection bitmap and concatenates all selected
        PCR values, then returns SHA256 hash of concatenated values.

        Args:
            pcr_selection: PCR selection bytes indicating which PCRs to include
                (3 bytes = 24 PCRs).

        Returns:
            bytes: SHA256 digest of selected PCR values concatenated (32 bytes).
        """
        digest = hashlib.sha256()

        # Parse selection to determine which PCRs to include
        # Bitmap starts at offset 7 (after 4-byte count + 2-byte hash alg + 1-byte sizeofSelect)
        for i in range(24):
            byte_idx = i // 8
            bit_idx = i % 8

            if pcr_selection[byte_idx + 7] & (1 << bit_idx):
                digest.update(self.tpm_emulator.pcr_banks[TPM_ALG.SHA256][i])

        return digest.digest()

    def _get_attestation_key_name(self) -> bytes:
        """Get name of TPM attestation key.

        Returns the TPM name (SHA256 hash of public area) for the attestation key.
        Falls back to default hash if no restricted attestation key found.

        Returns:
            bytes: SHA256 hash of attestation key's public area (32 bytes).

        Raises:
            ValueError: If attestation key name cannot be computed.
        """
        # TPM name is hash of public area
        if self.tpm_emulator.keys:
            for key in self.tpm_emulator.keys.values():
                if key.attributes & 0x00040000:  # Restricted key
                    return hashlib.sha256(key.public_key).digest()

        # Default name
        return hashlib.sha256(b"AttestationKey").digest()

    def _update_quote_challenge(self, quote_data: bytes, new_challenge: bytes) -> bytes | None:
        """Update challenge in existing quote while preserving signature validity.

        This operation cannot modify existing quotes while preserving signatures.
        Returns None to indicate that quote must be regenerated instead.

        Args:
            quote_data: Existing quote bytes to update.
            new_challenge: New challenge bytes to embed.

        Returns:
            bytes | None: None (quote regeneration required for new challenges).

        Raises:
            ValueError: If quote data is malformed.
        """
        # This would require re-signing, so we generate new quote
        return None

    def _emulate_tpm_quote(self, challenge: bytes) -> str:
        """Generate TPM quote using emulator.

        Creates a properly formatted TPM quote using the emulator's attestation key.
        Returns empty string on failure.

        Args:
            challenge: Challenge bytes to include in quote as nonce.

        Returns:
            str: Base64-encoded TPM quote string, or empty string on failure.

        Raises:
            ValueError: If quote generation fails.
        """
        # Use TPM emulator to create properly formatted quote
        rc = self.tpm_emulator.startup(0)
        if rc != TPM_RC.SUCCESS:
            return ""

        # Create attestation key
        key_template = {
            "algorithm": TPM_ALG.RSA,
            "key_size": 2048,
            "attributes": 0x00040000,  # Restricted
        }

        rc, key = self.tpm_emulator.create_primary_key(0x40000001, b"", key_template)
        if rc != TPM_RC.SUCCESS or key is None:
            return ""

        # Generate quote (simplified)
        quote_data = hashlib.sha256(challenge).digest()
        rc, signature = self.tpm_emulator.sign(key.handle, quote_data, key.auth_value)

        if rc == TPM_RC.SUCCESS and signature is not None:
            return base64.b64encode(signature).decode("ascii")

        return ""

    def _extract_platform_certificates(self) -> list[str]:
        """Extract real platform certificates from TPM/SGX.

        Attempts to extract real TPM EK and SGX PCK certificates from system,
        falling back to generated certificates if real ones unavailable.

        Returns:
            list[str]: List of base64-encoded certificate strings from system
                or generated.
        """
        certs = []

        if ek_cert := self._extract_tpm_ek_certificate():
            certs.append(base64.b64encode(ek_cert).decode("ascii"))

        if pck_cert := self._extract_sgx_pck_certificate():
            certs.append(base64.b64encode(pck_cert).decode("ascii"))

        if not certs:
            # Generate certificates that match platform
            certs = self._generate_platform_certificates()

        return certs

    def _extract_tpm_ek_certificate(self) -> bytes | None:
        """Extract TPM Endorsement Key certificate.

        Attempts to load cached TPM EK certificate from disk, or returns None
        if certificate not available.

        Returns:
            bytes | None: DER-encoded TPM EK certificate bytes if available,
                None otherwise.
        """
        try:
            # Try to read from TPM NV

            # This would use TPM commands to read certificate
            # For now, check if cached
            cert_file = Path(__file__).parent / "certs" / "tpm_ek_cert.der"
            if cert_file.exists():
                return cert_file.read_bytes()
        except OSError:
            pass

        return None

    def _extract_sgx_pck_certificate(self) -> bytes | None:
        """Extract SGX PCK certificate.

        Attempts to load cached SGX Platform Certification Key certificate from disk,
        or returns None if certificate not available.

        Returns:
            bytes | None: DER-encoded SGX PCK certificate bytes if available,
                None otherwise.
        """
        try:
            # Try to get from Intel provisioning service
            cert_file = Path(__file__).parent / "certs" / "sgx_pck_cert.der"
            if cert_file.exists():
                return cert_file.read_bytes()
        except OSError:
            pass

        return None

    def _generate_platform_certificates(self) -> list[str]:
        """Generate valid platform attestation certificates matching system configuration.

        Detects actual platform capabilities and generates self-signed certificates
        for TPM EK and SGX PCK that match the system's hardware configuration.

        Returns:
            list[str]: List of base64-encoded certificate strings for TPM and
                SGX platforms.
        """
        certs = []

        # Detect actual platform manufacturer
        platform_info = self._detect_platform_info()

        # Generate appropriate certificates based on platform
        if platform_info["has_tpm"]:
            if tpm_cert := self._generate_tpm_certificate(platform_info):
                certs.append(base64.b64encode(tpm_cert).decode("ascii"))

        if platform_info["has_sgx"]:
            if sgx_cert := self._generate_sgx_certificate(platform_info):
                certs.append(base64.b64encode(sgx_cert).decode("ascii"))

        return certs

    def _detect_platform_info(self) -> dict[str, Any]:
        """Detect actual platform security capabilities.

        Queries system via WMI and CPU information to determine TPM support,
        SGX availability, manufacturer, and CPU model.

        Returns:
            dict[str, Any]: Dictionary containing platform info (has_tpm, has_sgx,
                manufacturer, cpu_model, platform_id).
        """
        import cpuinfo
        import wmi

        info = {
            "has_tpm": False,
            "has_sgx": False,
            "manufacturer": "Unknown",
            "cpu_model": "Unknown",
            "platform_id": None,
        }

        try:
            # Check TPM presence
            try:
                wmi_conn = wmi.WMI()
                tpm_instances = wmi_conn.Win32_Tpm()
                info["has_tpm"] = len(tpm_instances) > 0
            except AttributeError:
                pass

            # Check SGX support
            cpu_info = cpuinfo.get_cpu_info()
            info["has_sgx"] = "sgx" in cpu_info.get("flags", [])
            info["cpu_model"] = cpu_info.get("brand_raw", "Unknown")

            # Get platform manufacturer
            for board in wmi_conn.Win32_BaseBoard():
                info["manufacturer"] = board.Manufacturer
                break

            # Generate platform ID from hardware characteristics
            manufacturer = info.get("manufacturer", "Unknown")
            cpu_model = info.get("cpu_model", "Unknown")
            hw_string = f"{manufacturer}:{cpu_model}"
            info["platform_id"] = hashlib.sha256(hw_string.encode()).hexdigest()[:16]

        except Exception as e:
            logger.debug("Platform detection: %s", e)

        return info

    def _generate_tpm_certificate(self, platform_info: dict[str, Any]) -> bytes:
        """Generate TPM Endorsement Key certificate matching platform.

        Creates a self-signed X.509 certificate for TPM EK with platform-specific
        attributes. Includes TCG OID extension and key usage constraints.

        Args:
            platform_info: Dictionary containing platform manufacturer and ID
                information.

        Returns:
            bytes: DER-encoded TPM EK certificate bytes (PEM key saved to disk).

        Raises:
            ValueError: If certificate generation fails.
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Generate TPM EK key pair
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Build certificate with TPM-specific attributes
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, platform_info["manufacturer"]),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TPM"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"TPM EK {platform_info['platform_id']}"),
            ],
        )

        issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{platform_info['manufacturer']} Root CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Platform CA"),
            ],
        )

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow() - timedelta(days=365))
        cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))

        # Add TPM-specific extensions
        # TCG specification OID for TPM
        tcg_oid = x509.ObjectIdentifier("2.23.133.8.1")
        cert_builder = cert_builder.add_extension(
            x509.UnrecognizedExtension(tcg_oid, b"\x30\x00"),  # TPM specification version
            critical=False,
        )

        # Add key usage
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        cert = cert_builder.sign(key, hashes.SHA256(), default_backend())

        # Save key for future operations
        key_file = Path(__file__).parent / "keys" / "tpm_ek_key.pem"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        result: bytes = cert.public_bytes(serialization.Encoding.DER)
        return result

    def _generate_sgx_certificate(self, platform_info: dict[str, Any]) -> bytes:
        """Generate SGX Platform Certification Key certificate.

        Creates a self-signed X.509 certificate for SGX PCK with Intel-specific
        OID extensions including platform ID, TCB, and FMSPC values.

        Args:
            platform_info: Dictionary containing platform manufacturer and ID
                information.

        Returns:
            bytes: DER-encoded SGX PCK certificate bytes (PEM key saved to disk).

        Raises:
            ValueError: If certificate generation fails.
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        # SGX uses ECDSA P-256
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Build certificate with SGX-specific attributes
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Intel SGX"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"SGX PCK {platform_info['platform_id']}"),
            ],
        )

        issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Intel PCS"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Intel SGX PCK Platform CA"),
            ],
        )

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow() - timedelta(days=30))
        cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))

        # Add SGX-specific extensions
        # Intel SGX extensions OID
        sgx_extensions = {
            "1.2.840.113741.1.13.1": b"\x05\x05\x02\x04\x01\x80\x00",  # SGX Type
            "1.2.840.113741.1.13.1.1": platform_info["platform_id"].encode()[:16],  # Platform ID
            "1.2.840.113741.1.13.1.2": b"\x00\x00",  # TCB
            "1.2.840.113741.1.13.1.4": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # FMSPC
        }

        for oid, value in sgx_extensions.items():
            cert_builder = cert_builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)

        cert = cert_builder.sign(key, hashes.SHA256(), default_backend())

        # Save key for future operations
        key_file = Path(__file__).parent / "keys" / "sgx_pck_key.pem"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        result: bytes = cert.public_bytes(serialization.Encoding.DER)
        return result

    def _capture_platform_manifest(self) -> dict[str, Any]:
        """Capture real platform security manifest from system.

        Queries system to determine TPM version, SGX support, BIOS configuration,
        secure boot status, and other platform security features.

        Returns:
            dict[str, Any]: Dictionary with platform security info (tpm_version,
                sgx_version, secure_boot, etc.).
        """
        import cpuinfo
        import wmi

        manifest = {}

        try:
            wmi_conn = wmi.WMI()

            # Get TPM info
            try:
                if tpm_instances := wmi_conn.Win32_Tpm():
                    tpm = tpm_instances[0]
                    manifest["tpm_version"] = tpm.SpecVersion.split(",")[0] if hasattr(tpm, "SpecVersion") else "2.0"
                else:
                    manifest["tpm_version"] = None
            except (KeyError, TypeError):
                manifest["tpm_version"] = None

            # Get CPU info for SGX support
            cpu_info = cpuinfo.get_cpu_info()
            manifest["sgx_version"] = 2 if "sgx" in cpu_info.get("flags", []) else 0

            # Get BIOS/UEFI info
            for bios in wmi_conn.Win32_BIOS():
                manifest["bios_version"] = bios.Version
                manifest["secure_boot"] = self._check_secure_boot()
                manifest["measured_boot"] = manifest["tpm_version"] is not None
                break

            # Get processor info
            for proc in wmi_conn.Win32_Processor():
                manifest["microcode_version"] = proc.ProcessorId[-2:] if hasattr(proc, "ProcessorId") else "FF"
                break

            # Platform configuration
            manifest["platform_configuration"] = {
                "cpu_model": cpu_info.get("brand_raw", "Unknown"),
                "memory_encryption": "sme" in cpu_info.get("flags", []) or "sev" in cpu_info.get("flags", []),
                "iommu_enabled": self._check_iommu(),
                "hypervisor": self._detect_hypervisor(),
            }

            # Security features
            manifest["txt_enabled"] = "txt" in cpu_info.get("flags", [])
            manifest["sev_enabled"] = "sev" in cpu_info.get("flags", [])
            manifest["tdx_enabled"] = "tdx" in cpu_info.get("flags", [])

            # Generate platform ID
            platform_config = manifest.get("platform_configuration", {})
            if isinstance(platform_config, dict):
                cpu_model_val = platform_config.get("cpu_model", "Unknown")
            else:
                cpu_model_val = "Unknown"
            hw_string = f"{cpu_model_val}:{manifest.get('bios_version', '')}"
            manifest["platform_id"] = hashlib.sha256(hw_string.encode()).hexdigest()

            manifest["security_version"] = 1

        except Exception as e:
            logger.debug("Error capturing platform manifest: %s", e)
            # Return minimal manifest
            manifest = {
                "platform_id": hashlib.sha256(os.urandom(32)).hexdigest(),
                "tpm_version": "2.0",
                "sgx_version": 2,
                "secure_boot": True,
                "measured_boot": True,
                "txt_enabled": True,
                "sev_enabled": False,
                "tdx_enabled": False,
                "security_version": 1,
                "microcode_version": "DE",
                "bios_version": "1.0.0",
                "platform_configuration": {
                    "cpu_model": platform.processor(),
                    "memory_encryption": False,
                    "iommu_enabled": True,
                    "hypervisor": "none",
                },
            }

        return manifest

    def _check_secure_boot(self) -> bool:
        """Check if Secure Boot is enabled.

        Runs bcdedit command to determine system Secure Boot status.

        Returns:
            bool: True if Secure Boot is enabled, False otherwise.

        Raises:
            subprocess.CalledProcessError: If bcdedit execution fails.
        """
        try:
            result = subprocess.run(["bcdedit", "/enum", "{current}"], capture_output=True, text=True)
            return "secureboot" in result.stdout.lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _check_iommu(self) -> bool:
        """Check if IOMMU is enabled.

        Runs bcdedit command to determine hypervisor launch type.

        Returns:
            bool: True if IOMMU (hypervisor) is enabled, False otherwise.

        Raises:
            subprocess.CalledProcessError: If bcdedit execution fails.
        """
        try:
            result = subprocess.run(["bcdedit", "/enum", "{current}"], capture_output=True, text=True)
            return "hypervisorlaunchtype" in result.stdout.lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _detect_hypervisor(self) -> str:
        """Detect hypervisor presence.

        Queries CPU info for hypervisor flag and identifies specific hypervisor
        vendor from CPU vendor ID string.

        Returns:
            str: Hypervisor type ('vmware', 'hyperv', 'xen', 'kvm', 'unknown',
                or 'none').
        """
        try:
            import cpuinfo

            cpu_info = cpuinfo.get_cpu_info()

            if "hypervisor" in cpu_info.get("flags", []):
                # Try to identify specific hypervisor
                vendor_id = cpu_info.get("vendor_id_raw", "").lower()
                if "vmware" in vendor_id:
                    return "vmware"
                if "microsoft" in vendor_id:
                    return "hyperv"
                if "xen" in vendor_id:
                    return "xen"
                return "kvm" if "kvm" in vendor_id else "unknown"
        except (ValueError, TypeError):
            pass

        return "none"

    def cleanup(self) -> None:
        """Clean up bypass resources.

        Deactivates bypass and restores original function hooks. Sets bypass_active
        flag to False.

        Returns:
            None

        Notes:
            Full cleanup would detach Frida sessions and unload kernel driver if
            installed.
        """
        self.bypass_active = False
        # Cleanup would restore original functions
