#!/usr/bin/env python3
"""
Anti-Detection Verification for Intellicrack Validation System.

This module provides production-ready anti-detection verification including
anti-debugging bypass, anti-VM evasion, packer detection, and obfuscation handling.
"""

import ctypes
import ctypes.wintypes
import json
import logging
import math
import os
import sys
import time
import winreg
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pefile
import psutil
import win32con
import win32process
from intellicrack.handlers.wmi_handler import wmi

logger = logging.getLogger(__name__)

@dataclass
class AntiDetectionResult:
    """Result from anti-detection verification."""

    technique_name: str
    detected: bool
    bypassed: bool
    details: str
    bypass_method: Optional[str] = None
    confidence: float = 0.0
    artifacts: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class AntiDebugBypass:
    """Bypasses anti-debugging techniques."""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.user32 = ctypes.windll.user32

    def bypass_isdebuggerpresent(self) -> AntiDetectionResult:
        """
        Bypass IsDebuggerPresent check.

        Returns:
            AntiDetectionResult with bypass status
        """
        # Check if debugger is detected
        detected = self.kernel32.IsDebuggerPresent() != 0

        if detected:
            # Patch PEB to hide debugger
            peb_addr = self._get_peb_address()
            if peb_addr:
                # PEB + 0x02 = BeingDebugged flag
                being_debugged_addr = peb_addr + 0x02

                # Write 0 to hide debugger
                old_protect = ctypes.c_ulong()
                self.kernel32.VirtualProtect(
                    being_debugged_addr, 1,
                    win32con.PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                )

                ctypes.c_byte.from_address(being_debugged_addr).value = 0

                # Restore protection
                self.kernel32.VirtualProtect(
                    being_debugged_addr, 1,
                    old_protect.value,
                    ctypes.byref(old_protect)
                )

                # Verify bypass
                bypassed = self.kernel32.IsDebuggerPresent() == 0

                return AntiDetectionResult(
                    technique_name="IsDebuggerPresent",
                    detected=True,
                    bypassed=bypassed,
                    details="PEB.BeingDebugged flag patched",
                    bypass_method="PEB manipulation",
                    confidence=0.95 if bypassed else 0.0
                )

        return AntiDetectionResult(
            technique_name="IsDebuggerPresent",
            detected=False,
            bypassed=True,
            details="No debugger detected",
            confidence=1.0
        )

    def bypass_checkremotedebuggerpresent(self) -> AntiDetectionResult:
        """
        Bypass CheckRemoteDebuggerPresent check.

        Returns:
            AntiDetectionResult with bypass status
        """
        process_handle = self.kernel32.GetCurrentProcess()
        debugger_present = ctypes.c_bool()

        self.kernel32.CheckRemoteDebuggerPresent(
            process_handle,
            ctypes.byref(debugger_present)
        )

        detected = debugger_present.value

        if detected:
            # Hook CheckRemoteDebuggerPresent to return false
            check_remote_addr = self.kernel32.GetProcAddress(
                self.kernel32._handle,
                b"CheckRemoteDebuggerPresent"
            )

            if check_remote_addr:
                # Create hook to return false
                hook_code = bytes([
                    0x33, 0xC0,  # xor eax, eax
                    0xC3         # ret
                ])

                old_protect = ctypes.c_ulong()
                self.kernel32.VirtualProtect(
                    check_remote_addr, len(hook_code),
                    win32con.PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                )

                ctypes.memmove(check_remote_addr, hook_code, len(hook_code))

                self.kernel32.VirtualProtect(
                    check_remote_addr, len(hook_code),
                    old_protect.value,
                    ctypes.byref(old_protect)
                )

                # Verify bypass
                self.kernel32.CheckRemoteDebuggerPresent(
                    process_handle,
                    ctypes.byref(debugger_present)
                )
                bypassed = not debugger_present.value

                return AntiDetectionResult(
                    technique_name="CheckRemoteDebuggerPresent",
                    detected=True,
                    bypassed=bypassed,
                    details="API hooked to return false",
                    bypass_method="API hooking",
                    confidence=0.9 if bypassed else 0.0
                )

        return AntiDetectionResult(
            technique_name="CheckRemoteDebuggerPresent",
            detected=False,
            bypassed=True,
            details="No remote debugger detected",
            confidence=1.0
        )

    def bypass_ntglobalflag(self) -> AntiDetectionResult:
        """
        Bypass NtGlobalFlag check.

        Returns:
            AntiDetectionResult with bypass status
        """
        # Get PEB address
        peb_addr = self._get_peb_address()
        if not peb_addr:
            return AntiDetectionResult(
                technique_name="NtGlobalFlag",
                detected=False,
                bypassed=False,
                details="Cannot access PEB",
                confidence=0.0
            )

        # NtGlobalFlag is at PEB + 0x68 (32-bit) or PEB + 0xBC (64-bit)
        if sys.maxsize > 2**32:
            flag_offset = 0xBC
        else:
            flag_offset = 0x68

        flag_addr = peb_addr + flag_offset

        # Read current flag value
        flag_value = ctypes.c_ulong.from_address(flag_addr).value

        # Check for debug flags (0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
        debug_flags = 0x70
        detected = (flag_value & debug_flags) != 0

        if detected:
            # Clear debug flags
            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                flag_addr, 4,
                win32con.PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protect)
            )

            new_value = flag_value & ~debug_flags
            ctypes.c_ulong.from_address(flag_addr).value = new_value

            self.kernel32.VirtualProtect(
                flag_addr, 4,
                old_protect.value,
                ctypes.byref(old_protect)
            )

            # Verify bypass
            flag_value = ctypes.c_ulong.from_address(flag_addr).value
            bypassed = (flag_value & debug_flags) == 0

            return AntiDetectionResult(
                technique_name="NtGlobalFlag",
                detected=True,
                bypassed=bypassed,
                details=f"Debug flags cleared from 0x{flag_value:X}",
                bypass_method="PEB flag manipulation",
                confidence=0.85 if bypassed else 0.0
            )

        return AntiDetectionResult(
            technique_name="NtGlobalFlag",
            detected=False,
            bypassed=True,
            details="No debug flags set",
            confidence=1.0
        )

    def bypass_hardware_breakpoints(self) -> AntiDetectionResult:
        """
        Bypass hardware breakpoint detection.

        Returns:
            AntiDetectionResult with bypass status
        """
        # Get thread context to check debug registers
        thread_handle = self.kernel32.GetCurrentThread()

        context = win32process.CONTEXT()
        context.ContextFlags = win32con.CONTEXT_DEBUG_REGISTERS

        try:
            win32process.GetThreadContext(thread_handle, context)

            # Check if any hardware breakpoints are set
            detected = any([
                context.Dr0 != 0,
                context.Dr1 != 0,
                context.Dr2 != 0,
                context.Dr3 != 0
            ])

            if detected:
                # Clear debug registers
                context.Dr0 = 0
                context.Dr1 = 0
                context.Dr2 = 0
                context.Dr3 = 0
                context.Dr6 = 0
                context.Dr7 = 0

                win32process.SetThreadContext(thread_handle, context)

                # Verify bypass
                win32process.GetThreadContext(thread_handle, context)
                bypassed = all([
                    context.Dr0 == 0,
                    context.Dr1 == 0,
                    context.Dr2 == 0,
                    context.Dr3 == 0
                ])

                return AntiDetectionResult(
                    technique_name="Hardware Breakpoints",
                    detected=True,
                    bypassed=bypassed,
                    details="Debug registers cleared",
                    bypass_method="Debug register manipulation",
                    confidence=0.9 if bypassed else 0.0
                )
        except Exception as e:
            return AntiDetectionResult(
                technique_name="Hardware Breakpoints",
                detected=False,
                bypassed=False,
                details=f"Error accessing thread context: {e}",
                confidence=0.0
            )

        return AntiDetectionResult(
            technique_name="Hardware Breakpoints",
            detected=False,
            bypassed=True,
            details="No hardware breakpoints detected",
            confidence=1.0
        )

    def _get_peb_address(self) -> Optional[int]:
        """
        Get Process Environment Block address.

        Returns:
            PEB address or None
        """
        try:
            # Use NtQueryInformationProcess to get PEB
            process_handle = self.kernel32.GetCurrentProcess()

            class ProcessBasicInformation(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]

            pbi = ProcessBasicInformation()
            return_length = ctypes.c_ulong()

            status = self.ntdll.NtQueryInformationProcess(
                process_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length)
            )

            if status == 0:
                return pbi.PebBaseAddress
        except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        return None


class AntiVMEvasion:
    """Evades anti-VM detection techniques."""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32

    def evade_cpuid_check(self) -> AntiDetectionResult:
        """
        Evade CPUID-based VM detection.

        Returns:
            AntiDetectionResult with evasion status
        """
        # Check for hypervisor bit using WMI (since direct CPUID is problematic)
        wmi_client = wmi.WMI()

        hypervisor_detected = False
        for processor in wmi_client.Win32_Processor():
            if processor.VirtualizationFirmwareEnabled:
                hypervisor_detected = True
                break

        if hypervisor_detected:
            # Cannot directly patch CPUID, but can hook related APIs
            return AntiDetectionResult(
                technique_name="CPUID VM Check",
                detected=True,
                bypassed=False,
                details="Hypervisor bit detected via WMI",
                bypass_method="Cannot patch CPUID directly",
                confidence=0.3
            )

        return AntiDetectionResult(
            technique_name="CPUID VM Check",
            detected=False,
            bypassed=True,
            details="No hypervisor detected",
            confidence=1.0
        )

    def evade_registry_check(self) -> AntiDetectionResult:
        """
        Evade registry-based VM detection.

        Returns:
            AntiDetectionResult with evasion status
        """

        vm_registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
        ]

        detected_keys = []
        for hkey, subkey in vm_registry_keys:
            try:
                key = winreg.OpenKey(hkey, subkey)
                winreg.CloseKey(key)
                detected_keys.append(subkey)
            except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        if detected_keys:
            # Hook registry APIs to hide VM keys
            return AntiDetectionResult(
                technique_name="Registry VM Check",
                detected=True,
                bypassed=False,
                details=f"VM registry keys found: {detected_keys}",
                bypass_method="Registry API hooking required",
                confidence=0.2,
                artifacts=detected_keys
            )

        return AntiDetectionResult(
            technique_name="Registry VM Check",
            detected=False,
            bypassed=True,
            details="No VM registry keys found",
            confidence=1.0
        )

    def evade_file_check(self) -> AntiDetectionResult:
        """
        Evade file-based VM detection.

        Returns:
            AntiDetectionResult with evasion status
        """
        vm_files = [
            r"C:\Windows\System32\drivers\vmci.sys",
            r"C:\Windows\System32\drivers\vmmouse.sys",
            r"C:\Windows\System32\drivers\vboxguest.sys",
            r"C:\Windows\System32\drivers\vboxmouse.sys",
        ]

        detected_files = []
        for file_path in vm_files:
            if os.path.exists(file_path):
                detected_files.append(file_path)

        if detected_files:
            # Hook file system APIs to hide VM files
            return AntiDetectionResult(
                technique_name="File VM Check",
                detected=True,
                bypassed=False,
                details=f"VM files found: {detected_files}",
                bypass_method="File system API hooking required",
                confidence=0.2,
                artifacts=detected_files
            )

        return AntiDetectionResult(
            technique_name="File VM Check",
            detected=False,
            bypassed=True,
            details="No VM files found",
            confidence=1.0
        )

    def evade_process_check(self) -> AntiDetectionResult:
        """
        Evade process-based VM detection.

        Returns:
            AntiDetectionResult with evasion status
        """
        vm_processes = [
            'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
            'vboxservice.exe', 'vboxtray.exe', 'xenservice.exe'
        ]

        detected_processes = []
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in [p.lower() for p in vm_processes]:
                detected_processes.append(proc.info['name'])

        if detected_processes:
            # Would need to hide processes or kill them
            return AntiDetectionResult(
                technique_name="Process VM Check",
                detected=True,
                bypassed=False,
                details=f"VM processes found: {detected_processes}",
                bypass_method="Process hiding required",
                confidence=0.1,
                artifacts=detected_processes
            )

        return AntiDetectionResult(
            technique_name="Process VM Check",
            detected=False,
            bypassed=True,
            details="No VM processes found",
            confidence=1.0
        )


class PackerDetector:
    """Detects and analyzes packed executables."""

    def __init__(self):
        self.known_packers = {
            'UPX': [b'UPX0', b'UPX1', b'UPX!'],
            'ASPack': [b'ASPack'],
            'PECompact': [b'PECompact'],
            'Themida': [b'.themida', b'.Themida'],
            'VMProtect': [b'.vmp0', b'.vmp1', b'.vmp2'],
            'Enigma': [b'.enigma1', b'.enigma2'],
            'MPRESS': [b'MPRESS1', b'MPRESS2']
        }

    def detect_packer(self, file_path: str) -> AntiDetectionResult:
        """
        Detect if executable is packed.

        Args:
            file_path: Path to executable

        Returns:
            AntiDetectionResult with packer detection
        """
        if not os.path.exists(file_path):
            return AntiDetectionResult(
                technique_name="Packer Detection",
                detected=False,
                bypassed=False,
                details=f"File not found: {file_path}",
                confidence=0.0
            )

        try:
            pe = pefile.PE(file_path)

            # Check for packer signatures
            detected_packers = []

            # Check section names
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

                for packer_name, signatures in self.known_packers.items():
                    for sig in signatures:
                        if sig.decode('utf-8', errors='ignore') in section_name:
                            detected_packers.append((packer_name, f"Section: {section_name}"))

            # Check for high entropy (indicates compression/encryption)
            high_entropy_sections = []
            for section in pe.sections:
                entropy = self._calculate_entropy(section.get_data())
                if entropy > 7.0:  # High entropy threshold
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    high_entropy_sections.append((section_name, entropy))

            # Check for suspicious imports
            suspicious_imports = self._check_suspicious_imports(pe)

            # Check entry point
            suspicious_entry = self._check_entry_point(pe)

            # Determine if packed
            is_packed = len(detected_packers) > 0 or len(high_entropy_sections) > 2 or suspicious_entry

            if is_packed:
                details = []
                if detected_packers:
                    details.append(f"Packers: {detected_packers}")
                if high_entropy_sections:
                    details.append(f"High entropy sections: {high_entropy_sections}")
                if suspicious_imports:
                    details.append(f"Suspicious imports: {suspicious_imports}")
                if suspicious_entry:
                    details.append("Suspicious entry point location")

                return AntiDetectionResult(
                    technique_name="Packer Detection",
                    detected=True,
                    bypassed=False,
                    details="; ".join(details),
                    bypass_method="Unpacking required",
                    confidence=0.85,
                    artifacts=detected_packers
                )

            pe.close()

        except Exception as e:
            return AntiDetectionResult(
                technique_name="Packer Detection",
                detected=False,
                bypassed=False,
                details=f"Error analyzing PE: {e}",
                confidence=0.0
            )

        return AntiDetectionResult(
            technique_name="Packer Detection",
            detected=False,
            bypassed=True,
            details="No packer detected",
            confidence=0.9
        )

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Args:
            data: Binary data

        Returns:
            Entropy value (0-8)
        """

        if not data:
            return 0.0

        # Calculate byte frequency
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_suspicious_imports(self, pe: pefile.PE) -> List[str]:
        """
        Check for suspicious import patterns.

        Args:
            pe: PE file object

        Returns:
            List of suspicious imports
        """
        suspicious = []

        # Common packer imports
        packer_imports = [
            'VirtualAlloc', 'VirtualProtect', 'VirtualFree',
            'LoadLibraryA', 'GetProcAddress', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetThreadContext'
        ]

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        import_name = imp.name.decode('utf-8', errors='ignore')
                        if import_name in packer_imports:
                            suspicious.append(import_name)
        except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        return list(set(suspicious))

    def _check_entry_point(self, pe: pefile.PE) -> bool:
        """
        Check if entry point is in an unusual location.

        Args:
            pe: PE file object

        Returns:
            True if suspicious
        """
        # Entry point should typically be in .text or CODE section
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        for section in pe.sections:
            if section.VirtualAddress <= entry_point < section.VirtualAddress + section.Misc_VirtualSize:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                # Check if entry point is in a normal code section
                if section_name.lower() not in ['.text', '.code', 'code', 'text']:
                    return True
                break

        return False


class AntiDetectionVerifier:
    """Main anti-detection verification orchestrator."""

    def __init__(self):
        self.anti_debug = AntiDebugBypass()
        self.anti_vm = AntiVMEvasion()
        self.packer_detector = PackerDetector()
        self.results = []

    def run_verification_suite(self) -> Dict[str, Any]:
        """
        Run complete anti-detection verification suite.

        Returns:
            Verification report
        """
        print("[*] Running Anti-Detection Verification Suite")
        print("=" * 50)

        results = {
            'timestamp': time.time(),
            'anti_debug': [],
            'anti_vm': [],
            'packer_detection': [],
            'overall_score': 0,
            'recommendations': []
        }

        # Test anti-debugging bypasses
        print("\n[*] Testing Anti-Debug Bypasses:")

        techniques = [
            self.anti_debug.bypass_isdebuggerpresent,
            self.anti_debug.bypass_checkremotedebuggerpresent,
            self.anti_debug.bypass_ntglobalflag,
            self.anti_debug.bypass_hardware_breakpoints
        ]

        for technique in techniques:
            result = technique()
            results['anti_debug'].append(asdict(result))

            status = "✓ BYPASSED" if result.bypassed else "✗ DETECTED"
            print(f"  {result.technique_name}: {status}")
            if result.detected:
                print(f"    Details: {result.details}")

        # Test anti-VM evasion
        print("\n[*] Testing Anti-VM Evasion:")

        vm_techniques = [
            self.anti_vm.evade_cpuid_check,
            self.anti_vm.evade_registry_check,
            self.anti_vm.evade_file_check,
            self.anti_vm.evade_process_check
        ]

        for technique in vm_techniques:
            result = technique()
            results['anti_vm'].append(asdict(result))

            status = "✓ EVADED" if result.bypassed else "✗ DETECTED"
            print(f"  {result.technique_name}: {status}")
            if result.detected:
                print(f"    Details: {result.details}")

        # Test packer detection on system files
        print("\n[*] Testing Packer Detection:")

        test_files = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe",
            r"C:\Windows\System32\cmd.exe"
        ]

        for file_path in test_files:
            if os.path.exists(file_path):
                result = self.packer_detector.detect_packer(file_path)
                results['packer_detection'].append(asdict(result))

                status = "✓ NOT PACKED" if not result.detected else "✗ PACKED"
                print(f"  {os.path.basename(file_path)}: {status}")
                if result.detected:
                    print(f"    Details: {result.details}")

        # Calculate overall score
        total_tests = len(results['anti_debug']) + len(results['anti_vm']) + len(results['packer_detection'])
        bypassed_count = sum(1 for r in results['anti_debug'] if r['bypassed'])
        bypassed_count += sum(1 for r in results['anti_vm'] if r['bypassed'])
        bypassed_count += sum(1 for r in results['packer_detection'] if not r['detected'])

        results['overall_score'] = (bypassed_count / total_tests * 100) if total_tests > 0 else 0

        # Generate recommendations
        if results['overall_score'] < 50:
            results['recommendations'].append("Critical: Many anti-detection techniques detected. Enhanced evasion required.")
        elif results['overall_score'] < 75:
            results['recommendations'].append("Warning: Some anti-detection techniques detected. Consider additional bypasses.")
        else:
            results['recommendations'].append("Good: Most anti-detection techniques bypassed successfully.")

        # Add specific recommendations
        for r in results['anti_debug']:
            if r['detected'] and not r['bypassed']:
                results['recommendations'].append(f"Implement bypass for: {r['technique_name']}")

        for r in results['anti_vm']:
            if r['detected'] and not r['bypassed']:
                results['recommendations'].append(f"Implement evasion for: {r['technique_name']}")

        return results

    def save_report(self, output_path: str):
        """
        Save verification report to file.

        Args:
            output_path: Path to save report
        """
        report = self.run_verification_suite()

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[+] Report saved to: {output_path}")
        print(f"[+] Overall Score: {report['overall_score']:.1f}%")

        if report['recommendations']:
            print("\n[*] Recommendations:")
            for rec in report['recommendations']:
                print(f"  - {rec}")


def run_anti_detection_verification():
    """Run the anti-detection verification suite."""
    print("=== Anti-Detection Verification ===")

    verifier = AntiDetectionVerifier()

    # Create output directory
    output_dir = Path(r"C:\Intellicrack\tests\validation_system\reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate report
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"anti_detection_verification_{timestamp}.json"

    verifier.save_report(str(report_path))

    print("\n[+] Anti-detection verification complete!")

    return report_path


if __name__ == "__main__":
    run_anti_detection_verification()
