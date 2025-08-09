"""Protection analysis engine for binary protection detection and analysis.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import os
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

from ..utils.logger import get_logger


class ProtectionAnalyzer:
    """Comprehensive protection analysis engine for binary files."""

    def __init__(self, logger=None):
        """Initialize protection analyzer."""
        self.logger = logger or get_logger(__name__)
        self.protection_signatures = self._load_protection_signatures()
        self.entropy_threshold_high = 7.5
        self.entropy_threshold_low = 1.0
        
    def _load_protection_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load known protection system signatures."""
        return {
            "upx": {
                "name": "UPX Packer",
                "type": "packer",
                "signatures": [
                    b"UPX0", b"UPX1", b"UPX2", b"UPX!",
                    b"\x55\x50\x58\x30", b"\x55\x50\x58\x31"
                ],
                "strings": ["UPX", "upx"],
                "severity": "medium"
            },
            "vmprotect": {
                "name": "VMProtect",
                "type": "protector",
                "signatures": [
                    b"VMProtect",
                    b"\x60\xE8\x00\x00\x00\x00\x5D\x50\x51\x52\x53\x56\x57"
                ],
                "strings": ["VMProtect", "VMP"],
                "entropy_indicators": True,
                "severity": "high"
            },
            "themida": {
                "name": "Themida",
                "type": "protector",
                "signatures": [
                    b"Themida",
                    b"\xEB\x10\x00\x00\x00\x56\x69\x72\x74\x75\x61\x6C\x41\x6C\x6C\x6F\x63"
                ],
                "strings": ["Themida", "Oreans"],
                "severity": "high"
            },
            "asprotect": {
                "name": "ASProtect",
                "type": "protector", 
                "signatures": [
                    b"ASProtect",
                    b"\x68\x00\x00\x00\x00\x64\xFF\x35\x00\x00\x00\x00"
                ],
                "strings": ["ASProtect"],
                "severity": "medium"
            },
            "armadillo": {
                "name": "Armadillo",
                "type": "protector",
                "signatures": [
                    b"Armadillo",
                    b"\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00"
                ],
                "strings": ["Armadillo"],
                "severity": "medium"
            },
            "obsidium": {
                "name": "Obsidium",
                "type": "protector",
                "signatures": [
                    b"Obsidium",
                    b"\xEB\x02\xCD\x20\x03\xC0\x0F\x84"
                ],
                "strings": ["Obsidium"],
                "severity": "medium"
            },
            "dotfuscator": {
                "name": ".NET Reactor/Dotfuscator",
                "type": "obfuscator",
                "signatures": [
                    b"Dotfuscator", b".NET Reactor",
                    b"Eziriz", b"ConfuserEx"
                ],
                "strings": [".NET Reactor", "Dotfuscator", "ConfuserEx"],
                "severity": "medium"
            },
            "safengine": {
                "name": "SafeEngine Protector",
                "type": "protector",
                "signatures": [
                    b"SafeEngine",
                    b"\x60\xE8\x00\x00\x00\x00\x5D\x81\xED"
                ],
                "strings": ["SafeEngine"],
                "severity": "medium"
            }
        }
    
    def analyze(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Perform comprehensive protection analysis on a binary file."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return {"error": f"File not found: {file_path}"}
            
            self.logger.info(f"Starting protection analysis for: {file_path}")
            
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Basic file info
            file_info = self._get_file_info(file_path, file_data)
            
            # Protection detection
            detected_protections = self._detect_protections(file_data)
            
            # Entropy analysis
            entropy_analysis = self._analyze_entropy(file_data)
            
            # Section analysis (if supported)
            section_analysis = self._analyze_sections(file_path, file_data)
            
            # Import analysis
            import_analysis = self._analyze_imports(file_path, file_data)
            
            # Anti-analysis detection
            anti_analysis = self._detect_anti_analysis(file_data)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                detected_protections, entropy_analysis, section_analysis, anti_analysis
            )
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(
                detected_protections, entropy_analysis, anti_analysis
            )
            
            return {
                "file_info": file_info,
                "detected_protections": detected_protections,
                "entropy_analysis": entropy_analysis,
                "section_analysis": section_analysis,
                "import_analysis": import_analysis,
                "anti_analysis": anti_analysis,
                "recommendations": recommendations,
                "risk_score": risk_score,
                "analysis_timestamp": self._get_protection_timestamp()
            }
            
        except Exception as e:
            self.logger.error(f"Protection analysis failed: {e}")
            return {"error": str(e)}
    
    def _get_file_info(self, file_path: Path, file_data: bytes) -> Dict[str, Any]:
        """Get basic file information."""
        return {
            "filename": file_path.name,
            "filepath": str(file_path),
            "size": len(file_data),
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": hashlib.sha256(file_data).hexdigest(),
            "file_type": self._detect_file_type(file_data)
        }
    
    def _detect_file_type(self, file_data: bytes) -> str:
        """Detect file type from magic bytes."""
        if file_data.startswith(b'MZ'):
            return "PE"
        elif file_data.startswith(b'\x7fELF'):
            return "ELF" 
        elif file_data.startswith(b'\xfe\xed\xfa') or file_data.startswith(b'\xcf\xfa\xed\xfe'):
            return "Mach-O"
        elif file_data.startswith(b'\xd0\xcf\x11\xe0'):
            return "OLE2"
        elif file_data.startswith(b'PK'):
            return "ZIP/JAR"
        else:
            return "Unknown"
    
    def _detect_protections(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Detect protection systems using signatures and heuristics."""
        detections = []
        
        for protection_id, protection_info in self.protection_signatures.items():
            detected = False
            detection_details = {
                "name": protection_info["name"],
                "type": protection_info["type"],
                "severity": protection_info["severity"],
                "confidence": 0.0,
                "indicators": []
            }
            
            # Check binary signatures
            if "signatures" in protection_info:
                for signature in protection_info["signatures"]:
                    if signature in file_data:
                        detected = True
                        detection_details["confidence"] += 0.3
                        detection_details["indicators"].append(f"Binary signature: {signature.hex()}")
            
            # Check string signatures
            if "strings" in protection_info:
                for string_sig in protection_info["strings"]:
                    if string_sig.encode() in file_data:
                        detected = True
                        detection_details["confidence"] += 0.2
                        detection_details["indicators"].append(f"String signature: {string_sig}")
            
            # Check entropy indicators
            if protection_info.get("entropy_indicators"):
                entropy_score = self._calculate_section_entropy(file_data)
                if entropy_score > self.entropy_threshold_high:
                    detected = True
                    detection_details["confidence"] += 0.1
                    detection_details["indicators"].append(f"High entropy: {entropy_score:.2f}")
            
            if detected:
                detection_details["confidence"] = min(detection_details["confidence"], 1.0)
                detections.append(detection_details)
        
        # Custom heuristic detections
        heuristic_detections = self._heuristic_detection(file_data)
        detections.extend(heuristic_detections)
        
        return detections
    
    def _heuristic_detection(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Perform heuristic-based protection detection."""
        detections = []
        
        # Check for unusual section names (common in packed files)
        suspicious_section_names = [b'UPX0', b'UPX1', b'.vmp', b'.themida', b'.aspr', b'.obsid']
        for section_name in suspicious_section_names:
            if section_name in file_data:
                detections.append({
                    "name": f"Suspicious section: {section_name.decode('ascii', errors='ignore')}",
                    "type": "heuristic",
                    "severity": "medium",
                    "confidence": 0.6,
                    "indicators": [f"Suspicious section name: {section_name.decode('ascii', errors='ignore')}"]
                })
        
        # Check for anti-debug strings
        anti_debug_strings = [
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
            b"NtGlobalFlag", b"BeingDebugged", b"ProcessHeap",
            b"debugger", b"ollydbg", b"x64dbg", b"immunity"
        ]
        
        debug_indicators = []
        for debug_string in anti_debug_strings:
            if debug_string in file_data:
                debug_indicators.append(debug_string.decode('ascii', errors='ignore'))
        
        if debug_indicators:
            detections.append({
                "name": "Anti-debugging techniques",
                "type": "anti_analysis",
                "severity": "high",
                "confidence": 0.7,
                "indicators": [f"Anti-debug strings: {', '.join(debug_indicators)}"]
            })
        
        return detections
    
    def _analyze_entropy(self, file_data: bytes, block_size: int = 1024) -> Dict[str, Any]:
        """Analyze file entropy to detect packed/encrypted sections."""
        entropy_values = []
        
        for i in range(0, len(file_data), block_size):
            block = file_data[i:i + block_size]
            if len(block) < 64:
                continue
            
            # Calculate Shannon entropy
            byte_counts = {}
            for byte in block:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            entropy = 0.0
            for count in byte_counts.values():
                if count > 0:
                    probability = count / len(block)
                    entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
            
            entropy_values.append(entropy)
        
        if not entropy_values:
            return {"error": "Could not calculate entropy"}
        
        avg_entropy = sum(entropy_values) / len(entropy_values)
        max_entropy = max(entropy_values)
        min_entropy = min(entropy_values)
        
        high_entropy_blocks = sum(1 for e in entropy_values if e > self.entropy_threshold_high)
        low_entropy_blocks = sum(1 for e in entropy_values if e < self.entropy_threshold_low)
        
        return {
            "average_entropy": avg_entropy,
            "maximum_entropy": max_entropy,
            "minimum_entropy": min_entropy,
            "high_entropy_blocks": high_entropy_blocks,
            "low_entropy_blocks": low_entropy_blocks,
            "total_blocks": len(entropy_values),
            "entropy_distribution": entropy_values[:100],  # Limit for JSON serialization
            "assessment": self._assess_entropy(avg_entropy, high_entropy_blocks, len(entropy_values))
        }
    
    def _assess_entropy(self, avg_entropy: float, high_entropy_blocks: int, total_blocks: int) -> str:
        """Assess entropy analysis results."""
        if avg_entropy > 7.0 and high_entropy_blocks / total_blocks > 0.5:
            return "Highly likely packed/encrypted"
        elif avg_entropy > 6.0 and high_entropy_blocks / total_blocks > 0.3:
            return "Possibly packed/encrypted"
        elif avg_entropy < 2.0:
            return "Low entropy - possible padding or repeated data"
        else:
            return "Normal entropy distribution"
    
    def _calculate_section_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for data."""
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
        
        return entropy
    
    def _analyze_sections(self, file_path: Path, file_data: bytes) -> Dict[str, Any]:
        """Analyze file sections using appropriate parser."""
        try:
            if file_data.startswith(b'MZ') and HAS_PEFILE:
                return self._analyze_pe_sections(file_path)
            elif file_data.startswith(b'\x7fELF') and HAS_ELFTOOLS:
                return self._analyze_elf_sections(file_path)
            else:
                return {"error": "Unsupported file type or missing parser"}
        except Exception as e:
            return {"error": f"Section analysis failed: {e}"}
    
    def _analyze_pe_sections(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PE file sections."""
        try:
            pe = pefile.PE(str(file_path))
            sections = []
            
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "raw_address": section.PointerToRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": self._calculate_section_entropy(section.get_data())
                }
                
                # Analyze section characteristics
                characteristics = []
                if section.Characteristics & 0x20000000:
                    characteristics.append("executable")
                if section.Characteristics & 0x40000000:
                    characteristics.append("readable")
                if section.Characteristics & 0x80000000:
                    characteristics.append("writable")
                
                section_info["permissions"] = characteristics
                sections.append(section_info)
            
            pe.close()
            return {"sections": sections, "format": "PE"}
            
        except Exception as e:
            return {"error": f"PE analysis failed: {e}"}
    
    def _analyze_elf_sections(self, file_path: Path) -> Dict[str, Any]:
        """Analyze ELF file sections."""
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                sections = []
                
                for section in elf.iter_sections():
                    section_info = {
                        "name": section.name,
                        "type": section['sh_type'],
                        "address": hex(section['sh_addr']),
                        "size": section['sh_size'],
                        "offset": section['sh_offset'],
                        "flags": hex(section['sh_flags']),
                        "entropy": self._calculate_section_entropy(section.data())
                    }
                    sections.append(section_info)
                
                return {"sections": sections, "format": "ELF"}
                
        except Exception as e:
            return {"error": f"ELF analysis failed: {e}"}
    
    def _analyze_imports(self, file_path: Path, file_data: bytes) -> Dict[str, Any]:
        """Analyze imports for suspicious API usage."""
        try:
            if file_data.startswith(b'MZ') and HAS_PEFILE:
                return self._analyze_pe_imports(file_path)
            else:
                return {"error": "Import analysis not supported for this file type"}
        except Exception as e:
            return {"error": f"Import analysis failed: {e}"}
    
    def _analyze_pe_imports(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PE imports for suspicious functions."""
        try:
            pe = pefile.PE(str(file_path))
            imports = {}
            suspicious_functions = set()
            
            # Known suspicious functions
            suspicious_api_patterns = {
                "anti_debug": [
                    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "OutputDebugStringA"
                ],
                "crypto": [
                    "CryptAcquireContext", "CryptCreateHash", "CryptEncrypt",
                    "CryptDecrypt", "CryptGenKey"
                ],
                "injection": [
                    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                    "CreateRemoteThread", "SetWindowsHookEx"
                ],
                "persistence": [
                    "RegCreateKeyEx", "RegSetValueEx", "CreateService",
                    "OpenSCManager"
                ]
            }
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            functions.append({
                                "name": func_name,
                                "address": hex(imp.address) if imp.address else "N/A"
                            })
                            
                            # Check for suspicious functions
                            for category, sus_funcs in suspicious_api_patterns.items():
                                if func_name in sus_funcs:
                                    suspicious_functions.add((category, func_name))
                    
                    imports[dll_name] = functions
            
            pe.close()
            
            return {
                "imports": imports,
                "suspicious_functions": list(suspicious_functions),
                "total_imports": sum(len(funcs) for funcs in imports.values())
            }
            
        except Exception as e:
            return {"error": f"PE import analysis failed: {e}"}
    
    def _detect_anti_analysis(self, file_data: bytes) -> Dict[str, Any]:
        """Detect anti-analysis techniques."""
        techniques = []
        
        # VM detection strings
        vm_strings = [
            b"VMware", b"VirtualBox", b"QEMU", b"Xen", b"Hyper-V",
            b"vmmouse", b"vmtools", b"vboxservice"
        ]
        
        detected_vm_strings = []
        for vm_string in vm_strings:
            if vm_string in file_data:
                detected_vm_strings.append(vm_string.decode('ascii', errors='ignore'))
        
        if detected_vm_strings:
            techniques.append({
                "type": "VM Detection",
                "description": "Contains VM detection strings",
                "indicators": detected_vm_strings,
                "severity": "medium"
            })
        
        # Sandbox detection
        sandbox_strings = [
            b"sandbox", b"malware", b"virus", b"analysis",
            b"cuckoo", b"anubis", b"joebox"
        ]
        
        detected_sandbox_strings = []
        for sandbox_string in sandbox_strings:
            if sandbox_string in file_data:
                detected_sandbox_strings.append(sandbox_string.decode('ascii', errors='ignore'))
        
        if detected_sandbox_strings:
            techniques.append({
                "type": "Sandbox Evasion",
                "description": "Contains sandbox detection strings",
                "indicators": detected_sandbox_strings,
                "severity": "medium"
            })
        
        # Time delay patterns
        delay_patterns = [
            b"Sleep", b"WaitForSingleObject", b"timeGetTime",
            b"GetTickCount", b"QueryPerformanceCounter"
        ]
        
        detected_delay_patterns = []
        for delay_pattern in delay_patterns:
            if delay_pattern in file_data:
                detected_delay_patterns.append(delay_pattern.decode('ascii', errors='ignore'))
        
        if len(detected_delay_patterns) > 3:  # Multiple delay functions suggest evasion
            techniques.append({
                "type": "Time-based Evasion",
                "description": "Multiple time delay functions detected",
                "indicators": detected_delay_patterns,
                "severity": "low"
            })
        
        return {
            "techniques": techniques,
            "total_techniques": len(techniques),
            "risk_level": self._assess_anti_analysis_risk(techniques)
        }
    
    def _assess_anti_analysis_risk(self, techniques: List[Dict[str, Any]]) -> str:
        """Assess overall anti-analysis risk level."""
        if len(techniques) >= 3:
            return "high"
        elif len(techniques) >= 2:
            return "medium"
        elif len(techniques) >= 1:
            return "low"
        else:
            return "none"
    
    def _generate_recommendations(self, protections: List[Dict[str, Any]], 
                                  entropy: Dict[str, Any], sections: Dict[str, Any],
                                  anti_analysis: Dict[str, Any]) -> List[str]:
        """Generate analysis recommendations based on findings."""
        recommendations = []
        
        # Protection-based recommendations
        if protections:
            high_severity_protections = [p for p in protections if p["severity"] == "high"]
            if high_severity_protections:
                recommendations.append("High-strength protections detected. Consider specialized unpacking tools.")
            
            packer_detected = any(p["type"] == "packer" for p in protections)
            if packer_detected:
                recommendations.append("Packer detected. Try automated unpacking tools first.")
        
        # Entropy-based recommendations
        if entropy.get("assessment") == "Highly likely packed/encrypted":
            recommendations.append("High entropy indicates packing/encryption. Focus on unpacking analysis.")
        elif entropy.get("assessment") == "Low entropy - possible padding or repeated data":
            recommendations.append("Low entropy detected. Check for padding or null byte sections.")
        
        # Anti-analysis recommendations
        if anti_analysis.get("risk_level") == "high":
            recommendations.append("Multiple anti-analysis techniques detected. Use VM/sandbox-aware analysis.")
        elif anti_analysis.get("risk_level") in ["medium", "low"]:
            recommendations.append("Some evasion techniques detected. Monitor for analysis detection.")
        
        # General recommendations
        if not protections:
            recommendations.append("No obvious protections detected. Standard analysis techniques should work.")
        
        if not recommendations:
            recommendations.append("Standard binary analysis recommended.")
        
        return recommendations
    
    def _calculate_risk_score(self, protections: List[Dict[str, Any]],
                              entropy: Dict[str, Any], anti_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score."""
        score = 0
        max_score = 100
        
        # Protection score (0-40 points)
        protection_score = 0
        for protection in protections:
            if protection["severity"] == "high":
                protection_score += 15
            elif protection["severity"] == "medium":
                protection_score += 10
            elif protection["severity"] == "low":
                protection_score += 5
        
        protection_score = min(protection_score, 40)
        
        # Entropy score (0-30 points)
        entropy_score = 0
        if entropy.get("assessment") == "Highly likely packed/encrypted":
            entropy_score = 30
        elif entropy.get("assessment") == "Possibly packed/encrypted":
            entropy_score = 20
        elif entropy.get("assessment") == "Low entropy - possible padding or repeated data":
            entropy_score = 10
        
        # Anti-analysis score (0-30 points)
        anti_analysis_score = 0
        risk_level = anti_analysis.get("risk_level", "none")
        if risk_level == "high":
            anti_analysis_score = 30
        elif risk_level == "medium":
            anti_analysis_score = 20
        elif risk_level == "low":
            anti_analysis_score = 10
        
        total_score = protection_score + entropy_score + anti_analysis_score
        
        # Determine risk level
        if total_score >= 70:
            risk_level = "critical"
        elif total_score >= 50:
            risk_level = "high"
        elif total_score >= 30:
            risk_level = "medium"
        elif total_score >= 15:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "total_score": total_score,
            "max_score": max_score,
            "percentage": (total_score / max_score) * 100,
            "risk_level": risk_level,
            "breakdown": {
                "protection_score": protection_score,
                "entropy_score": entropy_score,
                "anti_analysis_score": anti_analysis_score
            }
        }
    
    def _get_protection_timestamp(self) -> str:
        """Get current timestamp for protection analysis."""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_protection_info(self, protection_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific protection system."""
        for protection_id, protection_info in self.protection_signatures.items():
            if (protection_info["name"].lower() == protection_name.lower() or
                protection_id.lower() == protection_name.lower()):
                return protection_info
        return None
    
    def add_custom_signature(self, name: str, signature_type: str, 
                             signatures: List[bytes], strings: List[str] = None,
                             severity: str = "medium") -> bool:
        """Add a custom protection signature."""
        try:
            custom_id = name.lower().replace(" ", "_")
            self.protection_signatures[custom_id] = {
                "name": name,
                "type": signature_type,
                "signatures": signatures,
                "strings": strings or [],
                "severity": severity
            }
            self.logger.info(f"Added custom signature: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add custom signature: {e}")
            return False